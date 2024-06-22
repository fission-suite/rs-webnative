use crate::{
    error::AccessKeyError,
    private::{PrivateRef, SnapshotKey, TemporalKey},
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use wnfs_common::{ipld_core::cid::Cid, HashOutput};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessKey {
    #[serde(rename = "wnfs/share/temporal")]
    Temporal(TemporalAccessKey),
    #[serde(rename = "wnfs/share/snapshot")]
    Snapshot(SnapshotAccessKey),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TemporalAccessKey {
    #[serde(with = "serde_byte_array")]
    pub(crate) label: HashOutput,
    pub(crate) content_cid: Cid,
    pub(crate) temporal_key: TemporalKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotAccessKey {
    #[serde(with = "serde_byte_array")]
    pub label: HashOutput,
    pub content_cid: Cid,
    pub snapshot_key: SnapshotKey,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl AccessKey {
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(serde_ipld_dagcbor::from_slice(bytes.as_ref())?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_ipld_dagcbor::to_vec(self)?)
    }

    pub fn get_label(&self) -> &HashOutput {
        match self {
            Self::Temporal(key) => &key.label,
            Self::Snapshot(key) => &key.label,
        }
    }

    pub fn get_temporal_key(&self) -> Result<&TemporalKey> {
        let Self::Temporal(key) = self else {
            bail!(AccessKeyError::UnsupportedSnapshotPrivateRefDerive)
        };

        Ok(&key.temporal_key)
    }

    pub fn get_snapshot_key(&self) -> SnapshotKey {
        match self {
            Self::Temporal(t) => t.temporal_key.derive_snapshot_key(),
            Self::Snapshot(s) => s.snapshot_key.clone(),
        }
    }

    pub fn get_content_cid(&self) -> &Cid {
        match self {
            Self::Temporal(key) => &key.content_cid,
            Self::Snapshot(key) => &key.content_cid,
        }
    }

    pub(crate) fn derive_private_ref(&self) -> Result<PrivateRef> {
        // TODO(appcypher): SnapshotAccessKey currently not supported for PrivateRef.
        let Self::Temporal(key) = self else {
            bail!(AccessKeyError::UnsupportedSnapshotPrivateRefDerive)
        };

        Ok(PrivateRef::with_temporal_key(
            key.label,
            key.temporal_key.clone(),
            key.content_cid,
        ))
    }
}

impl From<&PrivateRef> for TemporalAccessKey {
    fn from(private_ref: &PrivateRef) -> Self {
        Self {
            label: private_ref.label,
            content_cid: private_ref.content_cid,
            temporal_key: private_ref.temporal_key.clone(),
        }
    }
}

impl From<&PrivateRef> for SnapshotAccessKey {
    fn from(private_ref: &PrivateRef) -> Self {
        Self {
            label: private_ref.label,
            content_cid: private_ref.content_cid,
            snapshot_key: private_ref.temporal_key.derive_snapshot_key(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use testresult::TestResult;
    use wnfs_common::ipld_core::serde;

    #[async_std::test]
    async fn test_access_key() -> TestResult {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);

        let private_ref =
            PrivateRef::with_temporal_key(rng.gen(), TemporalKey(rng.gen()), Cid::default());

        let temporal_access_key = AccessKey::Temporal(TemporalAccessKey::from(&private_ref));
        let snapshot_access_key = AccessKey::Snapshot(SnapshotAccessKey::from(&private_ref));

        let temp_key = as_dag_json_value(&temporal_access_key)?;
        let snap_key = as_dag_json_value(&snapshot_access_key)?;

        insta::assert_json_snapshot!(temp_key);
        insta::assert_json_snapshot!(snap_key);

        Ok(())
    }

    fn as_dag_json_value(s: impl Serialize) -> Result<serde_json::Value> {
        let dag_json = serde_ipld_dagjson::to_vec(&serde::to_ipld(s)?)?;
        let value = serde_json::from_slice(&dag_json)?;
        Ok(value)
    }
}
