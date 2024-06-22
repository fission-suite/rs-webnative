//! File system metadata.

use anyhow::{bail, Result};
use chrono::{DateTime, TimeZone, Utc};
use ipld_core::ipld::Ipld;
use serde::{
    de::{DeserializeOwned, Error as DeError},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{collections::BTreeMap, fmt::Display};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// The type of file system node.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum NodeType {
    PublicFile,
    PublicDirectory,
    PrivateFile,
    PrivateDirectory,
    TemporalSharePointer,
    SnapshotSharePointer,
}

impl Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NodeType::PublicFile => "wnfs/pub/file",
            NodeType::PublicDirectory => "wnfs/pub/dir",
            NodeType::PrivateFile => "wnfs/priv/file",
            NodeType::PrivateDirectory => "wnfs/priv/dir",
            NodeType::TemporalSharePointer => "wnfs/share/temporal",
            NodeType::SnapshotSharePointer => "wnfs/share/snapshot",
        })
    }
}

/// The metadata of a node in the WNFS file system.
///
/// # Examples
///
/// ```
/// use wnfs_common::Metadata;
/// use chrono::Utc;
///
/// let metadata = Metadata::new(Utc::now());
///
/// println!("{:?}", metadata);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata(pub BTreeMap<String, Ipld>);

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl Metadata {
    /// Creates a new metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs_common::Metadata;
    /// use chrono::Utc;
    ///
    /// let metadata = Metadata::new(Utc::now());
    ///
    /// println!("{:?}", metadata);
    /// ```
    pub fn new(time: DateTime<Utc>) -> Self {
        let time = time.timestamp();
        Self(BTreeMap::from([
            ("created".into(), time.into()),
            ("modified".into(), time.into()),
        ]))
    }

    /// Updates modified time.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs_common::Metadata;
    /// use chrono::{Utc, TimeZone, Duration};
    ///
    /// let mut metadata = Metadata::new(Utc::now());
    /// let time = Utc::now() + Duration::days(1);
    ///
    /// metadata.upsert_mtime(time);
    ///
    /// let imprecise_time = Utc.timestamp_opt(time.timestamp(), 0).single();
    /// assert_eq!(metadata.get_modified(), imprecise_time);
    /// ```
    pub fn upsert_mtime(&mut self, time: DateTime<Utc>) {
        self.0.insert("modified".into(), time.timestamp().into());
    }

    /// Returns the created time.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs_common::Metadata;
    /// use chrono::{Utc, TimeZone};
    ///
    /// let time = Utc::now();
    /// let metadata = Metadata::new(time);
    ///
    /// let imprecise_time = Utc.timestamp_opt(time.timestamp(), 0).single();
    /// assert_eq!(metadata.get_created(), imprecise_time);
    /// ```
    ///
    /// Will return `None` if there's no created metadata on the
    /// node or if it's not a second-based POSIX timestamp integer.
    pub fn get_created(&self) -> Option<DateTime<Utc>> {
        self.0.get("created").and_then(|ipld| match ipld {
            Ipld::Integer(i) => Utc.timestamp_opt(i64::try_from(*i).ok()?, 0).single(),
            _ => None,
        })
    }

    /// Returns the modified time.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs_common::Metadata;
    /// use chrono::{Utc, TimeZone};
    ///
    /// let time = Utc::now();
    /// let metadata = Metadata::new(time);
    ///
    /// let imprecise_time = Utc.timestamp_opt(time.timestamp(), 0).single();
    /// assert_eq!(metadata.get_modified(), imprecise_time);
    /// ```
    ///
    /// Will return `None` if there's no created metadata on the
    /// node or if it's not a second-based POSIX timestamp integer.
    pub fn get_modified(&self) -> Option<DateTime<Utc>> {
        self.0.get("modified").and_then(|ipld| match ipld {
            Ipld::Integer(i) => Utc.timestamp_opt(i64::try_from(*i).ok()?, 0).single(),
            _ => None,
        })
    }

    /// Inserts a key-value pair into the metadata.
    /// If the key already existed, the value is updated, and the old value is returned.
    ///
    /// # Examples
    /// ```
    /// use wnfs_common::Metadata;
    /// use chrono::Utc;
    /// use ipld_core::ipld::Ipld;
    ///
    /// let mut metadata = Metadata::new(Utc::now());
    /// metadata.put("foo", Ipld::String("bar".into()));
    /// assert_eq!(metadata.0.get("foo"), Some(&Ipld::String("bar".into())));
    /// metadata.put("foo", Ipld::String("baz".into()));
    /// assert_eq!(metadata.0.get("foo"), Some(&Ipld::String("baz".into())));
    /// ```
    ///
    /// Returns (self, old_value), where old_value is `None` if the key did not exist prior to this call.
    pub fn put(&mut self, key: &str, value: Ipld) -> Option<Ipld> {
        self.0.insert(key.into(), value)
    }

    /// Returns metadata value behind given key.
    pub fn get(&self, key: &str) -> Option<&Ipld> {
        self.0.get(key)
    }

    /// Serializes and inserts given value at given key in metadata.
    pub fn put_serializable(&mut self, key: &str, value: impl Serialize) -> Result<Option<Ipld>> {
        let serialized = ipld_core::serde::to_ipld(value)?;
        Ok(self.put(key, serialized))
    }

    /// Returns deserialized metadata value behind given key.
    pub fn get_deserializable<D: DeserializeOwned>(&self, key: &str) -> Option<Result<D>> {
        self.get(key)
            .map(|ipld| Ok(ipld_core::serde::from_ipld(ipld.clone())?))
    }

    /// Deletes a key from the metadata.
    ///
    /// # Examples
    /// ```
    /// use wnfs_common::Metadata;
    /// use chrono::Utc;
    /// use ipld_core::ipld::Ipld;
    ///
    /// let mut metadata = Metadata::new(Utc::now());
    /// metadata.put("foo", Ipld::String("bar".into()));
    /// assert_eq!(metadata.0.get("foo"), Some(&Ipld::String("bar".into())));
    /// metadata.delete("foo");
    /// assert_eq!(metadata.0.get("foo"), None);
    /// ```
    ///
    /// Returns `Some<Ipld>` if the key existed prior to this call, otherwise None.
    pub fn delete(&mut self, key: &str) -> Option<Ipld> {
        self.0.remove(key)
    }

    /// Updates this metadata with the contents of another metadata. merge strategy is to take theirs.
    ///
    /// # Examples
    /// ```
    /// use wnfs_common::Metadata;
    /// use chrono::Utc;
    /// use ipld_core::ipld::Ipld;
    ///
    /// let mut metadata1 = Metadata::new(Utc::now());
    /// metadata1.put("foo", Ipld::String("bar".into()));
    /// let mut metadata2 = Metadata::new(Utc::now());
    /// metadata2.put("foo", Ipld::String("baz".into()));
    /// metadata1.update(&metadata2);
    /// assert_eq!(metadata1.0.get("foo"), Some(&Ipld::String("baz".into())));
    /// ```
    pub fn update(&mut self, other: &Self) {
        for (key, value) in other.0.iter() {
            self.0.insert(key.clone(), value.clone());
        }
    }

    pub(crate) fn hash(&self) -> Result<blake3::Hash> {
        let vec = serde_ipld_dagcbor::to_vec(self)?;
        Ok(blake3::hash(&vec))
    }

    /// Tie break this node with another one.
    /// Used for conflict reconciliation. We don't merge the two metadata maps
    /// together (yet), instead we compare their hashes. The one with the lower hash
    /// survives.
    pub fn tie_break_with(&mut self, other: &Self) -> Result<()> {
        if self.hash()?.as_bytes() > other.hash()?.as_bytes() {
            self.0 = other.0.clone();
        }

        Ok(())
    }
}

impl TryFrom<&Ipld> for NodeType {
    type Error = anyhow::Error;

    fn try_from(ipld: &Ipld) -> Result<Self> {
        match ipld {
            Ipld::String(s) => NodeType::try_from(s.as_str()),
            other => bail!("Expected `Ipld::String` got {:#?}", other),
        }
    }
}

impl TryFrom<&str> for NodeType {
    type Error = anyhow::Error;

    fn try_from(name: &str) -> Result<Self> {
        Ok(match name.to_lowercase().as_str() {
            "wnfs/priv/dir" => NodeType::PrivateDirectory,
            "wnfs/priv/file" => NodeType::PrivateFile,
            "wnfs/pub/dir" => NodeType::PublicDirectory,
            "wnfs/pub/file" => NodeType::PublicFile,
            "wnfs/share/temporal" => NodeType::TemporalSharePointer,
            "wnfs/share/snapshot" => NodeType::SnapshotSharePointer,
            _ => bail!("Unknown UnixFsNodeKind: {}", name),
        })
    }
}

impl From<&NodeType> for String {
    fn from(r#type: &NodeType) -> Self {
        match r#type {
            NodeType::PrivateDirectory => "wnfs/priv/dir".into(),
            NodeType::PrivateFile => "wnfs/priv/file".into(),
            NodeType::PublicDirectory => "wnfs/pub/dir".into(),
            NodeType::PublicFile => "wnfs/pub/file".into(),
            NodeType::TemporalSharePointer => "wnfs/share/temporal".into(),
            NodeType::SnapshotSharePointer => "wnfs/share/snapshot".into(),
        }
    }
}

impl Serialize for NodeType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        String::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let r#type = String::deserialize(deserializer)?;
        r#type.as_str().try_into().map_err(DeError::custom)
    }
}
//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::Metadata;
    use chrono::Utc;
    use testresult::TestResult;

    #[async_std::test]
    async fn metadata_can_encode_decode_as_cbor() -> TestResult {
        let metadata = Metadata::new(Utc::now());

        let encoded_metadata = serde_ipld_dagcbor::to_vec(&metadata)?;
        let decoded_metadata: Metadata = serde_ipld_dagcbor::from_slice(&encoded_metadata)?;

        assert_eq!(metadata, decoded_metadata);

        Ok(())
    }
}
