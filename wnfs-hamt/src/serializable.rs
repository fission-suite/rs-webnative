use crate::constants::HAMT_BITMASK_BYTE_SIZE;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use wnfs_common::ipld_core::cid::Cid;

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HamtSerializable<K, V> {
    pub(crate) root: NodeSerializable<K, V>,
    pub(crate) version: Version,
    pub(crate) structure: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NodeSerializable<K, V>(
    pub(crate) ByteArray<HAMT_BITMASK_BYTE_SIZE>,
    pub(crate) Vec<PointerSerializable<K, V>>,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum PointerSerializable<K, V> {
    Values(Vec<(K, V)>),
    Link(Cid),
}

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;

    #[test]
    fn test_pointer_link_roundtrip() -> TestResult {
        let pointers = PointerSerializable::<String, String>::Link(Cid::default());
        let bytes = serde_ipld_dagcbor::to_vec(&pointers)?;

        let pointers_back: PointerSerializable<String, String> =
            serde_ipld_dagcbor::from_slice(&bytes)?;

        assert_eq!(pointers, pointers_back);

        Ok(())
    }

    #[test]
    fn test_pointer_values_roundtrip() -> TestResult {
        let pointers = PointerSerializable::Values(vec![(1, 10), (2, 20), (3, 30)]);
        let bytes = serde_ipld_dagcbor::to_vec(&pointers)?;

        let pointers_back: PointerSerializable<u32, u32> = serde_ipld_dagcbor::from_slice(&bytes)?;

        assert_eq!(pointers, pointers_back);

        Ok(())
    }
}
