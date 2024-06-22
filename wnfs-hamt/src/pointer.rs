use super::{error::HamtError, hash::Hasher, Node, HAMT_VALUES_BUCKET_SIZE};
use crate::serializable::PointerSerializable;
use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use wnfs_common::{
    blockstore::Blockstore,
    ipld_core::cid::Cid,
    utils::{error, Arc, CondSync},
    Link, Storable,
};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// A key-value pair type.
///
/// # Examples
///
/// ```
/// use wnfs_hamt::Pair;
///
/// let pair = Pair::new("key", "value");
///
/// assert_eq!(pair.key, "key");
/// assert_eq!(pair.value, "value");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair<K, V> {
    pub key: K,
    pub value: V,
}

/// Each bit in the bitmask of a node maps a `Pointer` in the HAMT structure.
/// A `Pointer` can be either a link to a child node or a collection of key-value pairs.
pub(crate) enum Pointer<K: CondSync, V: CondSync, H: Hasher + CondSync> {
    Values(Vec<Pair<K, V>>),
    Link(Link<Arc<Node<K, V, H>>>),
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<K, V> Pair<K, V> {
    /// Create a new `Pair` from a key and value.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs_hamt::Pair;
    ///
    /// let pair = Pair::new("key", "value");
    ///
    /// assert_eq!(pair.key, "key");
    /// assert_eq!(pair.value, "value");
    /// ```
    pub fn new(key: K, value: V) -> Self {
        Self { key, value }
    }
}

impl<K: CondSync, V: CondSync, H: Hasher + CondSync> Pointer<K, V, H> {
    /// Converts a Link pointer to a canonical form to ensure consistent tree representation after deletes.
    pub async fn canonicalize(self, store: &impl Blockstore) -> Result<Option<Self>>
    where
        K: Storable + Clone + AsRef<[u8]>,
        V: Storable + Clone,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
        H: CondSync,
    {
        match self {
            Pointer::Link(link) => {
                let node = link.resolve_owned_value(store).await?;
                match node.pointers.len() {
                    0 => Ok(None),
                    1 if matches!(node.pointers[0], Pointer::Values(_)) => {
                        Ok(Some(node.pointers[0].clone()))
                    }
                    2..=HAMT_VALUES_BUCKET_SIZE if node.count_values().is_ok() => {
                        // Collect all the values of the node.
                        let mut values = node
                            .pointers
                            .iter()
                            .filter_map(|p| match p {
                                Pointer::Values(values) => Some(values.clone()),
                                _ => None,
                            })
                            .flatten()
                            .collect::<Vec<_>>();

                        // Bail if it's more values that we can fit into a bucket
                        if values.len() > HAMT_VALUES_BUCKET_SIZE {
                            return Ok(Some(Pointer::Link(Link::from(node))));
                        }

                        values.sort_unstable_by(|a, b| {
                            H::hash(&a.key).partial_cmp(&H::hash(&b.key)).unwrap()
                        });

                        Ok(Some(Pointer::Values(values)))
                    }
                    _ => Ok(Some(Pointer::Link(Link::from(node)))),
                }
            }
            _ => error(HamtError::NonCanonicalizablePointer),
        }
    }
}

impl<K, V, H> Storable for Pointer<K, V, H>
where
    K: Storable + CondSync,
    V: Storable + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    type Serializable = PointerSerializable<K::Serializable, V::Serializable>;

    async fn to_serializable(&self, store: &impl Blockstore) -> Result<Self::Serializable> {
        Ok(match self {
            Pointer::Values(values) => {
                let mut serializables = Vec::with_capacity(values.len());
                for pair in values.iter() {
                    serializables.push(pair.to_serializable(store).await?);
                }
                PointerSerializable::Values(serializables)
            }
            Pointer::Link(link) => {
                let cid = link.resolve_cid(store).await?;
                PointerSerializable::Link(cid)
            }
        })
    }

    async fn from_serializable(
        _cid: Option<&Cid>,
        serializable: Self::Serializable,
    ) -> Result<Self> {
        Ok(match serializable {
            PointerSerializable::Values(serializables) => {
                let mut values = Vec::with_capacity(serializables.len());
                for serializable in serializables {
                    values.push(Pair::from_serializable(None, serializable).await?);
                }
                Self::Values(values)
            }
            PointerSerializable::Link(cid) => Self::Link(Link::from_cid(cid)),
        })
    }
}

impl<K, V> Storable for Pair<K, V>
where
    K: Storable + CondSync,
    V: Storable + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
{
    type Serializable = (K::Serializable, V::Serializable);

    async fn to_serializable(&self, store: &impl Blockstore) -> Result<Self::Serializable> {
        let key = self.key.to_serializable(store).await?;
        let value = self.value.to_serializable(store).await?;
        Ok((key, value))
    }

    async fn from_serializable(
        _cid: Option<&Cid>,
        (key, value): Self::Serializable,
    ) -> Result<Self> {
        let key = K::from_serializable(None, key).await?;
        let value = V::from_serializable(None, value).await?;
        Ok(Pair { key, value })
    }
}

impl<K: Clone + CondSync, V: Clone + CondSync, H: Hasher + CondSync> Clone for Pointer<K, V, H> {
    fn clone(&self) -> Self {
        match self {
            Self::Values(arg0) => Self::Values(arg0.clone()),
            Self::Link(arg0) => Self::Link(arg0.clone()),
        }
    }
}

impl<K: Debug + CondSync, V: Debug + CondSync, H: Hasher + CondSync> std::fmt::Debug
    for Pointer<K, V, H>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Values(arg0) => f.debug_tuple("Values").field(arg0).finish(),
            Self::Link(arg0) => f.debug_tuple("Link").field(arg0).finish(),
        }
    }
}

impl<K: CondSync, V: CondSync, H: Hasher + CondSync> Default for Pointer<K, V, H> {
    fn default() -> Self {
        Pointer::Values(Vec::new())
    }
}

impl<K, V, H: Hasher + CondSync> PartialEq for Pointer<K, V, H>
where
    K: Storable + PartialEq + CondSync,
    V: Storable + PartialEq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Pointer::Values(vals), Pointer::Values(other_vals)) => vals == other_vals,
            (Pointer::Link(link), Pointer::Link(other_link)) => link == other_link,
            _ => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[async_std::test]
    async fn pointer_can_encode_decode_as_cbor() -> TestResult {
        let store = &InMemoryBlockstore::<64>::new();
        let pointer: Pointer<String, i32, blake3::Hasher> = Pointer::Values(vec![
            Pair {
                key: "James".into(),
                value: 4500,
            },
            Pair {
                key: "Peter".into(),
                value: 2000,
            },
        ]);

        let pointer_cid = pointer.store(store).await?;
        let decoded_pointer =
            Pointer::<String, i32, blake3::Hasher>::load(&pointer_cid, store).await?;

        assert_eq!(pointer, decoded_pointer);

        Ok(())
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use testresult::TestResult;
    use wnfs_common::utils::SnapshotBlockStore;

    #[async_std::test]
    async fn test_pointer() -> TestResult {
        let store = &SnapshotBlockStore::default();
        let pointer: Pointer<String, i32, blake3::Hasher> = Pointer::Values(vec![
            Pair {
                key: "James".into(),
                value: 4500,
            },
            Pair {
                key: "Peter".into(),
                value: 2000,
            },
        ]);

        let cid = pointer.store(store).await?;
        let ptr = store.get_block_snapshot(&cid).await?;

        insta::assert_json_snapshot!(ptr);

        Ok(())
    }
}
