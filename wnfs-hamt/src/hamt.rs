use super::{KeyValueChange, Node, HAMT_VERSION};
use crate::{serializable::HamtSerializable, Hasher};
use anyhow::Result;
use semver::Version;
use serde::{de::DeserializeOwned, Serialize};
use std::hash::Hash;
use wnfs_common::{
    blockstore::Blockstore,
    ipld_core::cid::Cid,
    utils::{Arc, CondSync},
    Link, Storable,
};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// Hash Array Mapped Trie (HAMT) is an implementation of an associative array that combines the characteristics
/// of a hash table and an array mapped trie.
///
/// This type wraps the actual implementation which can be found in the [`Node`](crate::Node).
///
/// # Examples
///
/// ```
/// use wnfs_hamt::Hamt;
///
/// let hamt = Hamt::<String, usize>::new();
/// println!("HAMT: {:?}", hamt);
/// ```
#[derive(Debug, Clone)]
pub struct Hamt<K: CondSync, V: CondSync, H = blake3::Hasher>
where
    H: Hasher + CondSync,
{
    pub root: Arc<Node<K, V, H>>,
    pub version: Version,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<K: CondSync, V: CondSync, H: Hasher + CondSync> Hamt<K, V, H> {
    /// Creates a new empty HAMT.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs_hamt::Hamt;
    ///
    /// let hamt = Hamt::<String, usize>::new();
    /// println!("HAMT: {:?}", hamt);
    /// ```
    pub fn new() -> Self {
        Self {
            root: Arc::new(Node::default()),
            version: HAMT_VERSION,
        }
    }

    /// Creates a new `HAMT` with the given root node.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Hamt, Node};
    ///
    /// let hamt = Hamt::<String, usize>::with_root(Arc::new(Node::default()));
    ///
    /// println!("HAMT: {:?}", hamt);
    /// ```
    pub fn with_root(root: Arc<Node<K, V, H>>) -> Self {
        Self {
            root,
            version: HAMT_VERSION,
        }
    }

    /// Gets the difference between two HAMTs at the key-value level.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Hamt, Node};
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::default();
    ///
    ///     let main_hamt = Hamt::<String, usize>::with_root({
    ///         let mut node = Arc::new(Node::default());
    ///         node.set("foo".into(), 400, store).await.unwrap();
    ///         node.set("bar".into(), 500, store).await.unwrap();
    ///         node
    ///     });
    ///
    ///     let other_hamt = Hamt::<String, usize>::with_root({
    ///         let mut node = Arc::new(Node::default());
    ///         node.set("foo".into(), 200, store).await.unwrap();
    ///         node.set("qux".into(), 600, store).await.unwrap();
    ///         node
    ///     });
    ///
    ///     let diff = main_hamt.diff(&other_hamt, store).await.unwrap();
    ///
    ///     println!("diff: {:#?}", diff);
    /// }
    pub async fn diff(
        &self,
        other: &Self,
        store: &impl Blockstore,
    ) -> Result<Vec<KeyValueChange<K, V>>>
    where
        K: Storable + Clone + Eq + Hash + AsRef<[u8]>,
        V: Storable + Clone + Eq,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        super::diff(
            Link::from(Arc::clone(&self.root)),
            Link::from(Arc::clone(&other.root)),
            store,
        )
        .await
    }
}

impl<K, V, H> Storable for Hamt<K, V, H>
where
    K: Storable + CondSync,
    V: Storable + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    type Serializable = HamtSerializable<K::Serializable, V::Serializable>;

    async fn to_serializable(&self, store: &impl Blockstore) -> Result<Self::Serializable> {
        Ok(HamtSerializable {
            root: self.root.to_serializable(store).await?,
            version: self.version.clone(),
            structure: "hamt".to_string(),
        })
    }

    async fn from_serializable(
        _cid: Option<&Cid>,
        serializable: Self::Serializable,
    ) -> Result<Self> {
        Ok(Self {
            root: Arc::new(Node::from_serializable(None, serializable.root).await?),
            version: serializable.version,
        })
    }
}

impl<K: CondSync, V: CondSync, H: Hasher + CondSync> Default for Hamt<K, V, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: CondSync, V: CondSync, H> PartialEq for Hamt<K, V, H>
where
    K: Storable + PartialEq + CondSync,
    V: Storable + PartialEq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.version == other.version
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[async_std::test]
    async fn hamt_can_encode_decode_as_cbor() {
        let store = &InMemoryBlockstore::<64>::new();
        let root = Arc::new(Node::default());
        let hamt: Hamt<String, i32> = Hamt::with_root(root);

        let hamt_cid = hamt.store(store).await.unwrap();
        let decoded_hamt = Hamt::load(&hamt_cid, store).await.unwrap();

        assert_eq!(hamt, decoded_hamt);
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use wnfs_common::utils::SnapshotBlockStore;

    #[async_std::test]
    async fn test_hamt() {
        let store = &SnapshotBlockStore::default();
        let node = &mut Arc::new(Node::<[u8; 4], String>::default());
        for i in 0..99_u32 {
            node.set(i.to_le_bytes(), i.to_string(), store)
                .await
                .unwrap();
        }

        let hamt = Hamt::with_root(Arc::clone(node));
        let cid = hamt.store(store).await.unwrap();
        let hamt = store.get_block_snapshot(&cid).await.unwrap();

        insta::assert_json_snapshot!(hamt);
    }
}
