use super::{
    error::HamtError,
    hash::{HashNibbles, Hasher},
    HashPrefix, Pair, Pointer, HAMT_BITMASK_BIT_SIZE, HAMT_BITMASK_BYTE_SIZE,
};
use crate::{serializable::NodeSerializable, HAMT_VALUES_BUCKET_SIZE};
use anyhow::{bail, Result};
use async_once_cell::OnceCell;
use async_recursion::async_recursion;
use bitvec::array::BitArray;
use either::{Either, Either::*};
#[cfg(feature = "log")]
use log::debug;
use serde::{de::DeserializeOwned, Serialize};
use serde_byte_array::ByteArray;
use std::{
    collections::HashMap,
    fmt::{self, Debug, Formatter},
    hash::Hash,
    marker::PhantomData,
};
use wnfs_common::{
    blockstore::Blockstore,
    ipld_core::cid::Cid,
    utils::{boxed_fut, Arc, BoxFuture, CondSend, CondSync},
    HashOutput, Link, Storable,
};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// The bitmask used by the HAMT which 16-bit, [u8; 2] type.
pub type BitMaskType = [u8; HAMT_BITMASK_BYTE_SIZE];

/// Represents a node in the HAMT tree structure.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use wnfs_hamt::Node;
/// use wnfs_common::MemoryBlockStore;
///
/// let store = &MemoryBlockStore::new();
/// let node = Arc::new(Node::<String, usize>::default());
///
/// assert!(node.is_empty());
/// ```
pub struct Node<K, V, H = blake3::Hasher>
where
    H: Hasher + CondSync,
    K: CondSync,
    V: CondSync,
{
    persisted_as: OnceCell<Cid>,
    pub(crate) bitmask: BitArray<BitMaskType>,
    pub(crate) pointers: Vec<Pointer<K, V, H>>,
    hasher: PhantomData<H>,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<K, V, H> Node<K, V, H>
where
    H: Hasher + CondSync,
    K: CondSync,
    V: CondSync,
{
    /// Sets a new value at the given key.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::Node;
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///     let mut node = Arc::new(Node::<String, usize>::default());
    ///
    ///     node.set("key".into(), 42, store).await.unwrap();
    ///     assert_eq!(node.get(&String::from("key"), store).await.unwrap(), Some(&42));
    /// }
    /// ```
    pub async fn set(self: &mut Arc<Self>, key: K, value: V, store: &impl Blockstore) -> Result<()>
    where
        K: Storable + AsRef<[u8]> + Clone,
        V: Storable + Clone,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let hash = &H::hash(&key);

        #[cfg(feature = "log")]
        debug!("set: hash = {:02x?}", hash);

        self.set_value(&mut HashNibbles::new(hash), key, value, store)
            .await
    }

    /// Gets the value at the given key.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::Node;
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///     let mut node = Arc::new(Node::<String, usize>::default());
    ///
    ///     node.set("key".into(), 42, store).await.unwrap();
    ///     assert_eq!(node.get(&String::from("key"), store).await.unwrap(), Some(&42));
    /// }
    /// ```
    pub async fn get<'a>(&'a self, key: &K, store: &impl Blockstore) -> Result<Option<&'a V>>
    where
        K: Storable + AsRef<[u8]>,
        V: Storable,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let hash = &H::hash(key);

        #[cfg(feature = "log")]
        debug!("get: hash = {:02x?}", hash);

        Ok(self
            .get_value(&mut HashNibbles::new(hash), store)
            .await?
            .map(|pair| &pair.value))
    }

    /// Obtain a mutable reference to a given key.
    ///
    /// Will copy parts of the tree to prepare for changes, if necessary.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::Node;
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &mut MemoryBlockStore::new();
    ///     let mut node = Arc::new(Node::<String, usize>::default());
    ///     node.set("key".into(), 40, store).await.unwrap();
    ///
    ///     let value = node.get_mut(&String::from("key"), store).await.unwrap().unwrap();
    ///     *value += 2;
    ///
    ///     assert_eq!(node.get(&String::from("key"), store).await.unwrap(), Some(&42));
    /// }
    /// ```
    // TODO(matheus23): Eventually provide a HashMap::Entry-similar API
    pub async fn get_mut<'a>(
        self: &'a mut Arc<Self>,
        key: &K,
        store: &'a impl Blockstore,
    ) -> Result<Option<&'a mut V>>
    where
        K: Storable + AsRef<[u8]> + Clone,
        V: Storable + Clone,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let hash = &H::hash(key);

        #[cfg(feature = "log")]
        debug!("get_mut: hash = {:02x?}", hash);

        Ok(self
            .get_value_mut(&mut HashNibbles::new(hash), store)
            .await?
            .map(|pair| &mut pair.value))
    }

    /// Removes the value at the given key.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Node, Pair};
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///     let mut node = Arc::new(Node::<String, usize>::default());
    ///
    ///     node.set("key".into(), 42, store).await.unwrap();
    ///     assert_eq!(node.get(&String::from("key"), store).await.unwrap(), Some(&42));
    ///
    ///     let value = node.remove(&String::from("key"), store).await.unwrap();
    ///     assert_eq!(value, Some(Pair::new("key".into(), 42)));
    ///     assert_eq!(node.get(&String::from("key"), store).await.unwrap(), None);
    /// }
    /// ```
    pub async fn remove(
        self: &mut Arc<Self>,
        key: &K,
        store: &impl Blockstore,
    ) -> Result<Option<Pair<K, V>>>
    where
        K: Storable + AsRef<[u8]> + Clone,
        V: Storable + Clone,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let hash = &H::hash(key);

        #[cfg(feature = "log")]
        debug!("remove: hash = {:02x?}", hash);

        self.remove_value(&mut HashNibbles::new(hash), store).await
    }

    /// Gets the value at the key matching the provided hash.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Node, Hasher};
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///     let mut node = Arc::new(Node::<String, usize>::default());
    ///
    ///     node.set("key".into(), 42, store).await.unwrap();
    ///
    ///     let key_hash = &blake3::Hasher::hash(&String::from("key"));
    ///     assert_eq!(node.get_by_hash(key_hash, store).await.unwrap(), Some(&42));
    /// }
    /// ```
    pub async fn get_by_hash<'a>(
        &'a self,
        hash: &HashOutput,
        store: &impl Blockstore,
    ) -> Result<Option<&'a V>>
    where
        K: Storable + AsRef<[u8]>,
        V: Storable,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        #[cfg(feature = "log")]
        debug!("get_by_hash: hash = {:02x?}", hash);

        Ok(self
            .get_value(&mut HashNibbles::new(hash), store)
            .await?
            .map(|pair| &pair.value))
    }

    /// Removes the value at the key matching the provided hash.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Node, Hasher, Pair};
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///     let mut node = Arc::new(Node::<String, usize>::default());
    ///
    ///     node.set("key".into(), 42, store).await.unwrap();
    ///     assert_eq!(node.get(&String::from("key"), store).await.unwrap(), Some(&42));
    ///
    ///     let key_hash = &blake3::Hasher::hash(&String::from("key"));
    ///     let value = node.remove_by_hash(key_hash, store).await.unwrap();
    ///
    ///     assert_eq!(value, Some(Pair::new("key".into(), 42)));
    ///     assert_eq!(node.get(&String::from("key"), store).await.unwrap(), None);
    /// }
    /// ```
    pub async fn remove_by_hash(
        self: &mut Arc<Self>,
        hash: &HashOutput,
        store: &impl Blockstore,
    ) -> Result<Option<Pair<K, V>>>
    where
        K: Storable + AsRef<[u8]> + Clone,
        V: Storable + Clone,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        self.remove_value(&mut HashNibbles::new(hash), store).await
    }

    /// Checks if the node is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::Node;
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///
    ///     let mut node = Arc::new(Node::<String, usize>::default());
    ///     assert!(node.is_empty());
    ///
    ///     node.set("key".into(), 42, store).await.unwrap();
    ///     assert!(!node.is_empty());
    /// }
    /// ```
    pub fn is_empty(&self) -> bool {
        self.bitmask.count_ones() == 0
    }

    /// Calculates the value index from the bitmask index.
    pub(crate) fn get_value_index(&self, bit_index: usize) -> usize {
        let shift_amount = HAMT_BITMASK_BIT_SIZE - bit_index;
        let mask = if shift_amount < HAMT_BITMASK_BIT_SIZE {
            let mut tmp = BitArray::<BitMaskType>::new([0xff, 0xff]);
            tmp.shift_left(shift_amount);
            tmp
        } else {
            BitArray::ZERO
        };
        debug_assert_eq!(mask.count_ones(), bit_index);
        (mask & self.bitmask).count_ones()
    }

    pub fn set_value<'a>(
        self: &'a mut Arc<Self>,
        hashnibbles: &'a mut HashNibbles,
        key: K,
        value: V,
        store: &'a impl Blockstore,
    ) -> BoxFuture<'a, Result<()>>
    where
        K: Storable + Clone + AsRef<[u8]> + 'a,
        V: Storable + Clone + 'a,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        Box::pin(async move {
            let bit_index = hashnibbles.try_next()?;
            let value_index = self.get_value_index(bit_index);

            #[cfg(feature = "log")]
            debug!(
                "set_value: bit_index = {}, value_index = {}",
                bit_index, value_index
            );

            let node = Arc::make_mut(self);
            node.persisted_as = OnceCell::new();

            // If the bit is not set yet, insert a new pointer.
            if !node.bitmask[bit_index] {
                node.pointers
                    .insert(value_index, Pointer::Values(vec![Pair { key, value }]));

                node.bitmask.set(bit_index, true);

                return Ok(());
            }

            match &mut node.pointers[value_index] {
                Pointer::Values(ref mut values) => {
                    if let Some(i) = values
                        .iter()
                        .position(|p| &H::hash(&p.key) == hashnibbles.digest)
                    {
                        // If the key is already present, update the value.
                        values[i] = Pair::new(key, value);
                    } else {
                        // Otherwise, insert the new value if bucket is not full. Create new node if it is.
                        if values.len() < HAMT_VALUES_BUCKET_SIZE {
                            // Insert in order of key.
                            let index = values
                                .iter()
                                .position(|p| &H::hash(&p.key) > hashnibbles.digest)
                                .unwrap_or(values.len());
                            values.insert(index, Pair::new(key, value));
                        } else {
                            // If values has reached threshold, we need to create a node link that splits it.
                            let mut sub_node = Arc::new(Node::<K, V, H>::default());
                            let cursor = hashnibbles.get_cursor();
                            // We can take because
                            // Pointer::Values() gets replaced with Pointer::Link at the end
                            let values = std::mem::take(values);
                            for Pair { key, value } in
                                values.into_iter().chain(Some(Pair::new(key, value)))
                            {
                                let hash = &H::hash(&key);
                                let hashnibbles = &mut HashNibbles::with_cursor(hash, cursor);
                                sub_node.set_value(hashnibbles, key, value, store).await?;
                            }
                            node.pointers[value_index] = Pointer::Link(Link::from(sub_node));
                        }
                    }
                }
                Pointer::Link(link) => {
                    let mut child: Arc<Node<K, V, H>> =
                        Arc::clone(link.resolve_value(store).await?);
                    child.set_value(hashnibbles, key, value, store).await?;
                    node.pointers[value_index] = Pointer::Link(Link::from(child));
                }
            }

            Ok(())
        })
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn get_value<'a>(
        &'a self,
        hashnibbles: &mut HashNibbles,
        store: &impl Blockstore,
    ) -> Result<Option<&'a Pair<K, V>>>
    where
        K: Storable + AsRef<[u8]>,
        V: Storable,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let bit_index = hashnibbles.try_next()?;

        // If the bit is not set yet, return None.
        if !self.bitmask[bit_index] {
            return Ok(None);
        }

        let value_index = self.get_value_index(bit_index);
        match &self.pointers[value_index] {
            Pointer::Values(values) => Ok({
                values
                    .iter()
                    .find(|p| &H::hash(&p.key) == hashnibbles.digest)
            }),
            Pointer::Link(link) => {
                let child = link.resolve_value(store).await?;
                child.get_value(hashnibbles, store).await
            }
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn get_value_mut<'a>(
        self: &'a mut Arc<Self>,
        hashnibbles: &mut HashNibbles,
        store: &'a impl Blockstore,
    ) -> Result<Option<&'a mut Pair<K, V>>>
    where
        K: Storable + AsRef<[u8]> + Clone,
        V: Storable + Clone,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let bit_index = hashnibbles.try_next()?;

        // If the bit is not set yet, return None.
        if !self.bitmask[bit_index] {
            return Ok(None);
        }

        let value_index = self.get_value_index(bit_index);
        let node = Arc::make_mut(self);
        node.persisted_as = OnceCell::new();

        match &mut node.pointers[value_index] {
            Pointer::Values(values) => Ok({
                values
                    .iter_mut()
                    .find(|p| &H::hash(&p.key) == hashnibbles.digest)
            }),
            Pointer::Link(link) => {
                let child = link.resolve_value_mut(store).await?;
                child.get_value_mut(hashnibbles, store).await
            }
        }
    }

    pub fn remove_value<'a>(
        self: &'a mut Arc<Self>,
        hashnibbles: &'a mut HashNibbles,
        store: &'a impl Blockstore,
    ) -> BoxFuture<'a, Result<Option<Pair<K, V>>>>
    where
        K: Storable + AsRef<[u8]> + Clone + 'a,
        V: Storable + Clone + 'a,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        Box::pin(async move {
            let bit_index = hashnibbles.try_next()?;

            // If the bit is not set yet, return None.
            if !self.bitmask[bit_index] {
                return Ok(None);
            }

            let value_index = self.get_value_index(bit_index);

            let node = Arc::make_mut(self);
            node.persisted_as = OnceCell::new();

            Ok(match &mut node.pointers[value_index] {
                // If there is only one value, we can remove the entire pointer.
                Pointer::Values(values) if values.len() == 1 => {
                    // If the key doesn't match, return without removing.
                    if &H::hash(&values[0].key) != hashnibbles.digest {
                        None
                    } else {
                        node.bitmask.set(bit_index, false);
                        match node.pointers.remove(value_index) {
                            Pointer::Values(mut values) => Some(values.pop().unwrap()),
                            _ => unreachable!(),
                        }
                    }
                }
                // Otherwise, remove just the value.
                Pointer::Values(ref mut values) => {
                    match values
                        .iter()
                        .position(|p| &H::hash(&p.key) == hashnibbles.digest)
                    {
                        Some(i) => {
                            let value = values.remove(i);
                            // We can take here because we replace the node.pointers here afterwards anyway
                            let values = std::mem::take(values);
                            node.pointers[value_index] = Pointer::Values(values);
                            Some(value)
                        }
                        None => None,
                    }
                }
                Pointer::Link(link) => {
                    let mut child = Arc::clone(link.resolve_value(store).await?);
                    let removed = child.remove_value(hashnibbles, store).await?;
                    if removed.is_some() {
                        // If something has been deleted, we attempt to canonicalize the pointer.
                        if let Some(pointer) =
                            Pointer::Link(Link::from(child)).canonicalize(store).await?
                        {
                            node.pointers[value_index] = pointer;
                        } else {
                            // This is None if the pointer now points to an empty node.
                            // In that case, we remove it from the parent.
                            node.bitmask.set(bit_index, false);
                            node.pointers.remove(value_index);
                        }
                    } else {
                        node.pointers[value_index] = Pointer::Link(Link::from(child))
                    };
                    removed
                }
            })
        })
    }

    /// Visits all the leaf nodes in the trie and calls the given function on each of them.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Node, Pair, Hasher};
    /// use wnfs_common::{utils, MemoryBlockStore};
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///     let mut node = Arc::new(Node::<[u8; 4], String>::default());
    ///     for i in 0..99_u32 {
    ///         node
    ///             .set(i.to_le_bytes(), i.to_string(), store)
    ///             .await
    ///             .unwrap();
    ///     }
    ///
    ///     let keys = node
    ///         .flat_map(&|Pair { key, .. }| Ok(*key), store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(keys.len(), 99);
    /// }
    /// ```
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn flat_map<F, T>(&self, f: &F, store: &impl Blockstore) -> Result<Vec<T>>
    where
        F: Fn(&Pair<K, V>) -> Result<T> + CondSync,
        K: Storable + AsRef<[u8]>,
        V: Storable,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
        T: CondSend,
    {
        let mut items = <Vec<T>>::new();
        for p in self.pointers.iter() {
            match p {
                Pointer::Values(values) => {
                    for pair in values {
                        items.push(f(pair)?);
                    }
                }
                Pointer::Link(link) => {
                    let child = link.resolve_value(store).await?;
                    items.extend(child.flat_map(f, store).await?);
                }
            }
        }

        Ok(items)
    }

    /// Given a hashprefix representing the path to a node in the trie. This function will
    /// return the key-value pair or the intermediate node that the hashprefix points to.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Node, HashPrefix, Hasher};
    /// use wnfs_common::{MemoryBlockStore, utils};
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///
    ///     let mut node = Arc::new(Node::<[u8; 4], String>::default());
    ///     for i in 0..100_u32 {
    ///         node
    ///             .set(i.to_le_bytes(), i.to_string(), store)
    ///             .await
    ///             .unwrap();
    ///     }
    ///
    ///     let hashprefix = HashPrefix::with_length(utils::to_hash_output(&[0x8C]), 2);
    ///     let result = node.get_node_at(&hashprefix, store).await.unwrap();
    ///
    ///     println!("Result: {:#?}", result);
    /// }
    /// ```
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub async fn get_node_at<'a>(
        &'a self,
        hashprefix: &HashPrefix,
        store: &impl Blockstore,
    ) -> Result<Option<Either<&'a Pair<K, V>, &'a Arc<Self>>>>
    where
        K: Storable + AsRef<[u8]>,
        V: Storable,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        self.get_node_at_helper(hashprefix, 0, store).await
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    async fn get_node_at_helper<'a>(
        &'a self,
        hashprefix: &HashPrefix,
        index: u8,
        store: &impl Blockstore,
    ) -> Result<Option<Either<&'a Pair<K, V>, &'a Arc<Self>>>>
    where
        K: Storable + AsRef<[u8]>,
        V: Storable,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let bit_index = hashprefix
            .get(index)
            .ok_or(HamtError::HashPrefixIndexOutOfBounds(index))? as usize;

        if !self.bitmask[bit_index] {
            return Ok(None);
        }

        let value_index = self.get_value_index(bit_index);
        match &self.pointers[value_index] {
            Pointer::Values(values) => Ok({
                values
                    .iter()
                    .find(|p| hashprefix.is_prefix_of(&H::hash(&p.key)))
                    .map(Left)
            }),
            Pointer::Link(link) => {
                let child = link.resolve_value(store).await?;
                if index == hashprefix.len() as u8 - 1 {
                    return Ok(Some(Right(child)));
                }

                child.get_node_at_helper(hashprefix, index + 1, store).await
            }
        }
    }

    /// Generates a hashmap from the node.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs_hamt::{Node, Hasher};
    /// use wnfs_common::MemoryBlockStore;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::new();
    ///
    ///     let mut node = Arc::new(Node::<[u8; 4], String>::default());
    ///     for i in 0..100_u32 {
    ///         node
    ///             .set(i.to_le_bytes(), i.to_string(), store)
    ///             .await
    ///             .unwrap();
    ///     }
    ///
    ///     let map = node.to_hashmap(store).await.unwrap();
    ///
    ///     assert_eq!(map.len(), 100);
    /// }
    /// ```
    pub async fn to_hashmap(&self, store: &impl Blockstore) -> Result<HashMap<K, V>>
    where
        K: Storable + AsRef<[u8]> + Clone + Eq + Hash,
        V: Storable + Clone,
        K::Serializable: Serialize + DeserializeOwned,
        V::Serializable: Serialize + DeserializeOwned,
    {
        let mut map = HashMap::new();
        let key_values = self
            .flat_map(
                &|Pair { key, value }| Ok((key.clone(), value.clone())),
                store,
            )
            .await?;

        for (key, value) in key_values {
            map.insert(key, value);
        }

        Ok(map)
    }

    /// Returns the count of the values in all the values pointer of a node.
    pub fn count_values(self: &Arc<Self>) -> Result<usize> {
        let mut len = 0;
        for i in self.pointers.iter() {
            if let Pointer::Values(values) = i {
                len += values.len();
            } else {
                bail!(HamtError::ValuesPointerExpected);
            }
        }

        Ok(len)
    }
}

impl<K: Clone + CondSync, V: CondSync + Clone, H: Hasher + CondSync> Clone for Node<K, V, H> {
    fn clone(&self) -> Self {
        Self {
            persisted_as: self
                .persisted_as
                .get()
                .cloned()
                .map(OnceCell::new_with)
                .unwrap_or_default(),
            bitmask: self.bitmask,
            pointers: self.pointers.clone(),
            hasher: PhantomData,
        }
    }
}

impl<K: CondSync, V: CondSync, H: Hasher + CondSync> Default for Node<K, V, H> {
    fn default() -> Self {
        Node {
            persisted_as: OnceCell::new(),
            bitmask: BitArray::ZERO,
            pointers: Vec::with_capacity(HAMT_BITMASK_BIT_SIZE),
            hasher: PhantomData,
        }
    }
}

impl<K, V, H> PartialEq for Node<K, V, H>
where
    K: Storable + PartialEq + CondSync,
    V: Storable + PartialEq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    fn eq(&self, other: &Self) -> bool {
        self.bitmask == other.bitmask && self.pointers == other.pointers
    }
}

impl<K, V, H> Debug for Node<K, V, H>
where
    K: Debug + CondSync,
    V: Debug + CondSync,
    H: Hasher + CondSync,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut bitmask_str = String::new();
        for i in self.bitmask.as_raw_slice().iter().rev() {
            bitmask_str.push_str(&format!("{i:08b}"));
        }

        f.debug_struct("Node")
            .field("bitmask", &bitmask_str)
            .field("pointers", &self.pointers)
            .finish()
    }
}

impl<K, V, H> Storable for Node<K, V, H>
where
    K: Storable + CondSync,
    V: Storable + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    type Serializable = NodeSerializable<K::Serializable, V::Serializable>;

    async fn to_serializable(&self, store: &impl Blockstore) -> Result<Self::Serializable> {
        let bitmask = ByteArray::from(self.bitmask.into_inner());

        let mut pointers = Vec::with_capacity(self.pointers.len());
        for pointer in self.pointers.iter() {
            // Boxing the future due to recursion
            pointers.push(boxed_fut(pointer.to_serializable(store)).await?);
        }

        Ok(NodeSerializable(bitmask, pointers))
    }

    async fn from_serializable(
        cid: Option<&Cid>,
        serializable: Self::Serializable,
    ) -> Result<Self> {
        let NodeSerializable(bitmask, ser_pointers) = serializable;

        let bitmask = BitArray::<BitMaskType>::new(bitmask.into());
        let bitmask_bits_set = bitmask.count_ones();

        if ser_pointers.len() != bitmask_bits_set {
            bail!(
                "pointers length does not match bitmask, bitmask bits set: {}, pointers length: {}",
                bitmask_bits_set,
                ser_pointers.len()
            );
        }

        let mut pointers = Vec::with_capacity(ser_pointers.len());
        for ser_pointer in ser_pointers {
            pointers.push(Pointer::from_serializable(cid, ser_pointer).await?);
        }

        Ok(Self {
            persisted_as: cid.cloned().map(OnceCell::new_with).unwrap_or_default(),
            bitmask,
            pointers,
            hasher: PhantomData,
        })
    }

    fn persisted_as(&self) -> Option<&OnceCell<Cid>> {
        Some(&self.persisted_as)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use helper::*;
    use wnfs_common::{blockstore::InMemoryBlockstore, utils};

    mod helper {
        use crate::Hasher;
        use once_cell::sync::Lazy;
        use wnfs_common::{utils, HashOutput};

        pub(super) static HASH_KV_PAIRS: Lazy<Vec<(HashOutput, &'static str)>> = Lazy::new(|| {
            vec![
                (utils::to_hash_output(&[0xE0]), "first"),
                (utils::to_hash_output(&[0xE1]), "second"),
                (utils::to_hash_output(&[0xE2]), "third"),
                (utils::to_hash_output(&[0xE3]), "fourth"),
            ]
        });

        #[derive(Debug, Clone)]
        pub(super) struct MockHasher;
        impl Hasher for MockHasher {
            fn hash<K: AsRef<[u8]>>(key: &K) -> HashOutput {
                HASH_KV_PAIRS
                    .iter()
                    .find(|(_, v)| key.as_ref() == <dyn AsRef<[u8]>>::as_ref(v))
                    .unwrap()
                    .0
            }
        }
    }

    #[async_std::test]
    async fn get_value_fetches_deeply_linked_value() {
        let store = &InMemoryBlockstore::<64>::new();

        // Insert 4 values to trigger the creation of a linked node.
        let working_node = &mut Arc::new(Node::<String, String, MockHasher>::default());
        for (digest, kv) in HASH_KV_PAIRS.iter().take(4) {
            let hashnibbles = &mut HashNibbles::new(digest);
            working_node
                .set_value(hashnibbles, kv.to_string(), kv.to_string(), store)
                .await
                .unwrap();
        }

        // Get the values.
        for (digest, kv) in HASH_KV_PAIRS.iter().take(4) {
            let hashnibbles = &mut HashNibbles::new(digest);
            let value = working_node.get_value(hashnibbles, store).await.unwrap();

            assert_eq!(value, Some(&Pair::new(kv.to_string(), kv.to_string())));
        }
    }

    #[async_std::test]
    async fn remove_value_canonicalizes_linked_node() {
        let store = &InMemoryBlockstore::<64>::new();

        // Insert 4 values to trigger the creation of a linked node.
        let working_node = &mut Arc::new(Node::<String, String, MockHasher>::default());
        for (digest, kv) in HASH_KV_PAIRS.iter().take(4) {
            let hashnibbles = &mut HashNibbles::new(digest);
            working_node
                .set_value(hashnibbles, kv.to_string(), kv.to_string(), store)
                .await
                .unwrap();
        }

        assert_eq!(working_node.pointers.len(), 1);

        // Remove the third value.
        let third_hashnibbles = &mut HashNibbles::new(&HASH_KV_PAIRS[2].0);
        working_node
            .remove_value(third_hashnibbles, store)
            .await
            .unwrap();

        // Check that the third value is gone.
        match &working_node.pointers[0] {
            Pointer::Values(values) => {
                assert_eq!(values.len(), 3);
            }
            _ => panic!("Expected values pointer"),
        }

        let value = working_node
            .get_value(third_hashnibbles, store)
            .await
            .unwrap();

        assert!(value.is_none());
    }

    #[async_std::test]
    async fn set_value_splits_when_bucket_threshold_reached() {
        let store = &InMemoryBlockstore::<64>::new();

        // Insert 3 values into the HAMT.
        let working_node = &mut Arc::new(Node::<String, String, MockHasher>::default());
        for (idx, (digest, kv)) in HASH_KV_PAIRS.iter().take(3).enumerate() {
            let kv = kv.to_string();
            let hashnibbles = &mut HashNibbles::new(digest);
            working_node
                .set_value(hashnibbles, kv.clone(), kv.clone(), store)
                .await
                .unwrap();

            match &working_node.pointers[0] {
                Pointer::Values(values) => {
                    assert_eq!(values.len(), idx + 1);
                    assert_eq!(values[idx].key, kv.clone());
                    assert_eq!(values[idx].value, kv.clone());
                }
                _ => panic!("Expected values pointer"),
            }
        }

        // Inserting the fourth value should introduce a link indirection.
        working_node
            .set_value(
                &mut HashNibbles::new(&HASH_KV_PAIRS[3].0),
                "fourth".to_string(),
                "fourth".to_string(),
                store,
            )
            .await
            .unwrap();

        match &working_node.pointers[0] {
            Pointer::Link(link) => {
                let node = link.get_value().unwrap();
                assert_eq!(node.bitmask.count_ones(), 4);
                assert_eq!(node.pointers.len(), 4);
            }
            _ => panic!("Expected link pointer"),
        }
    }

    #[async_std::test]
    async fn get_value_index_gets_correct_index() {
        let store = &InMemoryBlockstore::<64>::new();
        let hash_expected_idx_samples = [
            (&[0x00], 0),
            (&[0x20], 1),
            (&[0x10], 1),
            (&[0x30], 3),
            (&[0x50], 4),
            (&[0x60], 5),
            (&[0x70], 6),
            (&[0x40], 4),
            (&[0x80], 8),
            (&[0xA0], 9),
            (&[0xB0], 10),
            (&[0xC0], 11),
            (&[0x90], 9),
            (&[0xE0], 13),
            (&[0xD0], 13),
            (&[0xF0], 15),
        ];

        let working_node = &mut Arc::new(Node::<String, String>::default());
        for (hash, expected_idx) in hash_expected_idx_samples.into_iter() {
            let bytes = utils::to_hash_output(&hash[..]);
            let hashnibbles = &mut HashNibbles::new(&bytes);

            working_node
                .set_value(
                    hashnibbles,
                    expected_idx.to_string(),
                    expected_idx.to_string(),
                    store,
                )
                .await
                .unwrap();

            assert_eq!(
                working_node.pointers[expected_idx],
                Pointer::Values(vec![Pair::new(
                    expected_idx.to_string(),
                    expected_idx.to_string()
                )])
            );
        }
    }

    #[async_std::test]
    async fn node_can_insert_pair_and_retrieve() {
        let store = InMemoryBlockstore::<64>::new();
        let node = &mut Arc::new(Node::<String, (i32, f64)>::default());

        node.set("pill".into(), (10, 0.315), &store).await.unwrap();

        let value = node.get(&"pill".into(), &store).await.unwrap().unwrap();

        assert_eq!(value, &(10, 0.315));
    }

    #[async_std::test]
    async fn node_is_same_with_irrelevant_remove() {
        // These two keys' hashes have the same first nibble (7)
        let insert_key: String = "GL59 Tg4phDb  bv".into();
        let remove_key: String = "hK i3b4V4152EPOdA".into();

        let store = &InMemoryBlockstore::<64>::new();
        let node0: &mut Arc<Node<String, u64>> = &mut Arc::new(Node::default());

        node0.set(insert_key.clone(), 0, store).await.unwrap();
        node0.remove(&remove_key, store).await.unwrap();

        assert_eq!(node0.count_values().unwrap(), 1);
    }

    #[async_std::test]
    async fn node_history_independence_regression() {
        let store = &InMemoryBlockstore::<64>::new();

        let node1: &mut Arc<Node<String, u64>> = &mut Arc::new(Node::default());
        let node2: &mut Arc<Node<String, u64>> = &mut Arc::new(Node::default());

        node1.set("key 17".into(), 508, store).await.unwrap();
        node1.set("key 81".into(), 971, store).await.unwrap();
        node1.set("key 997".into(), 365, store).await.unwrap();
        node1.remove(&"key 17".into(), store).await.unwrap();
        node1.set("key 68".into(), 870, store).await.unwrap();
        node1.set("key 304".into(), 331, store).await.unwrap();

        node2.set("key 81".into(), 971, store).await.unwrap();
        node2.set("key 17".into(), 508, store).await.unwrap();
        node2.set("key 997".into(), 365, store).await.unwrap();
        node2.set("key 304".into(), 331, store).await.unwrap();
        node2.set("key 68".into(), 870, store).await.unwrap();
        node2.remove(&"key 17".into(), store).await.unwrap();

        let cid1 = node1.store(store).await.unwrap();
        let cid2 = node2.store(store).await.unwrap();

        assert_eq!(cid1, cid2);
    }

    #[async_std::test]
    async fn can_map_over_leaf_nodes() {
        let store = &InMemoryBlockstore::<64>::new();

        let node = &mut Arc::new(Node::<[u8; 4], String>::default());
        for i in 0..99_u32 {
            node.set(i.to_le_bytes(), i.to_string(), store)
                .await
                .unwrap();
        }

        let keys = node
            .flat_map(&|Pair { key, .. }| Ok(*key), store)
            .await
            .unwrap();

        assert_eq!(keys.len(), 99);
    }

    #[async_std::test]
    async fn can_fetch_node_at_hashprefix() {
        let store = &InMemoryBlockstore::<64>::new();

        let node = &mut Arc::new(Node::<String, String, MockHasher>::default());
        for (digest, kv) in HASH_KV_PAIRS.iter() {
            let hashnibbles = &mut HashNibbles::new(digest);
            node.set_value(hashnibbles, kv.to_string(), kv.to_string(), store)
                .await
                .unwrap();
        }

        for (digest, kv) in HASH_KV_PAIRS.iter().take(4) {
            let hashprefix = HashPrefix::with_length(*digest, 2);
            let result = node.get_node_at(&hashprefix, store).await.unwrap();
            let (key, value) = (kv.to_string(), kv.to_string());
            assert_eq!(result, Some(Either::Left(&Pair { key, value })));
        }

        let hashprefix = HashPrefix::with_length(utils::to_hash_output(&[0xE0]), 1);
        let result = node.get_node_at(&hashprefix, store).await.unwrap();

        assert!(matches!(result, Some(Either::Right(_))));
    }

    #[async_std::test]
    async fn can_generate_hashmap_from_node() {
        let store = &InMemoryBlockstore::<64>::new();

        let node = &mut Arc::new(Node::<[u8; 4], String>::default());
        const NUM_VALUES: u32 = 1000;
        for i in (u32::MAX - NUM_VALUES..u32::MAX).rev() {
            node.set(i.to_le_bytes(), i.to_string(), store)
                .await
                .unwrap();
        }

        let map = node.to_hashmap(store).await.unwrap();
        assert_eq!(map.len(), NUM_VALUES as usize);
        for i in (u32::MAX - NUM_VALUES..u32::MAX).rev() {
            assert_eq!(map.get(&i.to_le_bytes()).unwrap(), &i.to_string());
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::strategies::{
        node_from_operations, operations, operations_and_shuffled, Operations,
    };
    use proptest::prelude::*;
    use test_strategy::proptest;
    use wnfs_common::blockstore::InMemoryBlockstore;

    fn small_key() -> impl Strategy<Value = String> {
        (0..1000).prop_map(|i| format!("key {i}"))
    }

    #[proptest(cases = 50)]
    fn test_insert_idempotence(
        #[strategy(operations(small_key(), 0u64..1000, 0..100))] operations: Operations<
            String,
            u64,
        >,
        #[strategy(small_key())] key: String,
        #[strategy(0..1000u64)] value: u64,
    ) {
        async_std::task::block_on(async move {
            let store = &InMemoryBlockstore::<64>::new();
            let node = &mut node_from_operations(&operations, store).await.unwrap();

            node.set(key.clone(), value, store).await.unwrap();
            let cid1 = node.store(store).await.unwrap();

            node.set(key, value, store).await.unwrap();
            let cid2 = node.store(store).await.unwrap();

            prop_assert_eq!(cid1, cid2);
            Ok(())
        })?;
    }

    #[proptest(cases = 50)]
    fn test_remove_idempotence(
        #[strategy(operations(small_key(), 0u64..1000, 0..100))] operations: Operations<
            String,
            u64,
        >,
        #[strategy(small_key())] key: String,
    ) {
        async_std::task::block_on(async move {
            let store = &InMemoryBlockstore::<64>::new();
            let node = &mut node_from_operations(&operations, store).await.unwrap();

            node.remove(&key, store).await.unwrap();
            let cid1 = node.store(store).await.unwrap();

            node.remove(&key, store).await.unwrap();
            let cid2 = node.store(store).await.unwrap();

            prop_assert_eq!(cid1, cid2);
            Ok(())
        })?;
    }

    #[proptest(cases = 100)]
    fn node_can_encode_decode_as_cbor(
        #[strategy(operations(small_key(), 0u64..1000, 0..1000))] operations: Operations<
            String,
            u64,
        >,
    ) {
        async_std::task::block_on(async move {
            let store = &InMemoryBlockstore::<64>::new();
            let node = node_from_operations(&operations, store).await.unwrap();

            let node_cid = node.store(store).await.unwrap();
            let decoded_node = Node::<String, u64>::load(&node_cid, store).await.unwrap();

            prop_assert_eq!(node.as_ref(), &decoded_node);
            Ok(())
        })?;
    }

    #[proptest(cases = 1000, max_shrink_iters = 10_000)]
    fn node_operations_are_history_independent(
        #[strategy(operations_and_shuffled(small_key(), 0u64..1000, 0..100))] pair: (
            Operations<String, u64>,
            Operations<String, u64>,
        ),
    ) {
        async_std::task::block_on(async move {
            let (original, shuffled) = pair;

            let store = &InMemoryBlockstore::<64>::new();

            let node1 = node_from_operations(&original, store).await.unwrap();
            let node2 = node_from_operations(&shuffled, store).await.unwrap();

            let cid1 = node1.store(store).await.unwrap();
            let cid2 = node2.store(store).await.unwrap();

            prop_assert_eq!(cid1, cid2);
            Ok(())
        })?;
    }

    // This is sort of a "control group" for making sure that operations_and_shuffled is correct.
    #[proptest(cases = 200, max_shrink_iters = 10_000)]
    fn hash_map_is_history_independent(
        #[strategy(operations_and_shuffled(small_key(), 0u64..1000, 0..1000))] pair: (
            Operations<String, u64>,
            Operations<String, u64>,
        ),
    ) {
        let (original, shuffled) = pair;

        let map1 = HashMap::from(&original);
        let map2 = HashMap::from(&shuffled);

        prop_assert_eq!(map1, map2);
    }

    #[proptest]
    fn hamt_is_like_hash_map(
        #[strategy(operations(small_key(), 0u64..1000, 0..1000))] operations: Operations<
            String,
            u64,
        >,
    ) {
        async_std::task::block_on(async move {
            let store = &InMemoryBlockstore::<64>::new();

            let node = node_from_operations(&operations, store).await.unwrap();
            let map = HashMap::from(&operations);
            let map_result = node.to_hashmap(store).await.unwrap();

            prop_assert_eq!(map, map_result);
            Ok(())
        })?;
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use wnfs_common::utils::SnapshotBlockStore;

    #[async_std::test]
    async fn test_node() {
        let store = &SnapshotBlockStore::default();
        let node = &mut Arc::new(Node::<[u8; 4], String>::default());
        for i in 0..99_u32 {
            node.set(i.to_le_bytes(), i.to_string(), store)
                .await
                .unwrap();
        }

        let cid = node.store(store).await.unwrap();
        let node = store.get_block_snapshot(&cid).await.unwrap();

        insta::assert_json_snapshot!(node);
    }
}
