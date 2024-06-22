use super::HashNibbles;
use crate::{Hasher, Node, Pair, Pointer, HAMT_BITMASK_BIT_SIZE};
use anyhow::{Ok, Result};
use async_recursion::async_recursion;
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, hash::Hash, mem};
use wnfs_common::{
    blockstore::Blockstore,
    utils::{Arc, CondSync},
    Link, Storable,
};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// This type represents the different kinds of changes to a node.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeType {
    Add,
    Remove,
    Modify,
}

/// Represents a change to some key-value pair of a HAMT node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyValueChange<K, V> {
    pub r#type: ChangeType,
    pub key: K,
    pub value1: Option<V>,
    pub value2: Option<V>,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<K, V> KeyValueChange<K, V> {
    pub fn map<W>(self, f: &impl Fn(V) -> W) -> KeyValueChange<K, W> {
        let Self {
            r#type,
            key,
            value1,
            value2,
        } = self;
        KeyValueChange {
            r#type,
            key,
            value1: value1.map(f),
            value2: value2.map(f),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compare two nodes and get the key-value changes made to the main node.
///
/// This implementation gets all the changes to main node at the leaf node level.
///
/// This is a more expensive operation because it gathers the key value pairs under a node has
/// been added or removed even though we can simply return a reference to the node itself.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use wnfs_hamt::{Node, Pair, diff};
/// use wnfs_common::{Link, MemoryBlockstore};
///
/// #[async_std::main]
/// async fn main() {
///     let store = &InMemoryBlockstore::<64>::new();
///     let main_node = &mut Arc::new(Node::<[u8; 4], String>::default());
///     for i in 0u32..3 {
///         main_node
///             .set(i.to_le_bytes(), i.to_string(), store)
///             .await
///             .unwrap();
///     }
///
///     let other_node = &mut Arc::new(Node::<[u8; 4], String>::default());
///     other_node
///         .set(0_u32.to_le_bytes(), 0_u32.to_string(), store)
///         .await
///         .unwrap();
///
///     let changes = diff(
///         Link::from(Arc::clone(main_node)),
///         Link::from(Arc::clone(other_node)),
///         store,
///     )
///     .await
///     .unwrap();
///
///
///    println!("Changes {:#?}", changes);
/// }
/// ```
pub async fn diff<K, V, H>(
    main_link: Link<Arc<Node<K, V, H>>>,
    other_link: Link<Arc<Node<K, V, H>>>,
    store: &impl Blockstore,
) -> Result<Vec<KeyValueChange<K, V>>>
where
    K: Storable + Clone + Eq + Hash + AsRef<[u8]> + CondSync,
    V: Storable + Clone + Eq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    diff_helper(main_link, other_link, 1, store).await
}

#[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
#[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
pub async fn diff_helper<K, V, H>(
    main_link: Link<Arc<Node<K, V, H>>>,
    other_link: Link<Arc<Node<K, V, H>>>,
    depth: usize,
    store: &impl Blockstore,
) -> Result<Vec<KeyValueChange<K, V>>>
where
    K: Storable + Clone + Eq + Hash + AsRef<[u8]> + CondSync,
    V: Storable + Clone + Eq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    // If Cids are available, check to see if they are equal so we can skip further comparisons.
    if let (Some(cid), Some(cid2)) = (main_link.get_cid(), other_link.get_cid()) {
        if cid == cid2 {
            return Ok(vec![]);
        }
    }

    // Otherwise, get nodes from store.
    let mut main_node = main_link.resolve_owned_value(store).await?;

    let mut other_node = other_link.resolve_owned_value(store).await?;

    let mut changes = vec![];
    for index in 0..HAMT_BITMASK_BIT_SIZE {
        match (main_node.bitmask[index], other_node.bitmask[index]) {
            (true, false) => {
                // Main has a value, other doesn't.
                changes.extend(
                    generate_add_or_remove_changes(
                        &main_node.pointers[main_node.get_value_index(index)],
                        ChangeType::Add,
                        store,
                    )
                    .await?,
                );
            }
            (false, true) => {
                // Main doesn't have a value, other does.
                changes.extend(
                    generate_add_or_remove_changes(
                        &other_node.pointers[other_node.get_value_index(index)],
                        ChangeType::Remove,
                        store,
                    )
                    .await?,
                );
            }
            (true, true) => {
                // Main and other have a value. They may be the same or different so we check.
                let main_index = main_node.get_value_index(index);
                let main_pointer = mem::take(
                    Arc::make_mut(&mut main_node)
                        .pointers
                        .get_mut(main_index)
                        .unwrap(),
                );

                let other_index = other_node.get_value_index(index);
                let other_pointer = mem::take(
                    Arc::make_mut(&mut other_node)
                        .pointers
                        .get_mut(other_index)
                        .unwrap(),
                );

                changes.extend(pointers_diff(main_pointer, other_pointer, depth, store).await?);
            }
            (false, false) => { /* No change */ }
        }
    }

    Ok(changes)
}

async fn generate_add_or_remove_changes<K, V, H>(
    node_pointer: &Pointer<K, V, H>,
    r#type: ChangeType,
    store: &impl Blockstore,
) -> Result<Vec<KeyValueChange<K, V>>>
where
    K: Storable + Clone + Eq + Hash + AsRef<[u8]> + CondSync,
    V: Storable + Clone + Eq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    match node_pointer {
        Pointer::Values(values) => Ok(values
            .iter()
            .map(|Pair { key, value }| KeyValueChange {
                r#type,
                key: key.clone(),
                value1: Some(value.clone()),
                value2: None,
            })
            .collect()),
        Pointer::Link(link) => {
            let node = link.resolve_value(store).await?;
            node.as_ref()
                .flat_map(
                    &|Pair { key, value }| {
                        Ok(KeyValueChange {
                            r#type,
                            key: key.clone(),
                            value1: Some(value.clone()),
                            value2: None,
                        })
                    },
                    store,
                )
                .await
        }
    }
}

async fn pointers_diff<K, V, H>(
    main_pointer: Pointer<K, V, H>,
    other_pointer: Pointer<K, V, H>,
    depth: usize,
    store: &impl Blockstore,
) -> Result<Vec<KeyValueChange<K, V>>>
where
    K: Storable + Clone + Eq + Hash + AsRef<[u8]> + CondSync,
    V: Storable + Clone + Eq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    match (main_pointer, other_pointer) {
        (Pointer::Link(main_link), Pointer::Link(other_link)) => {
            diff_helper(main_link, other_link, depth + 1, store).await
        }
        (Pointer::Values(main_values), Pointer::Values(other_values)) => {
            let mut changes = vec![];
            let mut main_map = HashMap::<&K, &V>::default();
            let other_map = HashMap::<&K, &V>::from_iter(
                other_values.iter().map(|Pair { key, value }| (key, value)),
            );

            for Pair { key, value } in &main_values {
                match other_map.get(&key) {
                    Some(v) => {
                        if *v != value {
                            changes.push(KeyValueChange {
                                r#type: ChangeType::Modify,
                                key: key.clone(),
                                value1: Some(value.clone()),
                                value2: Some((*v).clone()),
                            });
                        }
                    }
                    None => {
                        changes.push(KeyValueChange {
                            r#type: ChangeType::Add,
                            key: key.clone(),
                            value1: Some(value.clone()),
                            value2: None,
                        });
                    }
                }

                main_map.insert(key, value);
            }

            for Pair { key, value } in &other_values {
                if !main_map.contains_key(key) {
                    changes.push(KeyValueChange {
                        r#type: ChangeType::Remove,
                        key: key.clone(),
                        value1: Some(value.clone()),
                        value2: None,
                    });
                }
            }

            Ok(changes)
        }
        (Pointer::Values(main_values), Pointer::Link(other_link)) => {
            let main_link = Link::from(create_node_from_pairs(main_values, depth, store).await?);
            diff_helper(main_link, other_link, depth + 1, store).await
        }
        (Pointer::Link(main_link), Pointer::Values(other_values)) => {
            let other_link = Link::from(create_node_from_pairs(other_values, depth, store).await?);
            diff_helper(main_link, other_link, depth + 1, store).await
        }
    }
}

async fn create_node_from_pairs<K, V, H>(
    values: Vec<Pair<K, V>>,
    depth: usize,
    store: &impl Blockstore,
) -> Result<Arc<Node<K, V, H>>>
where
    K: Storable + Clone + Eq + Hash + AsRef<[u8]> + CondSync,
    V: Storable + Clone + Eq + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    let mut node = Arc::new(Node::<_, _, H>::default());
    for Pair { key, value } in values {
        let digest = &H::hash(&key);
        let hashnibbles = &mut HashNibbles::with_cursor(digest, depth);
        node.set_value(hashnibbles, key, value, store).await?;
    }
    Ok(node)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{ChangeType::*, *};
    use helper::*;
    use std::collections::BTreeSet;
    use wnfs_common::blockstore::InMemoryBlockstore;

    mod helper {
        use crate::Hasher;
        use once_cell::sync::Lazy;
        use wnfs_common::{utils, HashOutput};

        pub(super) static HASH_KV_PAIRS: Lazy<Vec<(HashOutput, &'static str)>> = Lazy::new(|| {
            vec![
                (utils::to_hash_output(&[0xA0]), "first"),
                (utils::to_hash_output(&[0xA3]), "second"),
                (utils::to_hash_output(&[0xA7]), "third"),
                (utils::to_hash_output(&[0xAC]), "fourth"),
                (utils::to_hash_output(&[0xAE]), "fifth"),
            ]
        });

        #[derive(Debug, Clone)]
        pub(crate) struct MockHasher;
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
    async fn can_diff_main_node_with_added_removed_pairs() {
        let store = &InMemoryBlockstore::<64>::new();

        let main_node = &mut Arc::new(Node::<[u8; 4], String>::default());
        for i in 0u32..3 {
            main_node
                .set(i.to_le_bytes(), i.to_string(), store)
                .await
                .unwrap();
        }

        let other_node = &mut Arc::new(Node::<[u8; 4], String>::default());
        other_node
            .set(0_u32.to_le_bytes(), 0_u32.to_string(), store)
            .await
            .unwrap();

        let changes = diff(
            Link::from(Arc::clone(main_node)),
            Link::from(Arc::clone(other_node)),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            changes.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                KeyValueChange {
                    r#type: Add,
                    key: [2, 0, 0, 0,],
                    value1: Some(String::from("2")),
                    value2: None,
                },
                KeyValueChange {
                    r#type: Add,
                    key: [1, 0, 0, 0,],
                    value1: Some(String::from("1")),
                    value2: None,
                },
            ])
        );

        let changes = diff(
            Link::from(Arc::clone(other_node)),
            Link::from(Arc::clone(main_node)),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            changes.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                KeyValueChange {
                    r#type: Remove,
                    key: [2, 0, 0, 0,],
                    value1: Some(String::from("2")),
                    value2: None,
                },
                KeyValueChange {
                    r#type: Remove,
                    key: [1, 0, 0, 0,],
                    value1: Some(String::from("1")),
                    value2: None,
                },
            ])
        );
    }

    #[async_std::test]
    async fn can_diff_main_node_with_no_changes() {
        let store = &InMemoryBlockstore::<64>::new();

        let main_node = &mut Arc::new(Node::<_, _>::default());
        for i in 0_u32..3 {
            main_node
                .set(i.to_le_bytes(), i.to_string(), store)
                .await
                .unwrap();
        }

        let other_node = &mut Arc::new(Node::<_, _>::default());
        for i in 0_u32..3 {
            other_node
                .set(i.to_le_bytes(), i.to_string(), store)
                .await
                .unwrap();
        }

        let changes = diff(
            Link::from(Arc::clone(main_node)),
            Link::from(Arc::clone(other_node)),
            store,
        )
        .await
        .unwrap();

        assert!(changes.is_empty());
    }

    #[async_std::test]
    async fn can_diff_nodes_with_different_structure_and_modified_changes() {
        let store = &InMemoryBlockstore::<64>::new();

        // A node that adds the first 3 pairs of HASH_KV_PAIRS.
        let other_node = &mut Arc::new(Node::<_, _, MockHasher>::default());
        for (digest, kv) in HASH_KV_PAIRS.iter().take(3) {
            other_node
                .set_value(
                    &mut HashNibbles::new(digest),
                    kv.to_string(),
                    kv.to_string(),
                    store,
                )
                .await
                .unwrap();
        }

        // Another node that keeps the first pair, modify the second pair, removes the third pair, and adds the fourth and fifth pair.
        let main_node = &mut Arc::new(Node::<_, _, MockHasher>::default());
        main_node
            .set_value(
                &mut HashNibbles::new(&HASH_KV_PAIRS[0].0),
                HASH_KV_PAIRS[0].1.to_string(),
                HASH_KV_PAIRS[0].1.to_string(),
                store,
            )
            .await
            .unwrap();

        main_node
            .set_value(
                &mut HashNibbles::new(&HASH_KV_PAIRS[1].0),
                HASH_KV_PAIRS[1].1.to_string(),
                String::from("second_modified"),
                store,
            )
            .await
            .unwrap();

        for (digest, kv) in HASH_KV_PAIRS.iter().skip(3).take(2) {
            main_node
                .set_value(
                    &mut HashNibbles::new(digest),
                    kv.to_string(),
                    kv.to_string(),
                    store,
                )
                .await
                .unwrap();
        }

        let changes = diff(
            Link::from(Arc::clone(main_node)),
            Link::from(Arc::clone(other_node)),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            changes,
            vec![
                KeyValueChange {
                    r#type: Modify,
                    key: "second".to_string(),
                    value1: Some("second_modified".to_string()),
                    value2: Some("second".to_string()),
                },
                KeyValueChange {
                    r#type: Remove,
                    key: "third".to_string(),
                    value1: Some("third".to_string()),
                    value2: None,
                },
                KeyValueChange {
                    r#type: Add,
                    key: "fourth".to_string(),
                    value1: Some("fourth".to_string()),
                    value2: None,
                },
                KeyValueChange {
                    r#type: Add,
                    key: "fifth".to_string(),
                    value1: Some("fifth".to_string()),
                    value2: None,
                },
            ]
        );

        let changes = diff(
            Link::from(Arc::clone(other_node)),
            Link::from(Arc::clone(main_node)),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            changes,
            vec![
                KeyValueChange {
                    r#type: Modify,
                    key: "second".to_string(),
                    value1: Some("second".to_string()),
                    value2: Some("second_modified".to_string()),
                },
                KeyValueChange {
                    r#type: Add,
                    key: "third".to_string(),
                    value1: Some("third".to_string()),
                    value2: None,
                },
                KeyValueChange {
                    r#type: Remove,
                    key: "fourth".to_string(),
                    value1: Some("fourth".to_string()),
                    value2: None,
                },
                KeyValueChange {
                    r#type: Remove,
                    key: "fifth".to_string(),
                    value1: Some("fifth".to_string()),
                    value2: None,
                },
            ]
        );
    }
}

#[cfg(test)]
mod proptests {
    use crate::{
        strategies::{self, generate_kvs, generate_ops_and_changes, Change, Operations},
        ChangeType,
    };
    use async_std::task;
    use proptest::{prop_assert, prop_assert_eq};
    use std::collections::HashSet;
    use test_strategy::proptest;
    use wnfs_common::{blockstore::InMemoryBlockstore, utils::Arc, Link};

    #[proptest(cases = 100, max_shrink_iters = 4000)]
    fn diff_correspondence(
        #[strategy(generate_ops_and_changes())] ops_changes: (
            Operations<String, u64>,
            Vec<Change<String, u64>>,
        ),
    ) {
        task::block_on(async {
            let store = &InMemoryBlockstore::<64>::new();
            let (ops, strategy_changes) = ops_changes;

            let other_node = &mut strategies::node_from_operations(&ops, store).await.unwrap();
            strategies::prepare_node(other_node, &strategy_changes, store)
                .await
                .unwrap();

            let main_node = &mut Arc::clone(other_node);
            strategies::apply_changes(main_node, &strategy_changes, store)
                .await
                .unwrap();

            let changes = super::diff(
                Link::from(Arc::clone(main_node)),
                Link::from(Arc::clone(other_node)),
                store,
            )
            .await
            .unwrap();

            prop_assert_eq!(strategy_changes.len(), changes.len());
            for strategy_change in strategy_changes {
                let found_matching_change = changes.iter().any(|c| match &strategy_change {
                    Change::Add(k, _) => c.r#type == ChangeType::Add && &c.key == k,
                    Change::Modify(k, _) => c.r#type == ChangeType::Modify && &c.key == k,
                    Change::Remove(k) => c.r#type == ChangeType::Remove && &c.key == k,
                });
                prop_assert!(found_matching_change);
            }
            Ok(())
        })?;
    }

    #[proptest(cases = 1000, max_shrink_iters = 40000)]
    fn diff_unique_keys(
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs1: Vec<(String, u64)>,
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs2: Vec<(String, u64)>,
    ) {
        task::block_on(async {
            let store = &InMemoryBlockstore::<64>::new();

            let node1 = strategies::node_from_kvs(kvs1, store).await.unwrap();
            let node2 = strategies::node_from_kvs(kvs2, store).await.unwrap();

            let changes = super::diff(Link::from(node1), Link::from(node2), store)
                .await
                .unwrap();

            let change_set = changes
                .iter()
                .map(|c| c.key.clone())
                .collect::<HashSet<_>>();

            prop_assert_eq!(change_set.len(), changes.len());
            Ok(())
        })?;
    }

    #[proptest(cases = 100)]
    fn add_remove_flip(
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs1: Vec<(String, u64)>,
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs2: Vec<(String, u64)>,
    ) {
        task::block_on(async {
            let store = &InMemoryBlockstore::<64>::new();

            let node1 = strategies::node_from_kvs(kvs1, store).await.unwrap();
            let node2 = strategies::node_from_kvs(kvs2, store).await.unwrap();

            let changes = super::diff(
                Link::from(Arc::clone(&node1)),
                Link::from(Arc::clone(&node2)),
                store,
            )
            .await
            .unwrap();

            let flipped_changes = super::diff(Link::from(node2), Link::from(node1), store)
                .await
                .unwrap();

            prop_assert_eq!(changes.len(), flipped_changes.len());
            for change in changes {
                let found_matching_change = flipped_changes.iter().any(|c| match change.r#type {
                    ChangeType::Add => c.r#type == ChangeType::Remove && c.key == change.key,
                    ChangeType::Remove => c.r#type == ChangeType::Add && c.key == change.key,
                    ChangeType::Modify => c.r#type == ChangeType::Modify && c.key == change.key,
                });
                prop_assert!(found_matching_change);
            }
            Ok(())
        })?;
    }
}
