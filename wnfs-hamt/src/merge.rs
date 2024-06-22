use super::{ChangeType, Node};
use crate::{error::HamtError, Hasher};
use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::hash::Hash;
use wnfs_common::{
    blockstore::Blockstore,
    utils::{Arc, CondSync},
    Link, Storable,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Merges a node with another with the help of a resolver function.
pub async fn merge<K, V, H>(
    main_link: Link<Arc<Node<K, V, H>>>,
    other_link: Link<Arc<Node<K, V, H>>>,
    f: impl Fn(&V, &V) -> Result<V>,
    store: &impl Blockstore,
) -> Result<Arc<Node<K, V, H>>>
where
    K: Storable + Eq + Clone + CondSync + Hash + AsRef<[u8]>,
    V: Storable + Eq + Clone + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
    H: Hasher + CondSync,
{
    let kv_changes = super::diff(main_link.clone(), other_link.clone(), store).await?;

    let main_node = main_link.resolve_owned_value(store).await?;
    let other_node = other_link.resolve_owned_value(store).await?;

    let mut merge_node = Arc::clone(&main_node);
    for change in kv_changes {
        match change.r#type {
            ChangeType::Remove => {
                merge_node
                    .set(change.key, change.value1.unwrap(), store)
                    .await?;
            }
            ChangeType::Modify => {
                let main_value = main_node
                    .get(&change.key, store)
                    .await?
                    .ok_or(HamtError::KeyNotFound)?;

                let other_value = other_node
                    .get(&change.key, store)
                    .await?
                    .ok_or(HamtError::KeyNotFound)?;

                merge_node
                    .set(change.key, f(main_value, other_value)?, store)
                    .await?;
            }
            _ => (),
        }
    }

    Ok(merge_node)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use crate::strategies::{self, generate_kvs};
    use async_std::task;
    use proptest::prop_assert_eq;
    use std::cmp;
    use test_strategy::proptest;
    use wnfs_common::{blockstore::InMemoryBlockstore, utils::Arc, Link};

    #[proptest(cases = 100)]
    fn merge_associativity(
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs1: Vec<(String, u64)>,
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs2: Vec<(String, u64)>,
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs3: Vec<(String, u64)>,
    ) {
        task::block_on(async {
            let store = &InMemoryBlockstore::<64>::new();

            let node1 = strategies::node_from_kvs(kvs1, store).await.unwrap();
            let node2 = strategies::node_from_kvs(kvs2, store).await.unwrap();
            let node3 = strategies::node_from_kvs(kvs3, store).await.unwrap();

            let merge_node_left_assoc = {
                let tmp = super::merge(
                    Link::from(Arc::clone(&node1)),
                    Link::from(Arc::clone(&node2)),
                    |a, b| Ok(cmp::min(*a, *b)),
                    store,
                )
                .await
                .unwrap();

                super::merge(
                    Link::from(tmp),
                    Link::from(Arc::clone(&node3)),
                    |a, b| Ok(cmp::min(*a, *b)),
                    store,
                )
                .await
                .unwrap()
            };

            let merge_node_right_assoc = {
                let tmp = super::merge(
                    Link::from(node2),
                    Link::from(node3),
                    |a, b| Ok(cmp::min(*a, *b)),
                    store,
                )
                .await
                .unwrap();

                super::merge(
                    Link::from(node1),
                    Link::from(tmp),
                    |a, b| Ok(cmp::min(*a, *b)),
                    store,
                )
                .await
                .unwrap()
            };

            prop_assert_eq!(merge_node_left_assoc, merge_node_right_assoc);
            Ok(())
        })?;
    }

    #[proptest(cases = 100)]
    fn merge_commutativity(
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs1: Vec<(String, u64)>,
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs2: Vec<(String, u64)>,
    ) {
        task::block_on(async {
            let store = &InMemoryBlockstore::<64>::new();

            let node1 = strategies::node_from_kvs(kvs1, store).await.unwrap();
            let node2 = strategies::node_from_kvs(kvs2, store).await.unwrap();

            let merge_node_1 = super::merge(
                Link::from(Arc::clone(&node1)),
                Link::from(Arc::clone(&node2)),
                |a, b| Ok(cmp::min(*a, *b)),
                store,
            )
            .await
            .unwrap();

            let merge_node_2 = super::merge(
                Link::from(node2),
                Link::from(node1),
                |a, b| Ok(cmp::min(*a, *b)),
                store,
            )
            .await
            .unwrap();

            prop_assert_eq!(merge_node_1, merge_node_2);
            Ok(())
        })?;
    }

    #[proptest(cases = 100)]
    fn merge_idempotency(
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs1: Vec<(String, u64)>,
        #[strategy(generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100))] kvs2: Vec<(String, u64)>,
    ) {
        task::block_on(async {
            let store = &InMemoryBlockstore::<64>::new();

            let node1 = strategies::node_from_kvs(kvs1, store).await.unwrap();
            let node2 = strategies::node_from_kvs(kvs2, store).await.unwrap();

            let merge_node_1 = super::merge(
                Link::from(Arc::clone(&node1)),
                Link::from(Arc::clone(&node2)),
                |a, b| Ok(cmp::min(*a, *b)),
                store,
            )
            .await
            .unwrap();

            let merge_node_2 = super::merge(
                Link::from(Arc::clone(&merge_node_1)),
                Link::from(node2),
                |a, b| Ok(cmp::min(*a, *b)),
                store,
            )
            .await
            .unwrap();

            prop_assert_eq!(merge_node_1, merge_node_2);
            Ok(())
        })?;
    }
}
