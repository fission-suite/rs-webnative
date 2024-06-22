use crate::Node;
use anyhow::Result;
use proptest::{collection::*, prelude::*, strategy::Shuffleable};
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, fmt::Debug, hash::Hash};
use wnfs_common::{
    blockstore::Blockstore,
    utils::{Arc, CondSync},
    Storable,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Represents an operation that can be performed on a map-like data structure.
///
/// # Examples
///
/// ```
/// use wnfs_hamt::strategies::{self, Operation, Operations};
/// use wnfs_common::utils::Sampleable;
/// use proptest::{arbitrary::any, test_runner::TestRunner};
///
/// let mut runner = &mut TestRunner::deterministic();
/// let op = strategies::operation(any::<[u8; 32]>(), any::<String>()).sample(runner);
///
/// println!("{:?}", op);
/// ```
#[derive(Debug, Clone)]
pub enum Operation<K, V> {
    Insert(K, V),
    Remove(K),
    Reserialize,
}

/// A list of operations that can be applied to a map-like data structure.
///
/// # Examples
///
/// ```
/// use wnfs_hamt::strategies::{self, Operation, Operations};
/// use wnfs_common::utils::Sampleable;
/// use proptest::{arbitrary::any, test_runner::TestRunner};
///
/// let mut runner = &mut TestRunner::deterministic();
/// let ops = strategies::operations(any::<[u8; 32]>(), any::<String>(), 2).sample(runner);
///
/// assert_eq!(ops.0.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct Operations<K, V>(pub Vec<Operation<K, V>>);

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<K, V> Operation<K, V> {
    fn can_be_swapped_with(&self, other: &Operation<K, V>) -> bool
    where
        K: PartialEq,
        V: PartialEq,
    {
        match (self, other) {
            (Operation::Insert(key_a, val_a), Operation::Insert(key_b, val_b)) => {
                // We can't swap if the keys are the same and values different.
                // Because in those cases operation order matters.
                // E.g. insert "a" 10, insert "a" 11 != insert "a" 11, insert "a" 10
                // But insert "a" 10, insert "b" 11 == insert "b" 11, insert "a" 10
                // Or insert "a" 10, insert "a" 10 == insert "a" 10, insert "a" 10 ('swapped')
                key_a != key_b || val_a == val_b
            }
            (Operation::Insert(key_i, _), Operation::Remove(key_r)) => {
                // We can only swap if these two operations are unrelated.
                // Otherwise order matters.
                // E.g. insert "a" 10, remove "a" != remove "a", insert "a" 10
                key_i != key_r
            }
            (Operation::Remove(key_r), Operation::Insert(key_i, _)) => {
                // same as above
                key_i != key_r
            }
            (Operation::Remove(_), Operation::Remove(_)) => {
                // Removes can always be swapped
                true
            }
            (Operation::Reserialize, _) => true,
            (_, Operation::Reserialize) => true,
        }
    }
}

impl<K: PartialEq, V: PartialEq> Shuffleable for Operations<K, V> {
    fn shuffle_len(&self) -> usize {
        self.0.len()
    }

    /// Swaps the values if that wouldn't change the semantics.
    /// Otherwise it's a no-op.
    fn shuffle_swap(&mut self, a: usize, b: usize) {
        use std::cmp;
        if a == b {
            return;
        }
        let min = cmp::min(a, b);
        let max = cmp::max(a, b);
        let left = &self.0[min];
        let right = &self.0[max];

        for i in min..=max {
            let neighbor = &self.0[i];
            if !left.can_be_swapped_with(neighbor) {
                return;
            }
            if !right.can_be_swapped_with(neighbor) {
                return;
            }
        }

        // The reasoning for why this works now, is following:
        // Let's look at an example. We checked that we can do all of these swaps:
        // a x y z b
        // x a y z b
        // x y a z b
        // x y z a b
        // x y z b a
        // x y b z a
        // x b y z a
        // b x y z a
        // Observe how a moves to the right
        // and b moves to the left.
        // The end result is the same as
        // just swapping a and b.
        // With all calls to `can_be_swapped_with` above
        // we've made sure that this operation is now safe.

        self.0.swap(a, b);
    }
}

impl<K, V> From<&Operations<K, V>> for HashMap<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn from(ops: &Operations<K, V>) -> Self {
        let mut map = HashMap::default();
        for op in &ops.0 {
            match op {
                Operation::Insert(key, value) => {
                    map.insert(key.clone(), value.clone());
                }
                Operation::Remove(key) => {
                    map.remove(key);
                }
                Operation::Reserialize => {}
            }
        }
        map
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// This creates a node from a list of operations.
///
/// # Examples
///
/// ```
/// use wnfs_hamt::strategies::{self, Operation, Operations};
/// use wnfs_common::{MemoryBlockStore, utils::Sampleable};
/// use proptest::{arbitrary::any, test_runner::TestRunner};
///
/// #[async_std::main]
/// async fn main() {
///     let mut runner = &mut TestRunner::deterministic();
///     let ops = strategies::operations(any::<[u8; 32]>(), any::<String>(), 10).sample(runner);
///
///     let store = &MemoryBlockStore::new();
///     let node = strategies::node_from_operations(&ops, store).await.unwrap();
///
///     println!("{:?}", node);
/// }
/// ```
pub async fn node_from_operations<K, V>(
    operations: &Operations<K, V>,
    store: &impl Blockstore,
) -> Result<Arc<Node<K, V>>>
where
    K: Storable + Clone + Debug + CondSync + AsRef<[u8]>,
    V: Storable + Clone + Debug + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
{
    let mut node: Arc<Node<K, V>> = Arc::new(Node::default());
    for op in &operations.0 {
        match op {
            Operation::Insert(key, value) => {
                node.set(key.clone(), value.clone(), store).await?;
            }
            Operation::Remove(key) => {
                node.remove(key, store).await?;
            }
            Operation::Reserialize => {
                let cid = node.store(store).await?;
                node = Arc::new(Node::<K, V>::load(&cid, store).await?);
            }
        };
    }

    Ok(node)
}

/// Creates an insert or remove operation strategy based on the key and value provided.
///
/// # Examples
///
/// ```
/// use wnfs_hamt::strategies::{self, Operation, Operations};
/// use wnfs_common::utils::Sampleable;
/// use proptest::{arbitrary::any, test_runner::TestRunner};
///
/// let mut runner = &mut TestRunner::deterministic();
/// let op = strategies::operation(any::<[u8; 32]>(), any::<String>()).sample(runner);
///
/// println!("{:?}", op);
/// ```
pub fn operation<K: Debug, V: Debug>(
    key: impl Strategy<Value = K>,
    value: impl Strategy<Value = V>,
) -> impl Strategy<Value = Operation<K, V>> {
    (0..=2, key, value).prop_map(|(op, key, value)| match op {
        0 => Operation::Insert(key, value),
        1 => Operation::Remove(key),
        2 => Operation::Reserialize,
        _ => unreachable!("This case should be impossible. Values generated are only 0, 1, and 2"),
    })
}

/// Creates a list of operations strategy based on provided key and value strategies.
///
/// # Examples
///
/// ```
/// use wnfs_hamt::strategies::{self, Operation, Operations};
/// use wnfs_common::utils::Sampleable;
/// use proptest::{arbitrary::any, test_runner::TestRunner};
///
/// let mut runner = &mut TestRunner::deterministic();
/// let ops = strategies::operations(any::<[u8; 32]>(), any::<String>(), 2).sample(runner);
///
/// assert_eq!(ops.0.len(), 2);
/// ```
pub fn operations<K: Debug, V: Debug>(
    key: impl Strategy<Value = K>,
    value: impl Strategy<Value = V>,
    size: impl Into<SizeRange>,
) -> impl Strategy<Value = Operations<K, V>> {
    vec(operation(key, value), size).prop_map(|vec| Operations(vec))
}

/// Creates a list of operations with safe insert-remove shuffle.
///
/// # Examples
///
/// ```
/// use wnfs_hamt::strategies::{self, Operation, Operations};
/// use wnfs_common::utils::Sampleable;
/// use proptest::{arbitrary::any, test_runner::TestRunner};
///
/// let mut runner = &mut TestRunner::deterministic();
/// let ops = strategies::operations_and_shuffled(any::<[u8; 32]>(), any::<String>(), 2).sample(runner);
///
/// println!("{:?}", ops);
/// ```
pub fn operations_and_shuffled<K: PartialEq + Clone + Debug, V: PartialEq + Clone + Debug>(
    key: impl Strategy<Value = K>,
    value: impl Strategy<Value = V>,
    size: impl Into<SizeRange>,
) -> impl Strategy<Value = (Operations<K, V>, Operations<K, V>)> {
    operations(key, value, size)
        .prop_flat_map(|operations| (Just(operations.clone()), Just(operations).prop_shuffle()))
}
