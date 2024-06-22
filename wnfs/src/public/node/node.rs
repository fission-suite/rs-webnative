//! Public node system in-memory representation.

use super::PublicNodeSerializable;
use crate::{
    error::FsError,
    public::{PublicDirectory, PublicFile},
    traits::Id,
};
use anyhow::{bail, Result};
use async_once_cell::OnceCell;
use chrono::{DateTime, Utc};
use std::{cmp::Ordering, collections::BTreeSet};
use wnfs_common::{blockstore::Blockstore, ipld_core::cid::Cid, utils::Arc, Storable};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// A node in the WNFS public file system. This can either be a file or a directory.
///
/// # Examples
///
/// ```
/// use wnfs::public::{PublicDirectory, PublicNode};
/// use chrono::Utc;
///
/// let dir = PublicDirectory::new_rc(Utc::now());
/// let node = PublicNode::Dir(dir);
///
/// println!("Node: {:?}", node);
/// ```
#[derive(Debug, Clone)]
pub enum PublicNode {
    File(Arc<PublicFile>),
    Dir(Arc<PublicDirectory>),
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl PublicNode {
    /// Creates node with upserted modified time.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::public::{PublicDirectory, PublicNode};
    /// use chrono::{Utc, Duration, TimeZone};
    ///
    /// let dir = PublicDirectory::new_rc(Utc::now());
    /// let node = &mut PublicNode::Dir(dir);
    ///
    /// let time = Utc::now();
    /// node.upsert_mtime(time);
    ///
    /// let imprecise_time = Utc.timestamp_opt(time.timestamp(), 0).single();
    /// assert_eq!(
    ///     imprecise_time,
    ///     node.as_dir()
    ///         .unwrap()
    ///         .get_metadata()
    ///         .get_modified()
    /// );
    /// ```
    pub fn upsert_mtime(&mut self, time: DateTime<Utc>) {
        match self {
            Self::File(file) => {
                Arc::make_mut(file).metadata.upsert_mtime(time);
            }
            Self::Dir(dir) => {
                Arc::make_mut(dir).metadata.upsert_mtime(time);
            }
        }
    }

    /// Creates node with updated previous pointer value.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::public::{PublicDirectory, PublicNode};
    /// use chrono::Utc;
    /// use libipld_core::cid::Cid;
    /// use std::{sync::Arc, collections::BTreeSet};
    ///
    /// let dir = PublicDirectory::new_rc(Utc::now());
    /// let node = PublicNode::Dir(dir);
    ///
    /// let new_cids = [Cid::default()];
    /// let node = node.update_previous(new_cids.to_vec());
    ///
    /// assert_eq!(
    ///     &BTreeSet::from(new_cids),
    ///     node.as_dir()
    ///         .unwrap()
    ///         .get_previous()
    /// );
    /// ```
    pub fn update_previous(&self, cids: Vec<Cid>) -> Self {
        match self {
            Self::File(file) => {
                let mut file = (**file).clone();
                file.previous = cids.into_iter().collect();
                Self::File(Arc::new(file))
            }
            Self::Dir(dir) => {
                let mut dir = (**dir).clone();
                dir.previous = cids.into_iter().collect();
                Self::Dir(Arc::new(dir))
            }
        }
    }

    /// Gets previous ancestor of a node.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::public::{PublicDirectory, PublicNode};
    /// use chrono::Utc;
    ///
    /// let dir = PublicDirectory::new_rc(Utc::now());
    /// let node = PublicNode::Dir(dir);
    ///
    /// assert_eq!(
    ///     node.get_previous(),
    ///     node.as_dir()
    ///         .unwrap()
    ///         .get_previous()
    /// );
    /// ```
    pub fn get_previous(&self) -> &BTreeSet<Cid> {
        match self {
            Self::File(file) => file.get_previous(),
            Self::Dir(dir) => dir.get_previous(),
        }
    }

    /// Casts a node to a directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs::public::{PublicDirectory, PublicNode};
    /// use chrono::Utc;
    ///
    /// let dir = PublicDirectory::new_rc(Utc::now());
    /// let node = PublicNode::Dir(Arc::clone(&dir));
    ///
    /// assert_eq!(node.as_dir().unwrap(), dir);
    /// ```
    pub fn as_dir(&self) -> Result<Arc<PublicDirectory>> {
        Ok(match self {
            Self::Dir(dir) => Arc::clone(dir),
            _ => bail!(FsError::NotADirectory),
        })
    }

    /// Casts a node to a mutable directory.
    pub(crate) fn as_dir_mut(&mut self) -> Result<&mut Arc<PublicDirectory>> {
        Ok(match self {
            Self::Dir(dir) => dir,
            _ => bail!(FsError::NotADirectory),
        })
    }

    /// Casts a node to a file.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs::public::{PublicFile, PublicNode};
    /// use chrono::Utc;
    ///
    /// let file = PublicFile::new_rc(Utc::now());
    /// let node = PublicNode::File(Arc::clone(&file));
    ///
    /// assert_eq!(node.as_file().unwrap(), file);
    /// ```
    pub fn as_file(&self) -> Result<Arc<PublicFile>> {
        Ok(match self {
            Self::File(file) => Arc::clone(file),
            _ => bail!(FsError::NotAFile),
        })
    }

    /// Tries to resolve this node as a file. Fails with `NotAFile` otherwise.
    pub fn as_file_mut(&mut self) -> Result<&mut Arc<PublicFile>> {
        match self {
            Self::File(file) => Ok(file),
            _ => bail!(FsError::NotAFile),
        }
    }

    /// Returns true if underlying node is a directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::public::{PublicDirectory, PublicNode};
    /// use chrono::Utc;
    ///
    /// let dir = PublicDirectory::new_rc(Utc::now());
    /// let node = PublicNode::Dir(dir);
    ///
    /// assert!(node.is_dir());
    /// ```
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(_))
    }

    /// Returns true if the underlying node is a file.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::public::{PublicFile, PublicNode};
    /// use chrono::Utc;
    ///
    /// let file = PublicFile::new_rc(Utc::now());
    /// let node = PublicNode::File(file);
    ///
    /// assert!(node.is_file());
    /// ```
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// Comparing the merkle clocks of this node to the other node.
    ///
    /// This gives you information about which node is "ahead" of which other node
    /// (think similar to git).
    /// This is what the return types indicate:
    /// - `Ok(None)`: These two nodes don't share any history.
    /// - `Ok(Some(Ordering::Equal))`: These nodes represent the same point in history/are the same exact node.
    /// - `Ok(Some(Ordering::Less))`: The other node is "further ahead" in history than this node.
    /// - `Ok(Some(Ordering::Greater))`: This node is "further ahead".
    /// - `Err(_)`: Something went wrong during deserialization/in the blockstore.
    pub async fn causal_compare(
        &self,
        other: &Self,
        store: &impl Blockstore,
    ) -> Result<Option<Ordering>> {
        async fn next_previous_set(
            previous_set: BTreeSet<Cid>,
            visited_cids: &mut BTreeSet<Cid>,
            store: &impl Blockstore,
        ) -> Result<BTreeSet<Cid>> {
            let mut previous = BTreeSet::new();

            for cid in previous_set {
                let node = PublicNode::load(&cid, store).await?;
                previous.extend(
                    node.get_previous()
                        .iter()
                        .filter(|cid| visited_cids.insert(**cid))
                        .cloned(),
                );
            }

            Ok(previous)
        }

        let our_root = self.store(store).await?;
        let other_root = other.store(store).await?;

        if our_root == other_root {
            return Ok(Some(Ordering::Equal));
        }

        let mut our_previous_set = self.get_previous().clone();
        let mut other_previous_set = other.get_previous().clone();

        let mut our_visited = BTreeSet::new();
        let mut other_visited = BTreeSet::new();

        loop {
            if other_previous_set.contains(&our_root) {
                return Ok(Some(Ordering::Less));
            }

            if our_previous_set.contains(&other_root) {
                return Ok(Some(Ordering::Greater));
            }

            // early return optimization:
            // If one "previous CIDs frontier" is entirely within the other's visited set,
            // then it for sure can't hit the other root, so we know they diverged.
            let our_is_true_subset =
                !our_previous_set.is_empty() && our_previous_set.is_subset(&other_visited);
            let other_is_true_subset =
                !other_previous_set.is_empty() && other_previous_set.is_subset(&our_visited);
            if our_is_true_subset || other_is_true_subset {
                return Ok(None);
            }

            our_previous_set = next_previous_set(our_previous_set, &mut our_visited, store).await?;
            other_previous_set =
                next_previous_set(other_previous_set, &mut other_visited, store).await?;

            if our_previous_set.is_empty() && other_previous_set.is_empty() {
                return Ok(None); // No common causal history
            }
        }
    }
}

impl Id for PublicNode {
    fn get_id(&self) -> String {
        match self {
            PublicNode::File(file) => file.get_id(),
            PublicNode::Dir(dir) => dir.get_id(),
        }
    }
}

impl PartialEq for PublicNode {
    fn eq(&self, other: &PublicNode) -> bool {
        match (self, other) {
            (Self::File(self_file), Self::File(other_file)) => {
                Arc::ptr_eq(self_file, other_file) || self_file == other_file
            }
            (Self::Dir(self_dir), Self::Dir(other_dir)) => {
                Arc::ptr_eq(self_dir, other_dir) || self_dir == other_dir
            }
            _ => false,
        }
    }
}

impl From<PublicFile> for PublicNode {
    fn from(file: PublicFile) -> Self {
        Self::File(Arc::new(file))
    }
}

impl From<PublicDirectory> for PublicNode {
    fn from(dir: PublicDirectory) -> Self {
        Self::Dir(Arc::new(dir))
    }
}

impl Storable for PublicNode {
    type Serializable = PublicNodeSerializable;

    async fn to_serializable(&self, store: &impl Blockstore) -> Result<Self::Serializable> {
        Ok(match self {
            Self::File(file) => file.to_serializable(store).await?,
            Self::Dir(dir) => dir.to_serializable(store).await?,
        })
    }

    async fn from_serializable(
        cid: Option<&Cid>,
        serializable: Self::Serializable,
    ) -> Result<Self> {
        // TODO(matheus23) this is weird, refactor?
        Ok(match serializable {
            PublicNodeSerializable::File(file) => Self::File(Arc::new(
                PublicFile::from_serializable(cid, PublicNodeSerializable::File(file)).await?,
            )),
            PublicNodeSerializable::Dir(dir) => Self::Dir(Arc::new(
                PublicDirectory::from_serializable(cid, PublicNodeSerializable::Dir(dir)).await?,
            )),
        })
    }

    fn persisted_as(&self) -> Option<&OnceCell<Cid>> {
        match self {
            PublicNode::File(file) => file.as_ref().persisted_as(),
            PublicNode::Dir(dir) => dir.as_ref().persisted_as(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::public::{PublicDirectory, PublicFile, PublicNode};
    use chrono::Utc;
    use testresult::TestResult;
    use wnfs_common::{blockstore::InMemoryBlockstore, Storable};

    #[async_std::test]
    async fn serialized_public_node_can_be_deserialized() -> TestResult {
        let store = &InMemoryBlockstore::<64>::new();
        let dir_node: PublicNode = PublicDirectory::new(Utc::now()).into();
        let file_node: PublicNode = PublicFile::new(Utc::now()).into();

        // We add a round-trip, because... userland records whether it was newly created/loaded
        let file_node = PublicNode::load(&file_node.store(store).await?, store).await?;

        let dir_cid = dir_node.store(store).await?;
        let file_cid = file_node.store(store).await?;

        let loaded_file_node = PublicNode::load(&file_cid, store).await?;
        let loaded_dir_node = PublicNode::load(&dir_cid, store).await?;

        assert_eq!(loaded_file_node, file_node);
        assert_eq!(loaded_dir_node, dir_node);

        Ok(())
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use futures::{stream, StreamExt, TryStreamExt};
    use proptest::{collection::vec, prelude::*};
    use test_strategy::proptest;
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[derive(Debug, Clone, Copy)]
    enum Operation {
        Write(usize), // write to nth head
        Merge,        // merge all heads
        Fork(usize),  // fork the nth head
    }

    #[derive(Debug, Clone)]
    struct State {
        heads: Vec<Arc<PublicDirectory>>, // always nonempty
        fork_num: i64,
    }

    impl State {
        pub fn new(init_time: i64) -> Self {
            Self {
                heads: vec![Arc::new(PublicDirectory::new(Self::time(init_time)))],
                fork_num: 0,
            }
        }

        fn time(n: i64) -> DateTime<Utc> {
            DateTime::<Utc>::from_timestamp(n, 0).unwrap()
        }

        pub fn get_head(&self, n: usize) -> &Arc<PublicDirectory> {
            let len = self.heads.len();
            debug_assert!(len > 0);
            &self.heads[n % len] // so we don't need to account for the current state (number of heads) when generating n
        }

        pub fn get_head_mut(&mut self, n: usize) -> &mut Arc<PublicDirectory> {
            let len = self.heads.len();
            debug_assert!(len > 0);
            &mut self.heads[n % len] // so we don't need to account for the current state (number of heads) when generating n
        }

        pub async fn run(&mut self, op: &Operation, store: &impl Blockstore) -> Result<()> {
            match op {
                Operation::Write(n) => {
                    let head = self.get_head_mut(*n);
                    head.store(store).await?;
                    head.prepare_next_revision();
                }
                Operation::Merge => {
                    let head_cids = stream::iter(self.heads.iter())
                        .then(|head| head.store(store))
                        .try_collect::<BTreeSet<_>>()
                        .await?;
                    let mut dir = PublicDirectory::new(Self::time(0));
                    dir.previous = head_cids;
                    self.heads = vec![Arc::new(dir)];
                }
                Operation::Fork(n) => {
                    let mut head = (**self.get_head(*n)).clone();
                    self.fork_num += 1;
                    // To make sure we don't accidentally recreate the same CIDs
                    head.metadata.upsert_mtime(Self::time(self.fork_num));
                    self.heads.push(Arc::new(head));
                }
            }
            Ok(())
        }

        pub async fn run_all(
            &mut self,
            ops: impl IntoIterator<Item = Operation>,
            store: &impl Blockstore,
        ) -> Result<()> {
            for op in ops {
                self.run(&op, store).await?;
            }
            Ok(())
        }

        pub fn head_node(&self) -> PublicNode {
            debug_assert!(!self.heads.is_empty());
            PublicNode::Dir(Arc::clone(&self.heads[0]))
        }
    }

    fn op() -> impl Strategy<Value = Operation> {
        (0..=2, 0..16).prop_map(|(op, idx)| match op {
            0 => Operation::Write(idx as usize),
            1 => Operation::Merge,
            2 => Operation::Fork(idx as usize),
            _ => unreachable!(
                "This case should be impossible. Values generated are only 0, 1, and 2"
            ),
        })
    }

    async fn run_ops(
        init_time: i64,
        operations: impl IntoIterator<Item = Operation>,
        store: &impl Blockstore,
    ) -> Result<PublicNode> {
        let mut state = State::new(init_time);
        state.run_all(operations, store).await?;
        Ok(state.head_node())
    }

    #[proptest]
    fn test_reflexivity(#[strategy(vec(op(), 0..100))] operations: Vec<Operation>) {
        async_std::task::block_on(async move {
            let mut state = State::new(0);
            let store = &InMemoryBlockstore::<64>::new();

            state.run_all(operations, store).await.unwrap();
            let head_one = state.head_node();
            let head_two = state.head_node();

            prop_assert_eq!(
                head_one.causal_compare(&head_two, store).await.unwrap(),
                Some(Ordering::Equal)
            );

            Ok(())
        })?;
    }

    #[proptest(cases = 256, max_global_rejects = 10_000)]
    fn test_asymmetry(
        #[strategy(vec(op(), 0..30))] operations_one: Vec<Operation>,
        #[strategy(vec(op(), 0..30))] operations_two: Vec<Operation>,
    ) {
        async_std::task::block_on(async move {
            let store = &InMemoryBlockstore::<64>::new();
            let node_one = run_ops(0, operations_one, store).await.unwrap();
            let node_two = run_ops(0, operations_two, store).await.unwrap();

            let Some(cmp) = node_one.causal_compare(&node_two, store).await.unwrap() else {
                return Err(TestCaseError::reject("not testing causally incomparable"));
            };

            let Some(cmp_rev) = node_two.causal_compare(&node_one, store).await.unwrap() else {
                return Err(TestCaseError::fail(
                    "causally comparable one way, but not the other",
                ));
            };

            prop_assert_eq!(cmp.reverse(), cmp_rev);

            Ok(())
        })?;
    }

    #[proptest(cases = 100, max_global_rejects = 10_000)]
    fn test_transitivity(
        #[strategy(vec(op(), 0..20))] operations0: Vec<Operation>,
        #[strategy(vec(op(), 0..20))] operations1: Vec<Operation>,
        #[strategy(vec(op(), 0..20))] operations2: Vec<Operation>,
    ) {
        async_std::task::block_on(async move {
            let store = &InMemoryBlockstore::<64>::new();
            let node0 = run_ops(0, operations0, store).await.unwrap();
            let node1 = run_ops(0, operations1, store).await.unwrap();
            let node2 = run_ops(0, operations2, store).await.unwrap();

            let Some(cmp_0_1) = node0.causal_compare(&node1, store).await.unwrap() else {
                return Err(TestCaseError::reject("not testing causally incomparable"));
            };

            let Some(cmp_1_2) = node1.causal_compare(&node2, store).await.unwrap() else {
                return Err(TestCaseError::reject("not testing causally incomparable"));
            };

            let Some(cmp_0_2) = node0.causal_compare(&node2, store).await.unwrap() else {
                return Err(TestCaseError::reject("not testing causally incomparable"));
            };

            match (cmp_0_1, cmp_1_2) {
                (Ordering::Equal, Ordering::Equal) => prop_assert_eq!(cmp_0_2, Ordering::Equal),
                (Ordering::Less, Ordering::Less) => prop_assert_eq!(cmp_0_2, Ordering::Less),
                (Ordering::Less, Ordering::Equal) => prop_assert_eq!(cmp_0_2, Ordering::Less),
                (Ordering::Equal, Ordering::Less) => prop_assert_eq!(cmp_0_2, Ordering::Less),
                (Ordering::Equal, Ordering::Greater) => prop_assert_eq!(cmp_0_2, Ordering::Greater),
                (Ordering::Greater, Ordering::Equal) => prop_assert_eq!(cmp_0_2, Ordering::Greater),
                (Ordering::Greater, Ordering::Greater) => {
                    prop_assert_eq!(cmp_0_2, Ordering::Greater)
                }
                (Ordering::Less, Ordering::Greater) => {
                    return Err(TestCaseError::reject(
                        "a < b and b > c, there's no transitivity to test here",
                    ))
                }
                (Ordering::Greater, Ordering::Less) => {
                    return Err(TestCaseError::reject(
                        "a > b and b < c, there's no transitivity to test here",
                    ))
                }
            }

            Ok(())
        })?;
    }

    #[proptest]
    fn test_different_roots_incomparable(
        #[strategy(vec(op(), 0..100))] operations0: Vec<Operation>,
        #[strategy(vec(op(), 0..100))] operations1: Vec<Operation>,
    ) {
        async_std::task::block_on(async move {
            let store = &InMemoryBlockstore::<64>::new();
            let node0 = run_ops(0, operations0, store).await.unwrap();
            let node1 = run_ops(1, operations1, store).await.unwrap();

            prop_assert_eq!(node0.causal_compare(&node1, store).await.unwrap(), None);
            prop_assert_eq!(node1.causal_compare(&node0, store).await.unwrap(), None);
            Ok(())
        })?;
    }

    #[proptest]
    fn test_ops_after_merge_makes_greater(
        #[strategy(vec(op(), 0..100))] operations: Vec<Operation>,
        #[strategy(vec(op(), 0..100))] more_ops: Vec<Operation>,
    ) {
        async_std::task::block_on(async move {
            let mut state = State::new(0);
            let store = &InMemoryBlockstore::<64>::new();

            state.run_all(operations, store).await.unwrap();
            let head_one = state.head_node();
            state.run(&Operation::Merge, store).await.unwrap();
            state.run_all(more_ops, store).await.unwrap();
            let head_two = state.head_node();

            prop_assert_eq!(
                head_one.causal_compare(&head_two, store).await.unwrap(),
                Some(Ordering::Less)
            );
            prop_assert_eq!(
                head_two.causal_compare(&head_one, store).await.unwrap(),
                Some(Ordering::Greater)
            );

            Ok(())
        })?;
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use chrono::TimeZone;
    use wnfs_common::utils::SnapshotBlockStore;

    #[async_std::test]
    async fn public_file_and_directory_nodes() {
        let store = &SnapshotBlockStore::default();
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();

        let dir_node: PublicNode = PublicDirectory::new(time).into();
        let file_node: PublicNode = PublicFile::new(time).into();

        let dir_cid = dir_node.store(store).await.unwrap();
        let file_cid = file_node.store(store).await.unwrap();

        let dir = store.get_block_snapshot(&dir_cid).await.unwrap();
        let file = store.get_block_snapshot(&file_cid).await.unwrap();

        insta::assert_json_snapshot!(dir);
        insta::assert_json_snapshot!(file);
    }

    #[async_std::test]
    async fn public_fs() {
        let store = &SnapshotBlockStore::default();
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();

        let paths = [
            vec!["text.txt".into()],
            vec!["music".into(), "jazz".into()],
            vec!["videos".into(), "movies".into(), "anime".into()],
        ];

        let root_dir = &mut PublicDirectory::new_rc(time);
        let _ = root_dir.store(store).await.unwrap();

        for path in paths.iter() {
            root_dir
                .write(path, b"Hello, World!".to_vec(), time, store)
                .await
                .unwrap();
        }

        let cid = root_dir.store(store).await.unwrap();

        let values = store.get_dag_snapshot(cid).await.unwrap();
        insta::assert_json_snapshot!(values)
    }
}
