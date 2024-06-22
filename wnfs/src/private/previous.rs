use super::{
    encrypted::Encrypted, forest::traits::PrivateForest, PrivateDirectory, PrivateFile,
    PrivateNode, PrivateNodeHeader, TemporalKey,
};
use crate::error::FsError;
use anyhow::{bail, Result};
use skip_ratchet::{PreviousIterator, Ratchet};
use std::collections::BTreeSet;
use wnfs_common::{
    blockstore::Blockstore, ipld_core::cid::Cid, utils::Arc, PathNodes, PathNodesResult,
};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// Represents the state of an iterator through the history
/// of a private node on a path relative to a root directory.
pub struct PrivateNodeOnPathHistory<F: PrivateForest + Clone> {
    /// Keep a reference to the version of the forest used upon construction.
    /// It could *technically* change what's behind a certain key in between
    /// previous node requests, this forces it to be consistent.
    forest: F,
    /// Keep the original discrepancy budget for consistency & ease of use.
    discrepancy_budget: usize,
    /// The history of each path segment leading up to the final node
    path: Vec<PathSegmentHistory<F>>,
    /// The target node's history
    target: PrivateNodeHistory<F>,
}

struct PathSegmentHistory<F: PrivateForest> {
    /// The directory that the history was originally created relative to.
    dir: Arc<PrivateDirectory>,
    /// The history of said directory.
    history: PrivateNodeHistory<F>,
    /// The name of the child node to follow for history next.
    path_segment: String,
}

/// This represents the state of an iterator through the history of
/// only a single private node. It can only be constructed when you
/// know the past ratchet state of such a node.
pub struct PrivateNodeHistory<F: PrivateForest> {
    /// Keep a reference to the version of the forest used upon construction.
    /// It could *technically* change what's behind a certain key in between
    /// previous node requests, this forces it to be consistent.
    forest: F,
    /// The private node header is all we need to look up private nodes in the forest.
    /// This will always be the header of the *next* version after what's retrieved from
    /// the `ratchets` iterator.
    header: PrivateNodeHeader,
    /// The private node tracks which previous revision's value it was a modification of.
    previous: BTreeSet<(usize, Encrypted<Cid>)>,
    /// The iterator for previous revision ratchets.
    ratchets: PreviousIterator,
}

impl<F: PrivateForest> PrivateNodeHistory<F> {
    /// Create a history iterator for given private node up until `past_ratchet`.
    ///
    /// There must be an `n > 0` for which `node.get_header().ratchet == past_ratchet.inc_by(n)`.
    ///
    /// Discrepancy budget is used to bound the search for the actual `n`
    /// and prevent infinite looping in case it doesn't exist.
    pub fn of(
        node: &PrivateNode,
        past_node: &PrivateNode,
        discrepancy_budget: usize,
        forest: F,
    ) -> Result<Self> {
        Self::from_header(
            node.get_header().clone(),
            node.get_previous().clone(),
            &past_node.get_header().ratchet,
            discrepancy_budget,
            forest,
        )
    }

    /// Create a history iterator for a node given its header.
    ///
    /// See also `PrivateNodeHistory::of`.
    #[allow(clippy::mutable_key_type)]
    pub fn from_header(
        header: PrivateNodeHeader,
        previous: BTreeSet<(usize, Encrypted<Cid>)>,
        past_ratchet: &Ratchet,
        discrepancy_budget: usize,
        forest: F,
    ) -> Result<Self> {
        let ratchets = header
            .ratchet
            .previous(past_ratchet, discrepancy_budget)
            .map_err(FsError::NoIntermediateRatchet)?;

        Ok(PrivateNodeHistory {
            forest,
            header,
            previous,
            ratchets,
        })
    }

    /// Step the history one step back and retrieve the private node at the
    /// previous point in history.
    ///
    /// Returns `None` if there is no such node in the `PrivateForest` at that point in time.
    pub async fn get_previous_node(
        &mut self,
        store: &impl Blockstore,
    ) -> Result<Option<PrivateNode>> {
        let Some(previous_ratchet) = self.ratchets.next() else {
            return Ok(None);
        };

        let Some(previous_cid) = self.resolve_previous_cid(&previous_ratchet)? else {
            return Ok(None);
        };

        self.header.update_ratchet(previous_ratchet);

        let previous_node = PrivateNode::from_private_ref(
            &self
                .header
                .derive_revision_ref(&self.forest)
                .into_private_ref(previous_cid),
            &self.forest,
            store,
            self.header.name.parent(),
        )
        .await?;

        self.previous.clone_from(previous_node.get_previous());
        Ok(Some(previous_node))
    }

    fn resolve_previous_cid(&self, previous_ratchet: &Ratchet) -> Result<Option<Cid>> {
        // TODO(matheus23): Once we have private merge: Support walking forked history paths.
        // That would need an additional API that allows 'selecting' one of the forks before moving on.
        // Then this function would derive the nth-previous ratchet by "peeking" ahead the current
        // self.ratchets iterator for n (the "# of revisions back" usize attached to the previous pointer)
        let temporal_key = TemporalKey::new(previous_ratchet);
        let Some((_, first_backpointer)) = self
            .previous
            .iter()
            .find(|(revisions_back, _)| *revisions_back == 1)
        else {
            return Ok(None);
        };
        Ok(Some(*first_backpointer.resolve_value(&temporal_key)?))
    }

    /// Like `previous_node`, but attempts to resolve a directory.
    ///
    /// Returns `None` if there is no previous node with that revision in the `PrivateForest`,
    /// throws `FsError::NotADirectory` if the previous node happens to not be a directory.
    /// That should only happen for all nodes or for none.
    pub async fn get_previous_dir(
        &mut self,
        store: &impl Blockstore,
    ) -> Result<Option<Arc<PrivateDirectory>>> {
        match self.get_previous_node(store).await? {
            Some(PrivateNode::Dir(dir)) => Ok(Some(dir)),
            Some(_) => Err(FsError::NotADirectory.into()),
            None => Ok(None),
        }
    }

    /// Like `previous_node`, but attempts to resolve a file.
    ///
    /// Returns `None` if there is no previous node with that revision in the `PrivateForest`,
    /// throws `FsError::NotAFile` if the previous node happens to not be a file.
    /// That should only happen for all nodes or for none.
    pub async fn get_previous_file(
        &mut self,
        store: &impl Blockstore,
    ) -> Result<Option<Arc<PrivateFile>>> {
        match self.get_previous_node(store).await? {
            Some(PrivateNode::File(file)) => Ok(Some(file)),
            Some(_) => Err(FsError::NotAFile.into()),
            None => Ok(None),
        }
    }
}

impl<F: PrivateForest + Clone> PrivateNodeOnPathHistory<F> {
    /// Construct a history iterator for a private node at some path relative
    /// to some root directory.
    ///
    /// Returns errors when there is no private node at given path,
    /// or if the given `past_ratchet` is not within the `discrepancy_budget` to
    /// the given root `directory`, or simply unrelated.
    ///
    /// When `search_latest` is true, it follow the path in the current revision
    /// down to the child, and then look for the latest revision of the target node,
    /// including all in-between versions in the history.
    pub async fn of(
        directory: Arc<PrivateDirectory>,
        past_directory: Arc<PrivateDirectory>,
        discrepancy_budget: usize,
        path_segments: &[String],
        search_latest: bool,
        forest: F,
        store: &impl Blockstore,
    ) -> Result<PrivateNodeOnPathHistory<F>> {
        // To get the history on a node on a path from a given directory that we
        // know its newest and oldest ratchet of, we need to generate
        // `PrivateNodeHistory`s for each path segment up to the last node.
        //
        // This is what this function is doing, it constructs the `PrivateNodeOnPathHistory`.
        //
        // Stepping that history forward is then done in `PrivateNodeOnPathHistory#previous`.

        let (target_path, path_segments) = match path_segments.split_last() {
            None => {
                return Ok(PrivateNodeOnPathHistory {
                    forest: forest.clone(),
                    discrepancy_budget,
                    path: Vec::with_capacity(0),
                    target: PrivateNodeHistory::of(
                        &PrivateNode::Dir(directory),
                        &PrivateNode::Dir(past_directory),
                        discrepancy_budget,
                        forest.clone(),
                    )?,
                });
            }
            Some(split) => split,
        };

        let (path, target_history) = Self::path_nodes_and_target_history(
            Arc::clone(&directory),
            discrepancy_budget,
            path_segments,
            target_path,
            search_latest,
            forest.clone(),
            store,
        )
        .await?;

        let path = Self::path_segment_empty_histories(path, forest.clone(), discrepancy_budget)?;

        let mut previous_iter = PrivateNodeOnPathHistory {
            forest: forest.clone(),
            discrepancy_budget,
            path,
            target: target_history,
        };

        // For the first part of the path, we specifically set the history ourselves,
        // because we've had `past_ratchet` passed in from the outside.

        let new_ratchet = directory.header.ratchet.clone();

        previous_iter.path[0].history.ratchets = new_ratchet
            .previous(&past_directory.header.ratchet, discrepancy_budget)
            .map_err(FsError::NoIntermediateRatchet)?;

        Ok(previous_iter)
    }

    /// Accumulates the path nodes towards a target node and
    /// creates a `PrivateNodeHistory` for that target node from
    /// the latest version it could find (if `search_latest` is true)
    /// until the current revision.
    ///
    /// If `search_latest` is false, the target history is empty.
    async fn path_nodes_and_target_history(
        dir: Arc<PrivateDirectory>,
        discrepancy_budget: usize,
        path_segments: &[String],
        target_path_segment: &String,
        search_latest: bool,
        forest: F,
        store: &impl Blockstore,
    ) -> Result<(Vec<(Arc<PrivateDirectory>, String)>, PrivateNodeHistory<F>)> {
        // We only search for the latest revision in the private node.
        // It may have been deleted in future versions of its ancestor directories.
        let path_nodes = match dir
            .get_path_nodes(path_segments, false, &forest, store)
            .await?
        {
            PathNodesResult::Complete(path_nodes) => path_nodes,
            PathNodesResult::MissingLink(_, _) => bail!(FsError::NotFound),
            PathNodesResult::NotADirectory(_, _) => bail!(FsError::NotADirectory),
        };

        let Some(target) = (*path_nodes.tail)
            .lookup_node(target_path_segment, false, &forest, store)
            .await?
        else {
            bail!(FsError::NotFound);
        };

        let target_latest = if search_latest {
            target.search_latest(&forest, store).await?
        } else {
            target.clone()
        };

        let target_history =
            PrivateNodeHistory::of(&target_latest, &target, discrepancy_budget, forest.clone())?;

        let PathNodes { mut path, tail } = path_nodes;

        path.push((tail, target_path_segment.to_string()));

        Ok((path, target_history))
    }

    /// Takes a path of directories and initializes each path segment with an empty history.
    fn path_segment_empty_histories(
        path: Vec<(Arc<PrivateDirectory>, String)>,
        forest: F,
        discrepancy_budget: usize,
    ) -> Result<Vec<PathSegmentHistory<F>>> {
        let mut segments = Vec::new();
        for (dir, path_segment) in path {
            segments.push(PathSegmentHistory {
                dir: Arc::clone(&dir),
                history: PrivateNodeHistory::of(
                    &PrivateNode::Dir(Arc::clone(&dir)),
                    &PrivateNode::Dir(Arc::clone(&dir)),
                    discrepancy_budget,
                    forest.clone(),
                )?,
                path_segment,
            });
        }

        Ok(segments)
    }

    /// Step the history one revision back and retrieve the node at the configured path.
    ///
    /// Returns `None` if there is no more previous revisions.
    pub async fn get_previous(&mut self, store: &impl Blockstore) -> Result<Option<PrivateNode>> {
        // Finding the previous revision of a node works by trying to get
        // the previous revision of the path elements starting on the deepest
        // path node working upwards, in case the history of lower nodes
        // have been exhausted.
        //
        // Once another history entry on the path has been found, we proceed
        // to work back trying to construct new history entries by going downwards
        // on the same path from an older root revision, until we've completed
        // the whole path and found new history entries in every segment.

        if let Some(node) = self.target.get_previous_node(store).await? {
            return Ok(Some(node));
        }

        let Some(working_stack) = self.find_and_step_segment_history(store).await? else {
            return Ok(None);
        };

        if !self
            .repopulate_segment_histories(working_stack, store)
            .await?
        {
            return Ok(None);
        }

        let ancestor = self.path.last().expect(
            "Should not happen: path stack was empty after call to repopulate_segment_histories",
        );

        let Some(older_node) = ancestor
            .dir
            .lookup_node(&ancestor.path_segment, false, &self.forest, store)
            .await?
        else {
            return Ok(None);
        };

        self.target = match PrivateNodeHistory::from_header(
            self.target.header.clone(),
            self.target.previous.clone(),
            &older_node.get_header().ratchet,
            self.discrepancy_budget,
            self.forest.clone(),
        ) {
            Ok(history) => history,
            // NoIntermediateRatchet error
            Err(_) => {
                // The target element lives at the same path but has ratchets that are further
                // apart than `discrepancy_budget`.
                // It's likely this node was deleted and recreated in between these history
                // steps. Or it had its key rotated. Either way, the history stops here.
                return Ok(None);
            }
        };

        self.target.get_previous_node(store).await
    }

    /// Pops off elements from the path segment history stack until a
    /// path segment history is found which has history entries.
    /// Then this will put the previous directory on that stack and return
    /// all elements that were popped off.
    ///
    /// Returns None if the no path segment history in the stack has any
    /// more history entries.
    async fn find_and_step_segment_history(
        &mut self,
        store: &impl Blockstore,
    ) -> Result<Option<Vec<(Arc<PrivateDirectory>, String)>>> {
        let mut working_stack = Vec::with_capacity(self.path.len());

        loop {
            // Pop elements off the end of the path
            if let Some(mut segment) = self.path.pop() {
                // Try to find a path segment for which we have previous history entries
                if let Some(prev) = segment.history.get_previous_dir(store).await? {
                    segment.dir = prev;
                    self.path.push(segment);
                    // Once found, we can continue.
                    break;
                }

                working_stack.push((segment.dir, segment.path_segment));
            } else {
                // We have exhausted all histories of all path segments.
                // There's no way we can produce more history entries.
                return Ok(None);
            }
        }

        Ok(Some(working_stack))
    }

    /// After having popped off elements from the path segment history stack,
    /// and leaving behind a history-steppable element,
    /// push back steppable histories onto the stack.
    ///
    /// Must only be called when the path segment history stack has
    /// a steppable history entry on top.
    ///
    /// Returns false if there's no corresponding path in the previous revision.
    async fn repopulate_segment_histories(
        &mut self,
        working_stack: Vec<(Arc<PrivateDirectory>, String)>,
        store: &impl Blockstore,
    ) -> Result<bool> {
        // Work downwards from the previous history entry of a path segment we found
        for (directory, path_segment) in working_stack {
            let ancestor = self
                .path
                .last()
                .expect("Should not happen: repopulate_segment_histories called when the path stack was empty.");

            // Go down from the older ancestor directory parallel to the new revision's path
            let Some(PrivateNode::Dir(older_directory)) = ancestor
                .dir
                .lookup_node(&ancestor.path_segment, false, &self.forest, store)
                .await?
            else {
                return Ok(false);
            };

            let mut directory_history = match PrivateNodeHistory::of(
                &PrivateNode::Dir(directory),
                &PrivateNode::Dir(older_directory),
                self.discrepancy_budget,
                self.forest.clone(),
            ) {
                Ok(history) => history,
                // NoIntermediateRatchet error
                Err(_) => {
                    // in this case the two directories share the same name in different revisions,
                    // but their keys aren't related. It's likely that they don't share identity
                    // or there's some key rotation in between meaning we can't follow their history.
                    return Ok(false);
                }
            };

            // We need to find the in-between history entry! See the test case `previous_with_multiple_child_changes`.
            let Some(directory_prev) = directory_history.get_previous_dir(store).await? else {
                return Ok(false);
            };

            self.path.push(PathSegmentHistory {
                dir: directory_prev,
                history: directory_history,
                path_segment,
            });
        }

        Ok(true)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private::forest::hamt::HamtForest;
    use chrono::Utc;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use wnfs_common::blockstore::InMemoryBlockstore;

    struct TestSetup {
        rng: ChaCha12Rng,
        store: InMemoryBlockstore<64>,
        forest: Arc<HamtForest>,
        root_dir: Arc<PrivateDirectory>,
        discrepancy_budget: usize,
    }

    impl TestSetup {
        fn new() -> Self {
            let mut rng = ChaCha12Rng::seed_from_u64(0);
            let store = InMemoryBlockstore::<64>::new();
            let forest = Arc::new(HamtForest::new_rsa_2048(&mut rng));
            let root_dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), &mut rng);

            Self {
                rng,
                store,
                forest,
                root_dir,
                discrepancy_budget: 1_000_000,
            }
        }
    }

    #[async_std::test]
    async fn previous_of_root_node() {
        let TestSetup {
            mut rng,
            mut store,
            ref mut forest,
            mut root_dir,
            discrepancy_budget,
        } = TestSetup::new();

        let rng = &mut rng;
        let store = &mut store;

        root_dir.store(forest, store, rng).await.unwrap();

        let past_dir = root_dir.clone();

        root_dir
            .write(
                &["file.txt".into()],
                true,
                Utc::now(),
                b"file".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        root_dir
            .mkdir(&["docs".into()], true, Utc::now(), forest, store, rng)
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let mut iterator = PrivateNodeOnPathHistory::of(
            root_dir,
            past_dir,
            discrepancy_budget,
            &[],
            true,
            Arc::clone(forest),
            store,
        )
        .await
        .unwrap();

        assert!(iterator.get_previous(store).await.unwrap().is_some());
        assert!(iterator.get_previous(store).await.unwrap().is_some());
        assert!(iterator.get_previous(store).await.unwrap().is_none());
    }

    /// This test will generate the following file system structure:
    ///
    /// (horizontal = time series, vertical = hierarchy)
    /// ```plain
    /// ┌────────────┐              ┌────────────┐              ┌────────────┐
    /// │            │              │            │              │            │
    /// │    Root    ├─────────────►│    Root    ├─────────────►│    Root    │
    /// │            │              │            │              │            │
    /// └────────────┘              └─────┬──────┘              └─────┬──────┘
    ///                                   │                           │
    ///                                   │                           │
    ///                                   ▼                           ▼
    ///                             ┌────────────┐              ┌────────────┐
    ///                             │            │              │            │
    ///                             │    Docs    ├─────────────►│    Docs    │
    ///                             │            │              │            │
    ///                             └─────┬──────┘              └─────┬──────┘
    ///                                   │                           │
    ///                                   │                           │
    ///                                   ▼                           ▼
    ///                             ┌────────────┐              ┌────────────┐
    ///                             │            │              │            │
    ///                             │  Notes.md  ├─────────────►│  Notes.md  │
    ///                             │            │              │            │
    ///                             └────────────┘              └────────────┘
    /// ```
    ///
    /// Then, given the skip ratchet for revision 0 of "Root" and revision 2 of "Root",
    /// it will ask for the backwards-history of the "Root/Docs/Notes.md" file.
    #[async_std::test]
    async fn previous_of_path() {
        let TestSetup {
            mut rng,
            mut store,
            ref mut forest,
            mut root_dir,
            discrepancy_budget,
        } = TestSetup::new();

        let rng = &mut rng;
        let store = &mut store;

        root_dir.store(forest, store, rng).await.unwrap();

        let past_dir = root_dir.clone();

        let path = ["Docs".into(), "Notes.md".into()];

        root_dir
            .write(&path, true, Utc::now(), b"Hi".to_vec(), forest, store, rng)
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        root_dir
            .write(
                &path,
                true,
                Utc::now(),
                b"World".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let mut iterator = PrivateNodeOnPathHistory::of(
            root_dir,
            past_dir,
            discrepancy_budget,
            &path,
            true,
            Arc::clone(forest),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            iterator
                .get_previous(store)
                .await
                .unwrap()
                .unwrap()
                .as_file()
                .unwrap()
                .get_content(forest, store)
                .await
                .unwrap(),
            b"Hi".to_vec()
        );

        assert!(iterator.get_previous(store).await.unwrap().is_none());
    }

    /// This test will generate the following file system structure:
    ///
    /// (horizontal = time series, vertical = hierarchy)
    /// ```plain
    /// ┌────────────┐              ┌────────────┐
    /// │            │              │            │
    /// │    Root    ├─────────────►│    Root    │
    /// │            │              │            │
    /// └────────────┘              └─────┬──────┘
    ///                                   │
    ///                                   │
    ///                                   ▼
    ///                             ┌────────────┐              ┌────────────┐
    ///                             │            │              │            │
    ///                             │    Docs    ├─────────────►│    Docs    │
    ///                             │            │              │            │
    ///                             └─────┬──────┘              └─────┬──────┘
    ///                                   │                           │
    ///                                   │                           │
    ///                                   ▼                           ▼
    ///                             ┌────────────┐              ┌────────────┐
    ///                             │            │              │            │
    ///                             │  Notes.md  ├─────────────►│  Notes.md  │
    ///                             │            │              │            │
    ///                             └────────────┘              └────────────┘
    /// ```
    ///
    /// This is testing a case where the file system wasn't rooted completely.
    /// Imagine someone wrote the `Notes.md` file with only access up to `Root/Docs`.
    /// The file system diagram looks like this:
    #[async_std::test]
    async fn previous_of_seeking() {
        let TestSetup {
            mut rng,
            mut store,
            ref mut forest,
            mut root_dir,
            discrepancy_budget,
        } = TestSetup::new();

        let rng = &mut rng;
        let store = &mut store;

        root_dir.store(forest, store, rng).await.unwrap();

        let past_dir = root_dir.clone();

        let path = ["Docs".into(), "Notes.md".into()];

        root_dir
            .write(&path, true, Utc::now(), b"Hi".to_vec(), forest, store, rng)
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let docs_dir = root_dir
            .get_node(&["Docs".into()], true, forest, store)
            .await
            .unwrap();

        let mut docs_dir = docs_dir.unwrap().as_dir().unwrap();

        docs_dir
            .write(
                &["Notes.md".into()],
                true,
                Utc::now(),
                b"World".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        docs_dir.store(forest, store, rng).await.unwrap();

        let mut iterator = PrivateNodeOnPathHistory::of(
            root_dir,
            past_dir,
            discrepancy_budget,
            &path,
            true,
            Arc::clone(forest),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            iterator
                .get_previous(store)
                .await
                .unwrap()
                .unwrap()
                .as_file()
                .unwrap()
                .get_content(forest, store)
                .await
                .unwrap(),
            b"Hi".to_vec()
        );

        assert!(iterator.get_previous(store).await.unwrap().is_none());
    }

    /// This test will generate the following file system structure:
    ///
    /// (horizontal = time series, vertical = hierarchy)
    /// ```plain
    /// ┌────────────┐                              ┌────────────┐
    /// │            │                              │            │
    /// │    Root    ├─────────────────────────────►│    Root    │
    /// │            │                              │            │
    /// └─────┬──────┘                              └─────┬──────┘
    ///       │                                           │
    ///       │                                           │
    ///       ▼                                           ▼
    /// ┌────────────┐        ┌────────────┐        ┌────────────┐
    /// │            │        │            │        │            │
    /// │    Docs    ├───────►│    Docs    ├───────►│    Docs    │
    /// │            │        │            │        │            │
    /// └─────┬──────┘        └─────┬──────┘        └─────┬──────┘
    ///       │                     │                     │
    ///       │                     │                     │
    ///       ▼                     ▼                     ▼
    /// ┌────────────┐        ┌────────────┐        ┌────────────┐
    /// │            │        │            │        │            │
    /// │  Notes.md  ├───────►│  Notes.md  ├───────►│  Notes.md  │
    /// │            │        │            │        │            │
    /// └────────────┘        └────────────┘        └────────────┘
    /// ```
    ///
    /// This case happens when someone who only has access up to
    /// `Root/Docs` writes two revisions of `Notes.md` and
    /// is later rooted by another peer that has full root access.
    #[async_std::test]
    async fn previous_with_multiple_child_changes() {
        let TestSetup {
            mut rng,
            mut store,
            ref mut forest,
            mut root_dir,
            discrepancy_budget,
        } = TestSetup::new();

        let rng = &mut rng;
        let store = &mut store;

        let path = ["Docs".into(), "Notes.md".into()];

        root_dir
            .write(
                &path,
                true,
                Utc::now(),
                b"rev 0".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let past_dir = root_dir.clone();

        let docs_dir = root_dir
            .get_node(&["Docs".into()], true, forest, store)
            .await
            .unwrap();

        let mut docs_dir = docs_dir.unwrap().as_dir().unwrap();

        docs_dir
            .write(
                &["Notes.md".into()],
                true,
                Utc::now(),
                b"rev 1".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        docs_dir.store(forest, store, rng).await.unwrap();

        root_dir
            .write(
                &path,
                true,
                Utc::now(),
                b"rev 2".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let mut iterator = PrivateNodeOnPathHistory::of(
            root_dir,
            past_dir,
            discrepancy_budget,
            &path,
            true,
            Arc::clone(forest),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            iterator
                .get_previous(store)
                .await
                .unwrap()
                .unwrap()
                .as_file()
                .unwrap()
                .get_content(forest, store)
                .await
                .unwrap(),
            b"rev 1".to_vec()
        );

        assert_eq!(
            iterator
                .get_previous(store)
                .await
                .unwrap()
                .unwrap()
                .as_file()
                .unwrap()
                .get_content(forest, store)
                .await
                .unwrap(),
            b"rev 0".to_vec()
        );

        assert!(iterator.get_previous(store).await.unwrap().is_none());
    }

    /// This test will generate the following file system structure:
    ///
    /// (horizontal = time series, vertical = hierarchy)
    /// ```plain
    /// ┌────────────┐    ┌────────────┐    ┌────────────┐
    /// │            │    │            │    │            │
    /// │    Root    ├───►│    Root    ├───►│    Root    │
    /// │            │    │            │    │            │
    /// └─────┬──────┘    └─────┬──────┘    └─────┬──────┘
    ///       │                 │                 │
    ///       │ ┌───────────────┘                 │
    ///       ▼ ▼                                 ▼
    /// ┌────────────┐                      ┌────────────┐
    /// │            │                      │            │
    /// │    Docs    ├─────────────────────►│    Docs    │
    /// │            │                      │            │
    /// └─────┬──────┘                      └─────┬──────┘
    ///       │                                   │
    ///       │                                   │
    ///       ▼                                   ▼
    /// ┌────────────┐                      ┌────────────┐
    /// │            │                      │            │
    /// │  Notes.md  ├─────────────────────►│  Notes.md  │
    /// │            │                      │            │
    /// └────────────┘                      └────────────┘
    /// ```
    ///
    /// This scenario may happen very commonly when things are
    /// written to the root directory that aren't related to
    /// the path that is looked at for its history.
    #[async_std::test]
    async fn previous_with_unrelated_changes() {
        let TestSetup {
            mut rng,
            mut store,
            ref mut forest,
            mut root_dir,
            discrepancy_budget,
        } = TestSetup::new();

        let rng = &mut rng;
        let store = &mut store;

        let path = ["Docs".into(), "Notes.md".into()];

        root_dir
            .write(
                &path,
                true,
                Utc::now(),
                b"rev 0".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let past_dir = root_dir.clone();

        let mut root_dir = Arc::new(root_dir.prepare_next_revision().unwrap().clone());

        root_dir.store(forest, store, rng).await.unwrap();

        root_dir
            .write(
                &path,
                true,
                Utc::now(),
                b"rev 1".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let mut iterator = PrivateNodeOnPathHistory::of(
            root_dir,
            past_dir,
            discrepancy_budget,
            &path,
            true,
            Arc::clone(forest),
            store,
        )
        .await
        .unwrap();

        assert_eq!(
            iterator
                .get_previous(store)
                .await
                .unwrap()
                .unwrap()
                .as_file()
                .unwrap()
                .get_content(forest, store)
                .await
                .unwrap(),
            b"rev 0".to_vec()
        );

        assert!(iterator.get_previous(store).await.unwrap().is_none());
    }
}
