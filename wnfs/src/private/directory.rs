use super::{
    encrypted::Encrypted, forest::traits::PrivateForest, link::PrivateLink,
    PrivateDirectoryContentSerializable, PrivateFile, PrivateNode, PrivateNodeContentSerializable,
    PrivateNodeHeader, PrivateRef, TemporalKey,
};
use crate::{error::FsError, is_readable_wnfs_version, traits::Id, SearchResult, WNFS_VERSION};
use anyhow::{bail, ensure, Result};
use async_once_cell::OnceCell;
use chrono::{DateTime, Utc};
use rand_core::CryptoRngCore;
use std::{
    cmp::Ordering,
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::Debug,
};
use wnfs_common::{
    blockstore::{block::Block as _, Blockstore},
    ipld_core::cid::Cid,
    utils::{error, Arc, CondSend},
    Blake3Block, Metadata, PathNodes, PathNodesResult, CODEC_RAW,
};
use wnfs_nameaccumulator::{Name, NameSegment};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

pub type PrivatePathNodes = PathNodes<PrivateDirectory>;
pub type PrivatePathNodesResult = PathNodesResult<PrivateDirectory>;

/// A directory in the WNFS private file system.
///
/// # Examples
///
/// ```
/// use wnfs::private::{PrivateDirectory, forest::{hamt::HamtForest, traits::PrivateForest}};
/// use chrono::Utc;
/// use rand_chacha::ChaCha12Rng;
/// use rand_core::SeedableRng;
///
/// let rng = &mut ChaCha12Rng::from_entropy();
/// let forest = HamtForest::new_rsa_2048(rng);
/// let dir = PrivateDirectory::new(&forest.empty_name(), Utc::now(), rng);
///
/// println!("dir = {:?}", dir);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PrivateDirectory {
    pub header: PrivateNodeHeader,
    pub(crate) content: PrivateDirectoryContent,
}

pub(crate) struct PrivateDirectoryContent {
    pub(crate) persisted_as: OnceCell<Cid>,
    pub(crate) previous: BTreeSet<(usize, Encrypted<Cid>)>,
    pub(crate) metadata: Metadata,
    pub(crate) entries: BTreeMap<String, PrivateLink>,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl PrivateDirectory {
    /// Creates a new directory with provided details.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::private::{
    ///     PrivateDirectory, forest::hamt::HamtForest,
    ///     forest::traits::PrivateForest,
    /// };
    /// use wnfs_nameaccumulator::AccumulatorSetup;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = HamtForest::new_rsa_2048(rng);
    /// let dir = PrivateDirectory::new(&forest.empty_name(), Utc::now(), rng);
    ///
    /// println!("dir = {:?}", dir);
    /// ```
    pub fn new(
        parent_name: &Name,
        time: DateTime<Utc>,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Self {
        Self {
            header: PrivateNodeHeader::new(parent_name, rng),
            content: PrivateDirectoryContent {
                persisted_as: OnceCell::new(),
                previous: BTreeSet::new(),
                metadata: Metadata::new(time),
                entries: BTreeMap::new(),
            },
        }
    }

    /// Creates a `PrivateDirectory` with provided details and wraps it in an `Arc`.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::private::{
    ///     PrivateDirectory, forest::hamt::HamtForest,
    ///     forest::traits::PrivateForest,
    /// };
    /// use wnfs_nameaccumulator::AccumulatorSetup;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = HamtForest::new_rsa_2048(rng);
    /// let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    /// println!("dir = {:?}", dir);
    /// ```
    pub fn new_rc(
        parent_name: &Name,
        time: DateTime<Utc>,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Arc<Self> {
        Arc::new(Self::new(parent_name, time, rng))
    }

    /// This contstructor creates a new private directory and stores it in a provided `PrivateForest`.
    pub async fn new_and_store(
        parent_name: &Name,
        time: DateTime<Utc>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<Arc<Self>> {
        let dir = Arc::new(Self::new(parent_name, time, rng));
        dir.store(forest, store, rng).await?;
        Ok(dir)
    }

    /// Uses specified path segments and their existence in the file tree to generate `PathNodes`.
    ///
    /// Supports cases where the entire path does not exist.
    pub(crate) async fn get_path_nodes(
        self: Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<PrivatePathNodesResult> {
        use PathNodesResult::*;
        let mut working_node = self;
        let mut path_nodes = Vec::with_capacity(path_segments.len());

        for path_segment in path_segments {
            match working_node
                .lookup_node(path_segment, search_latest, forest, store)
                .await?
            {
                Some(PrivateNode::Dir(ref directory)) => {
                    path_nodes.push((Arc::clone(&working_node), path_segment.clone()));
                    working_node = Arc::clone(directory);
                }
                Some(_) => {
                    let path_nodes = PrivatePathNodes {
                        path: path_nodes,
                        tail: Arc::clone(&working_node),
                    };

                    return Ok(NotADirectory(path_nodes, path_segment.clone()));
                }
                None => {
                    let path_nodes = PrivatePathNodes {
                        path: path_nodes,
                        tail: Arc::clone(&working_node),
                    };

                    return Ok(MissingLink(path_nodes, path_segment.clone()));
                }
            }
        }

        Ok(Complete(PrivatePathNodes {
            path: path_nodes,
            tail: Arc::clone(&working_node),
        }))
    }

    /// Gets the metadata of the directory
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{
    ///     common::Metadata, private::PrivateDirectory,
    ///     private::forest::{hamt::HamtForest, traits::PrivateForest},
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048(rng);
    /// let time = Utc::now();
    /// let dir = PrivateDirectory::new_rc(
    ///     &forest.empty_name(),
    ///     time,
    ///     rng,
    /// );
    ///
    /// assert_eq!(dir.get_metadata(), &Metadata::new(time));
    /// ```
    #[inline]
    pub fn get_metadata<'a>(self: &'a Arc<Self>) -> &'a Metadata {
        &self.content.metadata
    }

    /// Looks up a node by its path name in the current directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateDirectory, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     root_dir
    ///         .mkdir(&["pictures".into(), "cats".into()], true, Utc::now(), forest, store, rng)
    ///         .await?;
    ///
    ///     let node = root_dir.lookup_node("pictures", true, forest, store).await?;
    ///
    ///     assert!(node.is_some());
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn lookup_node(
        &self,
        path_segment: &str,
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Option<PrivateNode>> {
        Ok(match self.content.entries.get(path_segment) {
            Some(private_link) => {
                let private_node = private_link
                    .resolve_node(forest, store, Some(self.header.name.clone()))
                    .await?;
                if search_latest {
                    Some(private_node.search_latest_reconciled(forest, store).await?)
                } else {
                    Some(private_node.clone())
                }
            }
            None => None,
        })
    }

    /// Looks up a node by its path name in the current directory.
    pub(crate) async fn lookup_node_mut<'a>(
        &'a mut self,
        path_segment: &str,
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Option<&'a mut PrivateNode>> {
        Ok(match self.content.entries.get_mut(path_segment) {
            Some(private_link) => {
                let private_node = private_link
                    .resolve_node_mut(forest, store, Some(self.header.name.clone()))
                    .await?;
                if search_latest {
                    *private_node = private_node.search_latest_reconciled(forest, store).await?;
                }

                Some(private_node)
            }
            None => None,
        })
    }

    pub(crate) async fn get_leaf_dir(
        self: &Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<SearchResult<Arc<Self>>> {
        let mut working_dir = Arc::clone(self);

        if search_latest {
            working_dir = working_dir.search_latest_reconciled(forest, store).await?;
        }

        for (depth, segment) in path_segments.iter().enumerate() {
            match working_dir
                .lookup_node(segment, search_latest, forest, store)
                .await?
            {
                Some(PrivateNode::Dir(directory)) => {
                    working_dir = Arc::clone(&directory);
                }
                Some(_) => return Ok(SearchResult::NotADir(working_dir, depth)),
                None => return Ok(SearchResult::Missing(working_dir, depth)),
            }
        }

        Ok(SearchResult::Found(working_dir))
    }

    pub(crate) async fn get_leaf_dir_mut<'a>(
        self: &'a mut Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<SearchResult<&'a mut Self>> {
        if search_latest {
            *self = self.clone().search_latest_reconciled(forest, store).await?;
        }

        let mut working_dir = self.prepare_next_revision()?;
        for (depth, segment) in path_segments.iter().enumerate() {
            match working_dir
                .lookup_node(segment, search_latest, forest, store)
                .await?
            {
                Some(PrivateNode::Dir(_)) => {
                    // We need this repeated lookup because Rust borrowck can't handle
                    // this mut borrow case yet without resorting to the unstable -Zpolonius flag.
                    // https://github.com/rust-lang/rust/issues/51545
                    working_dir = working_dir
                        .lookup_node_mut(segment, search_latest, forest, store)
                        .await
                        .unwrap()
                        .unwrap()
                        .as_dir_mut()
                        .unwrap()
                        .prepare_next_revision()?
                }
                Some(_) => return Ok(SearchResult::NotADir(working_dir, depth)),
                None => return Ok(SearchResult::Missing(working_dir, depth)),
            };
        }

        Ok(SearchResult::Found(working_dir))
    }

    #[allow(clippy::suspicious)]
    pub(crate) async fn get_or_create_leaf_dir_mut<'a>(
        self: &'a mut Arc<Self>,
        path_segments: &[String],
        time: DateTime<Utc>,
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<&'a mut Self> {
        match self
            .get_leaf_dir_mut(path_segments, search_latest, forest, store)
            .await?
        {
            SearchResult::Found(dir) => Ok(dir),
            SearchResult::Missing(mut dir, depth) => {
                for segment in &path_segments[depth..] {
                    dir = Arc::make_mut(
                        dir.content
                            .entries
                            .entry(segment.to_string())
                            .or_insert_with(|| {
                                PrivateLink::with_dir(Self::new(&dir.header.name, time, rng))
                            })
                            .resolve_node_mut(forest, store, Some(dir.header.name.clone()))
                            .await
                            .unwrap()
                            .as_dir_mut()
                            .unwrap(),
                    );
                }

                Ok(dir)
            }
            SearchResult::NotADir(_, _) => bail!(FsError::NotADirectory),
        }
    }

    /// This should be called to prepare a node for modifications,
    /// if it's meant to be a successor revision of the current revision.
    ///
    /// This doesn't have any effect if the current state hasn't been `.store()`ed yet.
    /// Otherwise, it clones itself, stores its current CID in the previous links and
    /// advances its ratchet.
    pub(crate) fn prepare_next_revision<'a>(self: &'a mut Arc<Self>) -> Result<&'a mut Self> {
        let Some(previous_cid) = self.content.persisted_as.get().cloned() else {
            // The current revision wasn't written yet.
            // There's no point in advancing the revision even further.
            return Ok(Arc::make_mut(self));
        };

        let temporal_key = self.header.derive_temporal_key();
        let previous_link = (1, Encrypted::from_value(previous_cid, &temporal_key)?);
        let cloned = Arc::make_mut(self);

        // We make sure to clear any cached states.
        cloned.content.persisted_as = OnceCell::new();
        cloned.content.previous = [previous_link].into_iter().collect();
        cloned.header.advance_ratchet();

        Ok(cloned)
    }

    /// Call this function to prepare this directory for conflict reconciliation merge changes.
    /// Advances this node to the revision given in `target_header`.
    /// Generates another previous link, unless this node is already a merge node, then this
    /// simply updates all previous links to use the correct steps back.
    /// Merge nodes preferably just grow in size. This allows them to combine more nicely
    /// without causing further conflicts.
    pub(crate) fn prepare_next_merge<'a>(
        self: &'a mut Arc<Self>,
        current_cid: Cid,
        target_header: PrivateNodeHeader,
    ) -> Result<&'a mut Self> {
        let ratchet_diff = target_header.ratchet_diff_for_merge(&self.header)?;

        if self.content.previous.len() > 1 {
            // This is a merge node
            let cloned = Arc::make_mut(self);
            cloned.content.persisted_as = OnceCell::new();
            cloned.header = target_header;
            cloned.content.previous = std::mem::take(&mut cloned.content.previous)
                .into_iter()
                .map(|(ratchet_steps, link)| (ratchet_steps + ratchet_diff, link))
                .collect();

            return Ok(cloned);
        }

        // It's not a merge node, we need to advance the revision

        let temporal_key = self.header.derive_temporal_key();
        let previous_link = (
            ratchet_diff,
            Encrypted::from_value(current_cid, &temporal_key)?,
        );
        let cloned = Arc::make_mut(self);

        // We make sure to clear any cached states.
        cloned.content.persisted_as = OnceCell::new();
        cloned.header = target_header;
        cloned.content.previous = [previous_link].into_iter().collect();

        Ok(cloned)
    }

    /// This prepares this directory for key rotation, usually for moving or
    /// copying the directory to some other place.
    ///
    /// Will reset the ratchet, so a different key is necessary for read access,
    /// will reset the inumber to reset write access,
    /// will update the name to be the sub-name of given parent name,
    /// so it inherits the write access rules from the new parent and
    /// resets the `persisted_as` pointer.
    pub(crate) fn prepare_key_rotation(
        &mut self,
        parent_name: &Name,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) {
        self.header.inumber = NameSegment::new(rng);
        self.header.update_name(parent_name);
        self.header.reset_ratchet(rng);
        self.content.persisted_as = OnceCell::new();
    }

    /// Follows a path and fetches the node at the end of the path.
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::{BlockStore, MemoryBlockStore},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     root_dir
    ///         .mkdir(&["pictures".into(), "cats".into()], true, Utc::now(), forest, store, rng)
    ///         .await
    ///         .unwrap();
    ///
    ///     let result = root_dir
    ///         .get_node(&["pictures".into(), "cats".into()], true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert!(result.is_some());
    /// }
    /// ```
    pub async fn get_node(
        self: &Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Option<PrivateNode>> {
        let Some((tail, path)) = path_segments.split_last() else {
            return Ok(None);
        };

        let SearchResult::Found(dir) = self
            .get_leaf_dir(path, search_latest, forest, store)
            .await?
        else {
            return Ok(None);
        };

        dir.lookup_node(tail, search_latest, forest, store).await
    }

    /// Reads specified file content from the directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateDirectory, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     let content = b"print('hello world')";
    ///
    ///     root_dir
    ///         .write(
    ///             &["code".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             content.to_vec(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await?;
    ///
    ///     let result = root_dir
    ///         .read(&["code".into(), "hello.py".into()], true, forest, store)
    ///         .await?;
    ///
    ///     assert_eq!(&result, content);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn read(
        self: &Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Vec<u8>> {
        let (path, filename) = crate::utils::split_last(path_segments)?;
        match self
            .get_leaf_dir(path, search_latest, forest, store)
            .await?
        {
            SearchResult::Found(dir) => {
                match dir
                    .lookup_node(filename, search_latest, forest, store)
                    .await?
                {
                    Some(PrivateNode::File(file)) => Ok(file.get_content(forest, store).await?),
                    Some(_) => error(FsError::NotAFile),
                    None => error(FsError::NotFound),
                }
            }
            _ => error(FsError::NotFound),
        }
    }

    /// Opens a mutable reference to the specified file.
    /// If the file is missing, it initializes an empty file and give a mut reference to that.
    /// If the file already exists, it will copy it to the next revision, update the edit time, and give a mut reference to that.
    /// # Examples
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::{BlockStore, MemoryBlockStore},
    /// };
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///    let store = &InMemoryBlockstore::<64>::new();
    ///    let rng = &mut ChaCha12Rng::from_entropy();
    ///    let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///    let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///     // The path to the file /code/hello.py as defined by our standards
    ///     let hello_py: &[String] = &["code".into(), "hello.py".into()];
    ///     // The original file content
    ///     let original_file_content = b"print('hello world')";
    ///     // Write content to the file
    ///     root_dir
    ///         .write(
    ///             hello_py,
    ///             true,
    ///             Utc::now(),
    ///             original_file_content.to_vec(),
    ///             forest,
    ///             store,
    ///             rng,
    ///        )
    ///        .await?;
    ///     // Clone the forest that was used to write the file
    ///     // Open the file mutably
    ///     let file = root_dir
    ///         .open_file_mut(hello_py, true, Utc::now(), forest, store, rng)
    ///         .await?;
    ///     // Define the content that will replace what is already in the file
    ///     let new_file_content = b"print('hello world 2')";
    ///     // Set the contents of the file, waiting for result and expecting no errors
    ///     file.set_content(&new_file_content[..], Utc::now(), forest, store, rng)
    ///         .await?;
    ///     // Read the file again
    ///     let result = root_dir.read(hello_py, true, forest, store).await?;
    ///     // Expect that the contents of the file are now different
    ///     assert_eq!(&result, new_file_content);
    ///
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::suspicious)]
    pub async fn open_file_mut<'a>(
        self: &'a mut Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        time: DateTime<Utc>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<&'a mut PrivateFile> {
        let (path, filename) = crate::utils::split_last(path_segments)?;
        let dir = self
            .get_or_create_leaf_dir_mut(path, time, search_latest, forest, store, rng)
            .await?;

        if !dir.content.entries.contains_key(filename.as_str()) {
            let link = PrivateLink::with_file(PrivateFile::new(&dir.header.name, time, rng));
            dir.content.entries.insert(filename.to_string(), link);
        }
        let lookup_result = dir
            .lookup_node_mut(filename, search_latest, forest, store)
            .await?;
        if let Some(PrivateNode::File(file)) = lookup_result {
            let file = file.prepare_next_revision()?;
            file.content.metadata.upsert_mtime(time);
            Ok(file)
        } else {
            bail!(FsError::NotAFile);
        }
    }

    /// Writes a file to the directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateDirectory, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     let content = b"print('hello world')";
    ///
    ///     root_dir
    ///         .write(
    ///             &["code".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             content.to_vec(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await?;
    ///
    ///     let result = root_dir
    ///         .read(&["code".into(), "hello.py".into()], true, forest, store)
    ///         .await?;
    ///
    ///     assert_eq!(&result, content);
    ///
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn write(
        self: &mut Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        time: DateTime<Utc>,
        content: Vec<u8>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let (path, filename) = crate::utils::split_last(path_segments)?;
        let dir = self
            .get_or_create_leaf_dir_mut(path, time, search_latest, forest, store, rng)
            .await?;

        match dir
            .lookup_node_mut(filename, search_latest, forest, store)
            .await?
        {
            Some(PrivateNode::File(file)) => {
                let file = file.prepare_next_revision()?;
                let content =
                    PrivateFile::prepare_content(&file.header.name, content, forest, store, rng)
                        .await?;
                file.content.content = content;
                file.content.metadata.upsert_mtime(time);
            }
            Some(PrivateNode::Dir(_)) => bail!(FsError::DirectoryAlreadyExists),
            None => {
                let file =
                    PrivateFile::with_content(&dir.header.name, time, content, forest, store, rng)
                        .await?;
                let link = PrivateLink::with_file(file);
                dir.content.entries.insert(filename.to_string(), link);
            }
        };

        Ok(())
    }

    /// Gets the latest version of the directory using exponential search.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{
    ///         PrivateNode, PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let mut init_dir = PrivateDirectory::new_and_store(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         forest,
    ///         store,
    ///         rng
    ///     ).await?;
    ///
    ///     let dir_clone = &mut Arc::clone(&init_dir);
    ///
    ///     dir_clone
    ///         .mkdir(&["pictures".into(), "cats".into()], true, Utc::now(), forest, store, rng)
    ///         .await?;
    ///
    ///     dir_clone.as_node().store(forest, store, rng).await?;
    ///
    ///     let latest_dir = init_dir.search_latest(forest, store).await?;
    ///
    ///     let found_node = latest_dir.lookup_node("pictures", true, forest, store).await?;
    ///
    ///     assert!(found_node.is_some());
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub async fn search_latest(
        self: Arc<Self>,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Arc<Self>> {
        PrivateNode::Dir(self)
            .search_latest(forest, store)
            .await?
            .as_dir()
    }

    /// Like `search_latest`, but does a linear search and picks up any
    /// writes that may need to be reconciled in the process.
    /// If it finds that there's multiple concurrent writes to reconcile, then
    /// it creates a merged directory and returns that.
    pub async fn search_latest_reconciled(
        self: Arc<Self>,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Arc<Self>> {
        PrivateNode::Dir(self)
            .search_latest_reconciled(forest, store)
            .await?
            .as_dir()
    }

    /// Creates a new directory at the specified path.
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::{BlockStore, MemoryBlockStore},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     root_dir
    ///         .mkdir(&["pictures".into(), "cats".into()], true, Utc::now(), forest, store, rng)
    ///         .await
    ///         .unwrap();
    ///
    ///     let node = root_dir.lookup_node("pictures", true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert!(node.is_some());
    /// }
    /// ```
    pub async fn mkdir(
        self: &mut Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        time: DateTime<Utc>,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let _ = self
            .get_or_create_leaf_dir_mut(path_segments, time, search_latest, forest, store, rng)
            .await?;

        Ok(())
    }

    /// Returns names and metadata of directory's immediate children.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateDirectory, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     root_dir
    ///         .write(
    ///             &["code".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             b"print('hello world')".to_vec(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await?;
    ///
    ///     root_dir
    ///         .mkdir(&["code".into(), "bin".into()], true, Utc::now(), forest, store, rng)
    ///         .await?;
    ///
    ///     let result = root_dir.ls(&["code".into()], true, forest, store).await?;
    ///
    ///     assert_eq!(result.len(), 2);
    ///     assert_eq!(
    ///         result.iter().map(|t| &t.0).collect::<Vec<_>>(),
    ///         ["bin", "hello.py"]
    ///     );
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn ls(
        self: &Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Vec<(String, Metadata)>> {
        match self
            .get_leaf_dir(path_segments, search_latest, forest, store)
            .await?
        {
            SearchResult::Found(dir) => {
                let mut result = vec![];
                for (name, link) in dir.content.entries.iter() {
                    match link
                        .resolve_node(forest, store, Some(dir.header.name.clone()))
                        .await?
                    {
                        PrivateNode::File(file) => {
                            result.push((name.clone(), file.content.metadata.clone()));
                        }
                        PrivateNode::Dir(dir) => {
                            result.push((name.clone(), dir.content.metadata.clone()));
                        }
                    }
                }
                Ok(result)
            }
            SearchResult::NotADir(_, _) => bail!(FsError::NotADirectory),
            _ => bail!(FsError::NotFound),
        }
    }

    /// Get the names of directory's immediate children.
    ///
    /// Other than [PrivateDirectory::ls] this returns only the names, without loading the
    /// metadata for each node from the store.
    pub fn get_entries<'a>(self: &'a Arc<Self>) -> impl Iterator<Item = &'a String> {
        self.content.entries.iter().map(|x| x.0)
    }

    /// Removes a file or directory from the directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::{BlockStore, MemoryBlockStore},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     root_dir
    ///         .write(
    ///             &["code".into(), "python".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             b"print('hello world')".to_vec(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let result = root_dir
    ///         .ls(&["code".into()], true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 1);
    ///
    ///     root_dir
    ///         .rm(&["code".into(), "python".into()], true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     let result = root_dir
    ///         .ls(&["code".into()], true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 0);
    /// }
    /// ```
    pub async fn rm(
        self: &mut Arc<Self>,
        path_segments: &[String],
        search_latest: bool,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<PrivateNode> {
        let (path, node_name) = crate::utils::split_last(path_segments)?;
        let SearchResult::Found(dir) = self
            .get_leaf_dir_mut(path, search_latest, forest, store)
            .await?
        else {
            bail!(FsError::NotFound)
        };

        let removed_node = match dir.content.entries.remove(node_name) {
            Some(link) => {
                link.resolve_owned_node(forest, store, Some(dir.header.name.clone()))
                    .await?
            }
            None => bail!(FsError::NotFound),
        };

        Ok(removed_node)
    }

    /// Attaches a node to the specified directory.
    ///
    /// Fixes up the subtree bare names to refer to the new parent.
    #[allow(clippy::too_many_arguments)]
    async fn attach(
        self: &mut Arc<Self>,
        mut node: PrivateNode,
        path_segments: &[String],
        search_latest: bool,
        time: DateTime<Utc>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let (path, node_name) = crate::utils::split_last(path_segments)?;
        let SearchResult::Found(dir) = self
            .get_leaf_dir_mut(path, search_latest, forest, store)
            .await?
        else {
            bail!(FsError::NotFound);
        };

        ensure!(
            !dir.content.entries.contains_key(node_name),
            FsError::FileAlreadyExists
        );

        node.upsert_mtime(time);
        node.update_ancestry(&dir.header.name, forest, store, rng)
            .await?;

        dir.content
            .entries
            .insert(node_name.clone(), PrivateLink::from(node));

        Ok(())
    }

    /// Moves a file or directory from one path to another.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::{BlockStore, MemoryBlockStore},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     root_dir
    ///         .write(
    ///             &["code".into(), "python".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             b"print('hello world')".to_vec(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let result = root_dir
    ///         .basic_mv(
    ///             &["code".into(), "python".into(), "hello.py".into()],
    ///             &["code".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let result = root_dir
    ///         .ls(&["code".into()], true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 2);
    /// }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn basic_mv(
        self: &mut Arc<Self>,
        path_segments_from: &[String],
        path_segments_to: &[String],
        search_latest: bool,
        time: DateTime<Utc>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let removed_node = self
            .rm(path_segments_from, search_latest, forest, store)
            .await?;

        self.attach(
            removed_node,
            path_segments_to,
            search_latest,
            time,
            forest,
            store,
            rng,
        )
        .await
    }

    /// Copies a file or directory from one path to another.
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::{BlockStore, MemoryBlockStore},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     root_dir
    ///         .write(
    ///             &["code".into(), "python".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             b"print('hello world')".to_vec(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     root_dir
    ///         .cp(
    ///             &["code".into(), "python".into(), "hello.py".into()],
    ///             &["code".into(), "hello.py".into()],
    ///             true,
    ///             Utc::now(),
    ///             forest,
    ///             store,
    ///             rng
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let result = root_dir
    ///         .ls(&["code".into()], true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 2);
    /// }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn cp(
        self: &mut Arc<Self>,
        path_segments_from: &[String],
        path_segments_to: &[String],
        search_latest: bool,
        time: DateTime<Utc>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let result = self
            .get_node(path_segments_from, search_latest, forest, store)
            .await?;

        self.attach(
            result.ok_or(FsError::NotFound)?,
            path_segments_to,
            search_latest,
            time,
            forest,
            store,
            rng,
        )
        .await
    }

    /// Stores this PrivateDirectory in the PrivateForest.
    pub(crate) async fn store(
        &self,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<PrivateRef> {
        let header_cid = self.header.store(store, forest).await?;
        let temporal_key = self.header.derive_temporal_key();
        let name_with_revision = self.header.get_revision_name();

        let content_cid = self
            .content
            .store(header_cid, &temporal_key, forest, store, rng)
            .await?;

        forest
            .put_encrypted(
                &name_with_revision,
                [header_cid, content_cid].into_iter(),
                store,
            )
            .await?;

        Ok(self
            .header
            .derive_revision_ref(forest)
            .into_private_ref(content_cid))
    }

    /// Creates a new [`PrivateDirectory`] from a [`PrivateDirectoryContentSerializable`].
    pub(crate) async fn from_serializable(
        serializable: PrivateDirectoryContentSerializable,
        temporal_key: &TemporalKey,
        cid: Cid,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        parent_name: Option<Name>,
    ) -> Result<Self> {
        if !is_readable_wnfs_version(&serializable.version) {
            bail!(FsError::UnexpectedVersion(serializable.version));
        }

        let mut entries_decrypted = BTreeMap::new();
        for (name, private_ref_serializable) in serializable.entries {
            let private_ref =
                PrivateRef::from_serializable(private_ref_serializable, temporal_key)?;
            entries_decrypted.insert(name, PrivateLink::from_ref(private_ref));
        }

        let content = PrivateDirectoryContent {
            persisted_as: OnceCell::new_with(cid),
            metadata: serializable.metadata,
            previous: serializable.previous.into_iter().collect(),
            entries: entries_decrypted,
        };

        let header = PrivateNodeHeader::load(
            &serializable.header_cid,
            temporal_key,
            forest,
            store,
            parent_name,
        )
        .await?;
        Ok(Self { header, content })
    }

    /// Wraps the directory in a [`PrivateNode`].
    pub fn as_node(self: &Arc<Self>) -> PrivateNode {
        PrivateNode::Dir(Arc::clone(self))
    }

    /// Merges two directories that have been stored before together
    /// (their CIDs must be passed in).
    /// This only merges the directories shallowly. It doesn't recursively merge
    /// them. This is handled by directories calling `search_latest_reconciled`
    /// on every level.
    /// Every directory should have a corresponding "identity directory" which is the
    /// empty directory, which when merged, results in no change.
    /// This function is both commutative and associative.
    /// If there's a conflict, it prefers keeping the directory, then tie-breaks on
    /// the private ref.
    pub(crate) async fn merge(
        self: &mut Arc<Self>,
        target_header: PrivateNodeHeader,
        our_cid: Cid,
        other: &Arc<Self>,
        other_cid: Cid,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<()> {
        if our_cid == other_cid {
            return Ok(());
        }

        let other_ratchet_diff = target_header.ratchet_diff_for_merge(&other.header)?;

        let parent_name = Some(self.header.name.clone());

        let our = self.prepare_next_merge(our_cid, target_header)?;

        if our.content.previous.len() > 1 {
            // This is a merge node. We'll just add its previous links.
            our.content.previous.extend(
                other
                    .content
                    .previous
                    .iter()
                    .cloned()
                    .map(|(rev_back, link)| (rev_back + other_ratchet_diff, link)),
            );
        } else {
            // The other node represents a write - we need to store a link to its CID
            let temporal_key = &other.header.derive_temporal_key();
            our.content.previous.insert((
                other_ratchet_diff,
                Encrypted::from_value(other_cid, temporal_key)?,
            ));
        }

        our.content
            .metadata
            .tie_break_with(&other.content.metadata)?;

        for (name, other_link) in other.content.entries.iter() {
            match our.content.entries.entry(name.clone()) {
                Entry::Vacant(vacant) => {
                    vacant.insert(other_link.clone());
                }
                Entry::Occupied(mut occupied) => {
                    let our_link = occupied.get_mut();

                    // We just tie-break on the content cid.
                    // It's assumed both links have been resolved to their
                    // PrivateRef before, and we can tie-break on their content_cid.
                    // Otherwise, how would we have gotten `our_cid` and `other_cid`
                    // in this context? Both of these were gotten from `.store()`ing the
                    // nodes, which includes resolving the children to `PrivateRef`s.
                    let our_content_hash = our_link.crdt_tiebreaker()?;
                    let other_content_hash = other_link.crdt_tiebreaker()?;

                    let ord = our_content_hash.cmp(&other_content_hash);
                    if ord == Ordering::Equal {
                        // there's nothing for us to do, they're equal
                    } else {
                        let our_node = our_link
                            .resolve_node_mut(forest, store, parent_name.clone())
                            .await?;

                        let other_node = other_link
                            .resolve_node(forest, store, parent_name.clone())
                            .await?;

                        match (our_node, other_node) {
                            (PrivateNode::Dir(_), PrivateNode::File(_)) => {
                                // our node wins, we don't need to do anything.
                            }
                            (PrivateNode::File(_), PrivateNode::Dir(_)) => {
                                // a directory wins over a file
                                our_link.clone_from(other_link);
                            }
                            // file vs. file and dir vs. dir cases
                            _ => {
                                // We tie-break as usual
                                if ord == Ordering::Greater {
                                    our_link.clone_from(other_link);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Debug for PrivateDirectoryContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateDirectoryContent")
            .field(
                "persisted_as",
                &self
                    .persisted_as
                    .get()
                    .map_or("None".to_string(), |cid| format!("Some({cid})")),
            )
            .field("previous", &self.previous)
            .field("metadata", &self.metadata)
            .field("entries", &self.entries)
            .finish()
    }
}

impl PrivateDirectoryContent {
    /// Serializes the directory to dag-cbor.
    pub(crate) async fn to_dag_cbor(
        &self,
        temporal_key: &TemporalKey,
        header_cid: Cid,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<Vec<u8>> {
        let mut entries = BTreeMap::new();

        for (name, private_link) in self.entries.iter() {
            let private_ref_serializable = private_link
                .resolve_ref(forest, store, rng)
                .await?
                .to_serializable(temporal_key)?;
            entries.insert(name.clone(), private_ref_serializable);
        }

        Ok(serde_ipld_dagcbor::to_vec(
            &PrivateNodeContentSerializable::Dir(PrivateDirectoryContentSerializable {
                version: WNFS_VERSION,
                previous: self.previous.iter().cloned().collect(),
                header_cid,
                metadata: self.metadata.clone(),
                entries,
            }),
        )?)
    }

    /// Encrypts the directory contents by
    /// - wrapping all subdirectory temporal keys given the current temporal key
    /// - encrypting the whole directory using the snapshot key derived from the temporal key.
    ///
    /// The resulting ciphertext is then stored in the given BlockStore. Its CID is finally returned.
    ///
    /// Randomness is required for randomized encryption.
    ///
    /// The header cid is required as it's not stored in the PrivateDirectoryContent itself, but
    /// stored in the serialized format.
    #[allow(clippy::suspicious)]
    pub(crate) async fn store(
        &self,
        header_cid: Cid,
        temporal_key: &TemporalKey,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<Cid> {
        Ok(*self
            .persisted_as
            .get_or_try_init::<anyhow::Error>(async {
                // TODO(matheus23) deduplicate when reworking serialization (see file.rs)
                let snapshot_key = temporal_key.derive_snapshot_key();

                // Serialize node to cbor.
                let bytes = self
                    .to_dag_cbor(temporal_key, header_cid, forest, store, rng)
                    .await?;

                // Encrypt bytes with snapshot key.
                let block = snapshot_key.encrypt(&bytes, rng)?;

                // Store content section in blockstore and get Cid.
                let block = Blake3Block::new(CODEC_RAW, block);
                let cid = block.cid()?;
                store.put(block).await?;
                Ok(cid)
            })
            .await?)
    }
}

impl PartialEq for PrivateDirectoryContent {
    fn eq(&self, other: &Self) -> bool {
        self.previous == other.previous
            && self.metadata == other.metadata
            && self.entries == other.entries
    }
}

impl Clone for PrivateDirectoryContent {
    fn clone(&self) -> Self {
        Self {
            persisted_as: self
                .persisted_as
                .get()
                .cloned()
                .map(OnceCell::new_with)
                .unwrap_or_default(),
            previous: self.previous.clone(),
            metadata: self.metadata.clone(),
            entries: self.entries.clone(),
        }
    }
}

impl Id for PrivateDirectory {
    fn get_id(&self) -> String {
        format!("{:p}", &self.header)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private::forest::hamt::HamtForest;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use test_log::test;
    use testresult::TestResult;
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[test(async_std::test)]
    async fn look_up_can_fetch_file_added_to_directory() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        let content = b"Hello, World!".to_vec();

        root_dir
            .write(
                &["text.txt".into()],
                true,
                Utc::now(),
                content.clone(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .read(&["text.txt".into()], true, forest, store)
            .await
            .unwrap();

        assert_eq!(result, content);
    }

    #[test(async_std::test)]
    async fn look_up_cannot_fetch_file_not_added_to_directory() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &HamtForest::new_rsa_2048_rc(rng);
        let root_dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        let node = root_dir
            .lookup_node("Unknown", true, forest, store)
            .await
            .unwrap();

        assert!(node.is_none());
    }

    #[test(async_std::test)]
    async fn get_node_can_fetch_node_from_root_dir() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .mkdir(
                &["pictures".into(), "dogs".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .write(
                &["pictures".into(), "cats".into(), "tabby.jpg".into()],
                true,
                Utc::now(),
                b"file".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        assert!(root_dir
            .get_node(
                &["pictures".into(), "cats".into(), "tabby.jpg".into()],
                true,
                forest,
                store,
            )
            .await
            .unwrap()
            .is_some());

        assert!(root_dir
            .get_node(
                &["pictures".into(), "cats".into(), "tabby.jpeg".into()],
                true,
                forest,
                store,
            )
            .await
            .unwrap()
            .is_none());

        assert!(root_dir
            .get_node(
                &["images".into(), "parrots".into(), "coco.png".into()],
                true,
                forest,
                store,
            )
            .await
            .unwrap()
            .is_none());

        assert!(root_dir
            .get_node(
                &["pictures".into(), "dogs".into(), "bingo.jpg".into()],
                true,
                forest,
                store,
            )
            .await
            .unwrap()
            .is_none());
    }

    #[test(async_std::test)]
    async fn mkdir_can_create_new_directory() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .mkdir(
                &["tamedun".into(), "pictures".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .get_node(&["tamedun".into(), "pictures".into()], true, forest, store)
            .await
            .unwrap();

        assert!(result.is_some());
    }

    #[test(async_std::test)]
    async fn ls_can_list_children_under_directory() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .mkdir(
                &["tamedun".into(), "pictures".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .write(
                &["tamedun".into(), "pictures".into(), "puppy.jpg".into()],
                true,
                Utc::now(),
                b"puppy".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .mkdir(
                &["tamedun".into(), "pictures".into(), "cats".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .ls(&["tamedun".into(), "pictures".into()], true, forest, store)
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, String::from("cats"));
        assert_eq!(result[1].0, String::from("puppy.jpg"));
    }

    #[test(async_std::test)]
    async fn rm_can_remove_children_from_directory() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .mkdir(
                &["tamedun".into(), "pictures".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .write(
                &["tamedun".into(), "pictures".into(), "puppy.jpg".into()],
                true,
                Utc::now(),
                b"puppy".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .mkdir(
                &["tamedun".into(), "pictures".into(), "cats".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .rm(&["tamedun".into(), "pictures".into()], true, forest, store)
            .await
            .unwrap();

        let result = root_dir
            .rm(&["tamedun".into(), "pictures".into()], true, forest, store)
            .await;

        assert!(result.is_err());
    }

    #[async_std::test]
    async fn read_can_fetch_userland_of_file_added_to_directory() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .write(
                &["text.txt".into()],
                true,
                Utc::now(),
                b"text".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .read(&["text.txt".into()], true, forest, store)
            .await
            .unwrap();

        assert_eq!(result, b"text".to_vec());
    }

    #[test(async_std::test)]
    async fn search_latest_finds_the_most_recent() {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        let path = ["Documents".into(), "file.txt".into()];

        root_dir
            .write(
                &path,
                false,
                Utc::now(),
                b"One".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let old_root = &Arc::clone(root_dir);

        root_dir
            .write(&path, true, Utc::now(), b"Two".to_vec(), forest, store, rng)
            .await
            .unwrap();

        root_dir.store(forest, store, rng).await.unwrap();

        let new_read = root_dir.read(&path, false, forest, store).await.unwrap();

        let old_read = Arc::clone(old_root)
            .read(&path, false, forest, store)
            .await
            .unwrap();

        let old_read_latest = old_root.read(&path, true, forest, store).await.unwrap();
        let new_read_latest = root_dir.read(&path, true, forest, store).await.unwrap();

        assert_eq!(&String::from_utf8_lossy(&new_read), "Two");
        assert_eq!(&String::from_utf8_lossy(&old_read), "One");
        assert_eq!(&String::from_utf8_lossy(&old_read_latest), "Two");
        assert_eq!(&String::from_utf8_lossy(&new_read_latest), "Two");
    }

    #[async_std::test]
    async fn cp_can_copy_sub_directory_to_another_valid_location_with_updated_ancestry() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .write(
                &["pictures".into(), "cats".into(), "tabby.jpg".into()],
                true,
                Utc::now(),
                b"tabby".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .write(
                &["pictures".into(), "cats".into(), "luna.png".into()],
                true,
                Utc::now(),
                b"luna".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .mkdir(&["images".into()], true, Utc::now(), forest, store, rng)
            .await
            .unwrap();

        root_dir
            .cp(
                &["pictures".into(), "cats".into()],
                &["images".into(), "cats".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .ls(&["images".into()], true, forest, store)
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, String::from("cats"));

        let result = root_dir
            .ls(&["pictures".into()], true, forest, store)
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, String::from("cats"));

        let result = root_dir
            .get_node(&["images".into(), "cats".into()], true, forest, store)
            .await
            .unwrap();

        let cats_name_segments = result.unwrap().get_header().name.get_segments().clone();

        let images_dir_inumber = root_dir
            .lookup_node("images", true, forest, store)
            .await
            .unwrap()
            .unwrap()
            .get_header()
            .inumber
            .clone();

        let pictures_dir_inumber = root_dir
            .lookup_node("pictures", true, forest, store)
            .await
            .unwrap()
            .unwrap()
            .get_header()
            .inumber
            .clone();

        assert!(cats_name_segments.contains(&images_dir_inumber));
        assert!(!cats_name_segments.contains(&pictures_dir_inumber));
    }

    #[async_std::test]
    async fn mv_can_move_sub_directory_to_another_valid_location_with_updated_ancestry() {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .write(
                &["pictures".into(), "cats".into(), "tabby.jpg".into()],
                true,
                Utc::now(),
                b"tabby".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .write(
                &["pictures".into(), "cats".into(), "luna.png".into()],
                true,
                Utc::now(),
                b"luna".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .mkdir(&["images".into()], true, Utc::now(), forest, store, rng)
            .await
            .unwrap();

        root_dir
            .basic_mv(
                &["pictures".into(), "cats".into()],
                &["images".into(), "cats".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .ls(&["images".into()], true, forest, store)
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, String::from("cats"));

        let result = root_dir
            .ls(&["pictures".into()], true, forest, store)
            .await
            .unwrap();

        assert_eq!(result.len(), 0);

        let result = root_dir
            .get_node(&["images".into(), "cats".into()], true, forest, store)
            .await
            .unwrap();

        let cats_name_segments = result.unwrap().get_header().name.get_segments().clone();

        let images_dir_inumber = root_dir
            .lookup_node("images", true, forest, store)
            .await
            .unwrap()
            .unwrap()
            .get_header()
            .inumber
            .clone();

        let pictures_dir_inumber = root_dir
            .lookup_node("pictures", true, forest, store)
            .await
            .unwrap()
            .unwrap()
            .get_header()
            .inumber
            .clone();

        assert!(cats_name_segments.contains(&images_dir_inumber));
        assert!(!cats_name_segments.contains(&pictures_dir_inumber));
    }

    #[async_std::test]
    async fn mv_cannot_move_sub_directory_to_invalid_location() {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .mkdir(
                &[
                    "videos".into(),
                    "movies".into(),
                    "anime".into(),
                    "ghibli".into(),
                ],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .basic_mv(
                &["videos".into(), "movies".into()],
                &["videos".into(), "movies".into(), "anime".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await;

        assert!(result.is_err());
    }

    #[async_std::test]
    async fn mv_can_rename_directories() {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
        let content = b"file".to_vec();

        root_dir
            .write(
                &["file.txt".into()],
                true,
                Utc::now(),
                content.clone(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        root_dir
            .basic_mv(
                &["file.txt".into()],
                &["renamed.txt".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        let result = root_dir
            .read(&["renamed.txt".into()], true, forest, store)
            .await
            .unwrap();

        assert!(result == content);

        let result = root_dir
            .lookup_node("file.txt", true, forest, store)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[async_std::test]
    async fn mv_fails_moving_directories_to_files() {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        root_dir
            .mkdir(
                &["movies".into(), "ghibli".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

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

        let result = root_dir
            .basic_mv(
                &["movies".into(), "ghibli".into()],
                &["file.txt".into()],
                true,
                Utc::now(),
                forest,
                store,
                rng,
            )
            .await;

        assert!(result.is_err());
    }

    #[async_std::test]
    async fn write_doesnt_generate_previous_link() {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let old_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        let new_dir = &mut Arc::clone(old_dir);
        new_dir
            .write(
                &["file.txt".into()],
                false,
                Utc::now(),
                b"Hello".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        assert!(old_dir.content.previous.is_empty());
        assert!(new_dir.content.previous.is_empty());
    }

    #[async_std::test]
    async fn store_before_write_generates_previous_link() {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let old_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
        old_dir.store(forest, store, rng).await.unwrap();

        let new_dir = &mut Arc::clone(old_dir);
        new_dir
            .write(
                &["file.txt".into()],
                false,
                Utc::now(),
                b"Hello".to_vec(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

        assert!(old_dir.content.previous.is_empty());
        assert_eq!(new_dir.content.previous.len(), 1);
    }

    #[async_std::test]
    async fn search_latest_also_searches_the_root() -> Result<()> {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048(rng);
        let old_dir =
            PrivateDirectory::new_and_store(&forest.empty_name(), Utc::now(), forest, store, rng)
                .await?;

        let path = &["some".into(), "test.txt".into()];
        let content = b"Hello";

        let dir = &mut Arc::clone(&old_dir);
        dir.write(path, true, Utc::now(), content.to_vec(), forest, store, rng)
            .await?;
        dir.as_node().store(forest, store, rng).await?;

        // Now we'll read from the `old_dir` with search_latest: true, this should work.
        let read_back = old_dir.read(path, true, forest, store).await?;

        assert_eq!(&read_back, content);

        Ok(())
    }

    #[async_std::test]
    async fn test_regression_read_old_access_key() -> Result<()> {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048(rng);
        let mut dir =
            PrivateDirectory::new_and_store(&forest.empty_name(), Utc::now(), forest, store, rng)
                .await?;

        let access_key = dir.as_node().store(forest, store, rng).await?;

        let first = b"Hi".to_vec();
        let second = b"Hi again".to_vec();
        let path = &["test.txt".into()];

        dir.write(path, true, Utc::now(), first.clone(), forest, store, rng)
            .await?;

        dir.as_node().store(forest, store, rng).await?;

        let mut loaded_dir = PrivateNode::load(&access_key, forest, store, None)
            .await?
            .as_dir()?;

        assert_eq!(loaded_dir.read(path, true, forest, store).await?, first);

        loaded_dir
            .write(path, true, Utc::now(), second.clone(), forest, store, rng)
            .await?;

        loaded_dir.as_node().store(forest, store, rng).await?;

        // regression: This assertion used to fail
        assert_eq!(loaded_dir.read(path, true, forest, store).await?, second);

        Ok(())
    }

    #[async_std::test]
    async fn test_regression_read_old_file_access_key() -> Result<()> {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut HamtForest::new_rsa_2048(rng);
        let mut dir =
            PrivateDirectory::new_and_store(&forest.empty_name(), Utc::now(), forest, store, rng)
                .await?;

        let first = b"Hi".to_vec();
        let second = b"Hi again".to_vec();
        let path = &["test.txt".into()];

        dir.write(path, true, Utc::now(), first.clone(), forest, store, rng)
            .await?;

        dir.as_node().store(forest, store, rng).await?;

        let file_access_key = dir
            .get_node(path, true, forest, store)
            .await?
            .unwrap()
            .store(forest, store, rng)
            .await?;

        dir.write(path, true, Utc::now(), second.clone(), forest, store, rng)
            .await?;

        dir.as_node().store(forest, store, rng).await?;

        let node = PrivateNode::load(&file_access_key, forest, store, None).await?;
        // regression: This call used to fail
        let loaded_file = node.search_latest(forest, store).await?.as_file()?;

        let content = loaded_file.get_content(forest, store).await?;

        assert_eq!(content, second);

        Ok(())
    }

    #[async_std::test]
    async fn test_conflict_reconciliation_merges_dirs() -> TestResult {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut Arc::new(HamtForest::new_rsa_2048(rng));
        let mut dir =
            PrivateDirectory::new_and_store(&forest.empty_name(), Utc::now(), forest, store, rng)
                .await?;

        // Another client works on a fork
        let mut fork = Arc::clone(&dir);
        let forest_fork = &mut Arc::clone(forest);

        dir.write(
            &["first_client.txt".into()],
            true,
            Utc::now(),
            b"first".to_vec(),
            forest,
            store,
            rng,
        )
        .await?;

        dir.store(forest, store, rng).await?;

        // concurrent write
        fork.write(
            &["second_client.txt".into()],
            true,
            Utc::now(),
            b"second".to_vec(),
            forest_fork,
            store,
            rng,
        )
        .await?;

        fork.store(forest, store, rng).await?;

        // we merge the forests
        *forest = Arc::new(forest.merge(forest_fork, store).await?);

        // This should reconcile the changes
        dir = dir.search_latest_reconciled(forest, store).await?;

        let entries = dir.get_entries().cloned().collect::<Vec<_>>();

        assert_eq!(
            entries,
            vec![
                "first_client.txt".to_string(),
                "second_client.txt".to_string()
            ]
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_conflict_reconciliation_concurrently_created_files() -> TestResult {
        let rng = &mut ChaCha12Rng::from_entropy();
        let store = &InMemoryBlockstore::<64>::new();
        let forest = &mut Arc::new(HamtForest::new_rsa_2048(rng));
        let mut dir =
            PrivateDirectory::new_and_store(&forest.empty_name(), Utc::now(), forest, store, rng)
                .await?;

        dir.write(
            &["file.txt".into()],
            true,
            Utc::now(),
            b"init".to_vec(),
            forest,
            store,
            rng,
        )
        .await?;

        dir.store(forest, store, rng).await?;

        // Another client works on a fork
        let mut fork = Arc::clone(&dir);
        let forest_fork = &mut Arc::clone(forest);

        dir.write(
            &["file.txt".into()],
            true,
            Utc::now(),
            b"first".to_vec(),
            forest,
            store,
            rng,
        )
        .await?;

        dir.store(forest, store, rng).await?;

        // concurrent write
        fork.write(
            &["file.txt".into()],
            true,
            Utc::now(),
            b"second".to_vec(),
            forest_fork,
            store,
            rng,
        )
        .await?;

        fork.store(forest, store, rng).await?;

        // we merge the forests
        *forest = Arc::new(forest.merge(forest_fork, store).await?);

        let content =
            String::from_utf8(dir.read(&["file.txt".into()], true, forest, store).await?)?;

        assert_ne!(content, "init");
        assert!(content == "first" || content == "second");

        Ok(())
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::{private::forest::hamt::HamtForest, utils};
    use chrono::TimeZone;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use wnfs_common::{utils::SnapshotBlockStore, Storable};

    #[async_std::test]
    async fn test_private_fs() -> Result<()> {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &mut SnapshotBlockStore::default();
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let base_name = forest.empty_name();
        let paths = [
            vec!["text.txt".into()],
            vec!["music".into(), "jazz".into()],
            vec!["videos".into(), "movies".into(), "anime".into()],
        ];

        let root_dir = &mut PrivateDirectory::new_rc(&base_name, time, rng);

        for path in paths.iter() {
            root_dir
                .write(
                    path,
                    true,
                    time,
                    b"Hello World".to_vec(),
                    forest,
                    store,
                    rng,
                )
                .await?;
        }

        let _ = root_dir.store(forest, store, rng).await?;
        let cid = forest.store(store).await?;

        utils::walk_dir(store, forest, root_dir, rng).await?;

        let values = store.get_dag_snapshot(cid).await?;
        insta::assert_json_snapshot!(values);

        Ok(())
    }
}
