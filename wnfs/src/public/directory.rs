//! Public fs directory node.

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use crate::{
    error, utils, AsyncSerialize, BlockStore, FsError, Id, Metadata, NodeType, PathNodes,
    PathNodesResult, RemembersCid,
};
use anyhow::{bail, ensure, Result};
use async_once_cell::OnceCell;
use async_recursion::async_recursion;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use libipld::Cid;
use semver::Version;
use serde::{
    de::Error as DeError, ser::Error as SerError, Deserialize, Deserializer, Serialize, Serializer,
};

use super::{PublicFile, PublicLink, PublicNode};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

pub type PublicPathNodes = PathNodes<PublicDirectory>;
pub type PublicPathNodesResult = PathNodesResult<PublicDirectory>;

/// Represents a directory in the WNFS public filesystem.
///
/// # Examples
///
/// ```
/// use wnfs::PublicDirectory;
/// use chrono::Utc;
///
/// let dir = PublicDirectory::new(Utc::now());
///
/// println!("Directory: {:?}", dir);
/// ```
#[derive(Debug)]
pub struct PublicDirectory {
    persisted_as: OnceCell<Cid>,
    pub metadata: Metadata,
    pub userland: BTreeMap<String, PublicLink>,
    pub previous: BTreeSet<Cid>,
}

#[derive(Serialize, Deserialize)]
struct PublicDirectorySerializable {
    r#type: NodeType,
    version: Version,
    metadata: Metadata,
    userland: BTreeMap<String, Cid>,
    previous: Vec<Cid>,
}

/// The result of an operation applied to a directory.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicOpResult<T> {
    /// The root directory.
    pub root_dir: Rc<PublicDirectory>,
    /// Implementation dependent but it usually the last leaf node operated on.
    pub result: T,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl PublicDirectory {
    /// Creates a new directory with provided time.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::PublicDirectory;
    /// use chrono::Utc;
    ///
    /// let dir = PublicDirectory::new(Utc::now());
    ///
    /// println!("Directory: {:?}", dir);
    /// ```
    pub fn new(time: DateTime<Utc>) -> Self {
        Self {
            persisted_as: OnceCell::new(),
            metadata: Metadata::new(time),
            userland: BTreeMap::new(),
            previous: BTreeSet::new(),
        }
    }

    /// Gets the previous Cids.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::PublicDirectory;
    /// use std::{rc::Rc, collections::BTreeSet};
    /// use chrono::Utc;
    ///
    /// let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///
    /// assert_eq!(dir.get_previous(), &BTreeSet::new());
    /// ```
    #[inline]
    pub fn get_previous<'a>(self: &'a Rc<Self>) -> &'a BTreeSet<Cid> {
        &self.previous
    }

    /// Gets the metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, Metadata};
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// let time = Utc::now();
    /// let dir = Rc::new(PublicDirectory::new(time));
    ///
    /// assert_eq!(dir.get_metadata(), &Metadata::new(time));
    /// ```
    #[inline]
    pub fn get_metadata<'a>(self: &'a Rc<Self>) -> &'a Metadata {
        &self.metadata
    }

    /// Takes care of creating previous links, in case the current
    /// directory was previously `.store()`ed.
    /// In any case it'll try to give you ownership of the directory if possible,
    /// otherwise it clones.
    fn prepare_next_revision(self: Rc<Self>) -> Self {
        let Some(previous_cid) = self.persisted_as.get().cloned() else {
            // If this revision was not yet persisted, we can
            // modify it without forcing it to be flushed to a
            // BlockStore.
            return Rc::try_unwrap(self).unwrap_or_else(|rc| (*rc).clone());
        };

        let mut cloned = Rc::try_unwrap(self).unwrap_or_else(|rc| (*rc).clone());
        // We need to reset the OnceCell.
        cloned.persisted_as = OnceCell::new();
        cloned.previous = [previous_cid].into_iter().collect();

        cloned
    }

    /// Creates a new `PublicPathNodes` that is not based on an existing file tree.
    pub(crate) fn create_path_nodes(
        path_segments: &[String],
        time: DateTime<Utc>,
    ) -> PublicPathNodes {
        let path: Vec<(Rc<PublicDirectory>, String)> = path_segments
            .iter()
            .map(|segment| (Rc::new(PublicDirectory::new(time)), segment.clone()))
            .collect();

        PublicPathNodes {
            path,
            tail: Rc::new(PublicDirectory::new(time)),
        }
    }

    /// Uses specified path segments and their existence in the file tree to generate `PathNodes`.
    ///
    /// Supports cases where the entire path does not exist.
    pub(crate) async fn get_path_nodes(
        self: Rc<Self>,
        path_segments: &[String],
        store: &impl BlockStore,
    ) -> Result<PublicPathNodesResult> {
        use PathNodesResult::*;
        let mut working_node = self;
        let mut path_nodes = Vec::with_capacity(path_segments.len());

        for segment in path_segments.iter() {
            match working_node.lookup_node(segment, store).await? {
                Some(PublicNode::Dir(ref directory)) => {
                    path_nodes.push((Rc::clone(&working_node), segment.clone()));
                    working_node = Rc::clone(directory);
                }
                Some(_) => {
                    let path_nodes = PathNodes {
                        path: path_nodes,
                        tail: Rc::clone(&working_node),
                    };

                    return Ok(NotADirectory(path_nodes, segment.clone()));
                }
                None => {
                    let path_nodes = PathNodes {
                        path: path_nodes,
                        tail: Rc::clone(&working_node),
                    };

                    return Ok(MissingLink(path_nodes, segment.clone()));
                }
            }
        }

        Ok(Complete(PublicPathNodes {
            path: path_nodes,
            tail: Rc::clone(&working_node),
        }))
    }

    /// Uses specified path segments to generate `PathNodes`. Creates missing directories as needed.
    pub(crate) async fn get_or_create_path_nodes(
        self: Rc<Self>,
        path_segments: &[String],
        time: DateTime<Utc>,
        store: &impl BlockStore,
    ) -> Result<PublicPathNodes> {
        use PathNodesResult::*;
        match self.get_path_nodes(path_segments, store).await? {
            Complete(path_nodes) => Ok(path_nodes),
            NotADirectory(_, _) => error(FsError::InvalidPath),
            MissingLink(path_so_far, missing_link) => {
                let missing_path = path_segments.split_at(path_so_far.path.len() + 1).1;
                let missing_path_nodes = Self::create_path_nodes(missing_path, time);

                Ok(PublicPathNodes {
                    path: [
                        path_so_far.path,
                        vec![(path_so_far.tail, missing_link)],
                        missing_path_nodes.path,
                    ]
                    .concat(),
                    tail: missing_path_nodes.tail,
                })
            }
        }
    }

    /// Fix up `PathNodes` so that parents refer to the newly updated children.
    fn fix_up_path_nodes(path_nodes: PublicPathNodes) -> Rc<Self> {
        let mut working_dir = path_nodes.tail;

        for (dir, segment) in path_nodes.path.into_iter().rev() {
            let mut dir = dir.prepare_next_revision();
            let link = PublicLink::with_dir(working_dir);
            dir.userland.insert(segment, link);
            working_dir = Rc::new(dir);
        }

        working_dir
    }

    /// Follows a path and fetches the node at the end of the path.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, MemoryBlockStore};
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let store = MemoryBlockStore::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .mkdir(&["pictures".into(), "cats".into()], Utc::now(), &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { root_dir, result } = root_dir
    ///         .get_node(&["pictures".into()], &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert!(result.is_some());
    /// }
    /// ```
    pub async fn get_node(
        self: Rc<Self>,
        path_segments: &[String],
        store: &impl BlockStore,
    ) -> Result<PublicOpResult<Option<PublicNode>>> {
        use PathNodesResult::*;
        let root_dir = Rc::clone(&self);

        Ok(match path_segments.split_last() {
            Some((path_segment, parent_path)) => {
                match self.get_path_nodes(parent_path, store).await? {
                    Complete(parent_path_nodes) => PublicOpResult {
                        root_dir,
                        result: parent_path_nodes
                            .tail
                            .lookup_node(path_segment, store)
                            .await?,
                    },
                    MissingLink(_, _) => bail!(FsError::NotFound),
                    NotADirectory(_, _) => bail!(FsError::NotFound),
                }
            }
            None => PublicOpResult {
                root_dir,
                result: Some(PublicNode::Dir(self)),
            },
        })
    }

    /// Looks up a node by its path name in the current directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, Id, MemoryBlockStore};
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let mut store = MemoryBlockStore::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .mkdir(&["pictures".into(), "cats".into()], Utc::now(), &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     let node = root_dir.lookup_node("pictures", &store).await.unwrap();
    ///
    ///     assert!(node.is_some());
    /// }
    /// ```
    pub async fn lookup_node(
        &self,
        path_segment: &str,
        store: &impl BlockStore,
    ) -> Result<Option<PublicNode>> {
        Ok(match self.userland.get(path_segment) {
            Some(link) => Some(link.resolve_value(store).await?.clone()),
            None => None,
        })
    }

    #[async_recursion(?Send)]
    /// Stores directory in provided block store.
    ///
    /// This function can be recursive if the directory contains other directories.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, Id, MemoryBlockStore, BlockStore};
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &mut MemoryBlockStore::default();
    ///     let dir = PublicDirectory::new(Utc::now());
    ///
    ///     let cid = dir.store(store).await.unwrap();
    ///
    ///     assert_eq!(
    ///         dir,
    ///         store.get_deserializable(&cid).await.unwrap()
    ///     );
    /// }
    /// ```
    pub async fn store(&self, store: &mut impl BlockStore) -> Result<Cid> {
        Ok(*self
            .persisted_as
            .get_or_try_init(async { store.put_async_serializable(self).await })
            .await?)
    }

    /// Reads specified file content from the directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, MemoryBlockStore};
    /// use libipld::cid::Cid;
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let mut store = MemoryBlockStore::default();
    ///     let cid = Cid::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .write(
    ///             &["pictures".into(), "cats".into(), "tabby.png".into()],
    ///             cid,
    ///             Utc::now(),
    ///             &store
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { root_dir, result } = root_dir
    ///         .read(&["pictures".into(), "cats".into(), "tabby.png".into()], &mut store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result, cid);
    /// }
    /// ```
    pub async fn read(
        self: Rc<Self>,
        path_segments: &[String],
        store: &impl BlockStore,
    ) -> Result<PublicOpResult<Cid>> {
        let root_dir = Rc::clone(&self);
        let (path, filename) = utils::split_last(path_segments)?;

        match self.get_path_nodes(path, store).await? {
            PathNodesResult::Complete(node_path) => {
                match node_path.tail.lookup_node(filename, store).await? {
                    Some(PublicNode::File(file)) => Ok(PublicOpResult {
                        root_dir,
                        result: file.userland,
                    }),
                    Some(PublicNode::Dir(_)) => error(FsError::NotAFile),
                    None => error(FsError::NotFound),
                }
            }
            _ => error(FsError::NotFound),
        }
    }

    /// Writes a file to the directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, MemoryBlockStore};
    /// use libipld::cid::Cid;
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let store = MemoryBlockStore::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .write(
    ///             &["pictures".into(), "cats".into(), "tabby.png".into()],
    ///             Cid::default(),
    ///             Utc::now(),
    ///             &store
    ///         )
    ///         .await
    ///         .unwrap();
    /// }
    /// ```
    pub async fn write(
        self: Rc<Self>,
        path_segments: &[String],
        content_cid: Cid,
        time: DateTime<Utc>,
        store: &impl BlockStore,
    ) -> Result<PublicOpResult<()>> {
        let (directory_path, filename) = utils::split_last(path_segments)?;

        // This will create directories if they don't exist yet
        let mut directory_path_nodes = self
            .get_or_create_path_nodes(directory_path, time, store)
            .await?;

        let mut directory = directory_path_nodes.tail.prepare_next_revision();

        // Modify the file if it already exists, otherwise create a new file with expected content
        let file = match directory.lookup_node(filename, store).await? {
            Some(PublicNode::File(file_before)) => {
                let mut file = file_before.prepare_next_revision();
                file.userland = content_cid;
                file.metadata.upsert_mtime(time);
                file
            }
            Some(PublicNode::Dir(_)) => bail!(FsError::DirectoryAlreadyExists),
            None => PublicFile::new(time, content_cid),
        };

        // insert the file into its parent directory
        directory
            .userland
            .insert(filename.to_string(), PublicLink::with_file(Rc::new(file)));
        directory_path_nodes.tail = Rc::new(directory);

        // Fix up the file path
        Ok(PublicOpResult {
            root_dir: Self::fix_up_path_nodes(directory_path_nodes),
            result: (),
        })
    }

    /// Creates a new directory at the specified path.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, Id, MemoryBlockStore};
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let store = MemoryBlockStore::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .mkdir(&["pictures".into(), "cats".into()], Utc::now(), &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { result, .. } = root_dir
    ///         .ls(&["pictures".into()], &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 1);
    ///     assert_eq!(result[0].0, "cats");
    /// }
    /// ```
    ///
    /// This method acts like `mkdir -p` in Unix because it creates intermediate directories if they do not exist.
    pub async fn mkdir(
        self: Rc<Self>,
        path_segments: &[String],
        time: DateTime<Utc>,
        store: &impl BlockStore,
    ) -> Result<PublicOpResult<()>> {
        let path_nodes = self
            .get_or_create_path_nodes(path_segments, time, store)
            .await?;

        Ok(PublicOpResult {
            root_dir: Self::fix_up_path_nodes(path_nodes),
            result: (),
        })
    }

    /// Returns names and metadata of directory's immediate children.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, MemoryBlockStore};
    /// use libipld::cid::Cid;
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let store = MemoryBlockStore::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .write(
    ///             &["pictures".into(), "cats".into(), "tabby.png".into()],
    ///             Cid::default(),
    ///             Utc::now(),
    ///             &store
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { root_dir, result } = root_dir
    ///         .ls(&["pictures".into(), "cats".into()], &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 1);
    ///     assert_eq!(result[0].0, "tabby.png");
    /// }
    /// ```
    pub async fn ls(
        self: Rc<Self>,
        path_segments: &[String],
        store: &impl BlockStore,
    ) -> Result<PublicOpResult<Vec<(String, Metadata)>>> {
        let root_dir = Rc::clone(&self);
        match self.get_path_nodes(path_segments, store).await? {
            PathNodesResult::Complete(path_nodes) => {
                let mut result = vec![];
                for (name, link) in path_nodes.tail.userland.iter() {
                    match link.resolve_value(store).await? {
                        PublicNode::File(file) => {
                            result.push((name.clone(), file.metadata.clone()));
                        }
                        PublicNode::Dir(dir) => {
                            result.push((name.clone(), dir.metadata.clone()));
                        }
                    }
                }
                Ok(PublicOpResult { root_dir, result })
            }
            _ => bail!(FsError::NotFound),
        }
    }

    /// Removes a file or directory from the directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, MemoryBlockStore};
    /// use libipld::cid::Cid;
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let store = MemoryBlockStore::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .write(
    ///             &["pictures".into(), "cats".into(), "tabby.png".into()],
    ///             Cid::default(),
    ///             Utc::now(),
    ///             &store
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { root_dir, result } = root_dir
    ///         .ls(&["pictures".into()], &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 1);
    ///
    ///     let PublicOpResult { root_dir, .. } = root_dir
    ///         .rm(&["pictures".into(), "cats".into()], &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { root_dir, result } = root_dir
    ///         .ls(&["pictures".into()], &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 0);
    /// }
    /// ```
    pub async fn rm(
        self: Rc<Self>,
        path_segments: &[String],
        store: &impl BlockStore,
    ) -> Result<PublicOpResult<PublicNode>> {
        let (directory_path, node_name) = utils::split_last(path_segments)?;

        let mut directory_node_path = match self.get_path_nodes(directory_path, store).await? {
            PublicPathNodesResult::Complete(node_path) => node_path,
            _ => bail!(FsError::NotFound),
        };

        let mut directory = directory_node_path.tail.prepare_next_revision();

        // Remove the entry from its parent directory
        let removed_node = match directory.userland.remove(node_name) {
            Some(link) => link.resolve_owned_value(store).await?,
            None => bail!(FsError::NotFound),
        };

        directory_node_path.tail = Rc::new(directory);

        Ok(PublicOpResult {
            root_dir: Self::fix_up_path_nodes(directory_node_path),
            result: removed_node,
        })
    }

    /// Moves a file or directory from one path to another.
    ///
    /// This function requires stating the destination name explicitly.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{PublicDirectory, PublicOpResult, MemoryBlockStore};
    /// use libipld::cid::Cid;
    /// use std::rc::Rc;
    /// use chrono::Utc;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let dir = Rc::new(PublicDirectory::new(Utc::now()));
    ///     let store = MemoryBlockStore::default();
    ///
    ///     let PublicOpResult { root_dir, .. } = dir
    ///         .write(
    ///             &["pictures".into(), "cats".into(), "tabby.png".into()],
    ///             Cid::default(),
    ///             Utc::now(),
    ///             &store
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { root_dir, .. } = root_dir
    ///         .basic_mv(
    ///             &["pictures".into(), "cats".into()],
    ///             &["cats".into()],
    ///             Utc::now(),
    ///             &store
    ///         )
    ///         .await
    ///         .unwrap();
    ///
    ///     let PublicOpResult { root_dir, result } = root_dir
    ///         .ls(&[], &store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert_eq!(result.len(), 2);
    /// }
    /// ```
    pub async fn basic_mv(
        self: Rc<Self>,
        path_segments_from: &[String],
        path_segments_to: &[String],
        time: DateTime<Utc>,
        store: &impl BlockStore,
    ) -> Result<PublicOpResult<()>> {
        let root_dir = Rc::clone(&self);
        let (directory_path, filename) = utils::split_last(path_segments_to)?;

        let PublicOpResult {
            root_dir,
            result: removed_node,
        } = root_dir.rm(path_segments_from, store).await?;

        let mut path_nodes = match root_dir.get_path_nodes(directory_path, store).await? {
            PublicPathNodesResult::Complete(node_path) => node_path,
            _ => bail!(FsError::NotFound),
        };

        let mut directory = path_nodes.tail.prepare_next_revision();

        ensure!(
            !directory.userland.contains_key(filename),
            FsError::FileAlreadyExists
        );

        let removed_node = removed_node.upsert_mtime(time);

        directory
            .userland
            .insert(filename.clone(), PublicLink::new(removed_node));

        path_nodes.tail = Rc::new(directory);

        Ok(PublicOpResult {
            root_dir: Self::fix_up_path_nodes(path_nodes),
            result: (),
        })
    }
}

impl Id for PublicDirectory {
    fn get_id(&self) -> String {
        format!("{:p}", &self.metadata)
    }
}

impl PartialEq for PublicDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata
            && self.userland == other.userland
            && self.previous == other.previous
    }
}

impl Clone for PublicDirectory {
    fn clone(&self) -> Self {
        Self {
            persisted_as: OnceCell::new_with(self.persisted_as.get().cloned()),
            metadata: self.metadata.clone(),
            userland: self.userland.clone(),
            previous: self.previous.clone(),
        }
    }
}

impl RemembersCid for PublicDirectory {
    fn persisted_as(&self) -> &OnceCell<Cid> {
        &self.persisted_as
    }
}

/// Implements async deserialization for serde serializable types.
#[async_trait(?Send)]
impl AsyncSerialize for PublicDirectory {
    async fn async_serialize<S, B>(&self, serializer: S, store: &mut B) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        B: BlockStore + ?Sized,
    {
        let encoded_userland = {
            let mut map = BTreeMap::new();
            for (name, link) in self.userland.iter() {
                map.insert(
                    name.clone(),
                    *link.resolve_cid(store).await.map_err(SerError::custom)?,
                );
            }
            map
        };

        (PublicDirectorySerializable {
            r#type: NodeType::PublicDirectory,
            version: Version::new(0, 2, 0),
            metadata: self.metadata.clone(),
            userland: encoded_userland,
            previous: self.previous.iter().cloned().collect(),
        })
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicDirectory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let PublicDirectorySerializable {
            r#type,
            version,
            metadata,
            userland,
            previous,
        } = PublicDirectorySerializable::deserialize(deserializer)?;

        if version.major != 0 || version.minor != 2 {
            return Err(DeError::custom(FsError::UnexpectedVersion(version)));
        }

        if r#type != NodeType::PublicDirectory {
            return Err(DeError::custom(FsError::UnexpectedNodeType(r#type)));
        }

        let userland = userland
            .into_iter()
            .map(|(name, cid)| (name, PublicLink::from_cid(cid)))
            .collect();

        Ok(Self {
            persisted_as: OnceCell::new(),
            metadata,
            userland,
            previous: previous.iter().cloned().collect(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dagcbor, public::PublicFile, MemoryBlockStore};
    use chrono::Utc;
    use libipld::Ipld;

    #[async_std::test]
    async fn look_up_can_fetch_file_added_to_directory() {
        let root_dir = Rc::new(PublicDirectory::new(Utc::now()));
        let store = MemoryBlockStore::default();
        let content_cid = Cid::default();
        let time = Utc::now();

        let PublicOpResult { root_dir, .. } = root_dir
            .write(&["text.txt".into()], content_cid, time, &store)
            .await
            .unwrap();

        let node = root_dir.lookup_node("text.txt", &store).await.unwrap();

        assert!(node.is_some());

        assert_eq!(
            node,
            Some(PublicNode::File(Rc::new(PublicFile::new(
                time,
                content_cid
            ))))
        );
    }

    #[async_std::test]
    async fn look_up_cannot_fetch_file_not_added_to_directory() {
        let root = PublicDirectory::new(Utc::now());
        let store = MemoryBlockStore::default();

        let node = root.lookup_node("Unknown", &store).await;

        assert!(node.is_ok());

        assert_eq!(node.unwrap(), None);
    }

    #[async_std::test]
    async fn directory_added_to_store_can_be_retrieved() {
        let root = PublicDirectory::new(Utc::now());
        let mut store = MemoryBlockStore::default();

        let cid = root.store(&mut store).await.unwrap();

        let encoded_dir = store.get_block(&cid).await.unwrap();
        let deserialized_dir = dagcbor::decode::<PublicDirectory>(encoded_dir.as_ref()).unwrap();

        assert_eq!(root, deserialized_dir);
    }

    #[async_std::test]
    async fn directory_can_encode_decode_as_cbor() {
        let root = PublicDirectory::new(Utc::now());
        let store = &mut MemoryBlockStore::default();

        let encoded_dir = dagcbor::async_encode(&root, store).await.unwrap();
        let decoded_dir = dagcbor::decode::<PublicDirectory>(encoded_dir.as_ref()).unwrap();

        assert_eq!(root, decoded_dir);
    }

    #[async_std::test]
    async fn mkdir_can_create_new_directory() {
        let time = Utc::now();
        let store = MemoryBlockStore::default();

        let PublicOpResult { root_dir, .. } = Rc::new(PublicDirectory::new(time))
            .mkdir(&["tamedun".into(), "pictures".into()], time, &store)
            .await
            .unwrap();

        let PublicOpResult { result, .. } = root_dir
            .get_node(&["tamedun".into(), "pictures".into()], &store)
            .await
            .unwrap();

        assert!(result.is_some());
    }

    #[async_std::test]
    async fn ls_can_list_children_under_directory() {
        let time = Utc::now();
        let store = MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let PublicOpResult { root_dir, .. } = root_dir
            .mkdir(&["tamedun".into(), "pictures".into()], time, &store)
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .write(
                &["tamedun".into(), "pictures".into(), "puppy.jpg".into()],
                Cid::default(),
                time,
                &store,
            )
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .mkdir(
                &["tamedun".into(), "pictures".into(), "cats".into()],
                time,
                &store,
            )
            .await
            .unwrap();

        let PublicOpResult { result, .. } = root_dir
            .ls(&["tamedun".into(), "pictures".into()], &store)
            .await
            .unwrap();

        assert_eq!(result.len(), 2);

        assert_eq!(result[0].0, String::from("cats"));

        assert_eq!(result[1].0, String::from("puppy.jpg"));
    }

    #[async_std::test]
    async fn rm_can_remove_children_from_directory() {
        let time = Utc::now();
        let store = MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let PublicOpResult { root_dir, .. } = root_dir
            .mkdir(&["tamedun".into(), "pictures".into()], time, &store)
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .write(
                &["tamedun".into(), "pictures".into(), "puppy.jpg".into()],
                Cid::default(),
                time,
                &store,
            )
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .mkdir(
                &["tamedun".into(), "pictures".into(), "cats".into()],
                time,
                &store,
            )
            .await
            .unwrap();

        let result = root_dir
            .rm(&["tamedun".into(), "pictures".into()], &store)
            .await;

        assert!(result.is_ok());

        let result = result
            .unwrap()
            .root_dir
            .rm(&["tamedun".into(), "pictures".into()], &store)
            .await;

        assert!(result.is_err());
    }

    #[async_std::test]
    async fn read_can_fetch_userland_of_file_added_to_directory() {
        let store = MemoryBlockStore::default();
        let content_cid = Cid::default();
        let time = Utc::now();

        let PublicOpResult { root_dir, .. } = Rc::new(PublicDirectory::new(time))
            .write(&["text.txt".into()], content_cid, time, &store)
            .await
            .unwrap();

        let PublicOpResult { result, .. } =
            root_dir.read(&["text.txt".into()], &store).await.unwrap();

        assert_eq!(result, content_cid);
    }

    #[async_std::test]
    async fn path_nodes_can_generates_new_path_nodes() {
        let store = MemoryBlockStore::default();
        let now = Utc::now();

        let path_nodes =
            PublicDirectory::create_path_nodes(&["Documents".into(), "Apps".into()], now);

        let fixed = PublicDirectory::fix_up_path_nodes(path_nodes.clone());
        let result = fixed
            .get_path_nodes(&["Documents".into(), "Apps".into()], &store)
            .await
            .unwrap();

        match result {
            PathNodesResult::MissingLink(_, segment) => panic!("MissingLink {segment}"),
            PathNodesResult::NotADirectory(_, segment) => panic!("NotADirectory {segment}"),
            PathNodesResult::Complete(path_nodes_2) => {
                assert_eq!(path_nodes.path.len(), path_nodes_2.path.len());
                assert_eq!(path_nodes.path[0].1, path_nodes_2.path[0].1);
                assert_eq!(path_nodes.path[1].1, path_nodes_2.path[1].1);
            }
        }
    }

    #[async_std::test]
    async fn mv_can_move_sub_directory_to_another_valid_location() {
        let time = Utc::now();
        let store = MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let PublicOpResult { root_dir, .. } = root_dir
            .write(
                &["pictures".into(), "cats".into(), "tabby.jpg".into()],
                Cid::default(),
                time,
                &store,
            )
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .write(
                &["pictures".into(), "cats".into(), "luna.png".into()],
                Cid::default(),
                time,
                &store,
            )
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .mkdir(&["images".into()], time, &store)
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .basic_mv(
                &["pictures".into(), "cats".into()],
                &["images".into(), "cats".into()],
                Utc::now(),
                &store,
            )
            .await
            .unwrap();

        let PublicOpResult { root_dir, result } =
            root_dir.ls(&["images".into()], &store).await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, String::from("cats"));

        let PublicOpResult { result, .. } =
            root_dir.ls(&["pictures".into()], &store).await.unwrap();

        assert_eq!(result.len(), 0);
    }

    #[async_std::test]
    async fn mv_cannot_move_sub_directory_to_invalid_location() {
        let time = Utc::now();
        let store = MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let PublicOpResult { root_dir, .. } = root_dir
            .mkdir(
                &[
                    "videos".into(),
                    "movies".into(),
                    "anime".into(),
                    "ghibli".into(),
                ],
                time,
                &store,
            )
            .await
            .unwrap();

        let result = root_dir
            .basic_mv(
                &["videos".into(), "movies".into()],
                &["videos".into(), "movies".into(), "anime".into()],
                Utc::now(),
                &store,
            )
            .await;

        assert!(result.is_err());
    }

    #[async_std::test]
    async fn mv_can_rename_directories() {
        let time = Utc::now();
        let store = MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let PublicOpResult { root_dir, .. } = root_dir
            .write(&["file.txt".into()], Cid::default(), time, &store)
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .basic_mv(
                &["file.txt".into()],
                &["renamed.txt".into()],
                Utc::now(),
                &store,
            )
            .await
            .unwrap();

        let PublicOpResult { result, .. } = root_dir
            .read(&["renamed.txt".into()], &store)
            .await
            .unwrap();

        assert!(result == Cid::default());
    }

    #[async_std::test]
    async fn mv_fails_moving_directories_to_files() {
        let time = Utc::now();
        let store = MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let PublicOpResult { root_dir, .. } = root_dir
            .mkdir(&["movies".into(), "ghibli".into()], time, &store)
            .await
            .unwrap();

        let PublicOpResult { root_dir, .. } = root_dir
            .write(&["file.txt".into()], Cid::default(), time, &store)
            .await
            .unwrap();

        let result = root_dir
            .basic_mv(
                &["movies".into(), "ghibli".into()],
                &["file.txt".into()],
                Utc::now(),
                &store,
            )
            .await;

        assert!(result.is_err());
    }

    #[async_std::test]
    async fn previous_links_get_set() {
        let time = Utc::now();
        let store = &mut MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let previous_cid = root_dir.store(store).await.unwrap();

        let PublicOpResult {
            root_dir: root_dir_after,
            ..
        } = root_dir.mkdir(&["test".into()], time, store).await.unwrap();

        let ipld = root_dir_after.async_serialize_ipld(store).await.unwrap();
        match ipld {
            Ipld::Map(map) => match map.get("previous") {
                Some(Ipld::List(previous)) => {
                    assert_eq!(previous, &vec![Ipld::Link(previous_cid)]);
                }
                _ => panic!("Expected 'previous' key to be a list"),
            },
            _ => panic!("Expected map!"),
        }
    }

    #[async_std::test]
    async fn prepare_next_revision_shortcuts_if_possible() {
        let time = Utc::now();
        let store = &mut MemoryBlockStore::default();
        let root_dir = Rc::new(PublicDirectory::new(time));

        let previous_cid = root_dir.store(store).await.unwrap();

        let next_dir = root_dir.prepare_next_revision();

        let yet_another_dir = Rc::new(next_dir).prepare_next_revision();

        assert_eq!(
            yet_another_dir.previous.into_iter().collect::<Vec<_>>(),
            vec![previous_cid]
        );
    }
}
