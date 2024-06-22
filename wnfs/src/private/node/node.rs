use super::{PrivateNodeHeader, TemporalKey};
use crate::{
    error::FsError,
    private::{
        encrypted::Encrypted, forest::traits::PrivateForest, link::PrivateLink, AccessKey,
        PrivateDirectory, PrivateFile, PrivateNodeContentSerializable, PrivateRef,
    },
    traits::Id,
};
use anyhow::{bail, Result};
use async_once_cell::OnceCell;
use async_recursion::async_recursion;
use chrono::{DateTime, Utc};
use rand_core::CryptoRngCore;
use skip_ratchet::{JumpSize, RatchetSeeker};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};
use wnfs_common::{
    blockstore::Blockstore,
    ipld_core::cid::Cid,
    utils::{Arc, CondSend},
    BlockStoreError,
};
use wnfs_nameaccumulator::Name;

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// A node in the WNFS private file system. This can either be a file or a directory.
///
/// # Examples
///
/// ```
/// use wnfs::private::{
///     PrivateDirectory, PrivateNode,
///     forest::{hamt::HamtForest, traits::PrivateForest},
/// };
/// use chrono::Utc;
/// use rand_chacha::ChaCha12Rng;
/// use rand_core::SeedableRng;
///
/// let rng = &mut ChaCha12Rng::from_entropy();
/// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
/// let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
/// let node = PrivateNode::Dir(dir);
///
/// println!("Node: {:?}", node);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum PrivateNode {
    File(Arc<PrivateFile>),
    Dir(Arc<PrivateDirectory>),
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl PrivateNode {
    /// Creates node with upserted modified time.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory, PrivateNode,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    /// };
    /// use chrono::{Utc, Duration, TimeZone};
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    /// let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    /// let node = PrivateNode::Dir(dir);
    ///
    /// let time = Utc::now() + Duration::days(1);
    /// let node = node.upsert_mtime(time);
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
    pub fn upsert_mtime(&self, time: DateTime<Utc>) -> Self {
        match self {
            Self::File(file) => {
                let mut file = (**file).clone();
                file.content.metadata.upsert_mtime(time);
                Self::File(Arc::new(file))
            }
            Self::Dir(dir) => {
                let mut dir = (**dir).clone();
                dir.content.metadata.upsert_mtime(time);
                Self::Dir(Arc::new(dir))
            }
        }
    }

    /// Updates bare name ancestry of private sub tree.
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    pub(crate) async fn update_ancestry(
        &mut self,
        parent_name: &Name,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        match self {
            Self::File(file_rc) => {
                let file = Arc::make_mut(file_rc);
                file.prepare_key_rotation(parent_name, rng).await?;
            }
            Self::Dir(dir_rc) => {
                let dir = Arc::make_mut(dir_rc);

                for private_link in &mut dir.content.entries.values_mut() {
                    let mut node = private_link
                        .resolve_node(forest, store, Some(dir.header.name.clone()))
                        .await?
                        .clone();
                    node.update_ancestry(&dir.header.name, forest, store, rng)
                        .await?;
                    *private_link = PrivateLink::from(node);
                }

                dir.prepare_key_rotation(parent_name, rng);
            }
        }
        Ok(())
    }

    /// Gets the header of the node.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory, PrivateNode,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    /// let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    /// let node = PrivateNode::Dir(Arc::clone(&dir));
    ///
    /// assert_eq!(&dir.header, node.get_header());
    /// ```
    #[inline]
    pub fn get_header(&self) -> &PrivateNodeHeader {
        match self {
            Self::File(file) => &file.header,
            Self::Dir(dir) => &dir.header,
        }
    }

    /// Gets the previous links of the node.
    ///
    /// The previous links are encrypted with the previous revision's
    /// temporal key, so you need to know an 'older' revision of the
    /// skip ratchet to decrypt these.
    ///
    /// The previous links is exactly one Cid in most cases and refers
    /// to the ciphertext Cid from the previous revision that this
    /// node is an update of.
    ///
    /// If this node is a merge-node, it has two or more previous Cids.
    /// A single previous Cid must be from the previous revision, but all
    /// other Cids may appear in even older revisions.
    #[allow(clippy::mutable_key_type)]
    pub fn get_previous(&self) -> &BTreeSet<(usize, Encrypted<Cid>)> {
        match self {
            Self::File(file) => &file.content.previous,
            Self::Dir(dir) => &dir.content.previous,
        }
    }

    /// Casts a node to a directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory, PrivateNode,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    /// let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    /// let node = PrivateNode::Dir(Arc::clone(&dir));
    ///
    /// assert_eq!(node.as_dir().unwrap(), dir);
    /// ```
    pub fn as_dir(&self) -> Result<Arc<PrivateDirectory>> {
        Ok(match self {
            Self::Dir(dir) => Arc::clone(dir),
            _ => bail!(FsError::NotADirectory),
        })
    }

    /// Casts a node to a mutable directory.
    pub fn as_dir_mut(&mut self) -> Result<&mut Arc<PrivateDirectory>> {
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
    /// use wnfs::{
    ///     private::{
    ///         PrivateFile, PrivateNode,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    /// let file = PrivateFile::new_rc(&forest.empty_name(), Utc::now(), rng);
    /// let node = PrivateNode::File(Arc::clone(&file));
    ///
    /// assert_eq!(node.as_file().unwrap(), file);
    /// ```
    pub fn as_file(&self) -> Result<Arc<PrivateFile>> {
        Ok(match self {
            Self::File(file) => Arc::clone(file),
            _ => bail!(FsError::NotAFile),
        })
    }

    /// Returns true if underlying node is a directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory, PrivateNode,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    /// let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    /// let node = PrivateNode::Dir(dir);
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
    /// use wnfs::{
    ///     private::{
    ///         PrivateFile, PrivateNode,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    /// let file = PrivateFile::new_rc(&forest.empty_name(), Utc::now(), rng);
    /// let node = PrivateNode::File(file);
    ///
    /// assert!(node.is_file());
    /// ```
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// Gets the latest version of the node using exponential search.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{
    ///         PrivateNode, PrivateDirectory,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::{BlockStore, MemoryBlockStore},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &MemoryBlockStore::default();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let mut init_dir = PrivateDirectory::new_and_store(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         forest,
    ///         store,
    ///         rng
    ///     ).await.unwrap();
    ///
    ///     let dir_clone = &mut Arc::clone(&init_dir);
    ///
    ///     dir_clone
    ///         .mkdir(&["pictures".into(), "cats".into()], true, Utc::now(), forest, store, rng)
    ///         .await
    ///         .unwrap();
    ///
    ///     dir_clone.as_node().store(forest, store, rng).await.unwrap();
    ///
    ///     let latest_node = PrivateNode::Dir(init_dir).search_latest(forest, store).await.unwrap();
    ///
    ///     let found_node = latest_node
    ///         .as_dir()
    ///         .unwrap()
    ///         .lookup_node("pictures", true, forest, store)
    ///         .await
    ///         .unwrap();
    ///
    ///     assert!(found_node.is_some());
    /// }
    /// ```
    pub async fn search_latest(
        &self,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<PrivateNode> {
        self.search_latest_nodes(forest, store)
            .await?
            .into_iter()
            .next()
            // We expect the latest revision to have found valid nodes.
            // otherwise it's a revision that's filled with other stuff
            // than PrivateNodes, which should be an error.
            .ok_or(FsError::NotFound.into())
    }

    /// Go to the latest known node and do conflict reconciliation, if multiple
    /// concurrent writes are detected.
    pub async fn reconcile_latest(
        &mut self,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        self.store(forest, store, rng).await?;
        self.search_latest_reconciled(forest, store).await?;
        Ok(())
    }

    /// Will reconcile this node with any newer changes fetched from the
    /// PrivateForest. But will overwrite any in-memory changes that haven't been
    /// persisted yet.
    pub async fn search_latest_reconciled(
        &self,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<PrivateNode> {
        let mut header = self.get_header().clone();
        let mut unmerged_heads = header.seek_unmerged_heads(forest, store).await?;

        if let Some((cid, head)) = unmerged_heads.pop_first() {
            if unmerged_heads.is_empty() {
                // There was only one unmerged head, we can fast forward
                Ok(head)
            } else {
                // We need to create a merge node
                Self::merge(header, (cid, head), unmerged_heads, forest, store).await
            }
        } else {
            // If None, then there's nothing to merge in (and this node was never stored)
            Ok(self.clone())
        }
    }

    /// Merges a non-empty set of conflicting private nodes together
    /// by merging them pair-wise.
    pub(crate) async fn merge(
        header: PrivateNodeHeader,
        (cid, node): (Cid, PrivateNode),
        nodes: BTreeMap<Cid, PrivateNode>,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<PrivateNode> {
        match node {
            PrivateNode::File(mut file) => {
                // They *should* all be files, but we won't error out if they're not.
                let files = nodes
                    .into_iter()
                    .filter_map(|(cid, node)| node.as_file().ok().map(|file| (cid, file)))
                    .collect::<BTreeMap<_, _>>();

                for (other_cid, other_file) in files {
                    file.merge(header.clone(), cid, &other_file, other_cid)?;
                }

                Ok(PrivateNode::File(file))
            }
            PrivateNode::Dir(mut dir) => {
                // They *should* all be directories, but we won't error out if one of them isn't.
                let dirs = nodes
                    .into_iter()
                    .filter_map(|(cid, node)| node.as_dir().ok().map(|dir| (cid, dir)))
                    .collect::<BTreeMap<_, _>>();

                for (other_cid, other_dir) in dirs {
                    // Need to pass in rng & mutable forest access
                    // for the cases where we haven't yet written a node to
                    // the forest, but need its hash for tie-breaking.
                    dir.merge(header.clone(), cid, &other_dir, other_cid, forest, store)
                        .await?;
                }

                Ok(PrivateNode::Dir(dir))
            }
        }
    }

    /// Seek ahead to the latest revision in this node's history.
    ///
    /// The result are all nodes from the latest revision, each one
    /// representing an instance of a concurrent write.
    pub async fn search_latest_nodes(
        &self,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Vec<PrivateNode>> {
        let header = self.get_header();

        let current_name = &header.get_revision_name();
        if !forest.has(current_name, store).await? {
            return Ok(vec![self.clone()]);
        }

        // Start an exponential search, starting with a small jump.
        // In many cases, we'll be at the latest revision already, so we only
        // do a single lookup to the next version, most likely realize it's not
        // there and thus stop seeking.
        let mut search = RatchetSeeker::new(header.ratchet.clone(), JumpSize::Small);
        let mut current_header = header.clone();

        loop {
            let current = search.current();
            current_header.update_ratchet(current.clone());

            let has_curr = forest
                .has(&current_header.get_revision_name(), store)
                .await?;

            let ord = if has_curr {
                Ordering::Less
            } else {
                Ordering::Greater
            };

            if !search.step(ord) {
                break;
            }
        }

        current_header.update_ratchet(search.current().clone());
        Ok(current_header
            .get_multivalue(forest, store)
            .await?
            .into_iter()
            .map(|(_, node)| node)
            .collect())
    }

    /// Tries to deserialize and decrypt a PrivateNode at provided PrivateRef
    /// from the PrivateForest.
    pub(crate) async fn from_private_ref(
        private_ref: &PrivateRef,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        parent_name: Option<Name>,
    ) -> Result<PrivateNode> {
        let cid = match forest
            .get_encrypted_by_hash(&private_ref.label, store)
            .await?
        {
            Some(cids) if cids.contains(&private_ref.content_cid) => private_ref.content_cid,
            _ => bail!(FsError::NotFound),
        };

        Self::from_cid(cid, &private_ref.temporal_key, forest, store, parent_name).await
    }

    pub(crate) async fn from_cid(
        cid: Cid,
        temporal_key: &TemporalKey,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        parent_name: Option<Name>,
    ) -> Result<PrivateNode> {
        let encrypted_bytes = store
            .get(&cid)
            .await?
            .ok_or_else(|| BlockStoreError::CIDNotFound(cid))?;
        let snapshot_key = temporal_key.derive_snapshot_key();
        let bytes = snapshot_key.decrypt(&encrypted_bytes)?;
        let node: PrivateNodeContentSerializable = serde_ipld_dagcbor::from_slice(&bytes)?;
        Ok(match node {
            PrivateNodeContentSerializable::File(file) => {
                let file = PrivateFile::from_serializable(
                    file,
                    temporal_key,
                    cid,
                    forest,
                    store,
                    parent_name,
                )
                .await?;
                PrivateNode::File(Arc::new(file))
            }
            PrivateNodeContentSerializable::Dir(dir) => {
                let dir = PrivateDirectory::from_serializable(
                    dir,
                    temporal_key,
                    cid,
                    forest,
                    store,
                    parent_name,
                )
                .await?;
                PrivateNode::Dir(Arc::new(dir))
            }
        })
    }

    pub(crate) fn get_persisted_as(&self) -> &OnceCell<Cid> {
        match self {
            Self::Dir(dir) => &dir.content.persisted_as,
            Self::File(file) => &file.content.persisted_as,
        }
    }

    pub(crate) async fn store_and_get_private_ref(
        &self,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<PrivateRef> {
        match self {
            Self::File(file) => file.store(forest, store, rng).await,
            Self::Dir(dir) => dir.store(forest, store, rng).await,
        }
    }

    /// Loads a node from the forest using provided access key.
    ///
    /// In case you're loading this node as a sub-node of another node, you need
    /// to provide the `parent_name`, so it can correctly create proofs relative
    /// to the parent name's base for the private forest.
    ///
    /// In case you're loading this node as the entry point into a WNFS, e.g.
    /// initially from an access key that was shared with you, simply provide `None`.
    /// In short, provide `None` iff
    /// - you have a certificate that gives you write access to exactly this node you're
    ///   loading specifically
    /// - you don't intend to prove writes to third parties.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{
    ///         PrivateNode, PrivateDirectory,
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
    ///     let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     let node = PrivateNode::Dir(dir);
    ///
    ///     let access_key = node.store(forest, store, rng).await.unwrap();
    ///
    ///     assert_eq!(
    ///         PrivateNode::load(&access_key, forest, store, None).await.unwrap(),
    ///         node
    ///     );
    /// }
    /// ```
    pub async fn load(
        access_key: &AccessKey,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        parent_name: Option<Name>,
    ) -> Result<PrivateNode> {
        let private_ref = access_key.derive_private_ref()?;
        PrivateNode::from_private_ref(&private_ref, forest, store, parent_name).await
    }

    /// Stores a node in the forest and returns an access key.
    pub async fn store(
        &self,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<AccessKey> {
        let private_ref = &self.store_and_get_private_ref(forest, store, rng).await?;
        Ok(AccessKey::Temporal(private_ref.into()))
    }
}

impl Id for PrivateNode {
    fn get_id(&self) -> String {
        match self {
            Self::File(file) => file.get_id(),
            Self::Dir(dir) => dir.get_id(),
        }
    }
}

impl From<PrivateFile> for PrivateNode {
    fn from(file: PrivateFile) -> Self {
        Self::File(Arc::new(file))
    }
}

impl From<PrivateDirectory> for PrivateNode {
    fn from(dir: PrivateDirectory) -> Self {
        Self::Dir(Arc::new(dir))
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
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[async_std::test]
    async fn serialized_private_node_can_be_deserialized() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let content = b"Lorem ipsum dolor sit amet";
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);
        let store = &InMemoryBlockstore::<64>::new();
        let file = PrivateFile::with_content(
            &forest.empty_name(),
            Utc::now(),
            content.to_vec(),
            forest,
            store,
            rng,
        )
        .await
        .unwrap();
        let mut directory = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

        directory
            .mkdir(&["music".into()], true, Utc::now(), forest, store, rng)
            .await
            .unwrap();

        let file_node = PrivateNode::File(Arc::new(file));
        let dir_node = PrivateNode::Dir(Arc::clone(&directory));

        let file_private_ref = file_node.store(forest, store, rng).await.unwrap();
        let dir_private_ref = dir_node.store(forest, store, rng).await.unwrap();

        let deserialized_file_node =
            PrivateNode::load(&file_private_ref, forest, store, Some(forest.empty_name()))
                .await
                .unwrap();

        let deserialized_dir_node =
            PrivateNode::load(&dir_private_ref, forest, store, Some(forest.empty_name()))
                .await
                .unwrap();

        assert_eq!(file_node, deserialized_file_node);
        assert_eq!(dir_node, deserialized_dir_node);
    }
}
