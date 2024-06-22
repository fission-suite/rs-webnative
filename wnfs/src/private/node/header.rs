use super::{PrivateNode, PrivateNodeHeaderSerializable, TemporalKey, REVISION_SEGMENT_DSI};
use crate::{
    error::FsError,
    private::{forest::traits::PrivateForest, RevisionRef},
};
use anyhow::{anyhow, bail, Result};
use futures::TryStreamExt;
use rand_core::CryptoRngCore;
use skip_ratchet::Ratchet;
use std::{collections::BTreeMap, fmt::Debug};
use wnfs_common::{
    blockstore::{block::Block as _, Blockstore},
    ipld_core::cid::Cid,
    Blake3Block, BlockStoreError, CODEC_RAW,
};
use wnfs_hamt::Hasher;
use wnfs_nameaccumulator::{Name, NameSegment};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// This is the header of a private node. It contains secret information about the node which includes
/// the inumber, the ratchet, and the identifying private name.
///
/// # Examples
///
/// ```
/// use wnfs::private::PrivateFile;
/// use wnfs_nameaccumulator::{AccumulatorSetup, Name};
/// use chrono::Utc;
/// use rand_chacha::ChaCha12Rng;
/// use rand_core::SeedableRng;
///
/// let rng = &mut ChaCha12Rng::from_entropy();
/// let setup = &AccumulatorSetup::from_rsa_2048(rng);
/// let file = PrivateFile::new(
///     &Name::empty(setup),
///     Utc::now(),
///     rng,
/// );
///
/// println!("Header: {:#?}", file.header);
/// ```
#[derive(Debug, Clone, Eq)]
pub struct PrivateNodeHeader {
    /// A unique identifier of the node.
    pub(crate) inumber: NameSegment,
    /// Used both for versioning and deriving keys for that enforces privacy.
    pub(crate) ratchet: Ratchet,
    /// Stores the name of this node for easier lookup.
    pub(crate) name: Name,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl PrivateNodeHeader {
    /// Creates a new PrivateNodeHeader.
    pub(crate) fn new(parent_name: &Name, rng: &mut impl CryptoRngCore) -> Self {
        let inumber = NameSegment::new(rng);

        Self {
            name: parent_name.with_segments_added(Some(inumber.clone())),
            ratchet: Ratchet::from_rng(rng),
            inumber,
        }
    }

    /// Advances the ratchet.
    pub(crate) fn advance_ratchet(&mut self) {
        self.ratchet.inc();
    }

    /// Updates the name to the child of given parent name.
    pub(crate) fn update_name(&mut self, parent_name: &Name) {
        self.name = parent_name.with_segments_added(Some(self.inumber.clone()));
    }

    /// Sets the ratchet and makes sure any caches are cleared.
    pub(crate) fn update_ratchet(&mut self, ratchet: Ratchet) {
        self.ratchet = ratchet;
    }

    /// Resets the ratchet.
    pub(crate) fn reset_ratchet(&mut self, rng: &mut impl CryptoRngCore) {
        self.update_ratchet(Ratchet::from_rng(rng));
    }

    /// Derives the revision ref of the current header.
    pub(crate) fn derive_revision_ref(&self, forest: &impl PrivateForest) -> RevisionRef {
        let temporal_key = self.derive_temporal_key();
        let label = blake3::Hasher::hash(&forest.get_accumulated_name(&self.get_revision_name()));

        RevisionRef {
            label,
            temporal_key,
        }
    }

    /// Derives the temporal key.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::private::PrivateFile;
    /// use wnfs_nameaccumulator::{AccumulatorSetup, Name};
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let setup = &AccumulatorSetup::from_rsa_2048(rng);
    /// let file = PrivateFile::new(&Name::empty(setup), Utc::now(), rng);
    /// let temporal_key = file.header.derive_temporal_key();
    ///
    /// println!("Temporal Key: {:?}", temporal_key);
    /// ```
    #[inline]
    pub fn derive_temporal_key(&self) -> TemporalKey {
        TemporalKey::new(&self.ratchet)
    }

    pub(crate) fn derive_revision_segment(&self) -> NameSegment {
        NameSegment::new_hashed(REVISION_SEGMENT_DSI, self.ratchet.key_derivation_data())
    }

    /// Gets the revision name for this node.
    ///
    /// It's this node's name with a last segment added that's
    /// unique but deterministic for each revision.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::private::{
    ///     PrivateFile,
    ///     forest::{hamt::HamtForest, traits::PrivateForest},
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    /// let file = PrivateFile::new(&forest.empty_name(), Utc::now(), rng);
    /// let revision_name = file.header.get_revision_name();
    ///
    /// println!("Revision name: {:?}", revision_name);
    /// ```
    pub fn get_revision_name(&self) -> Name {
        self.name
            .with_segments_added(Some(self.derive_revision_segment()))
    }

    /// Gets the name for this node.
    /// This name is persistent across revisions and can be used as the "allowed base name"
    /// for delegating write access.
    pub fn get_name(&self) -> &Name {
        &self.name
    }

    /// Encrypts this private node header in an block, then stores that in the given
    /// BlockStore and returns its CID.
    ///
    /// This *does not* store the block itself in the forest, only in the given block store.
    pub async fn store(&self, store: &impl Blockstore, forest: &impl PrivateForest) -> Result<Cid> {
        let temporal_key = self.derive_temporal_key();
        let cbor_bytes = serde_ipld_dagcbor::to_vec(&self.to_serializable(forest))?;
        let ciphertext = temporal_key.key_wrap_encrypt(&cbor_bytes)?;
        let block = Blake3Block::new(CODEC_RAW, ciphertext);
        let cid = block.cid()?;
        store.put(block).await?;
        Ok(cid)
    }

    pub(crate) fn to_serializable(
        &self,
        forest: &impl PrivateForest,
    ) -> PrivateNodeHeaderSerializable {
        PrivateNodeHeaderSerializable {
            inumber: self.inumber.clone(),
            ratchet: self.ratchet.clone(),
            name: forest.get_accumulated_name(&self.name),
        }
    }

    pub(crate) fn from_serializable(serializable: PrivateNodeHeaderSerializable) -> Self {
        Self {
            inumber: serializable.inumber,
            ratchet: serializable.ratchet,
            name: Name::new(serializable.name, []),
        }
    }

    /// Loads a private node header from a given CID linking to the ciphertext block
    /// to be decrypted with given key.
    pub(crate) async fn load(
        cid: &Cid,
        temporal_key: &TemporalKey,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        parent_name: Option<Name>,
    ) -> Result<Self> {
        let ciphertext = store
            .get(cid)
            .await?
            .ok_or_else(|| BlockStoreError::CIDNotFound(*cid))?;
        let cbor_bytes = temporal_key.key_wrap_decrypt(&ciphertext)?;
        let decoded: PrivateNodeHeaderSerializable = serde_ipld_dagcbor::from_slice(&cbor_bytes)?;
        let serialized_name = decoded.name.clone();
        let mut header = Self::from_serializable(decoded);
        if let Some(parent_name) = parent_name {
            let name = parent_name.with_segments_added([header.inumber.clone()]);
            let mounted_acc = forest.get_accumulated_name(&name);
            if mounted_acc != serialized_name {
                bail!(FsError::MountPointAndDeserializedNameMismatch(
                    format!("{mounted_acc:?}"),
                    format!("{serialized_name:?}"),
                ));
            }
            header.name = name;
        }
        Ok(header)
    }

    /// Returns the multivalue of nodes (and their corresponding CIDs) from
    /// the forest at this header's revision.
    pub(crate) async fn get_multivalue(
        &self,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Vec<(Cid, PrivateNode)>> {
        let mountpoint = self.name.parent();

        let name_hash =
            blake3::Hasher::hash(&forest.get_accumulated_name(&self.get_revision_name()));

        forest
            .get_multivalue_by_hash(&name_hash, &self.derive_temporal_key(), store, mountpoint)
            .try_collect::<Vec<_>>()
            .await
    }

    /// Seeks this header to the next free private forest slot
    /// as well as the set of private nodes that were written to
    pub(crate) async fn seek_unmerged_heads(
        &mut self,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<BTreeMap<Cid, PrivateNode>> {
        let mut previous_keys = Vec::with_capacity(1);
        let mut heads = BTreeMap::new();

        loop {
            let nodes = self.get_multivalue(forest, store).await?;

            if nodes.is_empty() {
                break;
            }

            for (cid, node) in nodes {
                // decrypt all previous links & remove any heads that they refer to
                for (reach_back, encrypted_cid) in node.get_previous().iter() {
                    // This requires linear memory in the amount of revisions we seek, but that's *probably* fine?
                    // I'm pretty sure we're allocating and holding on to more memory linearly in the implementation
                    // of `PrivateForest` per-revision anyways, so if we wanted to optimize that, we'd look there
                    // instead.
                    // None if reach_back > previous_keys.len(), then it's older than from where we started
                    if *reach_back <= previous_keys.len() {
                        let key = &previous_keys[previous_keys.len() - reach_back];
                        let previous_cid = encrypted_cid.resolve_value(key)?;
                        // We don't need to merge the older head, as we found a newer
                        // version of this node.
                        heads.remove(previous_cid);
                    }
                }
                // Add the newly found node to our heads
                heads.insert(cid, node);
            }

            previous_keys.push(TemporalKey::new(&self.ratchet));
            self.advance_ratchet();
        }

        Ok(heads)
    }

    pub(crate) fn ratchet_diff_for_merge(&self, other: &Self) -> Result<usize> {
        self.ratchet
            .compare(&other.ratchet, 10_000_000)
            .map_err(|e| {
                anyhow!("merge node set on different ratchet track (or history too far away): {e}")
            })?
            .try_into()
            .map_err(|_| anyhow!("merge node set to past revision"))
    }
}

impl PartialEq for PrivateNodeHeader {
    fn eq(&self, other: &Self) -> bool {
        // We skip equality-checking the name, since it depends on where the node header was mounted.
        // The inumber should suffice as identifier, the ratchet covers the revision part.
        self.inumber == other.inumber && self.ratchet == other.ratchet
    }
}
