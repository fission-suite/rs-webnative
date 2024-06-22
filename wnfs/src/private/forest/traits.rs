use crate::{
    error::CryptError,
    private::{PrivateNode, TemporalKey},
};
use anyhow::Result;
use async_stream::stream;
use futures::Future;
use std::collections::BTreeSet;
use wnfs_common::{
    blockstore::Blockstore,
    ipld_core::cid::Cid,
    utils::{BoxStream, CondSend, CondSync},
    HashOutput,
};
use wnfs_hamt::Pair;
use wnfs_nameaccumulator::{AccumulatorSetup, ElementsProof, Name, NameAccumulator};

/// A trait representing a (usually serializable) mapping from
/// WNFS names to a set of encrypted ciphertext blocks.
///
/// It also stores the accumulator setup information for running
/// name accumulator operations. Upon put or remove, it'll run
/// these operations for the caller.
pub trait PrivateForest: CondSync {
    /// Construct what represents the empty name in this forest.
    ///
    /// It is forest-specific, as it depends on the specific forest's
    /// accumulator setup.
    ///
    /// Two forests with the same accumulator setup will have the same
    /// empty name representation.
    fn empty_name(&self) -> Name {
        Name::empty(self.get_accumulator_setup())
    }

    /// Return the forest's accumulator setup.
    ///
    /// This setup needs to be generated during creation of a private
    /// forest. The setup creation needs to run in a trusted context,
    /// usually on the device that has root access to the private forest.
    ///
    /// It's used for the cryptographic accumulator operations underlying
    /// the private forest name accumulators.
    fn get_accumulator_setup(&self) -> &AccumulatorSetup;

    /// Accumulate all segments inside a name into a NameAccumulator and
    /// also return an ElementsProof witnessing the Name being accumulated correctly.
    ///
    /// This is a function on `PrivateForest` so it can implement a cache on this
    /// somewhat expensive operation.
    fn get_proven_name(&self, name: &Name) -> (NameAccumulator, ElementsProof);

    /// Accumulate all segments inside a name into a NameAccumulator.
    ///
    /// The default implementation simply returns `self.get_proven_name(name).0`.
    fn get_accumulated_name(&self, name: &Name) -> NameAccumulator {
        self.get_proven_name(name).0
    }

    /// Checks that a value with the given saturated name hash key exists.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{
    ///         PrivateDirectory, PrivateNode,
    ///         forest::{hamt::HamtForest, traits::PrivateForest},
    ///     },
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &mut MemoryBlockStore::default();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let dir = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///     let node = PrivateNode::Dir(dir);
    ///     let access_key = node.store(forest, store, rng).await.unwrap();
    ///
    ///     assert!(forest.has_by_hash(access_key.get_label(), store).await.unwrap());
    /// }
    /// ```
    fn has_by_hash(
        &self,
        name_hash: &HashOutput,
        store: &impl Blockstore,
    ) -> impl Future<Output = Result<bool>> + CondSend;

    /// Check whether a certain name has any values.
    fn has(
        &self,
        name: &Name,
        store: &impl Blockstore,
    ) -> impl Future<Output = Result<bool>> + CondSend;

    /// Adds new encrypted values at the given key.
    fn put_encrypted<I>(
        &mut self,
        name: &Name,
        values: I,
        store: &impl Blockstore,
    ) -> impl Future<Output = Result<NameAccumulator>> + CondSend
    where
        I: IntoIterator<Item = Cid> + CondSend,
        I::IntoIter: CondSend;

    /// Gets the CIDs to blocks of ciphertext by hash of name.
    fn get_encrypted_by_hash<'b>(
        &'b self,
        name_hash: &HashOutput,
        store: &impl Blockstore,
    ) -> impl Future<Output = Result<Option<&'b BTreeSet<Cid>>>> + CondSend;

    /// Gets the CIDs to blocks of ciphertext by name.
    fn get_encrypted(
        &self,
        name: &Name,
        store: &impl Blockstore,
    ) -> impl Future<Output = Result<Option<&BTreeSet<Cid>>>> + CondSend;

    /// Removes the CIDs to blocks of ciphertext by name.
    fn remove_encrypted(
        &mut self,
        name: &Name,
        store: &impl Blockstore,
    ) -> impl Future<Output = Result<Option<Pair<NameAccumulator, BTreeSet<Cid>>>>> + CondSend;

    /// Returns a stream of all private nodes that could be decrypted at given revision.
    ///
    /// The stream of results is ordered by CID.
    ///
    /// Each item in the resulting stream represents an instance of a concurrent write.
    fn get_multivalue_by_hash<'a>(
        &'a self,
        label: &'a HashOutput,
        temporal_key: &'a TemporalKey,
        store: &'a impl Blockstore,
        parent_name: Option<Name>,
    ) -> BoxStream<'a, Result<(Cid, PrivateNode)>>
    where
        Self: Sized,
    {
        Box::pin(stream! {
            match self
                .get_encrypted_by_hash(label, store)
                .await
            {
                Ok(Some(cids)) => {
                    for cid in cids {
                        match PrivateNode::from_cid(*cid, temporal_key, self, store, parent_name.clone()).await {
                            Ok(node) => yield Ok((*cid, node)),
                            Err(e) if e.downcast_ref::<CryptError>().is_some() => {
                                // we likely matched a PrivateNodeHeader instead of a PrivateNode.
                                // we skip it
                            }
                            // If something else goes wrong, we tell the user about it
                            Err(e) => yield Err(e)
                        }
                    }
                }
                Ok(None) => {},
                Err(e) => yield Err(e),
            }
        })
    }
}
