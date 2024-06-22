use super::{hamt::HamtForest, traits::PrivateForest};
use crate::error::{FsError, VerificationError};
use anyhow::{bail, Result};
use std::collections::{BTreeSet, HashMap};
use wnfs_common::{
    blockstore::Blockstore,
    ipld_core::cid::Cid,
    utils::{Arc, CondSend},
    HashOutput,
};
use wnfs_hamt::Pair;
use wnfs_nameaccumulator::{
    AccumulatorSetup, BatchedProofPart, BatchedProofVerification, ElementsProof, Name,
    NameAccumulator, UnbatchableProofPart,
};

/// This holds proofs that added, removed or changed labels in the private forest correspond
/// to only sub-entries of certain directory or file names/paths.
///
/// The idea is to update this structure while writing to the actual private forest.
/// To do this easily, use `ProvingHamtForest`.
///
/// This structure can then get serialized and transferred to an actor without read access
/// to verify a diff between two forests.
// TODO(matheus23) add serialization (ideally with capsule)
// Ideally serialization deduplicates the base (first part of the value tuple).
// E.g. by serializing as a nested map (somewhat inverting the way the hash map is laid out in memory in this struct).
#[derive(Debug, Clone)]
pub struct ForestProofs {
    proofs_by_commitment: HashMap<NameAccumulator, (NameAccumulator, UnbatchableProofPart)>,
    batched_proof_part: BatchedProofPart,
}

/// A hamt forest that also tracks label proofs on the side.
///
/// This can also be used for verifying that a private forest state is valid compared
/// to a different private forest state.
#[derive(Debug, Clone)]
pub struct ProvingHamtForest {
    pub forest: Arc<HamtForest>,
    pub proofs: ForestProofs,
}

impl ForestProofs {
    /// Initialize an empty proofs carrying struct
    pub fn new() -> Self {
        Self {
            proofs_by_commitment: HashMap::new(),
            batched_proof_part: BatchedProofPart::new(),
        }
    }

    /// Prove given name, add its proof to the struct and return the accumulated name
    pub fn add_and_prove_name(
        &mut self,
        name: &Name,
        setup: &AccumulatorSetup,
    ) -> Result<NameAccumulator> {
        let (accumulated, proof) = name.into_proven_accumulator(setup);
        let base = NameAccumulator::from_state(proof.base.clone());
        let commitment = accumulated.clone();

        self.batched_proof_part.add(&proof, setup);
        self.proofs_by_commitment
            .insert(commitment, (base, proof.part.clone()));

        Ok(accumulated)
    }

    /// Verify all proofs.
    ///
    /// Please note that this doesn't verify the integrity of a private forest per se.
    ///
    /// For that, one needs to also check that
    /// - Added/removed or modified names in the private forest have associated proofs
    /// - Each associated proof is rooted in a name accumulator that an actor has access to
    ///   (e.g. via a signature from the root owner).
    pub fn verify_proofs(&self, setup: &AccumulatorSetup) -> Result<()> {
        let mut verification = BatchedProofVerification::new(setup);

        for (commitment, (base, proof_part)) in self.proofs_by_commitment.iter() {
            verification.add(base, commitment, proof_part)?;
        }

        verification.verify(&self.batched_proof_part)
    }
}

impl ProvingHamtForest {
    /// Create a new proving forest from the state of an existing hamt forest.
    ///
    /// It will be initialized without proofs.
    pub fn new(forest: Arc<HamtForest>) -> Self {
        Self {
            forest,
            proofs: ForestProofs::new(),
        }
    }

    /// Create a new proving forest with given pre-existing proofs and current
    /// state of a hamt forest.
    pub fn from_proofs(proofs: ForestProofs, forest: Arc<HamtForest>) -> Self {
        Self { forest, proofs }
    }

    /// Verify the current state of the hamt forest against an older state.
    ///
    /// You need to provide a set of allowed "base" name accumulators.
    /// Them and all of their sub-entries (e.g. sub-directories or contained files)
    /// are allowed to change between the previous and current state.
    pub async fn verify_against_previous_state(
        &self,
        previous: &HamtForest,
        allowed_bases: &BTreeSet<NameAccumulator>,
        store: &impl Blockstore,
    ) -> Result<()> {
        let setup = self.forest.get_accumulator_setup();
        if setup != previous.get_accumulator_setup() {
            bail!(FsError::IncompatibleAccumulatorSetups);
        }

        self.proofs.verify_proofs(setup)?;

        for change in self.forest.diff(previous, store).await? {
            // Verify that there exists a proof for the changed label & obtain the base that
            // was proven from.
            let Some((base, _)) = self.proofs.proofs_by_commitment.get(&change.key) else {
                bail!(VerificationError::UnverifiedWrite(format!(
                    "{:?}",
                    change.key
                )));
            };

            // Verify that the base is allowed to be written to (e.g. has been signed by a party
            // with a signature chain up to the root owner).
            if !allowed_bases.contains(base) {
                bail!(VerificationError::WriteToDisallowedBase(format!(
                    "{base:?}"
                )));
            }
        }

        Ok(())
    }
}

impl Default for ForestProofs {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateForest for ProvingHamtForest {
    fn empty_name(&self) -> Name {
        self.forest.empty_name()
    }

    fn get_accumulator_setup(&self) -> &AccumulatorSetup {
        self.forest.get_accumulator_setup()
    }

    fn get_proven_name(&self, name: &Name) -> (NameAccumulator, ElementsProof) {
        self.forest.get_proven_name(name)
    }

    async fn has_by_hash(&self, name_hash: &HashOutput, store: &impl Blockstore) -> Result<bool> {
        self.forest.has_by_hash(name_hash, store).await
    }

    async fn has(&self, name: &Name, store: &impl Blockstore) -> Result<bool> {
        self.forest.has(name, store).await
    }

    async fn put_encrypted<I>(
        &mut self,
        name: &Name,
        values: I,
        store: &impl Blockstore,
    ) -> Result<NameAccumulator>
    where
        I: IntoIterator<Item = Cid> + CondSend,
        I::IntoIter: CondSend,
    {
        let ProvingHamtForest { forest, proofs } = self;

        proofs.add_and_prove_name(name, forest.get_accumulator_setup())?;

        Arc::make_mut(forest)
            .put_encrypted(name, values, store)
            .await
    }

    async fn get_encrypted_by_hash<'b>(
        &'b self,
        name_hash: &HashOutput,
        store: &impl Blockstore,
    ) -> Result<Option<&'b BTreeSet<Cid>>> {
        self.forest.get_encrypted_by_hash(name_hash, store).await
    }

    async fn get_encrypted(
        &self,
        name: &Name,
        store: &impl Blockstore,
    ) -> Result<Option<&BTreeSet<Cid>>> {
        self.forest.get_encrypted(name, store).await
    }

    async fn remove_encrypted(
        &mut self,
        name: &Name,
        store: &impl Blockstore,
    ) -> Result<Option<Pair<NameAccumulator, BTreeSet<Cid>>>> {
        let ProvingHamtForest { forest, proofs } = self;

        proofs.add_and_prove_name(name, forest.get_accumulator_setup())?;

        Arc::make_mut(&mut self.forest)
            .remove_encrypted(name, store)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{ForestProofs, ProvingHamtForest};
    use crate::private::forest::{hamt::HamtForest, traits::PrivateForest};
    use anyhow::Result;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use std::collections::BTreeSet;
    use wnfs_common::{blockstore::InMemoryBlockstore, ipld_core::cid::Cid, utils::Arc};
    use wnfs_nameaccumulator::{AccumulatorSetup, Name, NameAccumulator, NameSegment};

    #[test]
    fn forest_proofs_can_be_verified() -> Result<()> {
        let rng = &mut ChaCha12Rng::from_entropy();
        let setup = &AccumulatorSetup::from_rsa_2048(rng);
        let mut proofs = ForestProofs::new();

        let base = Name::empty(setup).with_segments_added(Some(NameSegment::new(rng)));
        let segments_one = [NameSegment::new(rng), NameSegment::new(rng)];
        let segments_two = [NameSegment::new(rng), NameSegment::new(rng)];
        let name_one = base.with_segments_added(segments_one);
        let name_two = base.with_segments_added(segments_two);

        proofs.add_and_prove_name(&name_one, setup)?;
        proofs.add_and_prove_name(&name_two, setup)?;

        assert!(proofs.verify_proofs(setup).is_ok());

        Ok(())
    }

    #[async_std::test]
    async fn proving_hamt_forest_can_be_verified() -> Result<()> {
        let rng = &mut ChaCha12Rng::from_entropy();
        let setup = &AccumulatorSetup::from_rsa_2048(rng);
        let store = &InMemoryBlockstore::<64>::new();
        let old_forest = Arc::new(HamtForest::new(setup.clone()));
        let mut forest = ProvingHamtForest::new(Arc::clone(&old_forest));

        let base = NameAccumulator::with_segments(&Some(NameSegment::new(rng)), setup);
        let name = Name::new(base.clone(), Some(NameSegment::new(rng)));

        let cid = Cid::default();
        forest.put_encrypted(&name, Some(cid), store).await?;

        let allowed_bases = BTreeSet::from([base.clone()]);

        let result = forest
            .verify_against_previous_state(&old_forest, &allowed_bases, store)
            .await;

        assert!(result.is_ok());

        Ok(())
    }
}
