#[cfg(not(feature = "rug"))]
#[cfg(feature = "num-bigint-dig")]
use crate::BigNumDig;
#[cfg(feature = "rug")]
use crate::BigNumRug;
use crate::{
    error::VerificationError,
    fns::{blake3_prime_digest, blake3_prime_digest_fast, multi_exp},
    traits::Big,
};
use anyhow::Result;
use num_traits::{One, Zero};
use once_cell::sync::OnceCell;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{hash::Hash, str::FromStr};
use wnfs_common::Storable;

/// The domain separation string for deriving the l hash in the PoKE* protocol.
const L_HASH_DSI: &str = "wnfs/1.0/PoKE*/l 128-bit hash derivation";

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

#[cfg(not(feature = "rug"))]
#[cfg(feature = "num-bigint-dig")]
pub type DefaultBig = BigNumDig;

#[cfg(feature = "rug")]
pub type DefaultBig = BigNumRug;

/// A WNFS name.
/// Each file or directory has a name.
/// Names consist of a set of name segments and are commited to name accumulators.
/// However, these names are based on RSA accumulators to make it possible
/// to prove a relationship between two names, e.g a file being contained in
/// a sub-directory of a directory while leaking as little information as possible.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name<B: Big = DefaultBig> {
    relative_to: NameAccumulator<B>,
    segments: Vec<NameSegment<B>>,
}

/// Represents a setup needed for RSA accumulator operation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct AccumulatorSetup<B: Big = DefaultBig> {
    #[serde(bound = "B: Big")]
    #[serde(deserialize_with = "crate::uint256_serde_be::deserialize::<B, _>")]
    #[serde(serialize_with = "crate::uint256_serde_be::serialize::<B, _>")]
    modulus: B::Num,
    #[serde(bound = "B: Big")]
    #[serde(deserialize_with = "crate::uint256_serde_be::deserialize::<B, _>")]
    #[serde(serialize_with = "crate::uint256_serde_be::serialize::<B, _>")]
    pub generator: B::Num,
}

/// A WNFS name represented as the RSA accumulator of all of its name segments.
#[derive(Clone, Eq)]
pub struct NameAccumulator<B: Big = DefaultBig> {
    /// A 2048-bit number
    state: B::Num,
    /// A cache for its serialized form
    serialized_cache: OnceCell<[u8; 256]>,
}

/// A name accumluator segment. A name accumulator commits to a set of these.
/// They are represented as 256-bit prime numbers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameSegment<B: Big = DefaultBig>(
    /// Invariant: Must be a 256-bit prime
    B::Num,
);

/// PoKE* (Proof of Knowledge of Exponent),
/// assuming that the base is trusted
/// (e.g. part of a common reference string).
#[derive(Clone, PartialEq, Eq)]
pub struct ElementsProof<B: Big = DefaultBig> {
    /// The accumulator's base, $u$
    pub base: B::Num,
    /// A part of the proof, $Q = u^q$, where $element = q*l + r$
    pub big_q: B::Num,
    /// Part of the proof that can't be batched
    pub part: UnbatchableProofPart<B>,
}

/// The part of PoKE* (Proof of Knowledge of Exponent) proofs that can't be batched.
/// This is very small (serialized typically <20 bytes, most likely just 17 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct UnbatchableProofPart<B: Big = DefaultBig> {
    /// The number to increase a hash by to land on the next prime.
    /// Helps to more quickly generate/verify the prime number $l$.
    pub l_hash_inc: u32,
    /// A part of the proof, the residue of the element that's proven, i.e. $r$ in $element = q*l + r$
    pub r: B::Num,
}

/// The part of a name accumulator proof that can be batched,
/// i.e. the size of this part of the proof is independent of
/// the number of elements being proven. It's always 2048-bit.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchedProofPart<B: Big = DefaultBig> {
    #[serde(bound = "B: Big")]
    #[serde(deserialize_with = "crate::uint256_serde_be::deserialize::<B, _>")]
    #[serde(serialize_with = "crate::uint256_serde_be::serialize::<B, _>")]
    big_q_product: B::Num,
}

/// Data that is kept around for verifying batch proofs.
pub struct BatchedProofVerification<'a, B: Big = DefaultBig> {
    bases_and_exponents: Vec<(B::Num, B::Num)>,
    setup: &'a AccumulatorSetup<B>,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<B: Big> Name<B> {
    /// Create the empty name
    pub fn empty(setup: &AccumulatorSetup<B>) -> Self {
        Self::new(NameAccumulator::empty(setup), None)
    }

    /// Create a name relative to some other committed name
    /// and with given segments added to that name.
    pub fn new(
        relative_to: NameAccumulator<B>,
        segments: impl IntoIterator<Item = NameSegment<B>>,
    ) -> Self {
        Self {
            relative_to,
            segments: segments.into_iter().collect(),
        }
    }

    /// Returns whether the name has any segments added to it or
    /// just represents an absolute path without relative segments.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Remove the last name segment, if possible.
    pub fn up(&mut self) {
        self.segments.pop();
    }

    /// Return the parent name, if possible.
    pub fn parent(&self) -> Option<Name<B>> {
        if self.is_root() {
            None
        } else {
            let mut name = self.clone();
            name.up();
            Some(name)
        }
    }

    pub fn get_segments(&self) -> &Vec<NameSegment<B>> {
        &self.segments
    }

    pub fn add_segments(&mut self, segments: impl IntoIterator<Item = NameSegment<B>>) {
        self.segments.extend(segments);
    }

    pub fn with_segments_added(&self, segments: impl IntoIterator<Item = NameSegment<B>>) -> Self {
        let mut clone = self.clone();
        clone.add_segments(segments);
        clone
    }

    /// Returns the commited name accumulator for this name
    /// as well as a proof that related the name accumulator that
    /// this name is relative to.
    ///
    /// This proof process is memoized. Running it twice won't duplicate work.
    pub fn into_proven_accumulator(
        &self,
        setup: &AccumulatorSetup<B>,
    ) -> (NameAccumulator<B>, ElementsProof<B>) {
        let mut name = self.relative_to.clone();
        let proof = name.add(self.segments.iter(), setup);
        (name, proof)
    }

    /// Return what name accumulator this name commits to.
    pub fn into_accumulator(&self, setup: &AccumulatorSetup<B>) -> NameAccumulator<B> {
        self.into_proven_accumulator(setup).0
    }
}

impl<B: Big> NameAccumulator<B> {
    /// Create the empty accumulator.
    pub fn empty(setup: &AccumulatorSetup<B>) -> Self {
        Self {
            state: setup.generator.clone(),
            serialized_cache: OnceCell::new(),
        }
    }

    /// Create an accumulator with given segments inside.
    pub fn with_segments<'a>(
        segments: impl IntoIterator<Item = &'a NameSegment<B>> + Clone,
        setup: &AccumulatorSetup<B>,
    ) -> Self
    where
        B: 'a,
    {
        let mut acc = Self::empty(setup);
        acc.add(segments, setup); // ignore proof
        acc
    }

    /// Create an accumulator from the number it's represented as.
    ///
    /// This needs to be a 2048-bit number in the RSA group from
    /// the accumulator setup used.
    pub fn from_state(state: B::Num) -> Self {
        Self {
            state,
            serialized_cache: OnceCell::new(),
        }
    }

    /// Add a set of elements to the accumulator and return a batch
    /// elements proof that verifies the change of state of the accumulator.
    pub fn add<'a>(
        &mut self,
        segments: impl IntoIterator<Item = &'a NameSegment<B>>,
        setup: &AccumulatorSetup<B>,
    ) -> ElementsProof<B>
    where
        B: 'a,
    {
        let segments = segments
            .into_iter()
            .map(|s| s.0.clone())
            .collect::<Vec<_>>();

        // Reset the serialized state
        self.serialized_cache = OnceCell::new();
        let witness = self.state.clone();

        self.state = B::modpow_product(&self.state, segments.iter(), &setup.modulus);

        let data = poke_fiat_shamir_l_hash_data::<B>(&setup.modulus, &witness, &self.state);
        let (l, l_hash_inc) = blake3_prime_digest::<B>(L_HASH_DSI, data, 16);

        let (q, r) = B::quotrem_product(segments.iter(), &l);

        let big_q = if B::Num::is_zero(&q) {
            B::Num::one()
        } else {
            B::modpow(&witness, &q, &setup.modulus)
        };

        ElementsProof {
            base: witness,
            big_q,
            part: UnbatchableProofPart { l_hash_inc, r },
        }
    }

    /// Deserialize a name accumulator from bytes.
    ///
    /// The byte array needs to be 256 bytes (2048 bits).
    pub fn parse_bytes(byte_buf: impl AsRef<[u8]>) -> Result<Self> {
        let mut bytes = [0u8; 256];
        bytes.copy_from_slice(byte_buf.as_ref());
        Ok(Self::parse_slice(bytes))
    }

    /// Deserialize a name accumulator from bytes.
    pub fn parse_slice(slice: [u8; 256]) -> Self {
        let state = B::from_bytes_be(&slice);
        Self {
            state,
            serialized_cache: OnceCell::from(slice),
        }
    }

    /// Serialize a name accumulator from bytes.
    pub fn into_bytes(self) -> [u8; 256] {
        let cache = self.serialized_cache;
        let state = self.state;
        cache.into_inner().unwrap_or_else(|| B::to_bytes_be(&state))
    }

    /// Serialize a name accumulator to bytes and return a reference.
    ///
    /// This call is memoized, serializing twice won't duplicate work.
    pub fn as_bytes(&self) -> &[u8; 256] {
        self.serialized_cache
            .get_or_init(|| B::to_bytes_be(&self.state))
    }
}

fn poke_fiat_shamir_l_hash_data<B: Big>(
    modulus: &B::Num,
    base: &B::Num,
    commitment: &B::Num,
) -> impl AsRef<[u8]> {
    [
        B::to_bytes_be::<256>(modulus),
        B::to_bytes_be::<256>(base),
        B::to_bytes_be::<256>(commitment),
    ]
    .concat()
}

impl<B: Big> AccumulatorSetup<B> {
    /// Finishes a setup given a 2048-bit RSA modulus encoded in big-endian.
    ///
    /// Remaining work is safe and doesn't require a trusted environment.
    pub fn with_modulus(modulus_big_endian: &[u8; 256], rng: &mut impl CryptoRngCore) -> Self {
        let modulus = B::from_bytes_be(modulus_big_endian);
        // The generator is just some random quadratic residue.
        let generator = B::squaremod(&B::rand_below(&modulus, rng), &modulus);
        Self { modulus, generator }
    }

    /// Does a trusted setup in-memory and throws away the prime factors.
    /// This requires generating two 1024-bit primes, so it's fairly slow.
    ///
    /// The toxic waste generated during this operation is zeroized as soon
    /// as possible. Keep in mind that in theory it's still possible for a
    /// priviliged process to observe the memory and copy out the toxic waste
    /// before it's deleted.
    pub fn trusted(rng: &mut impl CryptoRngCore) -> Self {
        let modulus = B::rand_rsa_modulus(rng);
        // The generator is just some random quadratic residue.
        let generator = B::squaremod(&B::rand_below(&modulus, rng), &modulus);
        Self { modulus, generator }
    }

    /// Faster than `trusted`, but depends on the 2048-bit [rsa factoring challenge]
    /// to not be broken.
    ///
    /// This is great for tests, as it doesn't require lots of primality tests.
    ///
    /// [rsa factoring challenge]: https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
    pub fn from_rsa_2048(rng: &mut impl CryptoRngCore) -> Self {
        let modulus = B::Num::from_str(
            "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357",
        ).ok().unwrap();
        let generator = B::squaremod(&B::rand_below(&modulus, rng), &modulus);
        Self { modulus, generator }
    }
}

impl<B: Big> NameSegment<B> {
    /// Create a new, random name segment
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        Self(B::rand_prime_256bit(rng))
    }

    /// Derive a name segment as the hash from some data
    pub fn new_hashed(domain_separation_info: &str, data: impl AsRef<[u8]>) -> Self {
        Self(blake3_prime_digest::<B>(domain_separation_info, data, 32).0)
    }
}

impl<B: Big> BatchedProofPart<B> {
    /// Create a new proof batcher.
    pub fn new() -> Self {
        Self {
            big_q_product: B::Num::one(),
        }
    }

    /// Add the batchable portion of a proof of elements
    /// for a certain name accumulator to this batch proof.
    pub fn add(&mut self, proof: &ElementsProof<B>, setup: &AccumulatorSetup<B>) {
        self.big_q_product *= &proof.big_q;
        self.big_q_product %= &setup.modulus;
    }
}

impl<'a, B: Big> BatchedProofVerification<'a, B> {
    /// Create a new verifier
    pub fn new(setup: &'a AccumulatorSetup<B>) -> Self {
        Self {
            bases_and_exponents: Vec::new(),
            setup,
        }
    }

    /// Add another relation to verify.
    ///
    /// This will return an error if the unbatchable
    /// proof part is invalid, either due to its "l" hash
    /// not being prime or the residue being out of range.
    ///
    /// This can happen if the base element or commitment
    /// don't fit this proof part.
    pub fn add(
        &mut self,
        base: &NameAccumulator<B>,
        commitment: &NameAccumulator<B>,
        proof_part: &UnbatchableProofPart<B>,
    ) -> Result<()> {
        let hasher =
            poke_fiat_shamir_l_hash_data::<B>(&self.setup.modulus, &base.state, &commitment.state);
        let l = blake3_prime_digest_fast::<B>(L_HASH_DSI, hasher, 16, proof_part.l_hash_inc)
            .ok_or(VerificationError::LHashNonPrime)?;

        if proof_part.r >= l {
            Err(VerificationError::ResidueOutsideRange)?;
        }

        let proof_kcr_base = (commitment.state.clone()
            * B::modpow(
                &B::mod_inv(&base.state, &self.setup.modulus)
                    .ok_or(VerificationError::NoInverse)?,
                &proof_part.r,
                &self.setup.modulus,
            ))
            % &self.setup.modulus;

        self.bases_and_exponents.push((proof_kcr_base, l));

        Ok(())
    }

    /// Verify the whole relation of previously added bases to their commitments using
    /// the batched proof.
    ///
    /// Will return an error if verification fails.
    pub fn verify(&self, batched_proof: &BatchedProofPart<B>) -> Result<()> {
        let exponents = self.bases_and_exponents.iter().map(|(_, l)| l);
        let tmp = B::modpow_product(&batched_proof.big_q_product, exponents, &self.setup.modulus);

        if tmp != multi_exp::<B>(&self.bases_and_exponents, &self.setup.modulus) {
            return Err(VerificationError::ValidationFailed.into());
        }

        Ok(())
    }
}

macro_rules! impl_storable {
    ( $ty:ty ) => {
        impl<B: Big> Storable for $ty {
            type Serializable = $ty;

            async fn to_serializable(
                &self,
                _store: &impl ::wnfs_common::blockstore::Blockstore,
            ) -> Result<Self::Serializable> {
                Ok(self.clone())
            }

            async fn from_serializable(
                _: Option<&::wnfs_common::ipld_core::cid::Cid>,
                serializable: Self::Serializable,
            ) -> Result<Self> {
                Ok(serializable)
            }
        }
    };
}

impl_storable!(AccumulatorSetup<B>);
impl_storable!(NameSegment<B>);
impl_storable!(NameAccumulator<B>);
impl_storable!(UnbatchableProofPart<B>);
impl_storable!(BatchedProofPart<B>);

impl<B: Big> Serialize for NameSegment<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::serialize(B::to_bytes_be::<32>(&self.0).as_ref(), serializer)
    }
}

impl<'de, B: Big> Deserialize<'de> for NameSegment<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        Ok(NameSegment(B::from_bytes_be(&bytes)))
    }
}

impl<'de, B: Big> Deserialize<'de> for NameAccumulator<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let byte_buf = serde_bytes::ByteBuf::deserialize(deserializer)?;
        NameAccumulator::parse_bytes(byte_buf).map_err(serde::de::Error::custom)
    }
}

impl<B: Big> Serialize for NameAccumulator<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::serialize(self.as_ref(), serializer)
    }
}

impl<'de, B: Big> Deserialize<'de> for UnbatchableProofPart<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (l_hash_inc, r): (u32, &serde_bytes::Bytes) = Deserialize::deserialize(deserializer)?;
        let r = B::from_bytes_be(r);
        Ok(Self { l_hash_inc, r })
    }
}

impl<B: Big> Serialize for UnbatchableProofPart<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let residue = B::to_bytes_be::<16>(&self.r);
        let r = serde_bytes::Bytes::new(&residue);
        (self.l_hash_inc, r).serialize(serializer)
    }
}

impl<B: Big> PartialEq for NameAccumulator<B> {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<B: Big> Ord for NameAccumulator<B> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.state.cmp(&other.state)
    }
}

impl<B: Big> PartialOrd for NameAccumulator<B> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<B: Big> std::fmt::Debug for NameAccumulator<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameAccumulator")
            .field("state", &self.state.to_string())
            .finish()
    }
}

impl<B: Big> Hash for NameAccumulator<B> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.state.hash(state);
    }
}

impl<B: Big> AsRef<[u8]> for NameAccumulator<B> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<B: Big> Default for BatchedProofPart<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Big> std::fmt::Debug for NameSegment<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NameSegment")
            .field(&self.0.to_string())
            .finish()
    }
}

impl<B: Big> std::fmt::Debug for AccumulatorSetup<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccumulatorSetup")
            .field("modulus", &self.modulus.to_string())
            .field("generator", &self.generator.to_string())
            .finish()
    }
}

impl<B: Big> std::fmt::Debug for UnbatchableProofPart<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnbatchableProofPart")
            .field("l_hash_inc", &self.l_hash_inc)
            .field("r", &self.r.to_string())
            .finish()
    }
}

impl<B: Big> std::fmt::Debug for ElementsProof<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElementsProof")
            .field("base", &self.base.to_string())
            .field("big_q", &self.big_q.to_string())
            .field("part", &self.part)
            .finish()
    }
}

impl<B: Big> std::fmt::Debug for BatchedProofPart<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchedProofPart")
            .field("big_q_product", &self.big_q_product.to_string())
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::DefaultBig;
    use crate::{
        AccumulatorSetup, BatchedProofPart, BatchedProofVerification, Big, BigNumDig, Name,
        NameAccumulator, NameSegment,
    };
    use anyhow::Result;
    use libipld::{
        cbor::DagCborCodec,
        prelude::{Decode, Encode},
        Ipld,
    };
    use num_bigint_dig::BigUint;
    use proptest::{prop_assert, prop_assert_eq};
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use std::io::Cursor;
    use test_strategy::proptest;

    #[test]
    fn name_segment_serialize_roundtrip() {
        let rng = &mut thread_rng();
        let segment = NameSegment::new(rng);

        let bytes = serde_ipld_dagcbor::to_vec(&segment).unwrap();
        let segment_back: NameSegment = serde_ipld_dagcbor::from_slice(&bytes).unwrap();

        assert_eq!(segment_back, segment);
    }

    #[test]
    fn name_accumulator_serialize_roundtrip() {
        let rng = &mut thread_rng();
        let setup = &AccumulatorSetup::from_rsa_2048(rng);
        let mut acc = NameAccumulator::empty(setup);

        acc.add(
            &[
                NameSegment::new(rng),
                NameSegment::new(rng),
                NameSegment::new(rng),
            ],
            setup,
        );

        let ipld = libipld::serde::to_ipld(&acc).unwrap();
        let mut bytes = Vec::new();
        ipld.encode(DagCborCodec, &mut bytes).unwrap();

        let ipld = Ipld::decode(DagCborCodec, &mut Cursor::new(bytes)).unwrap();
        let acc_back = libipld::serde::from_ipld::<NameAccumulator>(ipld).unwrap();

        assert_eq!(acc_back, acc);
    }

    #[test]
    fn name_batched_proof_example() -> Result<()> {
        let rng = &mut thread_rng();
        let setup = &AccumulatorSetup::<DefaultBig>::from_rsa_2048(rng);
        let mut name_note = Name::empty(setup);
        let mut name_image = Name::empty(setup);

        let root_dir_segment = NameSegment::new(rng);
        let docs_dir_segment = NameSegment::new(rng);
        let pics_dir_segment = NameSegment::new(rng);
        let note_file_segment = NameSegment::new(rng);
        let image_file_segment = NameSegment::new(rng);

        name_note.add_segments([
            root_dir_segment.clone(),
            docs_dir_segment,
            note_file_segment,
        ]);
        name_image.add_segments([root_dir_segment, pics_dir_segment, image_file_segment]);

        let (accum_note, proof_note) = name_note.into_proven_accumulator(setup);
        let (accum_image, proof_image) = name_image.into_proven_accumulator(setup);

        let mut batched_proof = BatchedProofPart::new();
        batched_proof.add(&proof_note, setup);
        batched_proof.add(&proof_image, setup);

        let name_base = Name::empty(setup).into_accumulator(setup);
        let mut verification = BatchedProofVerification::new(setup);
        verification.add(&name_base, &accum_note, &proof_note.part)?;
        verification.add(&name_base, &accum_image, &proof_image.part)?;
        verification.verify(&batched_proof)?;

        Ok(())
    }

    #[test]
    fn equals_ignores_serialization_cache() -> Result<()> {
        let rng = &mut thread_rng();
        let setup = &AccumulatorSetup::<DefaultBig>::from_rsa_2048(rng);

        let mut name_one = NameAccumulator::empty(setup);
        let mut name_two = NameAccumulator::empty(setup);

        assert_eq!(name_one, name_two);

        name_one.as_bytes(); // Force serialization

        assert_eq!(name_one, name_two);

        let segment = NameSegment::new(rng);
        name_one.add(Some(&segment), setup);
        name_two.add(Some(&segment), setup);

        assert_eq!(name_one, name_two);

        name_one.as_bytes(); // Force serialization

        assert_eq!(name_one, name_two);

        Ok(())
    }

    #[proptest(cases = 32)]
    fn batch_proofs(do_batch_step: [bool; 4], do_verify_step: [bool; 4], seed: u64) {
        let rng = &mut ChaCha12Rng::seed_from_u64(seed);
        let setup = &AccumulatorSetup::<DefaultBig>::from_rsa_2048(rng);
        let base_a = NameAccumulator::with_segments(&[NameSegment::new(rng)], setup);
        let base_b = NameAccumulator::with_segments(&[NameSegment::new(rng)], setup);

        let mut acc_a_one = base_a.clone();
        let mut acc_a_two = base_a.clone();
        let mut acc_b_one = base_b.clone();
        let mut acc_b_two = base_b.clone();

        let proof_a_one = acc_a_one.add(&[NameSegment::new(rng), NameSegment::new(rng)], setup);
        let proof_a_two = acc_a_two.add(&[NameSegment::new(rng), NameSegment::new(rng)], setup);
        let proof_b_one = acc_b_one.add(&[NameSegment::new(rng), NameSegment::new(rng)], setup);
        let proof_b_two = acc_b_two.add(&[NameSegment::new(rng), NameSegment::new(rng)], setup);

        let mut batched_proof = BatchedProofPart::new();
        if do_batch_step[0] {
            batched_proof.add(&proof_a_one, setup);
        }
        if do_batch_step[1] {
            batched_proof.add(&proof_a_two, setup);
        }
        if do_batch_step[2] {
            batched_proof.add(&proof_b_one, setup);
        }
        if do_batch_step[3] {
            batched_proof.add(&proof_b_two, setup);
        }

        let mut verify = BatchedProofVerification::new(setup);

        if do_verify_step[0] {
            verify.add(&base_a, &acc_a_one, &proof_a_one.part).unwrap();
        }
        if do_verify_step[1] {
            verify.add(&base_a, &acc_a_two, &proof_a_two.part).unwrap();
        }
        if do_verify_step[2] {
            verify.add(&base_b, &acc_b_one, &proof_b_one.part).unwrap();
        }
        if do_verify_step[3] {
            verify.add(&base_b, &acc_b_two, &proof_b_two.part).unwrap();
        }

        let result = verify.verify(&batched_proof);

        // If we end up only batching "step 3", but also verify only step 3, then that's fine.
        // If we end up batching step 3, but verifying step 2, then that should fail.
        let matching_batch_and_verify = do_batch_step
            .into_iter()
            .zip(do_verify_step.into_iter())
            .all(|(did_batch, did_verify)| did_batch == did_verify);

        if !matching_batch_and_verify {
            prop_assert!(result.is_err());
        } else {
            match result {
                Ok(_) => (),
                Err(e) => prop_assert_eq!("no error", format!("{e}")),
            }
        }
    }

    #[proptest]
    fn padded_biguint_encoding_roundtrips(num: u64) {
        let num = BigUint::from(num);
        let bytes = BigNumDig::to_bytes_be::<8>(&num);
        let parsed = BigUint::from_bytes_be(bytes.as_ref());
        prop_assert_eq!(parsed, num);
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::BigNumDig;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use wnfs_common::utils::SnapshotBlockStore;

    #[async_std::test]
    async fn test_name_accumulator() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = &SnapshotBlockStore::default();
        let setup = &AccumulatorSetup::<BigNumDig>::from_rsa_2048(rng);
        let mut acc = NameAccumulator::empty(setup);

        acc.add(
            &[
                NameSegment::new(rng),
                NameSegment::new(rng),
                NameSegment::new(rng),
            ],
            setup,
        );

        let cid = acc.store(store).await.unwrap();
        let name = store.get_block_snapshot(&cid).await.unwrap();

        insta::assert_json_snapshot!(name);
    }
}
