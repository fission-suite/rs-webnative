//! This example shows how to add a directory to a private forest (a HAMT) where encrypted ciphertexts are stored.
//! It also shows how to retrieve encrypted nodes from the forest using `AccessKey`s.

use anyhow::Result;
use chrono::Utc;
use rand_chacha::ChaCha12Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use wnfs::{
    nameaccumulator::AccumulatorSetup,
    private::{
        forest::{hamt::HamtForest, traits::PrivateForest},
        AccessKey, PrivateDirectory, PrivateNode,
    },
};
use wnfs_common::{
    blockstore::{Blockstore, InMemoryBlockstore},
    ipld_core::cid::Cid,
    utils::CondSend,
    Storable,
};

#[async_std::main]
async fn main() -> Result<()> {
    // Create an in-memory block store.
    let store = &InMemoryBlockstore::<64>::new();

    // Create a random number generator the private filesystem can use.
    let rng = &mut ChaCha12Rng::from_entropy();

    // Create a new private forest and get the cid to it.
    let (forest_cid, access_key) = create_forest_and_add_directory(store, rng).await?;

    // Deserialize private forest from the blockstore.
    let forest = HamtForest::load(&forest_cid, store).await?;

    // Fetch and decrypt a directory from the private forest using provided private ref.
    let dir = PrivateNode::load(&access_key, &forest, store, None).await?;

    // Print the directory.
    println!("{:#?}", dir);

    Ok(())
}

async fn create_forest_and_add_directory(
    store: &impl Blockstore,
    rng: &mut (impl CryptoRngCore + CondSend),
) -> Result<(Cid, AccessKey)> {
    // Do a trusted setup for WNFS' name accumulators
    let setup = AccumulatorSetup::trusted(rng);

    // Create the private forest (a HAMT), a map-like structure where file and directory ciphertexts are stored.
    let forest = &mut HamtForest::new_rc(setup);

    // Create a new directory.
    let dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

    // Add a /pictures/cats subdirectory.
    dir.mkdir(
        &["pictures".into(), "cats".into()],
        true,
        Utc::now(),
        forest,
        store,
        rng,
    )
    .await?;

    // Access key contains the materials for fetching and decrypting the directory node in the private forest.
    let access_key = dir.as_node().store(forest, store, rng).await?;

    // Persist encoded private forest to the block store.
    let forest_cid = forest.store(store).await?;

    Ok((forest_cid, access_key))
}
