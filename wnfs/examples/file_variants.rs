//! This example shows how to store multiple byte arrays per file, by storing
//! additional data in a file's metadata, which links out to externally encrypted data.

use anyhow::Result;
use chrono::Utc;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use wnfs::private::{
    forest::{hamt::HamtForest, traits::PrivateForest},
    PrivateFile, PrivateForestContent,
};
use wnfs_common::blockstore::InMemoryBlockstore;

#[async_std::main]
async fn main() -> Result<()> {
    // The usual in-memory testing setup for WNFS
    let store = &InMemoryBlockstore::<64>::new();
    let rng = &mut ChaCha12Rng::from_entropy();
    let forest = &mut HamtForest::new_rsa_2048(rng);

    // Create a new file (detached from any directory)
    let mut file = PrivateFile::with_content_rc(
        &forest.empty_name(),
        Utc::now(),
        b"main content".to_vec(),
        forest,
        store,
        rng,
    )
    .await?;

    // Create some content that's stored encrypted in the private forest.
    // The PrivateForestContent struct holds the keys and pointers to look it back up.
    // We use the file's name as the "path" for this content. This means anyone
    // who had write access to the file will have write access to the external content.
    let content = PrivateForestContent::new(
        file.header.get_name(),
        b"secondary content".to_vec(),
        forest,
        store,
        rng,
    )
    .await?;

    // We store the content in the file metadata.
    // This will update the `file: Arc<PrivateFile>` for us with a new reference.
    file.get_metadata_mut_rc()?
        .put("thumbnail", content.as_metadata_value()?);

    // We store the new reference in the forest.
    file.as_node().store(forest, store, rng).await?;

    // When can look up the private forest content again.
    let content_ipld = file.get_metadata().get("thumbnail").unwrap();
    let content = PrivateForestContent::from_metadata_value(content_ipld)?;

    assert_eq!(
        content.get_content(forest, store).await?,
        b"secondary content".to_vec()
    );

    Ok(())
}
