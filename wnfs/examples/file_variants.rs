//! This example shows how to store multiple byte arrays per file, by storing
//! additional data in a file's metadata, which links out to externally encrypted data.

use anyhow::Result;
use chrono::Utc;
use rand::thread_rng;
use std::rc::Rc;
use wnfs::private::{
    forest::{hamt::HamtForest, traits::PrivateForest},
    PrivateFile, PrivateForestContent,
};
use wnfs_common::MemoryBlockStore;

#[async_std::main]
async fn main() -> Result<()> {
    // The usual in-memory testing setup for WNFS
    let store = &MemoryBlockStore::default();
    let rng = &mut thread_rng();
    let forest = &mut HamtForest::new_rsa_2048(rng);

    // Create a new file (detached from any directory)
    let mut file = Rc::new(
        PrivateFile::with_content(
            &forest.empty_name(),
            Utc::now(),
            b"main content".to_vec(),
            forest,
            store,
            rng,
        )
        .await?,
    );

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
    // This will update the `file: Rc<PrivateFile>` for us with a new reference.
    content.store_in_metadata(file.get_metadata_mut()?, "thumbnail")?;

    println!("{:#?}", file.get_metadata().get("thumbnail"));

    // We store the new reference in the forest.
    file.as_node().store(forest, store, rng).await?;

    // When can look up the private forest content again.
    let content = PrivateForestContent::load_from_metadata(file.get_metadata(), "thumbnail")?;

    assert_eq!(
        content.get_content(forest, store).await?,
        b"secondary content".to_vec()
    );

    Ok(())
}
