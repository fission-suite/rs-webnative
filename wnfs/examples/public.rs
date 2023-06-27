//! This example shows how the different operations you can perform under a public filesystem.
//! More importantly, it shows the immutable nature of the filesystem.

use anyhow::Result;
use chrono::Utc;
use libipld_core::cid::Cid;
use std::rc::Rc;
use wnfs::public::PublicDirectory;
use wnfs_common::MemoryBlockStore;

#[async_std::main]
async fn main() -> Result<()> {
    // Create an in-memory blockstore.
    let store = MemoryBlockStore::default();

    // Create a new directory.
    let root_dir = &mut Rc::new(PublicDirectory::new(Utc::now()));

    // Add a /pictures/cats subdirectory.
    root_dir
        .mkdir(&["pictures".into(), "cats".into()], Utc::now(), &store)
        .await?;

    // Add a file to /pictures/dogs directory.
    root_dir
        .write(
            &["pictures".into(), "dogs".into(), "billie.jpeg".into()],
            Cid::default(),
            Utc::now(),
            &store,
        )
        .await?;

    // Delete /pictures/cats directory.
    root_dir
        .rm(&["pictures".into(), "cats".into()], &store)
        .await?;

    // List all the children of /pictures directory.
    let result = root_dir.ls(&["pictures".into()], &store).await.unwrap();

    // Print the result.
    println!("Files in /pictures: {result:#?}");

    Ok(())
}
