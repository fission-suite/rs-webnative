//! This example shows how to separate file system hierarchy data from file metadata at write-time,
//! storing data about hierarchy in a block store that is kept 'hot' so reads can be made fast,
//! and storing actual file content in a block store that is meant to be 'cold' as in, reads only
//! work with high latency.

use anyhow::Result;
use chrono::Utc;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use wnfs::private::{
    forest::{hamt::HamtForest, traits::PrivateForest},
    PrivateDirectory, PrivateNode,
};
use wnfs_common::{
    blockstore::{self, Blockstore, InMemoryBlockstore},
    ipld_core::cid::CidGeneric,
    Storable,
};

#[async_std::main]
async fn main() -> Result<()> {
    // Create a block store that holds all 'hot' data:
    let hot_store = InMemoryBlockstore::<64>::new();

    // Create a block store that holds all 'cold' data.
    // In reality this would probably be something that's accessible
    // with very high latency, but with a lot of bandwidth & storage.
    let cold_store = InMemoryBlockstore::<64>::new();

    // Create a random number generator for randomized encryption.
    let rng = &mut ChaCha12Rng::from_entropy();

    // Create a new private forest.
    // This represents your whole private file system, but hides any internal structure.
    let forest = &mut HamtForest::new_rsa_2048_rc(rng);

    // Create a new private directory
    let mut directory = PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);

    let file_path = ["datasets".into(), "recordings".into(), "monday.mp4".into()];
    let video = b"This isn't actually a video. But it could be!";

    // When 'opening' a file, we use the hot store to fetch any directories
    // on the path we may have already created before.
    let file = directory
        .open_file_mut(&file_path, true, Utc::now(), forest, &hot_store, rng)
        .await?;

    // `set_content` actually writes the data blocks to the blockstore in chunks,
    // so for this we provide the `cold_store`.
    file.set_content(&video[..], Utc::now(), forest, &cold_store, rng)
        .await?;

    // When storing the hierarchy data blocks, we use the `hot_store`:
    let access_key = directory.as_node().store(forest, &hot_store, rng).await?;

    // Same thing for the forest. Doing this will give us a single root CID
    // for all of the data, but parts separated into `hot_store` and `cold_store`:
    let private_root_cid = forest.store(&hot_store).await?;

    // We can now read out our data back:
    let forest = HamtForest::load(&private_root_cid, &hot_store).await?;

    let directory = PrivateNode::load(&access_key, &forest, &hot_store, None)
        .await?
        .as_dir()?;

    // Reading the file's data will fail when only provided the hot store:
    assert!(directory
        .read(&file_path, true, &forest, &hot_store)
        .await
        .is_err());

    // What we can do instead is construct a 'tiered blockstore' that first
    // tries to fetch from the hot store and if that doesn't work, tries the cold one:
    let tiered_store = TieredBlockStore {
        hot: hot_store,
        cold: cold_store,
    };

    let result = directory
        .read(&file_path, true, &forest, &tiered_store)
        .await?;

    println!("{}", String::from_utf8(result.clone())?);

    assert_eq!(result, video.to_vec());

    Ok(())
}

struct TieredBlockStore<H: Blockstore, C: Blockstore> {
    hot: H,
    cold: C,
}

impl<H: Blockstore, C: Blockstore> Blockstore for TieredBlockStore<H, C> {
    async fn get<const S: usize>(
        &self,
        cid: &CidGeneric<S>,
    ) -> Result<Option<Vec<u8>>, blockstore::Error> {
        if self.hot.has(cid).await? {
            self.hot.get(cid).await
        } else {
            self.cold.get(cid).await
        }
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &CidGeneric<S>,
        data: &[u8],
    ) -> Result<(), blockstore::Error> {
        self.hot.put_keyed(cid, data).await
    }
}
