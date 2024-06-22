use crate::{
    error::FsError,
    private::{
        forest::{hamt::HamtForest, traits::PrivateForest},
        AccessKey, PrivateDirectory, PrivateNode,
    },
    public::PublicDirectory,
    WNFS_VERSION,
};
use anyhow::{bail, Result};
#[cfg(test)]
use chrono::TimeZone;
use chrono::{DateTime, Utc};
use rand_chacha::ChaCha12Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wnfs_common::{
    blockstore::{block::Block as _, Blockstore},
    ipld_core::cid::Cid,
    utils::{Arc, CondSend},
    Blake3Block, BlockStoreError, Metadata, Storable, CODEC_DAG_CBOR,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RootTree<B: Blockstore> {
    pub store: B,
    pub forest: Arc<HamtForest>,
    pub public_root: Arc<PublicDirectory>,
    pub exchange_root: Arc<PublicDirectory>,
    pub private_map: BTreeMap<Vec<String>, Arc<PrivateDirectory>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootTreeSerializable {
    pub public: Cid,
    pub exchange: Cid,
    pub forest: Cid,
    pub version: Version,
}

/// A directory from a particular WNFS partition
pub enum Partition {
    Public(Arc<PublicDirectory>),
    Exchange(Arc<PublicDirectory>),
    Private(Vec<String>, Arc<PrivateDirectory>),
    // TODO(matheus23): Support mounting only singular files
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<B: Blockstore> RootTree<B> {
    pub fn empty_with(store: B, rng: &mut impl CryptoRngCore, time: DateTime<Utc>) -> RootTree<B> {
        Self {
            store,
            forest: Arc::new(HamtForest::new_rsa_2048(rng)),
            public_root: PublicDirectory::new_rc(time),
            exchange_root: PublicDirectory::new_rc(time),
            private_map: BTreeMap::new(),
        }
    }

    pub fn empty(store: B) -> RootTree<B> {
        Self::empty_with(store, &mut ChaCha12Rng::from_entropy(), Utc::now())
    }

    pub async fn new(
        forest: Arc<HamtForest>,
        store: B,
        time: DateTime<Utc>,
        private_map: BTreeMap<Vec<String>, Arc<PrivateDirectory>>,
    ) -> RootTree<B> {
        Self {
            store,
            forest,
            public_root: PublicDirectory::new_rc(time),
            exchange_root: PublicDirectory::new_rc(time),
            private_map,
        }
    }

    pub async fn create_private_root(&mut self, path: &[String]) -> Result<AccessKey> {
        self.create_private_root_with(path, Utc::now(), &mut ChaCha12Rng::from_entropy())
            .await
    }

    pub async fn create_private_root_with(
        &mut self,
        path: &[String],
        time: DateTime<Utc>,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<AccessKey> {
        match path.first().map(|p| p.as_str()) {
            Some("private") => {}
            Some("public") | Some("exchange") => bail!(FsError::DirectoryAlreadyExists),
            Some(_) => bail!(FsError::InvalidPath),
            None => bail!(FsError::InvalidPath),
        };

        if self.private_map.contains_key(path) {
            bail!(FsError::DirectoryAlreadyExists)
        }

        let root = PrivateDirectory::new_and_store(
            &self.forest.empty_name(),
            time,
            &mut self.forest,
            &self.store,
            rng,
        )
        .await?;

        let access_key = root
            .as_node()
            .store(&mut self.forest, &self.store, rng)
            .await?;

        self.private_map.insert(path.to_vec(), root);

        Ok(access_key)
    }

    pub async fn load_private_root(
        &mut self,
        path: &[String],
        access_key: &AccessKey,
    ) -> Result<()> {
        let dir = PrivateNode::load(access_key, &self.forest, &self.store, None)
            .await?
            .as_dir()?;

        self.private_map.insert(path.to_vec(), dir);

        Ok(())
    }

    pub async fn store_private_root(&mut self, path: &[String]) -> Result<AccessKey> {
        self.store_private_root_with(path, &mut ChaCha12Rng::from_entropy())
            .await
    }

    pub async fn store_private_root_with(
        &mut self,
        path: &[String],
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<AccessKey> {
        let mut forest = Arc::clone(&self.forest);

        let (path, Partition::Private(_, dir)) = self.get_partition(path)? else {
            bail!("Path is not in the private partition");
        };

        let node = dir
            .get_node(path, true, &forest, &self.store)
            .await?
            .ok_or(FsError::NotFound)?;
        let access_key = node.store(&mut forest, &self.store, rng).await?;

        Ok(access_key)
    }

    pub fn get_partition<'p>(&self, path: &'p [String]) -> Result<(&'p [String], Partition)> {
        let Some(first) = path.first() else {
            bail!(FsError::InvalidPath)
        };

        match first.as_str() {
            "public" => Ok((&path[1..], Partition::Public(Arc::clone(&self.public_root)))),
            "exchange" => Ok((
                &path[1..],
                Partition::Exchange(Arc::clone(&self.exchange_root)),
            )),
            _ => {
                let (prefix, root) = self
                    .lookup_private_root(path)
                    .ok_or(FsError::PartitionNotFound)?;

                Ok((&path[prefix.len()..], Partition::Private(prefix, root)))
            }
        }
    }

    pub fn save_partition(&mut self, partition: Partition) {
        match partition {
            Partition::Public(public_root) => self.public_root = public_root,
            Partition::Exchange(exchange_root) => self.exchange_root = exchange_root,
            Partition::Private(prefix, private_root) => {
                self.private_map.insert(prefix, private_root);
            }
        }
    }

    fn find_private_root(&self, path: &[String]) -> Option<Vec<String>> {
        for i in 0..=path.len() {
            let prefix = &path[..i];
            let item = self.private_map.get(prefix);
            if item.is_some() {
                return Some(prefix.to_vec());
            }
        }
        None
    }

    pub fn lookup_private_root(
        &self,
        path: &[String],
    ) -> Option<(Vec<String>, Arc<PrivateDirectory>)> {
        if let Some(prefix) = self.find_private_root(path) {
            if let Some(item) = self.private_map.get(&prefix) {
                return Some((prefix, Arc::clone(item)));
            }
        }
        None
    }

    pub fn lookup_private_root_mut(
        &mut self,
        path: &[String],
    ) -> Option<(Vec<String>, &mut Arc<PrivateDirectory>)> {
        if let Some(prefix) = self.find_private_root(path) {
            if let Some(item) = self.private_map.get_mut(&prefix) {
                return Some((prefix, item));
            }
        }
        None
    }

    pub async fn ls(&self, path: &[String]) -> Result<Vec<(String, Metadata)>> {
        match self.get_partition(path)? {
            (path, Partition::Public(public_root)) => public_root.ls(path, &self.store).await,
            (path, Partition::Exchange(exchange_root)) => exchange_root.ls(path, &self.store).await,
            (path, Partition::Private(_, private_root)) => {
                private_root.ls(path, true, &self.forest, &self.store).await
            }
        }
    }

    pub async fn read(&self, path: &[String]) -> Result<Vec<u8>> {
        match self.get_partition(path)? {
            (path, Partition::Public(public_root)) => public_root.read(path, &self.store).await,
            (path, Partition::Exchange(exchange_root)) => {
                exchange_root.read(path, &self.store).await
            }
            (path, Partition::Private(_, private_root)) => {
                private_root
                    .read(path, true, &self.forest, &self.store)
                    .await
            }
        }
    }

    pub async fn write(&mut self, path: &[String], content: Vec<u8>) -> Result<()> {
        self.write_with(path, content, Utc::now(), &mut ChaCha12Rng::from_entropy())
            .await
    }

    pub async fn write_with(
        &mut self,
        path: &[String],
        content: Vec<u8>,
        time: DateTime<Utc>,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let forest = &mut Arc::clone(&self.forest);
        let partition = match self.get_partition(path)? {
            (path, Partition::Public(mut public_root)) => {
                public_root.write(path, content, time, &self.store).await?;
                Partition::Public(public_root)
            }
            (path, Partition::Exchange(mut exchange_root)) => {
                exchange_root
                    .write(path, content, time, &self.store)
                    .await?;
                Partition::Exchange(exchange_root)
            }
            (path, Partition::Private(prefix, mut private_root)) => {
                private_root
                    .write(path, true, time, content, forest, &self.store, rng)
                    .await?;
                Partition::Private(prefix, private_root)
            }
        };

        self.forest = Arc::clone(forest);
        self.save_partition(partition);

        Ok(())
    }

    pub async fn mkdir(&mut self, path: &[String]) -> Result<()> {
        self.mkdir_with(path, Utc::now(), &mut ChaCha12Rng::from_entropy())
            .await
    }

    pub async fn mkdir_with(
        &mut self,
        path: &[String],
        time: DateTime<Utc>,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let forest = &mut Arc::clone(&self.forest);
        let partition = match self.get_partition(path)? {
            (path, Partition::Public(mut public_root)) => {
                public_root.mkdir(path, time, &self.store).await?;
                Partition::Public(public_root)
            }
            (path, Partition::Exchange(mut exchange_root)) => {
                exchange_root.mkdir(path, time, &self.store).await?;
                Partition::Exchange(exchange_root)
            }
            (path, Partition::Private(prefix, mut private_root)) => {
                private_root
                    .mkdir(path, true, time, forest, &self.store, rng)
                    .await?;
                Partition::Private(prefix, private_root)
            }
        };

        self.forest = Arc::clone(forest);
        self.save_partition(partition);

        Ok(())
    }

    pub async fn rm(&mut self, path: &[String]) -> Result<()> {
        let forest = &mut Arc::clone(&self.forest);
        let partition = match self.get_partition(path)? {
            (path, Partition::Public(mut public_root)) => {
                public_root.rm(path, &self.store).await?;
                Partition::Public(public_root)
            }
            (path, Partition::Exchange(mut exchange_root)) => {
                exchange_root.rm(path, &self.store).await?;
                Partition::Exchange(exchange_root)
            }
            (path, Partition::Private(prefix, mut private_root)) => {
                private_root.rm(path, true, forest, &self.store).await?;
                Partition::Private(prefix, private_root)
            }
        };

        self.forest = Arc::clone(forest);
        self.save_partition(partition);

        Ok(())
    }

    pub async fn basic_mv(&mut self, path_from: &[String], path_to: &[String]) -> Result<()> {
        self.basic_mv_with(
            path_from,
            path_to,
            Utc::now(),
            &mut ChaCha12Rng::from_entropy(),
        )
        .await
    }

    pub async fn basic_mv_with(
        &mut self,
        path_from: &[String],
        path_to: &[String],
        time: DateTime<Utc>,
        rng: &mut (impl CryptoRngCore + CondSend),
    ) -> Result<()> {
        let forest = &mut Arc::clone(&self.forest);
        let partition = match (self.get_partition(path_from)?, self.get_partition(path_to)?) {
            ((path_from, Partition::Public(mut public_root)), (path_to, Partition::Public(_))) => {
                public_root
                    .basic_mv(path_from, path_to, time, &self.store)
                    .await?;
                Partition::Public(public_root)
            }
            (
                (path_from, Partition::Exchange(mut exchange_root)),
                (path_to, Partition::Exchange(_)),
            ) => {
                exchange_root
                    .basic_mv(path_from, path_to, time, &self.store)
                    .await?;
                Partition::Public(exchange_root)
            }
            (
                (path_from, Partition::Private(prefix_from, mut private_root)),
                (path_to, Partition::Private(prefix_to, _)),
            ) if prefix_from == prefix_to => {
                private_root
                    .basic_mv(path_from, path_to, true, time, forest, &self.store, rng)
                    .await?;
                Partition::Private(prefix_from, private_root)
            }
            _ => bail!("Moving files or directories across partitions is not yet supported."),
        };

        self.forest = Arc::clone(forest);
        self.save_partition(partition);

        Ok(())
    }

    pub async fn store(&mut self) -> Result<Cid> {
        self.store_with(&mut ChaCha12Rng::from_entropy()).await
    }

    pub async fn store_with(&mut self, rng: &mut (impl CryptoRngCore + CondSend)) -> Result<Cid> {
        for (_, root) in self.private_map.iter() {
            root.store(&mut self.forest, &self.store, rng).await?;
        }

        let serializable = RootTreeSerializable {
            public: self.public_root.store(&self.store).await?,
            exchange: self.exchange_root.store(&self.store).await?,
            forest: self.forest.store(&self.store).await?,
            version: WNFS_VERSION,
        };

        let block = Blake3Block::new(CODEC_DAG_CBOR, serde_ipld_dagcbor::to_vec(&serializable)?);
        let cid = block.cid()?;
        self.store.put(block).await?;

        Ok(cid)
    }

    pub async fn load(cid: &Cid, store: B) -> Result<RootTree<B>> {
        let deserialized: RootTreeSerializable = serde_ipld_dagcbor::from_slice(
            &store
                .get(cid)
                .await?
                .ok_or_else(|| BlockStoreError::CIDNotFound(*cid))?,
        )?;
        let forest = Arc::new(HamtForest::load(&deserialized.forest, &store).await?);
        let public_root = Arc::new(PublicDirectory::load(&deserialized.public, &store).await?);
        let exchange_root = Arc::new(PublicDirectory::load(&deserialized.exchange, &store).await?);

        Ok(Self {
            store,
            forest,
            public_root,
            exchange_root,
            private_map: BTreeMap::new(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[async_std::test]
    async fn test_roots_read_write() {
        let store = InMemoryBlockstore::<64>::new();
        let mut root_tree = RootTree::empty(store);
        root_tree
            .create_private_root(&["private".into()])
            .await
            .unwrap();

        // Public root

        root_tree
            .write(
                &["public".into(), "test".into(), "file".into()],
                b"hello world".to_vec(),
            )
            .await
            .unwrap();

        let content = root_tree
            .read(&["public".into(), "test".into(), "file".into()])
            .await
            .unwrap();

        assert_eq!(content, b"hello world".to_vec());

        // Exchange root

        root_tree
            .write(
                &["exchange".into(), "test".into(), "file".into()],
                b"hello world".to_vec(),
            )
            .await
            .unwrap();

        let content = root_tree
            .read(&["exchange".into(), "test".into(), "file".into()])
            .await
            .unwrap();

        assert_eq!(content, b"hello world".to_vec());

        // Private root

        root_tree
            .write(
                &["private".into(), "test".into(), "file".into()],
                b"hello world".to_vec(),
            )
            .await
            .unwrap();

        let content = root_tree
            .read(&["private".into(), "test".into(), "file".into()])
            .await
            .unwrap();

        assert_eq!(content, b"hello world".to_vec());
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::utils;
    use wnfs_common::utils::SnapshotBlockStore;

    #[async_std::test]
    async fn test_root_filesystems() {
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let store = SnapshotBlockStore::default();
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let paths = [
            // (["public".into()], vec!["text.txt".into()]),
            // (["exchange".into()], vec!["music".into(), "jazz".into()]),
            (vec!["private".into(), "videos".into()]),
        ];

        let mut root_tree = RootTree::empty_with(store, rng, time);
        root_tree
            .create_private_root_with(&["private".into()], time, rng)
            .await
            .unwrap();

        println!("{:#?}", root_tree.private_map);

        for path in paths.iter() {
            root_tree
                .write_with(path, b"hello world".to_vec(), time, rng)
                .await
                .unwrap();
        }

        let root_cid = root_tree.store_with(rng).await.unwrap();
        let forest = &mut Arc::clone(&root_tree.forest);
        let (_, root_dir) = root_tree.lookup_private_root(&["private".into()]).unwrap();

        utils::walk_dir(&mut root_tree.store, forest, &root_dir, rng)
            .await
            .unwrap();

        let values = root_tree.store.get_dag_snapshot(root_cid).await.unwrap();

        insta::assert_json_snapshot!(values);
    }
}
