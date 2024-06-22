use crate::private::{
    forest::{hamt::HamtForest, traits::PrivateForest},
    FileContent, PrivateDirectory, PrivateForestContent, PrivateNode, PrivateRef, SnapshotKey,
    TemporalKey,
};
use anyhow::Result;
use bytes::Bytes;
use rand_core::CryptoRngCore;
use wnfs_common::{
    ipld_core::ipld::Ipld,
    utils::{Arc, BytesToIpld, CondSend, SnapshotBlockStore},
};
use wnfs_nameaccumulator::Name;

struct EncryptedBlockHandler {
    snapshot_key: SnapshotKey,
}

impl BytesToIpld for EncryptedBlockHandler {
    fn convert(&self, bytes: &Bytes) -> Result<Ipld> {
        Ok(serde_ipld_dagcbor::from_slice(
            &self.snapshot_key.decrypt(bytes.as_ref())?,
        )?)
    }
}

struct KeyWrappedBlockHandler {
    temporal_key: TemporalKey,
}

impl BytesToIpld for KeyWrappedBlockHandler {
    fn convert(&self, bytes: &Bytes) -> Result<Ipld> {
        Ok(serde_ipld_dagcbor::from_slice(
            &self.temporal_key.key_wrap_decrypt(bytes.as_ref())?,
        )?)
    }
}

struct FileShardHandler {
    key: SnapshotKey,
}

impl BytesToIpld for FileShardHandler {
    fn convert(&self, bytes: &Bytes) -> Result<Ipld> {
        Ok(Ipld::Bytes(self.key.decrypt(bytes.as_ref())?))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn walk_dir(
    store: &mut SnapshotBlockStore,
    forest: &mut Arc<HamtForest>,
    root_dir: &Arc<PrivateDirectory>,
    rng: &mut (impl CryptoRngCore + CondSend),
) -> Result<()> {
    let mut stack = vec![root_dir.clone()];
    while let Some(dir) = stack.pop() {
        let private_ref: PrivateRef = dir.store(forest, store, rng).await?;
        let temporal_key = private_ref.temporal_key;
        let snapshot_key = temporal_key.derive_snapshot_key();
        store.add_block_handler(
            private_ref.content_cid,
            Arc::new(EncryptedBlockHandler { snapshot_key }),
        );
        store.add_block_handler(
            dir.header.store(store, forest).await?,
            Arc::new(KeyWrappedBlockHandler { temporal_key }),
        );

        let entries = dir.ls(&[], true, forest, store).await?;
        for (name, _) in entries.iter() {
            let node = dir.lookup_node(name, true, forest, store).await?;
            match node.as_ref() {
                Some(PrivateNode::Dir(dir)) => {
                    stack.push(dir.clone());
                }
                Some(PrivateNode::File(file)) => {
                    let private_ref: PrivateRef = file.store(forest, store, rng).await?;
                    let temporal_key = private_ref.temporal_key;
                    let snapshot_key = temporal_key.derive_snapshot_key();
                    store.add_block_handler(
                        private_ref.content_cid,
                        Arc::new(EncryptedBlockHandler { snapshot_key }),
                    );
                    store.add_block_handler(
                        file.header.store(store, forest).await?,
                        Arc::new(KeyWrappedBlockHandler { temporal_key }),
                    );
                    if let FileContent::External(PrivateForestContent {
                        key,
                        block_count,
                        base_name,
                        ..
                    }) = &file.content.content
                    {
                        for name in PrivateForestContent::generate_shard_labels(
                            key,
                            0,
                            *block_count,
                            &Name::new(base_name.clone(), []),
                        ) {
                            match forest.get_encrypted(&name, store).await? {
                                Some(cids) => {
                                    let key = key.clone();
                                    store.add_block_handler(
                                        *cids.first().unwrap(),
                                        Arc::new(FileShardHandler { key }),
                                    )
                                }
                                None => unreachable!(),
                            };
                        }
                    }
                }
                None => unreachable!(),
            }
        }
    }

    Ok(())
}
