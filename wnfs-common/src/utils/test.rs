use super::{Arc, CondSync};
use crate::{BlockStoreError, CODEC_DAG_CBOR, CODEC_DAG_PB, CODEC_RAW};
use anyhow::Result;
use base64_serde::base64_serde_type;
use blockstore::{Blockstore, InMemoryBlockstore};
use bytes::Bytes;
use cid::Cid;
use ipld_core::ipld::Ipld;
use parking_lot::Mutex;
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

pub trait BytesToIpld: CondSync {
    fn convert(&self, bytes: &Bytes) -> Result<Ipld>;
}

type BlockHandler = Arc<dyn BytesToIpld>;

#[derive(Default)]
pub struct SnapshotBlockStore {
    inner: InMemoryBlockstore<64>,
    block_handlers: Arc<Mutex<HashMap<Cid, BlockHandler>>>,
}

base64_serde_type!(Base64Standard, base64::engine::general_purpose::STANDARD);

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockSnapshot {
    pub cid: String,
    pub value: Value,
    #[serde(with = "Base64Standard")]
    pub bytes: Bytes,
}

pub trait Sampleable {
    type Value;
    fn sample(&self, runner: &mut TestRunner) -> Self::Value;
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl SnapshotBlockStore {
    pub async fn get_block_snapshot(&self, cid: &Cid) -> Result<BlockSnapshot> {
        let bytes = self
            .get(cid)
            .await?
            .ok_or_else(|| BlockStoreError::CIDNotFound(*cid))?;
        self.handle_block(cid, &Bytes::from(bytes))
    }

    pub fn handle_block(&self, cid: &Cid, bytes: &Bytes) -> Result<BlockSnapshot> {
        let ipld = match cid.codec() {
            CODEC_DAG_CBOR => serde_ipld_dagcbor::from_slice(bytes)?,
            CODEC_RAW => match self.block_handlers.lock().get(cid) {
                Some(func) => func.convert(bytes)?,
                None => Ipld::Bytes(bytes.to_vec()),
            },
            _ => unimplemented!(),
        };

        let json_value = serde_ipld_dagjson::to_vec(&ipld)?;
        let value = serde_json::from_slice(&json_value)?;
        Ok(BlockSnapshot {
            cid: cid.to_string(),
            value,
            bytes: bytes.clone(),
        })
    }

    pub async fn get_dag_snapshot(&self, root_cid: Cid) -> Result<Vec<BlockSnapshot>> {
        let mut frontier = VecDeque::from([root_cid]);
        let mut visited = HashSet::new();
        let mut snapshots = Vec::new();

        while let Some(cid) = frontier.pop_front() {
            if !visited.insert(cid) {
                continue;
            }

            let snapshot = self.get_block_snapshot(&cid).await?;
            // Compute further references:
            match cid.codec() {
                CODEC_DAG_CBOR => serde_ipld_dagcbor::from_slice::<Ipld>(&snapshot.bytes)?
                    .references(&mut frontier),
                CODEC_DAG_PB => ipld_dagpb::links(&snapshot.bytes, &mut frontier)?,
                CODEC_RAW => {}
                other => unimplemented!("unimplemented codec: {other}"),
            };
            snapshots.push(snapshot);
        }

        Ok(snapshots)
    }

    pub fn add_block_handler(&mut self, cid: Cid, f: BlockHandler) {
        self.block_handlers.lock().insert(cid, f);
    }
}

impl Blockstore for SnapshotBlockStore {
    async fn get<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
    ) -> blockstore::Result<Option<Vec<u8>>> {
        self.inner.get(cid).await
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
        data: &[u8],
    ) -> blockstore::Result<()> {
        self.inner.put_keyed(cid, data).await
    }
}

impl<V, S> Sampleable for S
where
    S: Strategy<Value = V>,
{
    type Value = V;

    fn sample(&self, runner: &mut TestRunner) -> Self::Value {
        self.new_tree(runner)
            .expect("Couldn't generate test value")
            .current()
    }
}
