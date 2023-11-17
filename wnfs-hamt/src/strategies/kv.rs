use crate::Node;
use anyhow::Result;
use proptest::{collection::vec, sample::SizeRange, strategy::Strategy};
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, fmt::Debug, hash::Hash, sync::Arc};
use wnfs_common::BlockStore;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub fn generate_kvs<K: Debug + Clone, V: Debug + Clone>(
    key: impl Strategy<Value = K>,
    value: impl Strategy<Value = V>,
    size: impl Into<SizeRange>,
) -> impl Strategy<Value = Vec<(K, V)>>
where
    K: Eq + Hash,
{
    vec((key, value), size).prop_map(|vec| {
        vec.into_iter()
            .collect::<HashMap<K, V>>()
            .into_iter()
            .collect()
    })
}

pub async fn node_from_kvs<K, V>(
    pairs: Vec<(K, V)>,
    store: &(impl BlockStore + Sync),
) -> Result<Arc<Node<K, V>>>
where
    K: DeserializeOwned + Serialize + Clone + Debug + AsRef<[u8]> + Send + Sync,
    V: DeserializeOwned + Serialize + Clone + Debug + Send + Sync,
{
    let mut node: Arc<Node<K, V>> = Arc::new(Node::default());
    for (k, v) in pairs {
        node.set(k, v, store).await?;
    }

    Ok(node)
}
