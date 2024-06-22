use crate::Node;
use anyhow::Result;
use proptest::{collection::vec, sample::SizeRange, strategy::Strategy};
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, fmt::Debug, hash::Hash};
use wnfs_common::{
    blockstore::Blockstore,
    utils::{Arc, CondSync},
    Storable,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub fn generate_kvs<K, V>(
    key: impl Strategy<Value = K>,
    value: impl Strategy<Value = V>,
    size: impl Into<SizeRange>,
) -> impl Strategy<Value = Vec<(K, V)>>
where
    K: Debug + Clone + Eq + Hash,
    V: Debug + Clone,
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
    store: &impl Blockstore,
) -> Result<Arc<Node<K, V>>>
where
    K: Storable + Clone + Debug + AsRef<[u8]> + CondSync,
    V: Storable + Clone + Debug + CondSync,
    K::Serializable: Serialize + DeserializeOwned,
    V::Serializable: Serialize + DeserializeOwned,
{
    let mut node: Arc<Node<K, V>> = Arc::new(Node::default());
    for (k, v) in pairs {
        node.set(k, v, store).await?;
    }

    Ok(node)
}
