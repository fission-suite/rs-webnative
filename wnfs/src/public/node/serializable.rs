use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wnfs_common::{ipld_core::cid::Cid, Metadata};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicNodeSerializable {
    #[serde(rename = "wnfs/pub/file")]
    File(PublicFileSerializable),
    #[serde(rename = "wnfs/pub/dir")]
    Dir(PublicDirectorySerializable),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicFileSerializable {
    pub version: Version,
    pub metadata: Metadata,
    pub previous: Vec<Cid>,
    pub userland: Cid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicDirectorySerializable {
    pub version: Version,
    pub metadata: Metadata,
    pub previous: Vec<Cid>,
    pub userland: BTreeMap<String, Cid>,
}
