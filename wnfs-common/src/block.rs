use bytes::Bytes;
use cid::{multihash::Multihash, Cid};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The value representing the DAG-JSON codec.
///
/// - <https://ipld.io/docs/codecs/#known-codecs>
/// - <https://github.com/multiformats/multicodec/blob/master/table.csv>
pub const CODEC_DAG_JSON: u64 = 0x0129;

/// The value representing the DAG-CBOR codec.
///
/// - <https://ipld.io/docs/codecs/#known-codecs>
/// - <https://github.com/multiformats/multicodec/blob/master/table.csv>
pub const CODEC_DAG_CBOR: u64 = 0x71;

/// The value representing the DAG-Protobuf codec.
///
/// - <https://ipld.io/docs/codecs/#known-codecs>
/// - <https://github.com/multiformats/multicodec/blob/master/table.csv>
pub const CODEC_DAG_PB: u64 = 0x70;

/// The value representing the raw codec.
///
/// - <https://ipld.io/docs/codecs/#known-codecs>
/// - <https://github.com/multiformats/multicodec/blob/master/table.csv>
pub const CODEC_RAW: u64 = 0x55;

const MULTICODEC_BLAKE3: u64 = 0x1e;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

pub struct Blake3Block {
    cid: Cid,
    bytes: Bytes,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl Blake3Block {
    pub fn new(codec: u64, bytes: impl Into<Bytes>) -> Self {
        let bytes: Bytes = bytes.into();

        // Compute the Blake3 hash of the bytes
        let hash = blake3::hash(&bytes);

        let multihash =
            Multihash::wrap(MULTICODEC_BLAKE3, hash.as_bytes()).expect("constant hash size");

        // Represent the hash as a V1 CID
        let cid = Cid::new_v1(codec, multihash);

        Self { cid, bytes }
    }
}

impl blockstore::block::Block<64> for Blake3Block {
    fn cid(&self) -> Result<Cid, blockstore::block::CidError> {
        Ok(self.cid)
    }

    fn data(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
