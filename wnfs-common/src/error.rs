//! Errors

use cid::Cid;
use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// Block store errors.
#[derive(Debug, Error)]
pub enum BlockStoreError {
    #[error("Maximum block size exceeded: Encountered block with {0} bytes")]
    MaximumBlockSizeExceeded(usize),

    #[error("Cannot find specified CID in block store: {0}")]
    CIDNotFound(Cid),

    #[error("CID error during blockstore operation: {0}")]
    CIDError(#[from] cid::Error),

    #[error(transparent)]
    Custom(#[from] anyhow::Error),
}
