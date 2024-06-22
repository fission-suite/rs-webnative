//! This crate contains the common types and functions used by the WNFS crates.
pub mod block;
mod error;
mod link;
mod metadata;
mod pathnodes;
mod storable;
pub mod utils;

pub use block::*;
pub use error::*;
pub use link::*;
pub use metadata::*;
pub use pathnodes::*;
pub use storable::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub const HASH_BYTE_SIZE: usize = 32;
pub const MAX_BLOCK_SIZE: usize = usize::pow(2, 18);

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// The general size of digests in WNFS.
pub type HashOutput = [u8; HASH_BYTE_SIZE];

//--------------------------------------------------------------------------------------------------
// Re-exports
//--------------------------------------------------------------------------------------------------

pub mod ipld_core {
    pub use ipld_core::*;
}

pub mod blockstore {
    pub use blockstore::*;
}
