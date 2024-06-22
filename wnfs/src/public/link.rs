//! Public node link.

use super::{PublicDirectory, PublicFile, PublicNode};
use anyhow::Result;
use wnfs_common::{blockstore::Blockstore, ipld_core::cid::Cid, utils::Arc, Link};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// A link to another node in the WNFS public file system. It can be held as a simple serialised CID or as a reference to the node itself.
///
/// The public file system is a DAG so we don't have to worry bout cyclic references.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicLink(Link<PublicNode>);

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl PublicLink {
    /// Creates a new `Link` that starts out as a Cid.
    #[inline]
    pub fn from_cid(cid: Cid) -> Self {
        Self(Link::from_cid(cid))
    }

    /// Create a new link to a node.
    #[inline]
    pub fn new(node: PublicNode) -> Self {
        Self(Link::from(node))
    }

    /// Creates a link to a directory node.
    #[inline]
    pub fn with_dir(dir: PublicDirectory) -> Self {
        Self(Link::from(PublicNode::Dir(Arc::new(dir))))
    }

    /// Creates a link to a directory node.
    #[inline]
    pub fn with_rc_dir(dir: Arc<PublicDirectory>) -> Self {
        Self(Link::from(PublicNode::Dir(dir)))
    }

    /// Creates a link to a file node.
    #[inline]
    pub fn with_file(file: PublicFile) -> Self {
        Self(Link::from(PublicNode::File(Arc::new(file))))
    }

    /// Gets the Cid stored in type. It attempts to get it from the store if it is not present in type.
    #[inline]
    pub async fn resolve_cid(&self, store: &impl Blockstore) -> Result<Cid> {
        self.0.resolve_cid(store).await
    }

    /// Gets the value stored in link. It attempts to get it from the store if it is not present in link.
    #[inline]
    pub async fn resolve_value(&self, store: &impl Blockstore) -> Result<&PublicNode> {
        self.0.resolve_value(store).await
    }

    /// Gets mut value stored in link. It attempts to get it from the store if it is not present in link.
    #[inline]
    pub async fn resolve_value_mut(&mut self, store: &impl Blockstore) -> Result<&mut PublicNode> {
        self.0.resolve_value_mut(store).await
    }

    /// Gets an owned value from type. It attempts to it get from the store if it is not present in type.
    #[inline]
    pub async fn resolve_owned_value(self, store: &impl Blockstore) -> Result<PublicNode> {
        self.0.resolve_owned_value(store).await
    }

    /// Compares two links for equality. Attempts to get them from store if they are not already cached.
    #[inline]
    pub async fn deep_eq(&self, other: &Self, store: &impl Blockstore) -> Result<bool> {
        self.0.deep_eq(&other.0, store).await
    }
}

impl From<PublicNode> for PublicLink {
    #[inline]
    fn from(value: PublicNode) -> Self {
        Self(Link::from(value))
    }
}
