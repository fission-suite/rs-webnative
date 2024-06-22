use crate::{utils::CondSync, Storable};
use anyhow::Result;
use async_once_cell::OnceCell;
use blockstore::Blockstore;
use cid::Cid;
use std::fmt::{self, Debug, Formatter};

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// A data structure that represents a link in the IPLD graph. Basically it is a "link" to some content addressable value of `T`.
///
/// It supports representing the "link" with a Cid or the deserialized value itself.
///
/// Link needs a `Blockstore` to be able to resolve Cids to corresponding values of `T` and vice versa.
pub enum Link<T> {
    /// A variant of `Link` that started out as a `Cid`.
    /// If the decoded value is resolved using `resolve_value`, then the `value_cache` gets populated and
    /// further calls to `resolve_value` will just return from that cache.
    Encoded { cid: Cid, value_cache: OnceCell<T> },
    /// A variant of `Link` that started out as a deserialized value `T`.
    /// If the cid is resolved using `resolve_cid`, then `T`'s `.persisted_as` from the
    /// `Storable` trait is called and that `OnceCell<Cid>` is populated, preventing
    /// further calls to `resolve_cid` from duplicating work.
    Decoded { value: T },
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<T: Storable + CondSync> Link<T> {
    /// Creates a new `Link` that starts out as a Cid.
    pub fn from_cid(cid: Cid) -> Self {
        Self::Encoded {
            cid,
            value_cache: OnceCell::new(),
        }
    }

    /// Gets the Cid stored in type. It attempts to get it from the store if it is not present in type.
    pub async fn resolve_cid(&self, store: &impl Blockstore) -> Result<Cid> {
        match self {
            Self::Encoded { cid, .. } => Ok(*cid),
            Self::Decoded { value } => value.store(store).await,
        }
    }

    /// Gets the value stored in link. It attempts to get it from the store if it is not present in link.
    pub async fn resolve_value(&self, store: &impl Blockstore) -> Result<&T> {
        match self {
            Self::Encoded { cid, value_cache } => {
                value_cache.get_or_try_init(T::load(cid, store)).await
            }
            Self::Decoded { value, .. } => Ok(value),
        }
    }

    /// Gets mut value stored in link. It attempts to get it from the store if it is not present in link.
    pub async fn resolve_value_mut(&mut self, store: &impl Blockstore) -> Result<&mut T> {
        match self {
            Self::Encoded { cid, value_cache } => {
                let value = match value_cache.take() {
                    Some(v) => v,
                    None => T::load(cid, store).await?,
                };

                *self = Self::Decoded { value };

                Ok(match self {
                    Self::Decoded { value } => value,
                    _ => unreachable!(),
                })
            }
            Self::Decoded { value, .. } => Ok(value),
        }
    }

    /// Gets the cid data stored in type.
    ///
    /// NOTE: This does not attempt to get it from the store if it does not exist..
    pub fn get_cid(&self) -> Option<&Cid> {
        match self {
            Self::Encoded { cid, .. } => Some(cid),
            Self::Decoded { value } => value.persisted_as().and_then(OnceCell::get),
        }
    }

    /// Gets the value stored in type.
    ///
    /// NOTE: This does not attempt to get it from the store if it does not exist.
    pub fn get_value(&self) -> Option<&T> {
        match self {
            Self::Encoded { value_cache, .. } => value_cache.get(),
            Self::Decoded { value } => Some(value),
        }
    }

    /// Gets an owned value from type. It attempts to it get from the store if it is not present in type.
    pub async fn resolve_owned_value(self, store: &impl Blockstore) -> Result<T>
    where
        T: Storable,
    {
        match self {
            Self::Encoded { cid, value_cache } => match value_cache.into_inner() {
                Some(cached) => Ok(cached),
                None => Ok(T::load(&cid, store).await?),
            },
            Self::Decoded { value, .. } => Ok(value),
        }
    }

    /// Checks if there is a Cid cached in link.
    pub fn has_cid(&self) -> bool {
        self.get_cid().is_some()
    }

    /// Checks if there is a value stored in link.
    pub fn has_value(&self) -> bool {
        match self {
            Self::Encoded { value_cache, .. } => value_cache.get().is_some(),
            _ => true,
        }
    }

    /// Compares two links for equality. Attempts to get them from store if they are not already cached.
    pub async fn deep_eq(&self, other: &Link<T>, store: &impl Blockstore) -> Result<bool>
    where
        T: PartialEq + Storable,
    {
        if self == other {
            return Ok(true);
        }

        Ok(self.resolve_cid(store).await? == other.resolve_cid(store).await?)
    }
}

impl<T: Storable> From<T> for Link<T> {
    fn from(value: T) -> Self {
        Self::Decoded { value }
    }
}

impl<T> Clone for Link<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Encoded { cid, value_cache } => Self::Encoded {
                cid: *cid,
                value_cache: value_cache
                    .get()
                    .cloned()
                    .map(OnceCell::new_with)
                    .unwrap_or_default(),
            },
            Self::Decoded { value } => Self::Decoded {
                value: value.clone(),
            },
        }
    }
}

impl<T: Storable + CondSync> PartialEq for Link<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Encoded { cid, .. }, Self::Encoded { cid: cid2, .. }) => cid == cid2,
            (Self::Decoded { value, .. }, Self::Decoded { value: value2, .. }) => value == value2,
            (Self::Encoded { cid, .. }, Self::Decoded { value: value2, .. }) => {
                if let Some(cid2) = other.get_cid() {
                    cid == cid2
                } else if let Some(value) = self.get_value() {
                    value == value2
                } else {
                    false
                }
            }
            (Self::Decoded { value, .. }, Self::Encoded { cid: cid2, .. }) => {
                if let Some(cid) = self.get_cid() {
                    cid == cid2
                } else if let Some(value2) = other.get_value() {
                    value == value2
                } else {
                    false
                }
            }
        }
    }
}

impl<T> Debug for Link<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoded { cid, value_cache } => f
                .debug_struct("Link::Encoded")
                .field("cid", &format!("{cid}"))
                .field("value_cache", &value_cache.get())
                .finish(),
            Self::Decoded { value } => f.debug_tuple("Link::Decoded").field(value).finish(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{Link, Storable};
    use anyhow::Result;
    use async_once_cell::OnceCell;
    use blockstore::{Blockstore, InMemoryBlockstore};
    use cid::Cid;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Example {
        price: u64,
        #[serde(skip, default = "OnceCell::new")]
        persisted_as: OnceCell<Cid>,
    }

    impl Storable for Example {
        type Serializable = Example;

        async fn to_serializable(&self, _store: &impl Blockstore) -> Result<Self::Serializable> {
            Ok(self.clone())
        }

        async fn from_serializable(
            cid: Option<&Cid>,
            mut serializable: Self::Serializable,
        ) -> Result<Self> {
            serializable.persisted_as = cid.cloned().map(OnceCell::new_with).unwrap_or_default();
            Ok(serializable)
        }

        fn persisted_as(&self) -> Option<&OnceCell<Cid>> {
            Some(&self.persisted_as)
        }
    }

    impl Clone for Example {
        fn clone(&self) -> Self {
            Self {
                price: self.price,
                persisted_as: self
                    .persisted_as
                    .get()
                    .cloned()
                    .map(OnceCell::new_with)
                    .unwrap_or_default(),
            }
        }
    }

    impl PartialEq for Example {
        fn eq(&self, other: &Self) -> bool {
            self.price == other.price
        }
    }

    impl Example {
        fn new(price: u64) -> Self {
            Self {
                price,
                persisted_as: OnceCell::new(),
            }
        }
    }

    #[async_std::test]
    async fn link_value_can_be_resolved() {
        let store = &InMemoryBlockstore::<64>::new();
        let example = Example::new(256);
        let cid = example.store(store).await.unwrap();
        let link = Link::<Example>::from_cid(cid);

        let value = link.resolve_value(store).await.unwrap();
        assert_eq!(value, &example);
        assert!(link.has_value());
    }

    #[async_std::test]
    async fn link_cid_can_be_resolved() {
        let example = Example::new(12_000_500);
        let store = &InMemoryBlockstore::<64>::new();
        let link = Link::<Example>::from(example.clone());

        let cid = link.resolve_cid(store).await.unwrap();
        let value = Example::load(&cid, store).await.unwrap();

        assert_eq!(value, example);
    }
}
