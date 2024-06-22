use super::{
    encrypted::Encrypted, forest::traits::PrivateForest, PrivateFileContentSerializable,
    PrivateNode, PrivateNodeContentSerializable, PrivateNodeHeader, PrivateRef, SnapshotKey,
    TemporalKey, AUTHENTICATION_TAG_SIZE, BLOCK_SEGMENT_DSI, HIDING_SEGMENT_DSI, NONCE_SIZE,
};
use crate::{
    error::FsError, is_readable_wnfs_version, traits::Id, utils::OnceCellDebug, WNFS_VERSION,
};
use anyhow::{bail, Result};
use async_once_cell::OnceCell;
use async_stream::try_stream;
use chrono::{DateTime, Utc};
use futures::{future, AsyncRead, Stream, StreamExt, TryStreamExt};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet, iter};
use wnfs_common::{
    blockstore::{block::Block as _, Blockstore},
    ipld_core::{cid::Cid, ipld::Ipld},
    utils::{self, Arc, BoxStream},
    Blake3Block, BlockStoreError, Metadata, CODEC_RAW, MAX_BLOCK_SIZE,
};
use wnfs_nameaccumulator::{Name, NameAccumulator, NameSegment};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The maximum block size is 2 ^ 18 but the first 24 bytes are reserved for the cipher text's initialization vector.
/// The ciphertext then also contains a 16 byte authentication tag.
/// This leaves a maximum of (2 ^ 18) - 24 - 16 = 262,104 bytes for the actual data.
///
/// More on that [here][priv-file].
///
/// [priv-file]: https://github.com/wnfs-wg/spec/blob/matheus23/file-sharding/spec/private-wnfs.md#314-private-file
pub const MAX_BLOCK_CONTENT_SIZE: usize = MAX_BLOCK_SIZE - NONCE_SIZE - AUTHENTICATION_TAG_SIZE;

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

/// A file in the WNFS private file system.
///
/// # Examples
///
/// ```
/// use anyhow::Result;
/// use chrono::Utc;
/// use rand_chacha::ChaCha12Rng;
/// use rand_core::SeedableRng;
/// use wnfs::{
///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
///     common::{MemoryBlockStore, utils::get_random_bytes},
/// };
///
/// #[async_std::main]
/// async fn main() -> Result<()> {
///     let store = &InMemoryBlockstore::<64>::new();
///     let rng = &mut ChaCha12Rng::from_entropy();
///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
///
///     let file = PrivateFile::with_content(
///         &forest.empty_name(),
///         Utc::now(),
///         get_random_bytes::<100>(rng).to_vec(),
///         forest,
///         store,
///         rng,
///     )
///     .await?;
///
///     println!("file = {:?}", file);
///
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PrivateFile {
    pub header: PrivateNodeHeader,
    pub(crate) content: PrivateFileContent,
}

pub(crate) struct PrivateFileContent {
    pub(crate) persisted_as: OnceCell<Cid>,
    pub(crate) previous: BTreeSet<(usize, Encrypted<Cid>)>,
    pub(crate) metadata: Metadata,
    pub(crate) content: FileContent,
}

/// The content of a file.
/// It is stored inline or stored in blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum FileContent {
    Inline { data: Vec<u8> },
    External(PrivateForestContent),
}

/// Keys and pointers to encrypted content stored in a `PrivateForest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateForestContent {
    pub(crate) key: SnapshotKey,
    pub(crate) base_name: NameAccumulator,
    pub(crate) block_count: u64,
    pub(crate) block_content_size: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum MetadataContentCapsule<T> {
    PrivateForestContent(T),
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl PrivateFile {
    /// Creates an empty file.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::private::{
    ///     PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest},
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = HamtForest::new_rsa_2048(rng);
    /// let file = PrivateFile::new(&forest.empty_name(), Utc::now(), rng);
    ///
    /// println!("file = {:?}", file);
    /// ```
    pub fn new(parent_name: &Name, time: DateTime<Utc>, rng: &mut impl CryptoRngCore) -> Self {
        Self {
            header: PrivateNodeHeader::new(parent_name, rng),
            content: PrivateFileContent {
                persisted_as: OnceCell::new(),
                metadata: Metadata::new(time),
                previous: BTreeSet::new(),
                content: FileContent::Inline { data: vec![] },
            },
        }
    }

    /// Creates an empty file wrapped in an `Arc`.
    ///
    /// # Examples
    ///
    /// ```
    /// use wnfs::private::{
    ///     PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest},
    /// };
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    ///
    /// let rng = &mut ChaCha12Rng::from_entropy();
    /// let forest = HamtForest::new_rsa_2048(rng);
    /// let file = PrivateFile::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    /// println!("file = {:?}", file);
    /// ```
    pub fn new_rc(
        parent_name: &Name,
        time: DateTime<Utc>,
        rng: &mut impl CryptoRngCore,
    ) -> Arc<Self> {
        Arc::new(Self::new(parent_name, time, rng))
    }

    /// Creates a file with provided content.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::{MemoryBlockStore, utils::get_random_bytes},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let file = PrivateFile::with_content(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         get_random_bytes::<100>(rng).to_vec(),
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await
    ///     .unwrap();
    ///
    ///     println!("file = {:?}", file);
    /// }
    /// ```
    pub async fn with_content(
        parent_name: &Name,
        time: DateTime<Utc>,
        content: Vec<u8>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let header = PrivateNodeHeader::new(parent_name, rng);
        let content = Self::prepare_content(header.get_name(), content, forest, store, rng).await?;

        Ok(Self {
            header,
            content: PrivateFileContent {
                persisted_as: OnceCell::new(),
                metadata: Metadata::new(time),
                previous: BTreeSet::new(),
                content,
            },
        })
    }

    /// Creates a file with provided content wrapped in an `Arc`.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::{MemoryBlockStore, utils::get_random_bytes},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let file = PrivateFile::with_content_rc(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         get_random_bytes::<100>(rng).to_vec(),
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await
    ///     .unwrap();
    ///
    ///     println!("file = {:?}", file);
    /// }
    /// ```
    pub async fn with_content_rc(
        parent_name: &Name,
        time: DateTime<Utc>,
        content: Vec<u8>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(
            Self::with_content(parent_name, time, content, forest, store, rng).await?,
        ))
    }

    /// Creates a file with provided content as a stream.
    ///
    /// Depending on the BlockStore implementation this will
    /// use essentially O(1) memory (roughly `2 * MAX_BLOCK_CONTENT_SIZE` bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use async_std::fs::File;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let disk_file = File::open("./test/fixtures/Clara Schumann, Scherzo no. 2, Op. 14.mp3").await?;
    ///
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let file = PrivateFile::with_content_streaming(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         disk_file,
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await?;
    ///
    ///     println!("file = {:?}", file);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn with_content_streaming(
        parent_name: &Name,
        time: DateTime<Utc>,
        content: impl AsyncRead + Unpin,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let header = PrivateNodeHeader::new(parent_name, rng);
        let content =
            Self::prepare_content_streaming(header.get_name(), content, forest, store, rng).await?;

        Ok(Self {
            header,
            content: PrivateFileContent {
                persisted_as: OnceCell::new(),
                metadata: Metadata::new(time),
                previous: BTreeSet::new(),
                content,
            },
        })
    }

    /// Creates a file with provided content as a stream wrapped in an `Arc`.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use async_std::fs::File;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::MemoryBlockStore,
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let disk_file = File::open("./test/fixtures/Clara Schumann, Scherzo no. 2, Op. 14.mp3").await?;
    ///
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let file = PrivateFile::with_content_streaming_rc(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         disk_file,
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await?;
    ///
    ///     println!("file = {:?}", file);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn with_content_streaming_rc(
        parent_name: &Name,
        time: DateTime<Utc>,
        content: impl AsyncRead + Unpin,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(
            Self::with_content_streaming(parent_name, time, content, forest, store, rng).await?,
        ))
    }

    /// Create a copy of this file without re-encrypting the actual content
    /// (if the ciphertext is external ciphertext), so this is really fast
    /// even if the file contains gigabytes of data.
    ///
    /// # Example
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateDirectory, PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::{MemoryBlockStore, utils::get_random_bytes},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let file = PrivateFile::with_content(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         get_random_bytes::<100>(rng).to_vec(),
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await?;
    ///
    ///     let root_dir = &mut PrivateDirectory::new_rc(&forest.empty_name(), Utc::now(), rng);
    ///
    ///     let copy = root_dir
    ///         .open_file_mut(&["some".into(), "copy.txt".into()], true, Utc::now(), forest, store, rng)
    ///         .await?;
    ///
    ///     copy.copy_content_from(&file, Utc::now());
    ///
    ///     assert_eq!(file.get_content(forest, store).await?, copy.get_content(forest, store).await?);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn copy_content_from(&mut self, other: &Self, time: DateTime<Utc>) {
        self.content.metadata.upsert_mtime(time);
        self.content.content = other.content.content.clone();
    }

    /// Streams the content of a file as chunk of blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::{MemoryBlockStore, utils::get_random_bytes},
    /// };
    /// use futures::{future, TryStreamExt};
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let content = get_random_bytes::<100>(rng).to_vec();
    ///     let file = PrivateFile::with_content(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         content.clone(),
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await?;
    ///
    ///     let mut stream_content = vec![];
    ///     file.stream_content(0, forest, store)
    ///         .try_for_each(|chunk| {
    ///             stream_content.extend_from_slice(&chunk);
    ///             future::ready(Ok(()))
    ///         })
    ///         .await?;
    ///
    ///     assert_eq!(content, stream_content);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn stream_content<'a>(
        &'a self,
        block_index: u64,
        forest: &'a impl PrivateForest,
        store: &'a impl Blockstore,
    ) -> BoxStream<'a, Result<Vec<u8>>> {
        match &self.content.content {
            FileContent::Inline { data } => Box::pin(try_stream! {
                if block_index != 0 {
                    Err(FsError::FileShardNotFound)?
                }

                yield data.clone()
            }),
            FileContent::External(content) => Box::pin(content.stream(block_index, forest, store)),
        }
    }

    /// Read the contents of this file.
    /// You can provide a byte offset from which to start reading,
    /// and you can provide a maximum amount of bytes you want to read.
    ///
    /// For more advanced cases, consider using `stream_content` instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateDirectory, PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::{MemoryBlockStore, utils::get_random_bytes},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///     let content = b"Hello, World!\n".repeat(1000).to_vec();
    ///
    ///     let file = PrivateFile::with_content(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         content,
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await
    ///     .unwrap();
    ///
    ///     let content = file.read_at(14, Some(28), forest, store).await?;
    ///
    ///     assert_eq!(content, b"Hello, World!\nHello, World!\n");
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn read_at<'a>(
        &'a self,
        byte_offset: u64,
        len_limit: Option<usize>,
        forest: &'a impl PrivateForest,
        store: &'a impl Blockstore,
    ) -> Result<Vec<u8>> {
        match &self.content.content {
            FileContent::Inline { data } => {
                let offset = byte_offset as usize;

                match len_limit {
                    Some(len) => Ok(data[offset..offset + len].to_vec()),
                    None => Ok(data[offset..].to_vec()),
                }
            }
            FileContent::External(external) => {
                external
                    .read_at(byte_offset, len_limit, forest, store)
                    .await
            }
        }
    }

    /// Gets the metadata of the file
    pub fn get_metadata(&self) -> &Metadata {
        &self.content.metadata
    }

    /// Returns a mutable reference to this file's metadata.
    pub fn get_metadata_mut(&mut self) -> &mut Metadata {
        &mut self.content.metadata
    }

    /// Returns a mutable reference to this file's metadata and ratchets forward its revision, if necessary.
    pub fn get_metadata_mut_rc<'a>(self: &'a mut Arc<Self>) -> Result<&'a mut Metadata> {
        Ok(self.prepare_next_revision()?.get_metadata_mut())
    }

    /// Gets the exact content size without fetching all content blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::{MemoryBlockStore, utils::get_random_bytes},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let content = get_random_bytes::<324_568>(rng).to_vec();
    ///     let file = PrivateFile::with_content(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         content.clone(),
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await?;
    ///
    ///     let mut size = file.size(forest, store).await?;
    ///
    ///     assert_eq!(content.len() as u64, size);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn size(&self, forest: &impl PrivateForest, store: &impl Blockstore) -> Result<u64> {
        match &self.content.content {
            FileContent::Inline { data } => Ok(data.len() as u64),
            FileContent::External(forest_content) => forest_content.size(forest, store).await,
        }
    }

    /// Gets the entire content of a file.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Result;
    /// use chrono::Utc;
    /// use rand_chacha::ChaCha12Rng;
    /// use rand_core::SeedableRng;
    /// use wnfs::{
    ///     private::{PrivateFile, forest::{hamt::HamtForest, traits::PrivateForest}},
    ///     common::{MemoryBlockStore, utils::get_random_bytes},
    /// };
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let store = &InMemoryBlockstore::<64>::new();
    ///     let rng = &mut ChaCha12Rng::from_entropy();
    ///     let forest = &mut HamtForest::new_rsa_2048_rc(rng);
    ///
    ///     let content = get_random_bytes::<100>(rng).to_vec();
    ///     let file = PrivateFile::with_content(
    ///         &forest.empty_name(),
    ///         Utc::now(),
    ///         content.clone(),
    ///         forest,
    ///         store,
    ///         rng,
    ///     )
    ///     .await?;
    ///
    ///     let mut all_content = file.get_content(forest, store).await?;
    ///
    ///     assert_eq!(content, all_content);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn get_content(
        &self,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Vec<u8>> {
        self.read_at(0, None, forest, store).await
    }

    /// Sets the content of a file.
    pub async fn set_content(
        &mut self,
        content: impl AsyncRead + Unpin,
        time: DateTime<Utc>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.content.metadata.upsert_mtime(time);
        // TODO(matheus23): Use heuristic to figure out whether to store data inline
        self.content.content =
            Self::prepare_content_streaming(self.header.get_name(), content, forest, store, rng)
                .await?;
        Ok(())
    }

    /// Determines where to put the content of a file. This can either be inline or stored up in chunks in a private forest.
    pub(super) async fn prepare_content(
        file_name: &Name,
        content: Vec<u8>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<FileContent> {
        // TODO(appcypher): Use a better heuristic to determine when to use external storage.
        Ok(FileContent::External(
            PrivateForestContent::new(file_name, content, forest, store, rng).await?,
        ))
    }

    /// Drains the content streamed-in and puts it into the private forest
    /// as blocks of encrypted data.
    /// Returns an external `FileContent` that contains necessary information
    /// to later retrieve the data.
    pub(super) async fn prepare_content_streaming(
        file_name: &Name,
        content: impl AsyncRead + Unpin,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<FileContent> {
        Ok(FileContent::External(
            PrivateForestContent::new_streaming(file_name, content, forest, store, rng).await?,
        ))
    }

    /// This should be called to prepare a node for modifications,
    /// if it's meant to be a successor revision of the current revision.
    ///
    /// This doesn't have any effect if the current state hasn't been `.store()`ed yet.
    /// Otherwise, it clones itself, stores its current CID in the previous links and
    /// advances its ratchet.
    pub(crate) fn prepare_next_revision<'a>(self: &'a mut Arc<Self>) -> Result<&'a mut Self> {
        let previous_cid = match self.content.persisted_as.get() {
            Some(cid) => *cid,
            None => {
                // The current revision wasn't written yet.
                // There's no point in advancing the revision even further.
                return Ok(Arc::make_mut(self));
            }
        };

        let temporal_key = self.header.derive_temporal_key();
        let previous_link = (1, Encrypted::from_value(previous_cid, &temporal_key)?);
        let cloned = Arc::make_mut(self);

        // We make sure to clear any cached states.
        cloned.content.persisted_as = OnceCell::new();
        cloned.content.previous = [previous_link].into_iter().collect();
        cloned.header.advance_ratchet();

        Ok(cloned)
    }

    /// Call this function to prepare this file for conflict reconciliation merge changes.
    /// Advances this node to the revision given in `target_header`.
    /// Generates another previous link, unless this node is already a merge node, then this
    /// simply updates all previous links to use the correct steps back.
    /// Merge nodes preferably just grow in size. This allows them to combine more nicely
    /// without causing further conflicts.
    pub(crate) fn prepare_next_merge<'a>(
        self: &'a mut Arc<Self>,
        current_cid: Cid,
        target_header: PrivateNodeHeader,
    ) -> Result<&'a mut Self> {
        let ratchet_diff = target_header.ratchet_diff_for_merge(&self.header)?;

        if self.content.previous.len() > 1 {
            // This is a merge node
            let cloned = Arc::make_mut(self);
            cloned.content.persisted_as = OnceCell::new();
            cloned.header = target_header;
            cloned.content.previous = std::mem::take(&mut cloned.content.previous)
                .into_iter()
                .map(|(ratchet_steps, link)| (ratchet_steps + ratchet_diff, link))
                .collect();

            return Ok(cloned);
        }

        // It's not a merge node, we need to advance the revision

        let temporal_key = self.header.derive_temporal_key();
        let previous_link = (
            ratchet_diff,
            Encrypted::from_value(current_cid, &temporal_key)?,
        );
        let cloned = Arc::make_mut(self);

        // We make sure to clear any cached states.
        cloned.content.persisted_as = OnceCell::new();
        cloned.header = target_header;
        cloned.content.previous = [previous_link].into_iter().collect();

        Ok(cloned)
    }

    /// This prepares this file for key rotation, usually for moving or
    /// copying the file to some other place.
    ///
    /// Will reset the ratchet, so a different key is necessary for read access,
    /// will reset the inumber to reset write access,
    /// will update the name to be the sub-name of given parent name,
    /// so it inherits the write access rules from the new parent and
    /// resets the `persisted_as` pointer.
    pub(crate) async fn prepare_key_rotation(
        &mut self,
        parent_name: &Name,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.header.inumber = NameSegment::new(rng);
        self.header.update_name(parent_name);
        self.header.reset_ratchet(rng);
        self.content.persisted_as = OnceCell::new();

        Ok(())
    }

    /// Stores this PrivateFile in the PrivateForest.
    pub(crate) async fn store(
        &self,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PrivateRef> {
        let header_cid = self.header.store(store, forest).await?;
        let temporal_key = self.header.derive_temporal_key();
        let snapshot_key = temporal_key.derive_snapshot_key();
        let name_with_revision = self.header.get_revision_name();

        let content_cid = self
            .content
            .store(header_cid, &snapshot_key, store, rng)
            .await?;

        forest
            .put_encrypted(&name_with_revision, [header_cid, content_cid], store)
            .await?;

        Ok(self
            .header
            .derive_revision_ref(forest)
            .into_private_ref(content_cid))
    }

    /// Creates a new [`PrivateFile`] from a [`PrivateFileContentSerializable`].
    pub(crate) async fn from_serializable(
        serializable: PrivateFileContentSerializable,
        temporal_key: &TemporalKey,
        cid: Cid,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
        parent_name: Option<Name>,
    ) -> Result<Self> {
        if !is_readable_wnfs_version(&serializable.version) {
            bail!(FsError::UnexpectedVersion(serializable.version));
        }

        let content = PrivateFileContent {
            persisted_as: OnceCell::new_with(cid),
            previous: serializable.previous.into_iter().collect(),
            metadata: serializable.metadata,
            content: serializable.content,
        };

        let header = PrivateNodeHeader::load(
            &serializable.header_cid,
            temporal_key,
            forest,
            store,
            parent_name,
        )
        .await?;
        Ok(Self { header, content })
    }

    /// Wraps the file in a [`PrivateNode`].
    pub fn as_node(self: &Arc<Self>) -> PrivateNode {
        PrivateNode::File(Arc::clone(self))
    }

    /// Merges two private files together.
    /// The files must have been stored before (that's the CIDs that
    /// are passed in).
    /// This function is both commutative and associative.
    pub(crate) fn merge(
        self: &mut Arc<Self>,
        target_header: PrivateNodeHeader,
        our_cid: Cid,
        other: &Arc<Self>,
        other_cid: Cid,
    ) -> Result<()> {
        if our_cid == other_cid {
            return Ok(());
        }

        let other_ratchet_diff = target_header.ratchet_diff_for_merge(&other.header)?;

        let our = self.prepare_next_merge(our_cid, target_header)?;

        if our.content.previous.len() > 1 {
            // This is a merge node. We'll just add its previous links.
            our.content.previous.extend(
                other
                    .content
                    .previous
                    .iter()
                    .cloned()
                    .map(|(rev_back, link)| (rev_back + other_ratchet_diff, link)),
            );
        } else {
            // The other node represents a write - we need to store a link to its CID
            let temporal_key = &other.header.derive_temporal_key();
            our.content.previous.insert((
                other_ratchet_diff,
                Encrypted::from_value(other_cid, temporal_key)?,
            ));
        }

        let our_hash = our.content.content.crdt_tiebreaker()?;
        let other_hash = other.content.content.crdt_tiebreaker()?;

        match our_hash.cmp(&other_hash) {
            Ordering::Greater => {
                our.content.content.clone_from(&other.content.content);
                our.content.metadata.clone_from(&other.content.metadata);
            }
            Ordering::Equal => {
                our.content
                    .metadata
                    .tie_break_with(&other.content.metadata)?;
            }
            Ordering::Less => {
                // we take ours
            }
        }

        Ok(())
    }
}

impl PrivateFileContent {
    /// Serializes the file to a dag-cbor representation.
    pub(crate) fn to_dag_cbor(&self, header_cid: Cid) -> Result<Vec<u8>> {
        Ok(serde_ipld_dagcbor::to_vec(
            &PrivateNodeContentSerializable::File(PrivateFileContentSerializable {
                version: WNFS_VERSION,
                previous: self.previous.iter().cloned().collect(),
                header_cid,
                metadata: self.metadata.clone(),
                content: self.content.clone(),
            }),
        )?)
    }

    #[allow(clippy::suspicious)]
    pub(crate) async fn store(
        &self,
        header_cid: Cid,
        snapshot_key: &SnapshotKey,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Cid> {
        Ok(*self
            .persisted_as
            .get_or_try_init::<anyhow::Error>(async {
                // TODO(matheus23) deduplicate when reworking serialization

                // Serialize node to cbor.
                let bytes = self.to_dag_cbor(header_cid)?;

                // Encrypt bytes with snapshot key.
                let block = snapshot_key.encrypt(&bytes, rng)?;

                // Store content section in blockstore and get Cid.
                let block = Blake3Block::new(CODEC_RAW, block);
                let cid = block.cid()?;
                store.put(block).await?;
                Ok(cid)
            })
            .await?)
    }
}

impl FileContent {
    pub(crate) fn crdt_tiebreaker(&self) -> Result<[u8; 32]> {
        let bytes = serde_ipld_dagcbor::to_vec(self)?;
        Ok(blake3::hash(&bytes).into())
    }
}

impl PrivateForestContent {
    /// Take some plaintext to encrypt and store in given private forest.
    ///
    /// The provided file name will be used as the "path" that controls
    /// who has write access to these blocks.
    ///
    /// E.g. using providing `PrivateFile.get_header().get_name()` would let
    /// these content block inherit the write access from that private file.
    ///
    /// This struct itself only holds the keys & pointers to the data, which
    /// is stored (encrypted) in the `PrivateForest` and `BlockStore` instead.
    pub async fn new(
        file_name: &Name,
        content: Vec<u8>,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let (key, base_name) = Self::prepare_key_and_base_name(file_name, rng);
        let block_count = (content.len() as f64 / MAX_BLOCK_CONTENT_SIZE as f64).ceil() as u64;

        for (name, index) in Self::generate_shard_labels(&key, 0, block_count, &base_name).zip(0..)
        {
            let start = index * MAX_BLOCK_CONTENT_SIZE;
            let end = content.len().min((index + 1) * MAX_BLOCK_CONTENT_SIZE);
            let slice = &content[start..end];

            let enc_bytes = key.encrypt(slice, rng)?;

            let block = Blake3Block::new(CODEC_RAW, enc_bytes);
            let content_cid = block.cid()?;
            store.put(block).await?;

            forest
                .put_encrypted(&name, Some(content_cid), store)
                .await?;
        }

        Ok(PrivateForestContent {
            key,
            base_name: forest.get_accumulated_name(&base_name),
            block_count,
            block_content_size: MAX_BLOCK_CONTENT_SIZE as u64,
        })
    }

    /// Like `new`, but allows streaming in the content.
    ///
    /// See `new` for more information.
    pub async fn new_streaming(
        file_name: &Name,
        mut content: impl AsyncRead + Unpin,
        forest: &mut impl PrivateForest,
        store: &impl Blockstore,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let (key, base_name) = Self::prepare_key_and_base_name(file_name, rng);

        let mut block_index = 0;

        loop {
            let mut current_block = vec![0u8; MAX_BLOCK_SIZE];
            let nonce = SnapshotKey::generate_nonce(rng);
            current_block[..NONCE_SIZE].copy_from_slice(nonce.as_ref());

            // read up to MAX_BLOCK_CONTENT_SIZE content

            let content_end = NONCE_SIZE + MAX_BLOCK_CONTENT_SIZE;
            let (bytes_written, done) =
                utils::read_fully(&mut content, &mut current_block[NONCE_SIZE..content_end])
                    .await?;

            // truncate the vector to its actual length.
            current_block.truncate(bytes_written + NONCE_SIZE);

            let tag = key.encrypt_in_place(&nonce, &mut current_block[NONCE_SIZE..])?;
            current_block.extend_from_slice(tag.as_ref());

            let block = Blake3Block::new(CODEC_RAW, current_block);
            let content_cid = block.cid()?;
            store.put(block).await?;

            let name = Self::create_block_name(&key, block_index, &base_name);
            forest
                .put_encrypted(&name, Some(content_cid), store)
                .await?;

            block_index += 1;

            if done {
                break;
            }
        }

        Ok(PrivateForestContent {
            key,
            base_name: forest.get_accumulated_name(&base_name),
            block_count: block_index,
            block_content_size: MAX_BLOCK_CONTENT_SIZE as u64,
        })
    }

    /// Load some previously stored keys & pointers to encrypted private forest content
    /// from given metadata key.
    pub fn from_metadata_value(value: &Ipld) -> Result<Self> {
        let wrapped: MetadataContentCapsule<Self> =
            wnfs_common::ipld_core::serde::from_ipld(value.clone())?;

        Ok(match wrapped {
            MetadataContentCapsule::PrivateForestContent(content) => content,
        })
    }

    // Serialize these pointers & keys into some data that can be stored in a `PrivateFile`'s metadata.
    pub fn as_metadata_value(&self) -> Result<Ipld> {
        Ok(wnfs_common::ipld_core::serde::to_ipld(
            MetadataContentCapsule::PrivateForestContent(&self),
        )?)
    }

    /// Decrypt & stream out the contents that `self` points to in given forest.
    pub fn stream<'a>(
        &'a self,
        block_index: u64,
        forest: &'a impl PrivateForest,
        store: &'a impl Blockstore,
    ) -> impl Stream<Item = Result<Vec<u8>>> + 'a {
        try_stream! {
            for name in Self::generate_shard_labels(
                &self.key,
                block_index,
                self.block_count,
                &Name::new(self.base_name.clone(), []),
            ) {
                // TODO(matheus23): take block_content_size into account
                let bytes = Self::decrypt_block(&self.key, &name, forest, store).await?;
                yield bytes
            }
        }
    }

    /// Reads a number of bytes starting from a given offset.
    pub async fn read_at<'a>(
        &'a self,
        byte_offset: u64,
        len_limit: Option<usize>,
        forest: &'a impl PrivateForest,
        store: &'a impl Blockstore,
    ) -> Result<Vec<u8>> {
        let block_content_size = MAX_BLOCK_CONTENT_SIZE as u64;
        let mut chunk_size_upper_bound = (self.get_size_upper_bound() - byte_offset) as usize;

        if let Some(len_limit) = len_limit {
            chunk_size_upper_bound = chunk_size_upper_bound.min(len_limit);
        }

        if chunk_size_upper_bound == 0 {
            return Ok(vec![]);
        }

        let first_block = byte_offset / block_content_size;
        let last_block = len_limit.map(|len| (byte_offset + len as u64) / block_content_size);

        let mut bytes = Vec::with_capacity(chunk_size_upper_bound);
        let mut content_stream = Box::pin(self.stream(first_block, forest, store)).enumerate();

        while let Some((i, chunk)) = content_stream.next().await {
            let chunk = chunk?;
            let index = first_block + i as u64;
            let from = if index == first_block {
                (byte_offset - index * block_content_size).min(chunk.len() as u64)
            } else {
                0
            };
            let to = if Some(index) == last_block {
                (byte_offset + len_limit.unwrap_or_default() as u64 - index * block_content_size)
                    .min(chunk.len() as u64)
            } else {
                chunk.len() as u64
            };
            bytes.extend_from_slice(&chunk[(from as usize)..(to as usize)]);
            if Some(index) == last_block {
                break;
            }
        }
        Ok(bytes)
    }

    /// Collect all content into a `Vec<u8>`.
    ///
    /// Make sure to check `get_size_upper_bound` in advance to avoid
    /// allocating huge byte arrays in-memory.
    pub async fn get_content(
        &self,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Vec<u8>> {
        let mut content = Vec::with_capacity(Self::get_size_upper_bound(self) as usize);
        self.stream(0, forest, store)
            .try_for_each(|chunk| {
                content.extend_from_slice(&chunk);
                future::ready(Ok(()))
            })
            .await?;
        Ok(content)
    }

    /// Gets an upper bound estimate of the content size.
    pub fn get_size_upper_bound(&self) -> u64 {
        self.block_count * self.block_content_size
    }

    /// Gets the exact size of the content.
    pub async fn size(&self, forest: &impl PrivateForest, store: &impl Blockstore) -> Result<u64> {
        let size_without_last_block =
            std::cmp::max(0, self.block_count - 1) * self.block_content_size;

        let size_last_block = self
            .read_at(size_without_last_block, None, forest, store)
            .await?
            .len() as u64;

        Ok(size_without_last_block + size_last_block)
    }

    /// Generates the labels for all of the content shard blocks.
    pub(crate) fn generate_shard_labels<'a>(
        key: &'a SnapshotKey,
        mut block_index: u64,
        block_count: u64,
        base_name: &'a Name,
    ) -> impl Iterator<Item = Name> + 'a {
        iter::from_fn(move || {
            if block_index >= block_count {
                return None;
            }

            let label = Self::create_block_name(key, block_index, base_name);
            block_index += 1;
            Some(label)
        })
    }

    async fn decrypt_block(
        key: &SnapshotKey,
        name: &Name,
        forest: &impl PrivateForest,
        store: &impl Blockstore,
    ) -> Result<Vec<u8>> {
        let cid = forest
            .get_encrypted(name, store)
            .await?
            .ok_or(FsError::FileShardNotFound)?
            .iter()
            .next()
            .expect("Expected set with at least a one cid");

        let enc_bytes = store
            .get(cid)
            .await?
            .ok_or_else(|| BlockStoreError::CIDNotFound(*cid))?;
        let bytes = key.decrypt(&enc_bytes)?;

        Ok(bytes)
    }

    fn create_block_name(key: &SnapshotKey, index: u64, base_name: &Name) -> Name {
        let mut vec = Vec::with_capacity(40);
        vec.extend(key.0); // 32 bytes
        vec.extend(index.to_le_bytes()); // 8 bytes
        let block_segment = NameSegment::new_hashed(BLOCK_SEGMENT_DSI, vec);

        base_name.with_segments_added(Some(block_segment))
    }

    fn prepare_key_and_base_name(
        file_name: &Name,
        rng: &mut impl CryptoRngCore,
    ) -> (SnapshotKey, Name) {
        let key = SnapshotKey::new(rng);
        let hiding_segment = NameSegment::new_hashed(HIDING_SEGMENT_DSI, key.as_bytes());
        let base_name = file_name.with_segments_added(Some(hiding_segment));

        (key, base_name)
    }
}

impl PartialEq for PrivateFileContent {
    fn eq(&self, other: &Self) -> bool {
        self.previous == other.previous
            && self.metadata == other.metadata
            && self.content == other.content
    }
}

impl Clone for PrivateFileContent {
    fn clone(&self) -> Self {
        Self {
            persisted_as: self
                .persisted_as
                .get()
                .cloned()
                .map(OnceCell::new_with)
                .unwrap_or_default(),
            previous: self.previous.clone(),
            metadata: self.metadata.clone(),
            content: self.content.clone(),
        }
    }
}

impl Id for PrivateFile {
    fn get_id(&self) -> String {
        format!("{:p}", &self.header)
    }
}

impl std::fmt::Debug for PrivateFileContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateFileContent")
            .field(
                "persisted_as",
                &OnceCellDebug(self.persisted_as.get().map(|cid| format!("{cid}"))),
            )
            .field("previous", &self.previous)
            .field("metadata", &self.metadata)
            .field("content", &self.content)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private::forest::hamt::HamtForest;
    use async_std::fs::File;
    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[async_std::test]
    async fn can_create_empty_file() {
        let store = &InMemoryBlockstore::<64>::new();
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let forest = &HamtForest::new_rsa_2048_rc(rng);

        let file = PrivateFile::new(&forest.empty_name(), Utc::now(), rng);
        let file_content = file.get_content(forest, store).await.unwrap();

        assert!(file_content.is_empty());
    }

    #[async_std::test]
    async fn can_stream_limited_content_from_file() {
        let mut content = vec![0u8; MAX_BLOCK_CONTENT_SIZE * 5];
        rand::thread_rng().fill(&mut content[..]);

        let store = &InMemoryBlockstore::<64>::new();
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);

        let file = PrivateFile::with_content(
            &forest.empty_name(),
            Utc::now(),
            content.clone(),
            forest,
            store,
            rng,
        )
        .await
        .unwrap();

        let mut collected_content = Vec::new();
        let mut block_limit = 2;
        file.stream_content(2, forest, store)
            .for_each(|chunk| {
                if block_limit == 0 {
                    return future::ready(());
                }

                collected_content.extend_from_slice(&chunk.unwrap());
                block_limit -= 1;
                future::ready(())
            })
            .await;

        assert_eq!(
            collected_content,
            content[2 * MAX_BLOCK_CONTENT_SIZE..4 * MAX_BLOCK_CONTENT_SIZE]
        );
    }

    #[async_std::test]
    async fn can_construct_file_from_stream() {
        let disk_file = File::open("./test/fixtures/Clara Schumann, Scherzo no. 2, Op. 14.mp3")
            .await
            .unwrap();

        let store = &InMemoryBlockstore::<64>::new();
        let rng = &mut ChaCha12Rng::seed_from_u64(0);
        let forest = &mut HamtForest::new_rsa_2048_rc(rng);

        let file = PrivateFile::with_content_streaming(
            &forest.empty_name(),
            Utc::now(),
            disk_file,
            forest,
            store,
            rng,
        )
        .await
        .unwrap();

        assert!(
            matches!(file.content.content, FileContent::External(PrivateForestContent { block_count, .. }) if block_count > 0)
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::MAX_BLOCK_CONTENT_SIZE;
    use crate::private::{
        forest::{hamt::HamtForest, traits::PrivateForest},
        PrivateFile,
    };
    use async_std::io::Cursor;
    use chrono::Utc;
    use futures::{future, StreamExt};
    use proptest::{prop_assert, prop_assert_eq};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use test_strategy::proptest;
    use wnfs_common::{blockstore::InMemoryBlockstore, BlockStoreError};

    /// Size of the test file at "./test/fixtures/Clara Schumann, Scherzo no. 2, Op. 14.mp3"
    const FIXTURE_SCHERZO_SIZE: usize = 4028150;

    #[proptest(cases = 100)]
    fn can_include_and_get_content_from_file(
        #[strategy(0..(MAX_BLOCK_CONTENT_SIZE * 2))] length: usize,
    ) {
        async_std::task::block_on(async {
            let content = vec![0u8; length];
            let store = &InMemoryBlockstore::<64>::new();
            let rng = &mut ChaCha12Rng::seed_from_u64(0);
            let forest = &mut HamtForest::new_rsa_2048_rc(rng);

            let file = PrivateFile::with_content(
                &forest.empty_name(),
                Utc::now(),
                content.clone(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

            let collected_content = file.get_content(forest, store).await.unwrap();

            prop_assert_eq!(collected_content, content);
            Ok(())
        })?;
    }

    #[proptest(cases = 10)]
    fn can_include_and_stream_content_from_file(
        #[strategy(0..(MAX_BLOCK_CONTENT_SIZE * 2))] length: usize,
    ) {
        async_std::task::block_on(async {
            let content = vec![0u8; length];
            let store = &InMemoryBlockstore::<64>::new();
            let rng = &mut ChaCha12Rng::seed_from_u64(0);
            let forest = &mut HamtForest::new_rsa_2048_rc(rng);

            let file = PrivateFile::with_content(
                &forest.empty_name(),
                Utc::now(),
                content.clone(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

            let mut collected_content = Vec::new();
            file.stream_content(0, forest, store)
                .for_each(|chunk| {
                    collected_content.extend_from_slice(&chunk.unwrap());
                    future::ready(())
                })
                .await;

            prop_assert_eq!(collected_content, content);
            Ok(())
        })?;
    }

    #[proptest(cases = 100)]
    fn can_propagate_missing_chunk_error(
        #[strategy(0..(MAX_BLOCK_CONTENT_SIZE * 2))] length: usize,
    ) {
        async_std::task::block_on(async {
            let store = &InMemoryBlockstore::<64>::new();
            let rng = &mut ChaCha12Rng::seed_from_u64(0);
            let forest = &mut HamtForest::new_rsa_2048_rc(rng);

            let mut file = PrivateFile::new(&forest.empty_name(), Utc::now(), rng);

            file.set_content(
                &mut Cursor::new(vec![5u8; length]),
                Utc::now(),
                forest,
                &InMemoryBlockstore::<64>::new(),
                rng,
            )
            .await
            .unwrap();

            let error = file
                .get_content(forest, store)
                .await
                .expect_err("Expected error");

            let error = error.downcast_ref::<BlockStoreError>().unwrap();

            prop_assert!(matches!(error, BlockStoreError::CIDNotFound(_)));
            Ok(())
        })?;
    }

    #[proptest(cases = 10)]
    fn can_read_section_of_file(
        #[strategy(0..FIXTURE_SCHERZO_SIZE)] size: usize,
        #[strategy(0..FIXTURE_SCHERZO_SIZE as u64)] offset: u64,
    ) {
        use async_std::{io::SeekFrom, prelude::*};
        async_std::task::block_on(async {
            let size = size.min(FIXTURE_SCHERZO_SIZE - offset as usize);
            let mut disk_file = async_std::fs::File::open(
                "./test/fixtures/Clara Schumann, Scherzo no. 2, Op. 14.mp3",
            )
            .await
            .unwrap();

            let rng = &mut ChaCha12Rng::seed_from_u64(0);
            let forest = &mut HamtForest::new_rsa_2048_rc(rng);
            let store = &InMemoryBlockstore::<64>::new();

            let file = PrivateFile::with_content_streaming(
                &forest.empty_name(),
                Utc::now(),
                disk_file.clone(),
                forest,
                store,
                rng,
            )
            .await
            .unwrap();

            let mut source_content = vec![0u8; size];
            disk_file.seek(SeekFrom::Start(offset)).await.unwrap();
            disk_file.read_exact(&mut source_content).await.unwrap();
            let wnfs_content = file
                .read_at(offset, Some(size), forest, store)
                .await
                .unwrap();

            prop_assert_eq!(source_content, wnfs_content);
            Ok(())
        })?;
    }
}
