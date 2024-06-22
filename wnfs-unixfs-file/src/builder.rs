use crate::{
    balanced_tree::{TreeBuilder, DEFAULT_DEGREE},
    chunker::{self, Chunker, ChunkerConfig, DEFAULT_CHUNK_SIZE_LIMIT},
    protobufs,
    types::{Block, BoxAsyncRead},
};
use anyhow::{anyhow, ensure, Result};
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use prost::Message;
use std::fmt::Debug;
use tokio::io::AsyncRead;
use wnfs_common::{blockstore::Blockstore, ipld_core::cid::Cid, utils::CondSend};

/// Representation of a constructed File.
pub struct File<'a> {
    content: BoxAsyncRead<'a>,
    tree_builder: TreeBuilder,
    chunker: Chunker,
}

impl<'a> Debug for File<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field(
                "content",
                &"Content::Reader(Pin<Box<dyn AsyncRead + Send>>)",
            )
            .field("tree_builder", &self.tree_builder)
            .field("chunker", &self.chunker)
            .finish()
    }
}

impl<'a> File<'a> {
    pub fn encode(
        self,
        store: &'a impl Blockstore,
    ) -> Result<impl Stream<Item = Result<(Cid, Block)>> + '_> {
        let chunks = self.chunker.chunks(self.content);
        Ok(self.tree_builder.stream_tree(chunks, store))
    }

    pub async fn store(self, store: &impl Blockstore) -> Result<Cid> {
        let blocks = self.encode(store)?;
        tokio::pin!(blocks);

        let mut root_cid = None;

        while let Some((cid, _)) = blocks.try_next().await? {
            root_cid = Some(cid);
        }

        root_cid.ok_or_else(|| anyhow!("error encoding file, no blocks produced"))
    }
}

/// Constructs a UnixFS file.
pub struct FileBuilder<'a> {
    reader: Option<BoxAsyncRead<'a>>,
    chunker: Chunker,
    degree: usize,
}

impl<'a> Default for FileBuilder<'a> {
    fn default() -> Self {
        Self {
            reader: None,
            chunker: Chunker::Fixed(chunker::Fixed::default()),
            degree: DEFAULT_DEGREE,
        }
    }
}

impl<'a> Debug for FileBuilder<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reader = if self.reader.is_some() {
            "Some(Box<AsyncRead>)"
        } else {
            "None"
        };
        f.debug_struct("FileBuilder")
            .field("chunker", &self.chunker)
            .field("degree", &self.degree)
            .field("reader", &reader)
            .finish()
    }
}

/// FileBuilder separates uses a reader or bytes to chunk the data into raw unixfs nodes
impl<'a> FileBuilder<'a> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn chunker(mut self, chunker: impl Into<Chunker>) -> Self {
        self.chunker = chunker.into();
        self
    }

    /// Set the chunker to be fixed size.
    pub fn fixed_chunker(mut self, chunk_size: usize) -> Self {
        self.chunker = Chunker::Fixed(chunker::Fixed::new(chunk_size));
        self
    }

    /// Use the rabin chunker.
    pub fn rabin_chunker(mut self) -> Self {
        self.chunker = Chunker::Rabin(Box::default());
        self
    }

    pub fn degree(mut self, degree: usize) -> Self {
        self.degree = degree;
        self
    }

    pub fn content_bytes(mut self, content: impl Into<Bytes>) -> Self {
        let bytes = content.into();
        self.reader = Some(Box::pin(std::io::Cursor::new(bytes)));
        self
    }

    pub fn content_reader(mut self, content: impl AsyncRead + CondSend + 'a) -> Self {
        self.reader = Some(Box::pin(content));
        self
    }

    pub fn build(self) -> Result<File<'a>> {
        let degree = self.degree;
        let chunker = self.chunker;
        let tree_builder = TreeBuilder::balanced_tree_with_degree(degree);

        if let Some(reader) = self.reader {
            return Ok(File {
                content: reader,
                chunker,
                tree_builder,
            });
        }

        anyhow::bail!("must have a reader for the content");
    }
}

pub(crate) fn encode_unixfs_pb(
    inner: &protobufs::Data,
    links: Vec<protobufs::PbLink>,
) -> Result<protobufs::PbNode> {
    let data = inner.encode_to_vec();
    ensure!(
        data.len() <= DEFAULT_CHUNK_SIZE_LIMIT,
        "node is too large: {} bytes",
        data.len()
    );

    Ok(protobufs::PbNode {
        links,
        data: Some(data.into()),
    })
}

/// Configuration for adding unixfs content
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Should the outer object be wrapped in a directory?
    pub wrap: bool,
    pub chunker: Option<ChunkerConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::DEFAULT_CHUNKS_SIZE;
    use wnfs_common::blockstore::InMemoryBlockstore;

    #[tokio::test]
    async fn test_builder_stream_small() -> Result<()> {
        let store = &InMemoryBlockstore::<64>::new();
        // Add a file
        let bar_encoded: Vec<_> = {
            let bar_reader = std::io::Cursor::new(b"bar");
            let bar = FileBuilder::new().content_reader(bar_reader).build()?;
            bar.encode(store)?.try_collect().await?
        };
        assert_eq!(bar_encoded.len(), 1);

        // TODO: check content
        Ok(())
    }

    #[tokio::test]
    async fn test_builder_stream_large() -> Result<()> {
        let store = &InMemoryBlockstore::<64>::new();
        // Add a file
        let bar_encoded: Vec<_> = {
            let bar_reader = std::io::Cursor::new(vec![1u8; 1024 * 1024]);
            let bar = FileBuilder::new().content_reader(bar_reader).build()?;
            bar.encode(store)?.try_collect().await?
        };
        assert_eq!(bar_encoded.len(), 5);

        // Add a file
        let mut baz_content = Vec::with_capacity(1024 * 1024 * 2);
        for i in 0..2 {
            for _ in 0..(1024 * 1024) {
                baz_content.push(i);
            }
        }

        let baz_encoded: Vec<_> = {
            let baz_reader = std::io::Cursor::new(baz_content);
            let baz = FileBuilder::new().content_reader(baz_reader).build()?;
            baz.encode(store)?.try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 9);

        // TODO: check content
        Ok(())
    }

    #[test]
    fn test_chunk_config_from_str() {
        assert_eq!(
            "fixed".parse::<ChunkerConfig>().unwrap(),
            ChunkerConfig::Fixed(DEFAULT_CHUNKS_SIZE)
        );
        assert_eq!(
            "fixed-123".parse::<ChunkerConfig>().unwrap(),
            ChunkerConfig::Fixed(123)
        );

        assert!("fixed-".parse::<ChunkerConfig>().is_err());
        assert!(format!("fixed-{}", DEFAULT_CHUNK_SIZE_LIMIT + 1)
            .parse::<ChunkerConfig>()
            .is_err());
        assert!("foo-123".parse::<ChunkerConfig>().is_err());
        assert!("foo".parse::<ChunkerConfig>().is_err());

        assert_eq!(
            "rabin".parse::<ChunkerConfig>().unwrap(),
            ChunkerConfig::Rabin
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::unixfs::UnixFsFile;
    use proptest::{option, strategy::Strategy};
    use rand_chacha::ChaCha12Rng;
    use rand_core::{RngCore, SeedableRng};
    use std::io::SeekFrom;
    use test_strategy::proptest;
    use testresult::TestResult;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    use wnfs_common::{blockstore::InMemoryBlockstore, MAX_BLOCK_SIZE};

    fn arb_chunker() -> impl Strategy<Value = ChunkerConfig> {
        option::of(1_000..MAX_BLOCK_SIZE).prop_map(|opt| match opt {
            Some(lim) => ChunkerConfig::Fixed(lim),
            None => ChunkerConfig::Rabin,
        })
    }

    #[proptest(cases = 64)]
    fn test_encode_decode_roundtrip(
        seed: u64,
        #[strategy(2..DEFAULT_DEGREE)] degree: usize,
        #[strategy(0usize..5_000_000)] len: usize,
        #[strategy(arb_chunker())] chunker: ChunkerConfig,
    ) {
        let store = &InMemoryBlockstore::<64>::new();
        let rng = &mut ChaCha12Rng::seed_from_u64(seed);
        let mut data = vec![0; len];
        rng.fill_bytes(&mut data);

        async_std::task::block_on(async {
            let root_cid = FileBuilder::new()
                .content_bytes(data.clone())
                .chunker(chunker)
                .degree(degree)
                .build()?
                .store(store)
                .await?;

            let file = UnixFsFile::load(root_cid, store).await?;
            assert_eq!(file.filesize(), Some(len as u64));

            let mut buffer = Vec::new();
            let mut reader = file.into_content_reader(store, None)?;
            reader.read_to_end(&mut buffer).await?;

            assert_eq!(buffer, data);

            Ok(()) as TestResult
        })
        .unwrap();
    }

    #[proptest(cases = 256)]
    fn test_seek_subarray(
        seed: u64,
        #[strategy(2..DEFAULT_DEGREE)] degree: usize,
        #[strategy(0usize..100_000)] len: usize,
        #[strategy(0usize..100_000)] seek_start: usize,
        #[strategy(0usize..1_000)] seek_len: usize,
        #[strategy(arb_chunker())] chunker: ChunkerConfig,
    ) {
        let store = &InMemoryBlockstore::<64>::new();
        let rng = &mut ChaCha12Rng::seed_from_u64(seed);
        let mut data = vec![0; len];
        rng.fill_bytes(&mut data);

        let seek_start = std::cmp::min(seek_start, len);
        let seek_len = std::cmp::min(seek_start + seek_len, len - seek_start);

        async_std::task::block_on(async {
            let root_cid = FileBuilder::new()
                .content_bytes(data.clone())
                .chunker(chunker)
                .degree(degree)
                .build()?
                .store(store)
                .await?;

            let file = UnixFsFile::load(root_cid, store).await?;
            assert_eq!(file.filesize(), Some(len as u64));

            let mut buffer = vec![0; seek_len];
            let mut reader = file.into_content_reader(store, None)?;
            reader.seek(SeekFrom::Start(seek_start as u64)).await?;
            let read = reader.read_exact(&mut buffer).await?;

            assert_eq!(read, seek_len);

            assert_eq!(buffer, data[seek_start..seek_start + seek_len]);

            Ok(()) as TestResult
        })
        .unwrap();
    }
}
