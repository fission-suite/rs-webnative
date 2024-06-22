use crate::{
    chunker::DEFAULT_CHUNK_SIZE_LIMIT,
    codecs::Codec,
    protobufs,
    types::{Block, Link, LinkRef, Links, PbLinks},
};
use anyhow::{anyhow, bail, ensure, Result};
use bytes::Bytes;
use futures::FutureExt;
use prost::Message;
use std::{
    collections::VecDeque,
    fmt::Debug,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncSeek};
use wnfs_common::{
    blockstore::Blockstore,
    ipld_core::cid::Cid,
    utils::{boxed_fut, BoxFuture},
    BlockStoreError, LoadIpld, Storable, StoreIpld,
};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive,
)]
#[repr(i32)]
pub enum DataType {
    Raw = 0,
    Directory = 1,
    File = 2,
    Metadata = 3,
    Symlink = 4,
    HamtShard = 5,
}

#[derive(Debug, PartialEq, Clone)]
pub enum UnixFsFile {
    Raw(Bytes),
    Node(Node),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Node {
    pub(super) outer: protobufs::PbNode,
    pub(super) inner: protobufs::Data,
}

impl Node {
    fn encode(&self) -> Result<Bytes> {
        let bytes = self.outer.encode_to_vec();
        Ok(bytes.into())
    }

    pub fn typ(&self) -> DataType {
        self.inner.r#type.try_into().expect("invalid data type")
    }

    pub fn data(&self) -> Option<Bytes> {
        self.inner.data.clone()
    }

    pub fn filesize(&self) -> Option<u64> {
        self.inner.filesize
    }

    pub fn blocksizes(&self) -> &[u64] {
        &self.inner.blocksizes
    }

    pub fn size(&self) -> Option<usize> {
        if self.outer.links.is_empty() {
            return Some(
                self.inner
                    .data
                    .as_ref()
                    .map(|d| d.len())
                    .unwrap_or_default(),
            );
        }

        None
    }

    pub fn links(&self) -> Links {
        Links::Node(PbLinks::new(&self.outer))
    }
}

impl UnixFsFile {
    pub fn empty() -> Self {
        UnixFsFile::Raw(Bytes::new())
    }

    pub async fn load(cid: Cid, store: &impl Blockstore) -> Result<Self> {
        let block = store
            .get(&cid)
            .await?
            .ok_or_else(|| BlockStoreError::CIDNotFound(cid))?;
        Self::decode(&cid, Bytes::from(block))
    }

    pub fn decode(cid: &Cid, buf: Bytes) -> Result<Self> {
        match cid.codec() {
            c if c == Codec::Raw as u64 => Ok(UnixFsFile::Raw(buf)),
            _ => {
                let outer = protobufs::PbNode::decode(buf)?;
                let inner_data = outer
                    .data
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| anyhow!("missing data"))?;
                let inner = protobufs::Data::decode(inner_data)?;
                let typ: DataType = inner.r#type.try_into()?;
                let node = Node { outer, inner };

                // ensure correct unixfs type
                match typ {
                    DataType::File => Ok(UnixFsFile::Node(node)),
                    _ => bail!("unixfs data type unsupported: {typ:?}"),
                }
            }
        }
    }

    pub fn encode(&self) -> Result<Block> {
        let res = match self {
            UnixFsFile::Raw(data) => {
                let out = data.clone();
                let links = vec![];
                Block::new(Codec::Raw, out, links)
            }
            UnixFsFile::Node(node) => {
                let out = node.encode()?;
                let links = node
                    .links()
                    .map(|x| Ok(x?.cid))
                    .collect::<Result<Vec<_>>>()?;
                Block::new(Codec::DagPb, out, links)
            }
        };

        ensure!(
            res.data().len() <= DEFAULT_CHUNK_SIZE_LIMIT,
            "node is too large: {} bytes",
            res.data().len()
        );

        Ok(res)
    }

    pub const fn typ(&self) -> Option<DataType> {
        match self {
            UnixFsFile::Raw(_) => None,
            UnixFsFile::Node(_) => Some(DataType::File),
        }
    }

    /// Returns the size in bytes of the underlying data.
    /// Available only for `Raw` and `File` which are a single block with no links.
    pub fn size(&self) -> Option<usize> {
        match self {
            UnixFsFile::Raw(data) => Some(data.len()),
            UnixFsFile::Node(node) => node.size(),
        }
    }

    /// Returns the filesize in bytes.
    /// Should only be set for `Raw` and `File`.
    pub fn filesize(&self) -> Option<u64> {
        match self {
            UnixFsFile::Raw(data) => Some(data.len() as u64),
            UnixFsFile::Node(node) => node.filesize(),
        }
    }

    /// Returns the blocksizes of the links
    /// Should only be set for File
    pub fn blocksizes(&self) -> &[u64] {
        match self {
            UnixFsFile::Raw(_) => &[],
            UnixFsFile::Node(node) => node.blocksizes(),
        }
    }

    pub fn links(&self) -> Links<'_> {
        match self {
            UnixFsFile::Raw(_) => Links::Leaf,
            UnixFsFile::Node(node) => Links::Node(PbLinks::new(&node.outer)),
        }
    }

    pub fn links_owned(&self) -> Result<VecDeque<Link>> {
        self.links().map(|l| l.map(|l| l.to_owned())).collect()
    }

    pub async fn get_link_by_name<S: AsRef<str>>(
        &self,
        link_name: S,
    ) -> Result<Option<LinkRef<'_>>> {
        let link_name = link_name.as_ref();
        self.links()
            .find(|l| match l {
                Ok(l) => l.name == Some(link_name),
                _ => false,
            })
            .transpose()
    }

    pub fn into_content_reader<B: Blockstore>(
        self,
        store: &B,
        pos_max: Option<usize>,
    ) -> Result<UnixFsFileReader<'_, B>> {
        let current_links = vec![self.links_owned()?];

        Ok(UnixFsFileReader {
            root_node: self,
            pos: 0,
            pos_max,
            current_node: CurrentNodeState::Outer,
            current_links,
            store,
        })
    }
}

impl Storable for UnixFsFile {
    type Serializable = UnixFsFile;

    async fn to_serializable(&self, _store: &impl Blockstore) -> Result<Self::Serializable> {
        Ok(self.clone())
    }

    async fn from_serializable(
        _cid: Option<&Cid>,
        serializable: Self::Serializable,
    ) -> Result<Self> {
        Ok(serializable)
    }
}

impl StoreIpld for UnixFsFile {
    fn encode_ipld(&self) -> Result<(Bytes, u64)> {
        let (codec, bytes, _) = self.encode()?.into_parts();
        Ok((bytes, codec.into()))
    }
}

impl LoadIpld for UnixFsFile {
    fn decode_ipld(cid: &Cid, bytes: Bytes) -> Result<Self> {
        UnixFsFile::decode(cid, bytes)
    }
}

#[derive(Debug)]
pub struct UnixFsFileReader<'a, B: Blockstore> {
    root_node: UnixFsFile,
    /// Absolute position in bytes
    pos: usize,
    /// Absolute max position in bytes, only used for clipping responses
    pos_max: Option<usize>,
    /// Current node being operated on, only used for nested nodes (not the root).
    current_node: CurrentNodeState<'a>,
    /// Stack of links left to traverse.
    current_links: Vec<VecDeque<Link>>,
    store: &'a B,
}

impl<'a, B: Blockstore> UnixFsFileReader<'a, B> {
    /// Returns the size in bytes, if known in advance.
    pub fn size(&self) -> Option<u64> {
        self.root_node.filesize()
    }
}

impl<'a, B: Blockstore + 'a> AsyncRead for UnixFsFileReader<'a, B> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let UnixFsFileReader {
            root_node,
            pos,
            pos_max,
            current_node,
            current_links,
            store,
        } = &mut *self;

        // let pos_old = *pos; Unused, see bytes_read below
        match root_node {
            UnixFsFile::Raw(data) => {
                read_data_to_buf(pos, *pos_max, &data[*pos..], buf);
                Poll::Ready(Ok(()))
            }
            UnixFsFile::Node(node) => poll_read_file_at(
                cx,
                node,
                *store,
                pos,
                *pos_max,
                buf,
                current_links,
                current_node,
            ),
        }
        // let bytes_read = *pos - pos_old; // Unused, used to be used for metrics
        // poll_res
    }
}

impl<'a, B: Blockstore + 'a> AsyncSeek for UnixFsFileReader<'a, B> {
    fn start_seek(mut self: Pin<&mut Self>, position: std::io::SeekFrom) -> std::io::Result<()> {
        let UnixFsFileReader {
            root_node,
            pos,
            current_node,
            current_links,
            ..
        } = &mut *self;
        let data_len = root_node.size();
        *current_node = CurrentNodeState::Outer;
        *current_links = vec![root_node.links_owned().unwrap()];
        match position {
            std::io::SeekFrom::Start(offset) => {
                let mut i = offset as usize;
                if let Some(data_len) = data_len {
                    if data_len == 0 {
                        *pos = 0;
                        return Ok(());
                    }
                    i = std::cmp::min(i, data_len - 1);
                }
                *pos = i;
            }
            std::io::SeekFrom::End(offset) => {
                if let Some(data_len) = data_len {
                    if data_len == 0 {
                        *pos = 0;
                        return Ok(());
                    }
                    let mut i = (data_len as i64 + offset) % data_len as i64;
                    if i < 0 {
                        i += data_len as i64;
                    }
                    *pos = i as usize;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot seek from end of unknown length",
                    ));
                }
            }
            std::io::SeekFrom::Current(offset) => {
                let mut i = *pos as i64 + offset;
                i = std::cmp::max(0, i);

                if let Some(data_len) = data_len {
                    if data_len == 0 {
                        *pos = 0;
                        return Ok(());
                    }
                    i = std::cmp::min(i, data_len as i64 - 1);
                }
                *pos = i as usize;
            }
        }
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.pos as u64))
    }
}

pub fn read_data_to_buf(
    pos: &mut usize,
    pos_max: Option<usize>,
    data: &[u8],
    buf: &mut tokio::io::ReadBuf<'_>,
) -> usize {
    let data_to_read = pos_max.map(|pos_max| pos_max - *pos).unwrap_or(data.len());
    let amt = std::cmp::min(std::cmp::min(data_to_read, buf.remaining()), data.len());
    buf.put_slice(&data[..amt]);
    *pos += amt;
    amt
}

pub fn find_block(node: &UnixFsFile, pos: u64, node_offset: u64) -> (u64, Option<usize>) {
    let pivots = node
        .blocksizes()
        .iter()
        .scan(node_offset, |state, &x| {
            *state += x;
            Some(*state)
        })
        .collect::<Vec<_>>();
    let block_index = match pivots.binary_search(&pos) {
        Ok(b) => b + 1,
        Err(b) => b,
    };
    if block_index < pivots.len() {
        let next_node_offset = if block_index > 0 {
            pivots[block_index - 1]
        } else {
            node_offset
        };
        (next_node_offset, Some(block_index))
    } else {
        (pivots[pivots.len() - 1], None)
    }
}

#[allow(clippy::large_enum_variant)]
pub enum CurrentNodeState<'a> {
    // Initial state
    Outer,
    // Need to load next node from the list
    NextNodeRequested {
        next_node_offset: usize,
    },
    // Node has been loaded and ready to be processed
    Loaded {
        node_offset: usize,
        node_pos: usize,
        node: UnixFsFile,
    },
    // Ongoing loading of the node
    Loading {
        node_offset: usize,
        fut: BoxFuture<'a, Result<UnixFsFile>>,
    },
}

impl<'a> Debug for CurrentNodeState<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurrentNodeState::Outer => write!(f, "CurrentNodeState::Outer"),
            CurrentNodeState::NextNodeRequested { next_node_offset } => {
                write!(f, "CurrentNodeState::None ({next_node_offset})")
            }
            CurrentNodeState::Loaded {
                node_offset,
                node_pos,
                node,
            } => {
                write!(
                    f,
                    "CurrentNodeState::Loaded({node_offset:?}, {node_pos:?}, {node:?})"
                )
            }
            CurrentNodeState::Loading { .. } => write!(f, "CurrentNodeState::Loading(Fut)"),
        }
    }
}

fn load_next_node<'a>(
    next_node_offset: usize,
    current_node: &mut CurrentNodeState<'a>,
    current_links: &mut Vec<VecDeque<Link>>,
    store: &'a impl Blockstore,
) -> bool {
    let links = loop {
        if let Some(last_mut) = current_links.last_mut() {
            if last_mut.is_empty() {
                // ignore empty links
                current_links.pop();
            } else {
                // found non empty links
                break last_mut;
            }
        } else {
            // no links left we are done
            return false;
        }
    };

    let link = links.pop_front().unwrap();

    *current_node = CurrentNodeState::Loading {
        node_offset: next_node_offset,
        fut: boxed_fut(UnixFsFile::load(link.cid, store)),
    };
    true
}

#[allow(clippy::too_many_arguments)]
fn poll_read_file_at<'a>(
    cx: &mut Context<'_>,
    root_node: &Node,
    store: &'a impl Blockstore,
    pos: &mut usize,
    pos_max: Option<usize>,
    buf: &mut tokio::io::ReadBuf<'_>,
    current_links: &mut Vec<VecDeque<Link>>,
    current_node: &mut CurrentNodeState<'a>,
) -> Poll<std::io::Result<()>> {
    loop {
        if let Some(pos_max) = pos_max {
            if pos_max <= *pos {
                return Poll::Ready(Ok(()));
            }
        }
        match current_node {
            CurrentNodeState::Outer => {
                // check for links
                if root_node.outer.links.is_empty() {
                    // simplest case just one file
                    let data = root_node.inner.data.as_deref().unwrap_or(&[][..]);
                    read_data_to_buf(pos, pos_max, &data[*pos..], buf);
                    return Poll::Ready(Ok(()));
                }

                // read root local data
                if let Some(ref data) = root_node.inner.data {
                    if *pos < data.len() {
                        read_data_to_buf(pos, pos_max, &data[*pos..], buf);
                        return Poll::Ready(Ok(()));
                    }
                }
                *current_node = CurrentNodeState::NextNodeRequested {
                    next_node_offset: 0,
                };
            }
            CurrentNodeState::NextNodeRequested { next_node_offset } => {
                let loaded_next_node =
                    load_next_node(*next_node_offset, current_node, current_links, store);
                if !loaded_next_node {
                    return Poll::Ready(Ok(()));
                }
            }
            CurrentNodeState::Loading { node_offset, fut } => {
                match fut.poll_unpin(cx) {
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(node)) => {
                        match node.links_owned() {
                            Ok(links) => {
                                if !links.is_empty() {
                                    let (next_node_offset, block_index) =
                                        find_block(&node, *pos as u64, *node_offset as u64);
                                    if let Some(block_index) = block_index {
                                        let new_links =
                                            links.into_iter().skip(block_index).collect();
                                        current_links.push(new_links);
                                    }
                                    *current_node = CurrentNodeState::NextNodeRequested {
                                        next_node_offset: next_node_offset as usize,
                                    }
                                } else {
                                    *current_node = CurrentNodeState::Loaded {
                                        node_offset: *node_offset,
                                        node_pos: *pos - *node_offset,
                                        node,
                                    }
                                }
                            }
                            Err(e) => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    e.to_string(),
                                )));
                            }
                        }
                        // TODO: do one read
                    }
                    Poll::Ready(Err(e)) => {
                        *current_node = CurrentNodeState::NextNodeRequested {
                            next_node_offset: *node_offset,
                        };
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                }
            }
            CurrentNodeState::Loaded {
                ref node_offset,
                ref mut node_pos,
                node: ref mut current_node_inner,
            } => match current_node_inner {
                UnixFsFile::Raw(data) => {
                    if *node_offset + data.len() <= *pos {
                        *current_node = CurrentNodeState::NextNodeRequested {
                            next_node_offset: node_offset + data.len(),
                        };
                        continue;
                    }
                    let bytes_read = read_data_to_buf(pos, pos_max, &data[*node_pos..], buf);
                    *node_pos += bytes_read;
                    return Poll::Ready(Ok(()));
                }
                UnixFsFile::Node(node) => {
                    if let Some(ref data) = node.inner.data {
                        if node_offset + data.len() <= *pos {
                            *current_node = CurrentNodeState::NextNodeRequested {
                                next_node_offset: node_offset + data.len(),
                            };
                            continue;
                        }
                        let bytes_read = read_data_to_buf(pos, pos_max, &data[*node_pos..], buf);
                        *node_pos += bytes_read;
                        return Poll::Ready(Ok(()));
                    }
                    *current_node = CurrentNodeState::NextNodeRequested {
                        next_node_offset: *node_offset,
                    };
                }
            },
        }
    }
}
