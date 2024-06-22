use crate::{codecs::Codec, protobufs};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::{io::Cursor, pin::Pin};
use tokio::io::AsyncRead;
use wnfs_common::{
    blockstore::{block::Block as _, Blockstore},
    ipld_core::cid::Cid,
    Blake3Block,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    codec: Codec,
    data: Bytes,
    links: Vec<Cid>,
}

impl Block {
    pub fn new(codec: Codec, data: Bytes, links: Vec<Cid>) -> Self {
        Self { codec, data, links }
    }

    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn links(&self) -> &[Cid] {
        &self.links
    }

    pub fn raw_data_size(&self) -> Option<u64> {
        match self.codec {
            Codec::Raw => Some(self.data.len() as u64),
            _ => None,
        }
    }

    pub async fn store(&self, store: &impl Blockstore) -> Result<Cid> {
        let block = Blake3Block::new(self.codec.into(), self.data.clone());
        let cid = block.cid()?;
        store.put(block).await?;
        Ok(cid)
    }

    pub fn into_parts(self) -> (Codec, Bytes, Vec<Cid>) {
        (self.codec, self.data, self.links)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub cid: Cid,
    pub name: Option<String>,
    pub tsize: Option<u64>,
}

impl Link {
    pub fn as_ref(&self) -> LinkRef<'_> {
        LinkRef {
            cid: self.cid,
            name: self.name.as_deref(),
            tsize: self.tsize,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRef<'a> {
    pub cid: Cid,
    pub name: Option<&'a str>,
    pub tsize: Option<u64>,
}

impl LinkRef<'_> {
    pub fn to_owned(&self) -> Link {
        Link {
            cid: self.cid,
            name: self.name.map(|t| t.to_string()),
            tsize: self.tsize,
        }
    }
}

#[derive(Debug)]
pub enum Links<'a> {
    Leaf,
    Node(PbLinks<'a>),
}

#[derive(Debug)]
pub struct PbLinks<'a> {
    i: usize,
    outer: &'a protobufs::PbNode,
}

impl<'a> PbLinks<'a> {
    pub fn new(outer: &'a protobufs::PbNode) -> Self {
        PbLinks { i: 0, outer }
    }
}

impl<'a> Iterator for Links<'a> {
    type Item = Result<LinkRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Links::Leaf => None,
            Links::Node(links) => links.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Links::Leaf => (0, Some(0)),
            Links::Node(links) => links.size_hint(),
        }
    }
}

impl<'a> Iterator for PbLinks<'a> {
    type Item = Result<LinkRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i == self.outer.links.len() {
            return None;
        }

        let l = &self.outer.links[self.i];
        self.i += 1;

        let res = l
            .hash
            .as_ref()
            .ok_or_else(|| anyhow!("missing link"))
            .and_then(|c| {
                Ok(LinkRef {
                    cid: Cid::read_bytes(Cursor::new(c))?,
                    name: l.name.as_deref(),
                    tsize: l.tsize,
                })
            });

        Some(res)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.outer.links.len(), Some(self.outer.links.len()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub type BoxAsyncRead<'a> = Pin<Box<dyn AsyncRead + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxAsyncRead<'a> = Pin<Box<dyn AsyncRead + 'a>>;
