use crate::HashOutput;
use anyhow::Result;
use futures::{AsyncRead, AsyncReadExt};
use libipld::IpldCodec;
use rand_core::CryptoRngCore;
use serde::de::Visitor;
use std::fmt;

//--------------------------------------------------------------------------------------------------
// Type Definitions
//--------------------------------------------------------------------------------------------------

pub struct ByteArrayVisitor<const N: usize>;

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a byte array of length {N}")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes: [u8; N] = v.try_into().map_err(E::custom)?;
        Ok(bytes)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub fn error<T>(err: impl std::error::Error + Send + Sync + 'static) -> Result<T> {
    Err(err.into())
}

pub async fn read_fully(
    stream: &mut (impl AsyncRead + Unpin),
    buffer: &mut [u8],
) -> Result<(usize, bool)> {
    let mut bytes_read = 0;
    let mut done = false;
    loop {
        let bytes_read_in_iteration = stream.read(&mut buffer[bytes_read..]).await?;

        bytes_read += bytes_read_in_iteration;

        if bytes_read_in_iteration == 0 {
            done = true;
            break;
        }

        if bytes_read == buffer.len() {
            break;
        }
    }
    Ok((bytes_read, done))
}

/// Generates a random byte array of the given length.
///
/// # Examples
///
/// ```
/// use rand::thread_rng;
/// use wnfs_common::utils;
///
/// let rng = &mut thread_rng();
/// let bytes = utils::get_random_bytes::<32>(rng);
///
/// assert_eq!(bytes.len(), 32);
/// ```
pub fn get_random_bytes<const N: usize>(rng: &mut impl CryptoRngCore) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Creates a [`HashOutput`][HashOutput] ([u8; 32]) from a possibly incomplete slice.
///
/// If the slice is smaller than `HashOutput`, the remaining bytes are filled with zeros.
///
/// # Examples
///
/// ```
/// use wnfs_common::utils;
///
/// let digest = utils::to_hash_output(&[0xff, 0x22]);
///
/// assert_eq!(digest.len(), 32);
/// ```
///
/// [HashOutput]: crate::HashOutput
pub fn to_hash_output(bytes: &[u8]) -> HashOutput {
    let mut nibbles = [0u8; 32];
    nibbles[..bytes.len()].copy_from_slice(bytes);
    nibbles
}

/// Tries to convert a u64 value to IPLD codec.
pub fn u64_to_ipld(value: u64) -> Result<IpldCodec> {
    Ok(value.try_into()?)
}
