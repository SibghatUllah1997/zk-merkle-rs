//! Split byte buffers into fixed-size Merkle-tree leaves.
//!
//! File-backed trees usually hash contiguous chunks rather than whole files.
//! This module only does the splitting; hashing and tree construction stay in
//! [`crate::hashing`] and [`crate::tree`].

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Rejected because a zero chunk size cannot partition a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSizeError;

impl core::fmt::Display for ChunkSizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("chunk size must be greater than zero")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChunkSizeError {}

/// Iterator over contiguous slices of at most `chunk_size` bytes.
///
/// The last item is shorter when the remaining length is not a multiple of the
/// chunk size. Empty input yields no items.
#[derive(Debug, Clone)]
pub struct Chunks<'a> {
    data: &'a [u8],
    chunk_size: usize,
}

impl<'a> Chunks<'a> {
    /// Walk `data` in slices of `chunk_size` bytes.
    pub fn new(data: &'a [u8], chunk_size: usize) -> Result<Self, ChunkSizeError> {
        if chunk_size == 0 {
            return Err(ChunkSizeError);
        }
        Ok(Self { data, chunk_size })
    }

    /// Size of each full chunk (the last yielded slice may be shorter).
    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Bytes not yet yielded.
    pub const fn remaining(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let n = core::cmp::min(self.chunk_size, self.data.len());
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Some(head)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match chunk_count(self.data.len(), self.chunk_size) {
            Ok(n) => (n, Some(n)),
            Err(_) => (0, Some(0)),
        }
    }
}

impl ExactSizeIterator for Chunks<'_> {}

impl core::iter::FusedIterator for Chunks<'_> {}

/// Number of chunks needed to cover `len` bytes at `chunk_size`.
///
/// Empty input needs zero chunks. `chunk_size == 0` is rejected.
pub fn chunk_count(len: usize, chunk_size: usize) -> Result<usize, ChunkSizeError> {
    if chunk_size == 0 {
        return Err(ChunkSizeError);
    }
    if len == 0 {
        return Ok(0);
    }
    Ok((len + chunk_size - 1) / chunk_size)
}

/// Split `data` into contiguous slices of at most `chunk_size` bytes.
///
/// The last slice is shorter when `data.len()` is not a multiple of
/// `chunk_size`. Empty input yields an empty vector.
///
/// ```
/// use merkle_tree::{chunk_bytes, verify_inclusion, MerkleTree};
///
/// let data = b"abcdefghijkl";
/// let chunks = chunk_bytes(data, 4).expect("size");
/// let tree = MerkleTree::from_leaves(chunks.iter().copied());
/// let root = tree.root().expect("root");
/// let proof = tree.prove(1).expect("proof");
/// assert!(verify_inclusion(b"efgh", &proof.steps, root));
/// ```
pub fn chunk_bytes(data: &[u8], chunk_size: usize) -> Result<Vec<&[u8]>, ChunkSizeError> {
    Ok(Chunks::new(data, chunk_size)?.collect())
}

/// Like [`chunk_bytes`], but copies each chunk into an owned buffer.
pub fn chunk_bytes_owned(data: &[u8], chunk_size: usize) -> Result<Vec<Vec<u8>>, ChunkSizeError> {
    Ok(Chunks::new(data, chunk_size)?
        .map(|chunk| chunk.to_vec())
        .collect())
}

/// Read `reader` into owned chunks of `chunk_size` bytes.
///
/// The last chunk is shorter when the stream length is not a multiple of
/// `chunk_size`. An empty stream yields no chunks. A zero `chunk_size`
/// returns [`std::io::ErrorKind::InvalidInput`]. Short reads and
/// [`std::io::ErrorKind::Interrupted`] are retried until a full chunk or EOF.
#[cfg(feature = "std")]
pub fn chunk_reader<R: std::io::Read>(
    mut reader: R,
    chunk_size: usize,
) -> std::io::Result<Vec<Vec<u8>>> {
    if chunk_size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            ChunkSizeError,
        ));
    }
    let mut out = Vec::new();
    loop {
        let mut buf = vec![0u8; chunk_size];
        let mut filled = 0usize;
        while filled < chunk_size {
            match reader.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
        if filled == 0 {
            break;
        }
        buf.truncate(filled);
        out.push(buf);
        if filled < chunk_size {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString, vec, vec::Vec};

    #[test]
    fn zero_size_is_rejected() {
        assert_eq!(Chunks::new(b"abc", 0).unwrap_err(), ChunkSizeError);
        assert_eq!(chunk_bytes(b"abc", 0).unwrap_err(), ChunkSizeError);
        assert_eq!(chunk_bytes_owned(b"abc", 0).unwrap_err(), ChunkSizeError);
        assert_eq!(chunk_count(8, 0).unwrap_err(), ChunkSizeError);
        assert_eq!(
            ChunkSizeError.to_string(),
            "chunk size must be greater than zero"
        );
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        assert!(chunk_bytes(b"", 4).unwrap().is_empty());
        assert!(chunk_bytes_owned(b"", 1).unwrap().is_empty());
        assert_eq!(chunk_count(0, 16).unwrap(), 0);
        assert_eq!(Chunks::new(b"", 8).unwrap().len(), 0);
    }

    #[test]
    fn exact_multiples_are_full_slices() {
        let data = b"abcdefgh";
        let chunks = chunk_bytes(data, 4).unwrap();
        assert_eq!(chunks, vec![&b"abcd"[..], &b"efgh"[..]]);
        assert_eq!(chunk_count(data.len(), 4).unwrap(), 2);
        assert_eq!(chunk_bytes(data, 8).unwrap(), vec![&data[..]]);
        assert_eq!(chunk_bytes(data, 1).unwrap().len(), 8);
    }

    #[test]
    fn remainder_is_a_short_final_chunk() {
        let data = b"hello!";
        let chunks = chunk_bytes(data, 4).unwrap();
        assert_eq!(chunks, vec![&b"hell"[..], &b"o!"[..]]);
        assert_eq!(chunk_count(data.len(), 4).unwrap(), 2);
        assert_eq!(chunk_bytes(b"abc", 4).unwrap(), vec![&b"abc"[..]]);
        assert_eq!(
            chunk_bytes(b"abcde", 2).unwrap().last().copied(),
            Some(&b"e"[..])
        );
    }

    #[test]
    fn owned_chunks_copy_bytes() {
        let data = b"xyz";
        let owned = chunk_bytes_owned(data, 2).unwrap();
        assert_eq!(owned, vec![b"xy".to_vec(), b"z".to_vec()]);
        assert_eq!(owned[0], b"xy");
    }

    #[test]
    fn iterator_is_fused_and_exact_size() {
        let mut chunks = Chunks::new(b"abcdefg", 3).unwrap();
        assert_eq!(chunks.chunk_size(), 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks.next(), Some(&b"abc"[..]));
        assert_eq!(chunks.remaining(), b"defg");
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks.next(), Some(&b"def"[..]));
        assert_eq!(chunks.next(), Some(&b"g"[..]));
        assert_eq!(chunks.next(), None);
        assert_eq!(chunks.next(), None);
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn chunks_cover_the_original_buffer() {
        let data = (0u8..=255).collect::<Vec<_>>();
        for size in 1..=64 {
            let joined: Vec<u8> = chunk_bytes(&data, size).unwrap().concat();
            assert_eq!(joined, data, "size {size}");
            assert_eq!(
                chunk_count(data.len(), size).unwrap(),
                chunk_bytes(&data, size).unwrap().len()
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn chunk_reader_matches_in_memory_split() {
        use std::io::{self, Cursor, Read};

        let data: Vec<u8> = (0..100).collect();
        let from_mem = chunk_bytes_owned(&data, 7).unwrap();
        let from_reader = chunk_reader(Cursor::new(&data), 7).unwrap();
        assert_eq!(from_reader, from_mem);
        assert!(chunk_reader(Cursor::new(&[] as &[u8]), 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            chunk_reader(Cursor::new(&data), 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        struct InterruptOnce<R> {
            inner: R,
            interrupted: bool,
        }
        impl<R: Read> Read for InterruptOnce<R> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.inner.read(buf)
            }
        }

        let retried = chunk_reader(
            InterruptOnce {
                inner: Cursor::new(&data),
                interrupted: false,
            },
            7,
        )
        .unwrap();
        assert_eq!(retried, from_mem);
    }
}
