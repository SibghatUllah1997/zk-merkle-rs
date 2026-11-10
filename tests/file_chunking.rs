//! File-style chunking: split a buffer, build a tree, prove every chunk.

use merkle_tree::{chunk_bytes, chunk_count, verify_inclusion, MerkleTree};

#[test]
fn every_chunk_has_a_verifiable_inclusion_proof() {
    let data: Vec<u8> = (0u8..=200).collect();
    let chunk_size = 9usize;
    let chunks = chunk_bytes(&data, chunk_size).expect("size");
    assert_eq!(
        chunks.len(),
        chunk_count(data.len(), chunk_size).expect("size")
    );
    assert_eq!(chunks.concat(), data);

    let tree = MerkleTree::from_leaves(chunks.iter().copied());
    let root = tree.root().expect("root");
    assert_eq!(tree.leaf_count(), chunks.len());

    for (index, chunk) in chunks.iter().enumerate() {
        let proof = tree.prove(index).expect("in range");
        assert!(
            verify_inclusion(chunk, &proof.steps, root),
            "chunk {index} must verify"
        );
    }

    let last = chunks.last().copied().unwrap();
    assert!(last.len() <= chunk_size);
    assert!(!last.is_empty());
}

#[test]
fn empty_buffer_is_an_empty_tree() {
    let chunks = chunk_bytes(b"", 32).expect("size");
    let tree = MerkleTree::from_leaves(chunks.iter().copied());
    assert!(tree.is_empty());
    assert!(tree.root().is_none());
}

#[cfg(feature = "std")]
#[test]
fn reader_chunks_match_slice_chunks_and_the_tree() {
    use std::io::Cursor;

    use merkle_tree::chunk_reader;

    let data = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let from_slice = chunk_bytes(data, 5).expect("size");
    let from_reader = chunk_reader(Cursor::new(&data[..]), 5).expect("read");
    assert_eq!(from_reader.len(), from_slice.len());
    for (owned, borrowed) in from_reader.iter().zip(from_slice.iter()) {
        assert_eq!(owned.as_slice(), *borrowed);
    }

    let tree = MerkleTree::from_leaves(from_reader.iter());
    let root = tree.root().expect("root");
    let proof = tree.prove(0).expect("first");
    assert!(verify_inclusion(&from_reader[0], &proof.steps, root));
}
