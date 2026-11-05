#![no_main]

use libfuzzer_sys::fuzz_target;
use merkle_tree::{hash_leaf, verify_inclusion, MerkleTree};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        let tree = MerkleTree::from_leaves(core::iter::empty::<&[u8]>());
        assert!(tree.is_empty());
        assert!(tree.root().is_none());
        assert!(tree.prove(0).is_none());
        return;
    }

    // First byte picks a leaf count in 1..=16; the rest is split into that many chunks.
    let count = (usize::from(data[0]) % 16) + 1;
    let payload = &data[1..];
    if payload.is_empty() {
        return;
    }
    let chunk = ((payload.len() + count - 1) / count).max(1);
    let leaves: Vec<&[u8]> = payload.chunks(chunk).take(count).collect();

    let tree = MerkleTree::from_leaves(leaves.iter().copied());
    let hashed = MerkleTree::from_hashed_leaves(leaves.iter().map(|leaf| hash_leaf(leaf)));
    let root = tree.root().expect("non-empty tree");
    assert_eq!(hashed.root(), Some(root));
    assert_eq!(tree.leaf_count(), leaves.len());
    assert!(tree.prove(tree.leaf_count()).is_none());

    for (index, leaf) in leaves.iter().enumerate() {
        let proof = tree.prove(index).expect("index in range");
        assert_eq!(proof.leaf_hash, hash_leaf(leaf));
        assert!(proof.verify(root));
        assert!(verify_inclusion(leaf, &proof.steps, root));
        let indexed = tree.prove_indexed(index).expect("indexed");
        assert_eq!(indexed.index, index);
        assert!(indexed.verify(root));
    }
});
