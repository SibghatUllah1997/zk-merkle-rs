//! Integration tests for BLAKE3-backed trees and proofs.
#![cfg(feature = "blake3")]

use merkle_tree::{
    blake3_hash_leaf, hash_leaf_with, verify_inclusion_many_with, verify_inclusion_with,
    HashAlgorithm, MerkleTree,
};

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

#[test]
fn blake3_proofs_verify_for_every_leaf_and_size() {
    for n in 1..=9 {
        let data = leaves(n);
        let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, &data).expect("b3");
        let root = tree.root().expect("root");
        for (i, leaf) in data.iter().enumerate() {
            let proof = tree.prove(i).expect("in range");
            assert_eq!(proof.leaf_hash, blake3_hash_leaf(leaf));
            assert_eq!(proof.verify_with(HashAlgorithm::Blake3, root), Ok(true));
            assert_eq!(
                verify_inclusion_with(HashAlgorithm::Blake3, leaf, &proof.steps, root),
                Ok(true)
            );
        }
    }
}

#[test]
fn blake3_proofs_do_not_verify_as_sha256() {
    let data = leaves(4);
    let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, &data).expect("b3");
    let root = tree.root().expect("root");
    let proof = tree.prove(2).expect("in range");
    assert!(!proof.verify(root));
    assert_eq!(proof.verify_with(HashAlgorithm::Sha256, root), Ok(false));
    assert_eq!(
        verify_inclusion_with(HashAlgorithm::Blake3, b"other", &proof.steps, root),
        Ok(false)
    );
}

#[test]
fn blake3_multiproof_checks_leaf_data() {
    let data = leaves(6);
    let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, &data).expect("b3");
    let root = tree.root().expect("root");
    let multi = tree.prove_many([1, 4]).expect("in range");
    assert_eq!(multi.verify_with(HashAlgorithm::Blake3, root), Ok(true));
    assert!(!multi.verify(root));

    let good = [(1, data[1].as_slice()), (4, data[4].as_slice())];
    assert_eq!(
        verify_inclusion_many_with(HashAlgorithm::Blake3, good, &multi, root),
        Ok(true)
    );
    let bad = [(1, data[1].as_slice()), (4, b"tampered".as_slice())];
    assert_eq!(
        verify_inclusion_many_with(HashAlgorithm::Blake3, bad, &multi, root),
        Ok(false)
    );
}

#[test]
fn prehashed_blake3_leaves_match_raw_constructor() {
    let data = leaves(5);
    let hashes: Vec<[u8; 32]> = data
        .iter()
        .map(|l| hash_leaf_with(HashAlgorithm::Blake3, l).expect("b3"))
        .collect();
    let from_raw = MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, &data).expect("b3");
    let from_hashed =
        MerkleTree::try_from_hashed_leaves_with(HashAlgorithm::Blake3, hashes).expect("b3");
    assert_eq!(from_raw.root(), from_hashed.root());
}
