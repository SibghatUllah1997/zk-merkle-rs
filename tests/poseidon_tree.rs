//! Integration tests for Poseidon-backed trees and proofs.
#![cfg(feature = "poseidon")]

use merkle_tree::{
    hash_leaf_with, poseidon_hash_leaf, verify_inclusion_compact_with, verify_inclusion_many_with,
    verify_inclusion_with, HashAlgorithm, MerkleTree,
};

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

#[test]
fn poseidon_proofs_verify_for_every_leaf_and_size() {
    for n in 1..=9 {
        let data = leaves(n);
        let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Poseidon, &data).expect("p");
        let root = tree.root().expect("root");
        for (i, leaf) in data.iter().enumerate() {
            let proof = tree.prove(i).expect("in range");
            assert_eq!(proof.leaf_hash, poseidon_hash_leaf(leaf));
            assert_eq!(proof.verify_with(HashAlgorithm::Poseidon, root), Ok(true));
            assert_eq!(
                verify_inclusion_with(HashAlgorithm::Poseidon, leaf, &proof.steps, root),
                Ok(true)
            );
        }
    }
}

#[test]
fn poseidon_proofs_do_not_verify_as_sha256() {
    let data = leaves(4);
    let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Poseidon, &data).expect("p");
    let root = tree.root().expect("root");
    let proof = tree.prove(2).expect("in range");
    assert!(!proof.verify(root));
    assert_eq!(proof.verify_with(HashAlgorithm::Sha256, root), Ok(false));
    assert_eq!(
        verify_inclusion_with(HashAlgorithm::Poseidon, b"other", &proof.steps, root),
        Ok(false)
    );
}

#[test]
fn poseidon_multiproof_and_compact_check_leaf_data() {
    let data = leaves(6);
    let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Poseidon, &data).expect("p");
    let root = tree.root().expect("root");
    let multi = tree.prove_many([1, 4]).expect("in range");
    assert_eq!(multi.verify_with(HashAlgorithm::Poseidon, root), Ok(true));
    assert!(!multi.verify(root));

    let good = [(1, data[1].as_slice()), (4, data[4].as_slice())];
    assert_eq!(
        verify_inclusion_many_with(HashAlgorithm::Poseidon, good, &multi, root),
        Ok(true)
    );
    let bad = [(1, data[1].as_slice()), (4, b"tampered".as_slice())];
    assert_eq!(
        verify_inclusion_many_with(HashAlgorithm::Poseidon, bad, &multi, root),
        Ok(false)
    );

    let compact = tree.prove_compact([1, 4]).expect("in range");
    assert_eq!(compact.verify_with(HashAlgorithm::Poseidon, root), Ok(true));
    assert!(!compact.verify(root));
    assert_eq!(
        verify_inclusion_compact_with(HashAlgorithm::Poseidon, good, &compact, root),
        Ok(true)
    );
    assert_eq!(
        verify_inclusion_compact_with(HashAlgorithm::Poseidon, bad, &compact, root),
        Ok(false)
    );
}

#[test]
fn prehashed_poseidon_leaves_match_raw_constructor() {
    let data = leaves(5);
    let hashes: Vec<[u8; 32]> = data
        .iter()
        .map(|l| hash_leaf_with(HashAlgorithm::Poseidon, l).expect("p"))
        .collect();
    let from_raw = MerkleTree::try_from_leaves_with(HashAlgorithm::Poseidon, &data).expect("p");
    let from_hashed =
        MerkleTree::try_from_hashed_leaves_with(HashAlgorithm::Poseidon, hashes).expect("p");
    assert_eq!(from_raw.root(), from_hashed.root());
}
