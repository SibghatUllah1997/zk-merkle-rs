//! Integration tests for naive multi-leaf inclusion proofs.

use merkle_tree::{verify_inclusion_many, verify_multiproof, MerkleTree};

#[test]
fn prove_many_matches_individual_proofs_for_small_trees() {
    for n in 1..=8 {
        let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let tree = MerkleTree::from_leaves(leaves.iter().map(|v| v.as_slice()));
        let root = tree.root().expect("root");

        let all = tree.prove_all();
        assert_eq!(all.len(), n);
        assert!(all.verify(root));
        assert!(verify_multiproof(&all, root));

        let pairs: Vec<(usize, &[u8])> = leaves
            .iter()
            .enumerate()
            .map(|(i, v)| (i, v.as_slice()))
            .collect();
        assert!(verify_inclusion_many(pairs, &all, root));

        for (i, item) in all.proofs.iter().enumerate() {
            assert_eq!(item.proof, tree.prove(i).unwrap());
        }
    }
}

#[test]
fn subset_multiproof_verifies_and_rejects_wrong_data() {
    let leaves = ["alpha", "beta", "gamma", "delta", "epsilon"];
    let tree = MerkleTree::from_leaves(leaves.map(|s| s.as_bytes()));
    let root = tree.root().expect("root");

    let multi = tree.prove_many([4, 1, 3]).expect("in range");
    assert_eq!(multi.indices(), vec![4, 1, 3]);
    assert!(multi.verify(root));
    assert!(verify_inclusion_many(
        [
            (4usize, b"epsilon".as_ref()),
            (1, b"beta".as_ref()),
            (3, b"delta".as_ref()),
        ],
        &multi,
        root
    ));

    assert!(!verify_inclusion_many(
        [
            (4usize, b"epsilon".as_ref()),
            (1, b"WRONG".as_ref()),
            (3, b"delta".as_ref()),
        ],
        &multi,
        root
    ));
    assert!(!verify_inclusion_many(
        [
            (1usize, b"beta".as_ref()),
            (4, b"epsilon".as_ref()),
            (3, b"delta".as_ref()),
        ],
        &multi,
        root
    ));
    assert!(!multi.verify([0u8; 32]));
}

#[test]
fn out_of_range_or_empty_requests() {
    let tree = MerkleTree::from_leaves(["a", "b"]);
    assert!(tree.prove_many([0, 2]).is_none());
    assert!(tree.prove_many([2]).is_none());
    let empty = tree
        .prove_many(core::iter::empty::<usize>())
        .expect("empty");
    assert!(empty.is_empty());
    assert!(verify_inclusion_many(
        core::iter::empty::<(usize, &[u8])>(),
        &empty,
        tree.root().unwrap()
    ));
}

#[test]
fn single_leaf_multiproof_is_the_leaf_hash() {
    let tree = MerkleTree::from_leaves(["solo"]);
    let root = tree.root().expect("root");
    let multi = tree.prove_many([0]).expect("in range");
    assert_eq!(multi.len(), 1);
    assert!(multi.proofs[0].proof.steps.is_empty());
    assert!(verify_inclusion_many(
        [(0usize, b"solo".as_ref())],
        &multi,
        root
    ));
}
