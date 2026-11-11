//! Property tests for tree construction, leaf metadata, and inclusion proofs.

use merkle_tree::{
    hash_leaf, parse_proof_steps, verify_inclusion, verify_inclusion_many, MerkleRoot, MerkleTree,
};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

fn cfg() -> ProptestConfig {
    ProptestConfig {
        cases: 48,
        max_shrink_iters: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..ProptestConfig::default()
    }
}

fn leaf_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=48)
}

fn any_leaves() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(leaf_bytes(), 0..=16)
}

fn nonempty_leaves() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(leaf_bytes(), 1..=16)
}

/// Layer count is `1 + log2(next_power_of_two(n))` for a non-empty tree,
/// matching duplicate-last padding of odd layers.
fn expected_layer_count(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        n.next_power_of_two().trailing_zeros() as usize + 1
    }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn construction_counts_and_constructors_agree(leaves in any_leaves()) {
        let tree = MerkleTree::from_leaves(leaves.iter());
        let collected: MerkleTree = leaves.iter().map(|v| v.as_slice()).collect();
        let hashed = MerkleTree::from_hashed_leaves(leaves.iter().map(|l| hash_leaf(l)));

        prop_assert_eq!(tree.leaf_count(), leaves.len());
        prop_assert_eq!(tree.is_empty(), leaves.is_empty());
        prop_assert_eq!(tree.layer_count(), expected_layer_count(leaves.len()));
        prop_assert_eq!(tree.hash_count(), MerkleTree::stored_hash_count(leaves.len()));
        prop_assert_eq!(tree.hash_count(), collected.hash_count());
        prop_assert_eq!(tree.hash_count(), hashed.hash_count());
        prop_assert_eq!(tree.storage_bytes(), tree.hash_count() * 32);
        prop_assert_eq!(tree.root(), collected.root());
        prop_assert_eq!(tree.root(), hashed.root());
        prop_assert_eq!(tree.leaf_infos(), collected.leaf_infos());
        prop_assert_eq!(tree.leaf_infos(), hashed.leaf_infos());
        prop_assert!(tree.prove(leaves.len()).is_none());
        prop_assert_eq!(tree.root().is_none(), leaves.is_empty());

        if let Some(root) = tree.root() {
            let hex = tree.root_hex().expect("hex");
            prop_assert_eq!(hex.len(), 64);
            prop_assert_eq!(MerkleRoot::from_hex(&hex).expect("parse").0, root);
            prop_assert_eq!(tree.root_typed().map(|r| r.0), Some(root));
        }

        for (i, leaf) in leaves.iter().enumerate() {
            let info = tree.leaf_info(i).expect("leaf info");
            prop_assert_eq!(info.index, i);
            prop_assert_eq!(info.hash, hash_leaf(leaf));
            prop_assert_eq!(tree.leaf_hash_at(i), Some(info.hash));
        }
    }

    #[test]
    fn every_generated_proof_verifies(leaves in nonempty_leaves()) {
        let tree = MerkleTree::from_leaves(leaves.iter());
        let root = tree.root().expect("non-empty");
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).expect("in range");
            prop_assert_eq!(proof.leaf_hash, hash_leaf(leaf));
            prop_assert_eq!(proof.steps.len(), tree.layer_count() - 1);
            prop_assert!(proof.verify(root));
            prop_assert!(verify_inclusion(leaf, &proof.steps, root));

            let spec = proof.steps_spec();
            let parsed = parse_proof_steps(&spec).expect("roundtrip");
            prop_assert_eq!(&parsed, &proof.steps);

            let indexed = tree.prove_indexed(i).expect("indexed");
            prop_assert_eq!(indexed.index, i);
            prop_assert!(indexed.verify(root));
            prop_assert_eq!(indexed.leaf_hex(), proof.leaf_hex());
            prop_assert_eq!(indexed.steps(), proof.steps.as_slice());
        }
    }

    #[test]
    fn tampered_proof_or_wrong_leaf_is_rejected(
        leaves in nonempty_leaves(),
        other in leaf_bytes(),
        flip in any::<u8>()
    ) {
        let tree = MerkleTree::from_leaves(leaves.iter());
        let root = tree.root().expect("non-empty");
        let index = (flip as usize) % leaves.len();
        let proof = tree.prove(index).expect("in range");

        if other != leaves[index] {
            prop_assert!(!verify_inclusion(&other, &proof.steps, root));
        }

        let mut tampered = proof.clone();
        if tampered.steps.is_empty() {
            tampered.leaf_hash[0] ^= flip | 1;
        } else {
            let byte = usize::from(flip) % 32;
            tampered.steps[0].sibling[byte] ^= flip | 1;
        }
        prop_assert!(!tampered.verify(root));
    }

    #[test]
    fn parse_proof_steps_never_panics_on_arbitrary_text(
        text in prop::collection::vec(any::<u8>(), 0..=160)
            .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    ) {
        let _ = parse_proof_steps(&text);
    }

    #[test]
    fn naive_multiproof_matches_single_paths(
        leaves in nonempty_leaves(),
        picks in prop::collection::vec(any::<u8>(), 1..=8)
    ) {
        let tree = MerkleTree::from_leaves(leaves.iter());
        let root = tree.root().expect("non-empty");
        let n = leaves.len();
        let indices: Vec<usize> = picks.iter().map(|b| (*b as usize) % n).collect();
        let multi = tree.prove_many(indices.iter().copied()).expect("in range");
        prop_assert_eq!(multi.indices(), indices.clone());
        prop_assert!(multi.verify(root));

        let pairs: Vec<(usize, &[u8])> = indices
            .iter()
            .map(|&i| (i, leaves[i].as_slice()))
            .collect();
        prop_assert!(verify_inclusion_many(pairs, &multi, root));

        for (slot, &i) in indices.iter().enumerate() {
            prop_assert_eq!(&multi.proofs[slot].proof, &tree.prove(i).unwrap());
        }

        let all = tree.prove_all();
        prop_assert_eq!(all.len(), n);
        prop_assert!(all.verify(root));
    }

    #[test]
    fn contiguous_layers_cover_the_buffer_without_gaps(leaves in any_leaves()) {
        let tree = MerkleTree::from_leaves(leaves.iter());
        let n = leaves.len();
        prop_assert_eq!(tree.layer_len(tree.layer_count()), None);
        prop_assert!(tree.layer_hashes(tree.layer_count()).is_none());

        if n == 0 {
            prop_assert_eq!(tree.hash_count(), 0);
            prop_assert!(tree.layer_hashes(0).is_none());
            return Ok(());
        }

        let mut expected_len = n;
        let mut covered = 0usize;
        let mut previous_end: Option<usize> = None;
        for level in 0..tree.layer_count() {
            let layer = tree.layer_hashes(level).expect("in range");
            prop_assert_eq!(tree.layer_len(level), Some(expected_len));
            prop_assert_eq!(layer.len(), expected_len);
            let start = layer.as_ptr() as usize;
            if let Some(end) = previous_end {
                prop_assert_eq!(start, end);
            }
            previous_end = Some(start + layer.len() * 32);
            covered += layer.len();
            expected_len = (expected_len + 1) / 2;
        }
        prop_assert_eq!(covered, tree.hash_count());
        let root = tree.root().expect("root");
        let root_layer = tree.layer_hashes(tree.layer_count() - 1).expect("root layer");
        prop_assert_eq!(root_layer, core::slice::from_ref(&root));

        let leaf_layer = tree.layer_hashes(0).expect("leaves");
        for (i, leaf) in leaves.iter().enumerate() {
            prop_assert_eq!(leaf_layer[i], hash_leaf(leaf));
            prop_assert_eq!(tree.leaf_hash_at(i), Some(leaf_layer[i]));
        }
    }
}
