//! Cached proof generation must match the direct path for every tree shape.

use merkle_tree::{verify_inclusion, MerkleTree};
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

fn leaves() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=32), 0..=48)
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn cached_proofs_match_and_verify(leaves in leaves()) {
        let tree = MerkleTree::from_leaves(&leaves);
        let cache = tree.proof_index_cache();
        prop_assert_eq!(cache.len(), tree.hash_count());
        prop_assert_eq!(cache.prove_all(), tree.prove_all());
        if let Some(root) = tree.root() {
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = cache.prove(i).expect("in range");
                prop_assert_eq!(Some(proof.clone()), tree.prove(i));
                prop_assert!(verify_inclusion(leaf, &proof.steps, root));
                let positions = cache.sibling_positions(i).expect("in range");
                prop_assert_eq!(positions.len(), proof.steps.len());
            }
        }
        prop_assert!(cache.prove(leaves.len()).is_none());
    }

    #[test]
    fn sibling_positions_point_at_proof_hashes(leaves in leaves(), pick in any::<usize>()) {
        let tree = MerkleTree::from_leaves(&leaves);
        prop_assume!(!tree.is_empty());
        let cache = tree.proof_index_cache();
        let index = pick % tree.leaf_count();
        let proof = cache.prove(index).expect("in range");
        let positions = cache.sibling_positions(index).expect("in range");
        // Rebuild the flat buffer from the public layer slices.
        let flat: Vec<[u8; 32]> = (0..tree.layer_count())
            .flat_map(|l| tree.layer_hashes(l).unwrap().to_vec())
            .collect();
        for (step, pos) in proof.steps.iter().zip(&positions) {
            prop_assert_eq!(step.sibling, flat[*pos]);
        }
    }
}

#[test]
fn cache_tracks_rebuilt_tree_after_append() {
    let mut tree = MerkleTree::from_leaves(["a", "b", "c"]);
    let before = tree.proof_index_cache().len();
    tree.extend(["d", "e"]);
    // A fresh cache is required after mutation; the old one could not outlive
    // the borrow that `extend` needed.
    let cache = tree.proof_index_cache();
    assert_ne!(cache.len(), before);
    assert_eq!(cache.prove_all(), tree.prove_all());
    assert!(std::ptr::eq(cache.tree(), &tree));
}
