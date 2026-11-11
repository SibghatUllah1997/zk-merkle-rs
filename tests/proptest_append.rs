//! Property tests: appending leaves must match building from scratch.

use merkle_tree::MerkleTree;
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

fn leaves(max: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=32), 0..=max)
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn append_one_by_one_equals_fresh_build(items in leaves(16)) {
        let mut tree = MerkleTree::from_leaves(core::iter::empty::<Vec<u8>>());
        for (i, item) in items.iter().enumerate() {
            prop_assert_eq!(tree.append(item), i);
        }
        let fresh = MerkleTree::from_leaves(&items);
        prop_assert_eq!(tree.root(), fresh.root());
        prop_assert_eq!(tree.leaf_count(), fresh.leaf_count());
        prop_assert_eq!(tree.layer_count(), fresh.layer_count());
        prop_assert_eq!(tree.hash_count(), fresh.hash_count());
        prop_assert_eq!(tree.storage_bytes(), fresh.storage_bytes());
        for level in 0..tree.layer_count() {
            prop_assert_eq!(tree.layer_hashes(level), fresh.layer_hashes(level));
        }
    }

    #[test]
    fn extend_after_prefix_equals_fresh_build(prefix in leaves(8), suffix in leaves(8)) {
        let mut tree = MerkleTree::from_leaves(&prefix);
        tree.extend(&suffix);
        let all: Vec<Vec<u8>> = prefix.iter().chain(suffix.iter()).cloned().collect();
        prop_assert_eq!(tree.root(), MerkleTree::from_leaves(&all).root());
    }

    #[test]
    fn every_proof_verifies_after_appends(prefix in leaves(8), suffix in leaves(8)) {
        let mut tree = MerkleTree::from_leaves(&prefix);
        for item in &suffix {
            tree.append(item);
        }
        if let Some(root) = tree.root() {
            for i in 0..tree.leaf_count() {
                prop_assert!(tree.prove(i).expect("proof").verify(root));
            }
        }
    }
}
