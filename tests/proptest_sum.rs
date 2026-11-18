//! Property tests for Merkle sum-tree totals and subtree sums.
#![cfg(feature = "merkle_sum")]

use merkle_tree::{MerkleSumTree, SumLeaf};
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

fn sum_leaf() -> impl Strategy<Value = SumLeaf> {
    (any::<u8>(), 0u128..=10_000).prop_map(|(id, amount)| SumLeaf::new([id; 32], amount))
}

fn any_leaves() -> impl Strategy<Value = Vec<SumLeaf>> {
    prop::collection::vec(sum_leaf(), 0..=16)
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn root_sum_equals_the_sum_of_leaves(leaves in any_leaves()) {
        let expected: u128 = leaves.iter().map(|leaf| leaf.amount).sum();
        let tree = MerkleSumTree::from_leaves(leaves).expect("small amounts fit");
        match tree.root() {
            None => prop_assert!(tree.is_empty()),
            Some((_, total)) => {
                prop_assert_eq!(total, expected);
                prop_assert_eq!(tree.root_node().map(|n| n.sum), Some(expected));
            }
        }
    }
}
