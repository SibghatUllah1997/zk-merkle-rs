//! Property tests for Merkle sum-tree totals and subtree sums.
#![cfg(feature = "merkle_sum")]

use merkle_tree::{MerkleSumTree, SumLeaf, SumNode};
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

fn nonempty_leaves() -> impl Strategy<Value = Vec<SumLeaf>> {
    prop::collection::vec(sum_leaf(), 1..=16)
}

/// Fold leaf amounts the same way the tree folds nodes: pair sums, promote an
/// odd leftover unchanged.
fn folded_layer_sums(amounts: &[u128]) -> Vec<Vec<u128>> {
    if amounts.is_empty() {
        return Vec::new();
    }
    let mut layer = amounts.to_vec();
    let mut layers = Vec::new();
    loop {
        layers.push(layer.clone());
        if layer.len() <= 1 {
            break;
        }
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut pairs = layer.chunks_exact(2);
        for pair in pairs.by_ref() {
            next.push(pair[0] + pair[1]);
        }
        if let Some(odd) = pairs.remainder().first() {
            next.push(*odd);
        }
        layer = next;
    }
    layers
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

    #[test]
    fn every_subtree_sum_matches_the_folded_leaf_amounts(leaves in nonempty_leaves()) {
        let amounts: Vec<u128> = leaves.iter().map(|leaf| leaf.amount).collect();
        let expected = folded_layer_sums(&amounts);
        let tree = MerkleSumTree::from_leaves(leaves.clone()).expect("small amounts fit");

        prop_assert_eq!(tree.layer_count(), expected.len());
        prop_assert_eq!(tree.layer_nodes(tree.layer_count()), None);

        for (level, sums) in expected.iter().enumerate() {
            let nodes = tree.layer_nodes(level).expect("in range");
            prop_assert_eq!(nodes.len(), sums.len(), "level {}", level);
            for (node, sum) in nodes.iter().zip(sums.iter()) {
                prop_assert_eq!(node.sum, *sum, "level {}", level);
            }
        }

        let leaf_layer = tree.layer_nodes(0).expect("non-empty");
        for (node, leaf) in leaf_layer.iter().zip(leaves.iter()) {
            prop_assert_eq!(node.sum, leaf.amount);
            prop_assert_eq!(*node, leaf.node());
        }
    }

    #[test]
    fn parent_layer_sums_are_checked_child_totals(leaves in nonempty_leaves()) {
        let tree = MerkleSumTree::from_leaves(leaves).expect("small amounts fit");
        for level in 0..tree.layer_count().saturating_sub(1) {
            let children = tree.layer_nodes(level).expect("child layer");
            let parents = tree.layer_nodes(level + 1).expect("parent layer");
            let mut pairs = children.chunks_exact(2);
            let mut parent_iter = parents.iter();
            for pair in pairs.by_ref() {
                let parent = parent_iter.next().expect("parent for pair");
                let rebuilt = SumNode::parent(&pair[0], &pair[1]).expect("fits");
                prop_assert_eq!(*parent, rebuilt);
                prop_assert_eq!(parent.sum, pair[0].sum + pair[1].sum);
            }
            if let Some(odd) = pairs.remainder().first() {
                let promoted = parent_iter.next().expect("promoted leftover");
                prop_assert_eq!(promoted, odd);
            }
            prop_assert!(parent_iter.next().is_none());
        }
    }
}
