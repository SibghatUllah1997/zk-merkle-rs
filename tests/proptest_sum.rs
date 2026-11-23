//! Property tests for Merkle sum-tree totals and subtree sums.
#![cfg(feature = "merkle_sum")]

use std::collections::BTreeMap;

use merkle_tree::{MerkleSumTree, SumBuildError, SumLeaf, SumNode, SumProofError};
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

/// Distinct account ids in increasing order. Amounts stay small so parent
/// totals cannot overflow `u128`.
fn distinct_sorted_leaves() -> impl Strategy<Value = Vec<SumLeaf>> {
    prop::collection::btree_map(any::<u8>(), 0u128..=10_000, 1..=12).prop_map(|map| {
        map.into_iter()
            .map(|(id, amount)| SumLeaf::new([id; 32], amount))
            .collect()
    })
}

/// First repeated account id, matching [`MerkleSumTree::from_unique_leaves`].
fn first_duplicate(leaves: &[SumLeaf]) -> Option<(usize, usize, [u8; 32])> {
    let mut seen = BTreeMap::new();
    for (index, leaf) in leaves.iter().enumerate() {
        if let Some(&first) = seen.get(&leaf.account_id) {
            return Some((first, index, leaf.account_id));
        }
        seen.insert(leaf.account_id, index);
    }
    None
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

    #[test]
    fn tampered_leaf_amount_fails_verification(
        leaves in nonempty_leaves(),
        which in any::<prop::sample::Index>(),
    ) {
        let tree = MerkleSumTree::from_leaves(leaves.clone()).expect("small amounts fit");
        let root = tree.root_node().expect("non-empty");
        let i = which.index(leaves.len());
        let proof = tree.prove(i).expect("in range");
        prop_assert_eq!(proof.verify(&leaves[i], &root), Ok(()));

        let lie = SumLeaf::new(leaves[i].account_id, leaves[i].amount ^ 1);
        prop_assert_eq!(proof.verify(&lie, &root), Err(SumProofError::HashMismatch));
        prop_assert_ne!(lie.hash(), leaves[i].hash());
    }

    #[test]
    fn tampered_sibling_amount_fails_when_the_path_has_steps(
        leaves in prop::collection::vec(sum_leaf(), 2..=16),
        which in any::<prop::sample::Index>(),
        step in any::<prop::sample::Index>(),
    ) {
        let tree = MerkleSumTree::from_leaves(leaves.clone()).expect("small amounts fit");
        let root = tree.root_node().expect("non-empty");
        let i = which.index(leaves.len());
        let mut proof = tree.prove(i).expect("in range");
        prop_assume!(!proof.steps.is_empty());
        let j = step.index(proof.steps.len());
        proof.steps[j].sibling.sum ^= 1;
        prop_assert_eq!(
            proof.verify(&leaves[i], &root),
            Err(SumProofError::HashMismatch)
        );
    }

    #[test]
    fn unique_constructor_matches_from_leaves_or_names_the_first_duplicate(
        leaves in nonempty_leaves(),
    ) {
        match MerkleSumTree::from_unique_leaves(leaves.clone()) {
            Ok(tree) => {
                prop_assert!(first_duplicate(&leaves).is_none());
                let expected = MerkleSumTree::from_leaves(leaves).expect("small amounts fit");
                prop_assert_eq!(tree, expected);
            }
            Err(SumBuildError::Duplicate {
                account_id,
                first,
                second,
            }) => {
                let (want_first, want_second, want_id) =
                    first_duplicate(&leaves).expect("a repeated id");
                prop_assert_eq!(first, want_first);
                prop_assert_eq!(second, want_second);
                prop_assert_eq!(account_id, want_id);
                prop_assert!(first < second);
            }
            Err(other) => prop_assert!(false, "unexpected error {other:?}"),
        }
    }

    #[test]
    fn unique_constructor_rejects_an_inserted_copy(
        leaves in distinct_sorted_leaves(),
        src in any::<prop::sample::Index>(),
        dst in any::<prop::sample::Index>(),
    ) {
        let src_i = src.index(leaves.len());
        let dst_i = dst.index(leaves.len() + 1);
        let mut with_dup = leaves.clone();
        with_dup.insert(dst_i, leaves[src_i]);
        let err = MerkleSumTree::from_unique_leaves(with_dup).expect_err("copied account id");
        match err {
            SumBuildError::Duplicate { account_id, .. } => {
                prop_assert_eq!(account_id, leaves[src_i].account_id);
            }
            other => prop_assert!(false, "unexpected error {other:?}"),
        }
    }

    #[test]
    fn sorted_constructor_accepts_strictly_increasing_ids(leaves in distinct_sorted_leaves()) {
        let sorted = MerkleSumTree::from_sorted_leaves(leaves.clone()).expect("sorted");
        let unique = MerkleSumTree::from_unique_leaves(leaves.clone()).expect("unique");
        prop_assert_eq!(&sorted, &unique);
        prop_assert!(sorted.is_sorted_unique());
        for (i, leaf) in leaves.iter().enumerate() {
            prop_assert_eq!(sorted.binary_search(&leaf.account_id), Some(i));
            prop_assert_eq!(sorted.position(&leaf.account_id), Some(i));
        }
    }

    #[test]
    fn sorted_constructor_rejects_an_adjacent_swap(
        leaves in distinct_sorted_leaves(),
        which in any::<prop::sample::Index>(),
    ) {
        prop_assume!(leaves.len() >= 2);
        let i = which.index(leaves.len() - 1);
        let mut decreasing = leaves;
        decreasing.swap(i, i + 1);
        let err = MerkleSumTree::from_sorted_leaves(decreasing).expect_err("not increasing");
        prop_assert_eq!(err, SumBuildError::Unsorted { index: i + 1 });
    }
}
