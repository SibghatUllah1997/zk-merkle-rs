//! Merkle sum leaf and node types through the public API.
#![cfg(feature = "merkle_sum")]

use merkle_tree::sum::{
    commit_sum_root, hash_sum_nodes, SUM_LEAF_PREFIX, SUM_NODE_PREFIX, SUM_ROOT_COMMIT_PREFIX,
};
use merkle_tree::{MerkleSumTree, SumLeaf, SumNode, SumOverflow};
use proptest::prelude::*;

#[test]
fn four_accounts_fold_to_their_total() {
    let leaves = [
        SumLeaf::new([1; 32], 10),
        SumLeaf::new([2; 32], 20),
        SumLeaf::new([3; 32], 30),
        SumLeaf::new([4; 32], 40),
    ];
    let n: Vec<SumNode> = leaves.iter().map(SumLeaf::node).collect();
    let left = SumNode::parent(&n[0], &n[1]).unwrap();
    let right = SumNode::parent(&n[2], &n[3]).unwrap();
    let root = SumNode::parent(&left, &right).unwrap();
    assert_eq!(root.sum, 100);
    assert_eq!(root.hash, hash_sum_nodes(&left, &right));

    let tree = MerkleSumTree::from_leaves(leaves).unwrap();
    assert_eq!(tree.root(), Some((root.hash, 100)));
}

#[test]
fn odd_leaf_tree_root_sum_equals_the_leaves() {
    let leaves = [
        SumLeaf::new([1; 32], 40),
        SumLeaf::new([2; 32], 2),
        SumLeaf::new([3; 32], 8),
    ];
    let tree = MerkleSumTree::from_leaves(leaves).unwrap();
    let (hash, total) = tree.root().unwrap();
    assert_eq!(total, 50);
    let ab = SumNode::parent(&leaves[0].node(), &leaves[1].node()).unwrap();
    let expected = SumNode::parent(&ab, &leaves[2].node()).unwrap();
    assert_eq!((hash, total), (expected.hash, expected.sum));
    assert!(MerkleSumTree::from_leaves([]).unwrap().root().is_none());
}

#[test]
fn moving_balance_between_accounts_changes_root() {
    let a = SumLeaf::new([1; 32], 10).node();
    let b = SumLeaf::new([2; 32], 20).node();
    let a2 = SumLeaf::new([1; 32], 15).node();
    let b2 = SumLeaf::new([2; 32], 15).node();
    let r1 = SumNode::parent(&a, &b).unwrap();
    let r2 = SumNode::parent(&a2, &b2).unwrap();
    assert_eq!(r1.sum, r2.sum);
    assert_ne!(r1.hash, r2.hash);
}

#[test]
fn overflow_is_an_error() {
    let big = SumNode::new([0; 32], u128::MAX);
    let one = SumNode::new([0; 32], 1);
    let err: SumOverflow = SumNode::parent(&big, &one).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("sum {} + 1 overflows u128", u128::MAX)
    );
}

#[test]
fn prefixes_are_distinct() {
    assert_eq!(SUM_LEAF_PREFIX, 0x30);
    assert_eq!(SUM_NODE_PREFIX, 0x31);
    assert_eq!(SUM_ROOT_COMMIT_PREFIX, 0x32);
    assert_ne!(SUM_LEAF_PREFIX, SUM_ROOT_COMMIT_PREFIX);
    assert_ne!(SUM_NODE_PREFIX, SUM_ROOT_COMMIT_PREFIX);
}

#[test]
fn committed_wrap_is_not_the_bare_root_hash() {
    let tree = MerkleSumTree::from_leaves([
        SumLeaf::new([1; 32], 40),
        SumLeaf::new([2; 32], 2),
        SumLeaf::new([3; 32], 8),
    ])
    .unwrap();
    let root = tree.root_node().unwrap();
    let bound = commit_sum_root(&root, 3);
    assert_ne!(bound, root.hash);
    assert_eq!(bound, commit_sum_root(&root, tree.len() as u64));
    assert_ne!(bound, commit_sum_root(&root, 2));
}

proptest! {
    #[test]
    fn parent_sum_is_checked_add(l in any::<u128>(), r in any::<u128>()) {
        let a = SumNode::new([1; 32], l);
        let b = SumNode::new([2; 32], r);
        match l.checked_add(r) {
            Some(total) => prop_assert_eq!(SumNode::parent(&a, &b).unwrap().sum, total),
            None => prop_assert!(SumNode::parent(&a, &b).is_err()),
        }
    }

    #[test]
    fn any_amount_change_changes_leaf_hash(id in any::<[u8; 32]>(), x in any::<u128>(), y in any::<u128>()) {
        prop_assume!(x != y);
        prop_assert_ne!(SumLeaf::new(id, x).hash(), SumLeaf::new(id, y).hash());
    }
}
