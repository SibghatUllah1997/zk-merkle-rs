//! Merkle sum leaf and node types through the public API.
#![cfg(feature = "merkle_sum")]

use merkle_tree::sum::{hash_sum_nodes, SUM_LEAF_PREFIX, SUM_NODE_PREFIX};
use merkle_tree::{SumLeaf, SumNode, SumOverflow};
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
