//! Frozen absence-proof vector for a three-leaf sorted sum tree.
//!
//! Leaves are account ids `[1; 32]`, `[3; 32]`, `[5; 32]` with amounts 40, 8,
//! and 2 (total 50). A change to the `0x30`/`0x31` domain tags, parent
//! hashing, or the `kind=absent` text format will miss this vector.
#![cfg(feature = "merkle_sum")]

use merkle_tree::sum::{
    parse_sum_absent_text, sum_absent_to_text, MerkleSumTree, SumLeaf, SumNode,
};

/// Published root hash of [`frozen_tree`].
const FROZEN_ROOT_HEX: &str = "8e91b938c73aa0109cf6b715de61226498bd0072e72b0f3f8e61f3d96983a5af";

/// Root total of [`frozen_tree`].
const FROZEN_SUM: u128 = 50;

/// Absence proof for query `[2; 32]`, which sits between the first two leaves.
const FROZEN_MID_TEXT: &str = "\
kind=absent
account=0202020202020202020202020202020202020202020202020202020202020202
left.account=0101010101010101010101010101010101010101010101010101010101010101
left.amount=40
left.index=0
left.leaf_count=3
left.step=R:779e4b15b78015d9b26cd927dfbed5aa80c038d5a0e055c04d85b291f43ac158:8
left.step=R:46cb71a6934b7ceccd918c3852c1ad67e71df3c183faca377a64c651065c39f3:2
right.account=0303030303030303030303030303030303030303030303030303030303030303
right.amount=8
right.index=1
right.leaf_count=3
right.step=L:87c3d6a24580717f2bde2fb354fdd56ed2260df2cf088f5ecc0f2b50d47c440d:40
right.step=R:46cb71a6934b7ceccd918c3852c1ad67e71df3c183faca377a64c651065c39f3:2
";

fn frozen_tree() -> MerkleSumTree {
    MerkleSumTree::from_sorted_leaves([
        SumLeaf::new([1u8; 32], 40),
        SumLeaf::new([3u8; 32], 8),
        SumLeaf::new([5u8; 32], 2),
    ])
    .expect("sorted")
}

fn frozen_root() -> SumNode {
    let hash: [u8; 32] = merkle_tree::try_from_hex32(FROZEN_ROOT_HEX).expect("frozen hex");
    SumNode::new(hash, FROZEN_SUM)
}

#[test]
fn frozen_tree_still_has_that_root() {
    let root = frozen_tree().root_node().expect("non-empty");
    assert_eq!(root, frozen_root());
}

#[test]
fn prover_still_emits_the_mid_gap_text() {
    let proof = frozen_tree().prove_absent(&[2u8; 32]).expect("missing");
    assert_eq!(sum_absent_to_text(&proof), FROZEN_MID_TEXT);
}

#[test]
fn frozen_mid_gap_still_verifies() {
    let proof = parse_sum_absent_text(FROZEN_MID_TEXT).expect("parse");
    assert_eq!(proof.query, [2u8; 32]);
    assert!(proof.verify(&frozen_root()).is_ok());
}

#[test]
fn frozen_mid_gap_rejects_the_wrong_total() {
    let proof = parse_sum_absent_text(FROZEN_MID_TEXT).expect("parse");
    let mut wrong = frozen_root();
    wrong.sum = FROZEN_SUM - 1;
    assert!(proof.verify(&wrong).is_err());
    let mut wrong_hash = frozen_root();
    wrong_hash.hash[0] ^= 1;
    assert!(proof.verify(&wrong_hash).is_err());
}

#[test]
fn present_ids_are_not_in_the_frozen_file() {
    let tree = frozen_tree();
    assert!(tree.prove_absent(&[1u8; 32]).is_none());
    assert!(tree.prove_absent(&[3u8; 32]).is_none());
    assert!(tree.prove_absent(&[5u8; 32]).is_none());
}
