//! Optional serde support for Merkle sum leaves, roots, and proofs.
#![cfg(all(feature = "merkle_sum", feature = "serde"))]

use merkle_tree::proof::SiblingSide;
use merkle_tree::sum::{
    MerkleSumTree, SumAbsenceProof, SumInclusionProof, SumLeaf, SumMultiProof, SumNode,
    SumProofStep,
};

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}

fn leaf(id: u8, amount: u128) -> SumLeaf {
    SumLeaf::new([id; 32], amount)
}

#[test]
fn sum_leaf_json_roundtrip() {
    let original = leaf(0xab, 1_000);
    let back = roundtrip(&original);
    assert_eq!(back, original);
    assert_eq!(back.hash(), original.hash());
}

#[test]
fn sum_root_json_names_hash_and_sum() {
    let left = leaf(1, 40).node();
    let right = leaf(2, 2).node();
    let root = SumNode::parent(&left, &right).unwrap();
    let back = roundtrip(&root);
    assert_eq!(back, root);
    assert_eq!(back.sum, 42);

    let value = serde_json::to_value(root).unwrap();
    assert_eq!(value["sum"], 42);
    assert!(value.get("hash").is_some());
}

#[test]
fn sum_proof_json_roundtrip_still_verifies() {
    let leaves = [leaf(1, 40), leaf(2, 2), leaf(3, 8)];
    let tree = MerkleSumTree::from_leaves(leaves).unwrap();
    let root = tree.root_node().unwrap();
    let proof = tree.prove(2).unwrap();
    let back: SumInclusionProof = roundtrip(&proof);
    assert_eq!(back, proof);
    assert!(back.verify(&leaves[2], &root).is_ok());
    assert_eq!(roundtrip(&root), root);
}

#[test]
fn sum_proof_step_preserves_side_and_sibling_sum() {
    let step = SumProofStep {
        sibling: SumNode::new([7; 32], 99),
        side: SiblingSide::Left,
    };
    let back = roundtrip(&step);
    assert_eq!(back.side, SiblingSide::Left);
    assert_eq!(back.sibling.sum, 99);
    assert_eq!(back.sibling.hash, [7; 32]);
}

#[test]
fn sum_multiproof_json_roundtrip_still_verifies() {
    let leaves = [leaf(1, 40), leaf(2, 2), leaf(3, 8)];
    let tree = MerkleSumTree::from_leaves(leaves).unwrap();
    let root = tree.root_node().unwrap();
    let multi = tree.prove_many([0, 2]).unwrap();
    let back: SumMultiProof = roundtrip(&multi);
    assert_eq!(back, multi);
    assert!(back.verify(&root).is_ok());
    assert_eq!(back.indices(), vec![0, 2]);
}

#[test]
fn absence_proof_json_roundtrip_still_verifies() {
    let leaves = [leaf(1, 40), leaf(3, 2), leaf(5, 8)];
    let tree = MerkleSumTree::from_sorted_leaves(leaves).unwrap();
    let root = tree.root_node().unwrap();
    let proof = tree.prove_absent(&[2u8; 32]).unwrap();
    let back: SumAbsenceProof = roundtrip(&proof);
    assert_eq!(back, proof);
    assert!(back.verify(&root).is_ok());
}
