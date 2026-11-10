//! Bare-metal smoke test for `merkle-tree`.
//!
//! This crate is `#![no_std]` and depends on `merkle-tree` with default
//! features off. CI builds it for `thumbv7em-none-eabihf`, a target that has
//! no `std` at all, so any accidental `std` use in the library (or in one of
//! its dependencies) fails the build instead of slipping through.
//!
//! The functions below touch the main public surface (tree, proofs,
//! multiproofs, the append-only log, chunking, and hex helpers). On the host
//! the same functions run as ordinary unit tests, so the smoke path is also
//! checked for correctness, not only for compiling.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use merkle_tree::{
    chunk_bytes, from_hex, parse_proof_steps, to_hex32, verify_inclusion, verify_inclusion_many,
    MerkleLog, MerkleTree,
};

/// Fixed input shared by every check, so results are deterministic.
const LEAVES: [&[u8]; 5] = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"];

/// Build a tree over [`LEAVES`] and return its root.
pub fn root_of_fixed_leaves() -> Option<[u8; 32]> {
    MerkleTree::from_leaves(LEAVES).root()
}

/// Prove and verify every leaf, both through the proof object and through the
/// free function that re-hashes the raw leaf bytes.
pub fn single_proofs_verify() -> bool {
    let tree = MerkleTree::from_leaves(LEAVES);
    let Some(root) = tree.root() else {
        return false;
    };
    LEAVES
        .iter()
        .enumerate()
        .all(|(i, leaf)| match tree.prove(i) {
            Some(proof) => proof.verify(root) && verify_inclusion(leaf, &proof.steps, root),
            None => false,
        })
}

/// A proof must survive a round trip through its compact text form, and must
/// stop verifying when checked against the wrong leaf.
pub fn proof_text_roundtrip() -> bool {
    let tree = MerkleTree::from_leaves(LEAVES);
    let (Some(root), Some(proof)) = (tree.root(), tree.prove(3)) else {
        return false;
    };
    let Ok(steps) = parse_proof_steps(&proof.steps_spec()) else {
        return false;
    };
    verify_inclusion(LEAVES[3], &steps, root) && !verify_inclusion(b"not-a-leaf", &steps, root)
}

/// Multiproof over a subset of indices, checked against the original bytes.
pub fn multiproof_verifies() -> bool {
    let tree = MerkleTree::from_leaves(LEAVES);
    let (Some(root), Some(multi)) = (tree.root(), tree.prove_many([0, 2, 4])) else {
        return false;
    };
    let picked = [(0, LEAVES[0]), (2, LEAVES[2]), (4, LEAVES[4])];
    multi.verify(root) && verify_inclusion_many(picked, &multi, root)
}

/// Grow a log one entry at a time; the final root must match a tree built in
/// one go, and every recorded checkpoint must still line up.
pub fn log_matches_tree() -> bool {
    let mut log = MerkleLog::new();
    for leaf in LEAVES {
        log.append(leaf);
    }
    log.root() == root_of_fixed_leaves()
        && log.checkpoints().len() == LEAVES.len()
        && log.history_matches()
}

/// Chunk a buffer into leaves and make sure the chunks rebuild the input.
pub fn chunking_roundtrip() -> bool {
    let data: Vec<u8> = (0u8..=200).collect();
    let Ok(chunks) = chunk_bytes(&data, 32) else {
        return false;
    };
    let rebuilt: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    let tree = MerkleTree::from_leaves(chunks.iter().copied());
    rebuilt == data && tree.leaf_count() == chunks.len() && tree.root().is_some()
}

/// Root hex encoding must decode back to the same bytes.
pub fn hex_roundtrip() -> bool {
    let Some(root) = root_of_fixed_leaves() else {
        return false;
    };
    matches!(from_hex(&to_hex32(&root)), Ok(bytes) if bytes.as_slice() == root.as_slice())
}

/// Run every check; handy as a single entry point for firmware-style callers.
pub fn run_all() -> bool {
    single_proofs_verify()
        && proof_text_roundtrip()
        && multiproof_verifies()
        && log_matches_tree()
        && chunking_roundtrip()
        && hex_roundtrip()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_stable() {
        assert_eq!(root_of_fixed_leaves(), root_of_fixed_leaves());
        assert!(root_of_fixed_leaves().is_some());
    }

    #[test]
    fn each_check_passes() {
        assert!(single_proofs_verify());
        assert!(proof_text_roundtrip());
        assert!(multiproof_verifies());
        assert!(log_matches_tree());
        assert!(chunking_roundtrip());
        assert!(hex_roundtrip());
    }

    #[test]
    fn run_all_passes() {
        assert!(run_all());
    }
}
