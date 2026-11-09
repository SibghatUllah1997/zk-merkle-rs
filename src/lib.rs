//! merkle-tree: Educational SHA-256 Merkle tree with inclusion proofs.
//!
//! This crate provides a small, easy-to-read Merkle tree implementation with
//! explicit domain separation and a clear API for building trees and verifying
//! inclusion proofs.
//!
//! Quickstart:
//!
//! ```
//! use merkle_tree::{verify_inclusion, MerkleTree};
//!
//! let leaves = [b"a".as_ref(), b"b", b"c", b"d"];
//! let tree = MerkleTree::from_leaves(leaves);
//! let collected: MerkleTree = ["a", "b", "c", "d"].into_iter().collect();
//! assert_eq!(tree.root(), collected.root());
//! let root = tree.root().expect("root");
//!
//! // Create and verify a proof for the leaf at index 2 ("c")
//! let proof = tree.prove(2).expect("proof");
//! assert!(proof.verify(root));
//!
//! // Or verify using the free function with raw leaf data:
//! assert!(verify_inclusion(b"c", &proof.steps, root));
//!
//! // Naive multiproof: independent paths, no sibling sharing
//! let multi = tree.prove_many([0, 2]).expect("in range");
//! assert!(multi.verify(root));
//! ```
//!
//! Design choices:
//! - Leaf hash: H(0x00 || data)
//! - Internal node hash: H(0x01 || left || right)
//! - Odd layers are padded by duplicating the last element (except a single-leaf
//!   tree, whose root is exactly the leaf hash)
//! - Hash function: sha2::Sha256 (audited crate; no hand-rolled crypto)
//! - Multiproofs are a list of independent paths; overlapping siblings are not
//!   shared yet
//! - Poseidon and Rescue names exist behind feature flags but do not hash yet
//!
//! Layout:
//! - [`hashing`] — domain-separated SHA-256, hex helpers, and hash placeholders
//! - [`error`] — length, hex, proof-step, and placeholder-hash errors
//! - [`proof`] — inclusion proofs, naive multiproofs, and verification
//! - [`tree`] — [`MerkleTree`], [`MerkleRoot`], and leaf metadata

#![cfg_attr(not(feature = "std"), no_std)]

// When building without the `std` feature, child modules pull Vec/String from `alloc`.
#[cfg(not(feature = "std"))]
extern crate alloc;

/// Command-line demo: build a tree, print the root, prove and verify inclusion.
///
/// Available when the `std` feature is enabled (the crate default).
#[cfg(feature = "std")]
pub mod cli;

/// Recoverable conversion and parse errors.
pub mod error;
/// Domain-separated SHA-256 hashing, hex helpers, and hash placeholders.
pub mod hashing;
/// Inclusion proofs, compact L/R step encoding, and naive multiproofs.
pub mod proof;
/// Merkle tree construction, typed roots, and leaf metadata.
pub mod tree;

pub use error::{try_array32, HashNotImplemented, HexError, LengthError, ParseStepsError};
pub use hashing::{
    from_hex, hash_leaf, hash_leaf_with, hash_nodes, hash_nodes_with, to_hex, to_hex32,
    try_from_hex32, HashAlgorithm, LEAF_PREFIX, NODE_PREFIX,
};
#[cfg(feature = "poseidon")]
pub use hashing::{
    poseidon_hash_leaf, poseidon_hash_nodes, POSEIDON_LEAF_PREFIX, POSEIDON_NODE_PREFIX,
};
#[cfg(feature = "rescue")]
pub use hashing::{rescue_hash_leaf, rescue_hash_nodes, RESCUE_LEAF_PREFIX, RESCUE_NODE_PREFIX};
pub use proof::{
    parse_proof_steps, verify_inclusion, verify_inclusion_many, verify_multiproof, InclusionProof,
    IndexedInclusionProof, MultiProof, ProofStep, SiblingSide,
};
pub use tree::{LeafInfo, MerkleRoot, MerkleTree};
