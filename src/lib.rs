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
//! ```
//!
//! Design choices:
//! - Leaf hash: H(0x00 || data)
//! - Internal node hash: H(0x01 || left || right)
//! - Odd layers are padded by duplicating the last element (except a single-leaf
//!   tree, whose root is exactly the leaf hash)
//! - Hash function: sha2::Sha256 (audited crate; no hand-rolled crypto)
//!
//! Layout:
//! - [`hashing`] — domain-separated SHA-256 and hex helpers
//! - [`error`] — length, hex, and proof-step errors
//! - [`proof`] — inclusion proofs and verification
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
/// Domain-separated SHA-256 hashing and hex helpers for 32-byte digests.
pub mod hashing;
/// Inclusion proofs and compact L/R step encoding.
pub mod proof;
/// Merkle tree construction, typed roots, and leaf metadata.
pub mod tree;

pub use error::{try_array32, HexError, LengthError, ParseStepsError};
pub use hashing::{
    from_hex, hash_leaf, hash_nodes, to_hex, to_hex32, try_from_hex32, LEAF_PREFIX, NODE_PREFIX,
};
pub use proof::{
    parse_proof_steps, verify_inclusion, InclusionProof, IndexedInclusionProof, ProofStep,
    SiblingSide,
};
pub use tree::{LeafInfo, MerkleRoot, MerkleTree};
