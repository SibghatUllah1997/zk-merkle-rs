//! merkle-tree: SHA-256 Merkle tree with inclusion proofs.
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
//!
//! // Compact multiproof: overlapping siblings stored once
//! let compact = tree.prove_compact([0, 2]).expect("in range");
//! assert!(compact.verify(root));
//! ```
//!
//! Design choices:
//! - Leaf hash: H(0x00 || data)
//! - Internal node hash: H(0x01 || left || right)
//! - Odd layers are padded by duplicating the last element (except a single-leaf
//!   tree, whose root is exactly the leaf hash)
//! - [`MerkleTree::committed_root`] binds the root to the leaf count, so a
//!   duplicated last leaf cannot pass as a different tree
//! - Hash function: sha2::Sha256 (audited crate; no hand-rolled crypto)
//! - Domain tags: [`DomainKind`] names the `0x00`/`0x01`/`0x02` prefixes and
//!   the reserved Poseidon/Rescue values
//! - Multiproofs are a list of independent paths; [`CompactMultiProof`]
//!   stores overlapping siblings once
//! - Poseidon (feature `poseidon`) is circom-compatible BN254 hashing; Rescue
//!   is still a placeholder
//! - Range proofs (feature `zk-range`) prove `0 <= amount < 2^64` with Halo 2
//! - Hashes are stored leaf-to-root in one buffer; see [`MerkleTree::hash_count`]
//!
//! Layout:
//! - [`hashing`] — domain-separated SHA-256, BLAKE3, Poseidon, and hex helpers
//! - [`error`] — length, hex, proof-step, and placeholder-hash errors
//! - [`proof`] — inclusion proofs, naive and compact multiproofs, verification
//! - [`tree`] — [`MerkleTree`], [`MerkleRoot`], and a contiguous hash buffer
//! - [`cache`] — [`ProofIndexCache`] for many proofs from one tree
//! - [`chunk`] — split byte buffers into fixed-size leaves
//! - [`log`] — append-only log with successive Merkle-root checkpoints
//! - [`features`] — which optional crate features this build compiled with
//! - `sum` (feature `merkle_sum`) — Merkle sum tree, inclusion proofs, a naive multi-account bundle (`prove_many`), sorted unique leaves, non-inclusion proofs, a published root bound to its leaf count (`commit_sum_root`), CSV leaves, layer totals, and serde-ready roots
//! - `solvency` (feature `merkle_sum`) — compare a published root and total with an independent liabilities snapshot, including whether account ids are strictly sorted
//! - `range` (feature `zk-range`) — 64-bit Halo 2 range-check circuit (`0 <= amount < 2^64`)
//! - `wasm` (feature `wasm`) — wasm-bindgen verifier for plain and sum-tree inclusion proofs
//!   and non-inclusion proofs (optional `verifyRangeProof` when `zk-range` is also enabled)

#![cfg_attr(not(feature = "std"), no_std)]

// When building without the `std` feature, child modules pull Vec/String from `alloc`.
#[cfg(not(feature = "std"))]
extern crate alloc;

/// Command-line demo: build a tree, print the root, prove and verify inclusion.
///
/// Available when the `std` feature is enabled (the crate default).
#[cfg(feature = "std")]
pub mod cli;

/// Cached parent/sibling positions for repeated proof generation.
pub mod cache;
/// Split byte buffers into fixed-size Merkle-tree leaves.
pub mod chunk;
/// Recoverable conversion and parse errors.
pub mod error;
/// Compile-time crate feature flags for this build.
pub mod features;
/// Domain-separated hashing, domain tags, hex helpers, and hash placeholders.
pub mod hashing;
/// Append-only log with successive Merkle-root checkpoints.
pub mod log;
/// Inclusion proofs, compact L/R step encoding, and multi-leaf proofs.
pub mod proof;
/// 64-bit Halo 2 range-check circuit for proof-of-reserves amounts.
#[cfg(feature = "zk-range")]
pub mod range;
/// Merkle sum tree, inclusion proofs, and CSV helpers for proof of reserves.
#[cfg(feature = "merkle_sum")]
pub mod solvency;
#[cfg(feature = "merkle_sum")]
pub mod sum;
/// Merkle tree construction, typed roots, and leaf metadata.
pub mod tree;
/// wasm-bindgen entry points that verify inclusion proofs in a browser.
#[cfg(feature = "wasm")]
pub mod wasm;

pub use cache::ProofIndexCache;
#[cfg(feature = "std")]
pub use chunk::chunk_reader;
pub use chunk::{chunk_bytes, chunk_bytes_owned, chunk_count, ChunkSizeError, Chunks};
pub use error::{
    try_array32, HashNotImplemented, HexError, LengthError, ParseStepsError, UnknownAlgorithm,
};
#[cfg(feature = "blake3")]
pub use hashing::{blake3_hash_leaf, blake3_hash_nodes};
pub use hashing::{
    commit_root, from_hex, hash_leaf, hash_leaf_with, hash_nodes, hash_nodes_with, to_hex,
    to_hex32, try_from_hex32, DomainKind, HashAlgorithm, LEAF_PREFIX, NODE_PREFIX,
    POSEIDON_LEAF_PREFIX, POSEIDON_NODE_PREFIX, RESCUE_LEAF_PREFIX, RESCUE_NODE_PREFIX,
    ROOT_COMMIT_PREFIX,
};
#[cfg(feature = "poseidon")]
pub use hashing::{poseidon_hash_leaf, poseidon_hash_nodes};
#[cfg(feature = "rescue")]
pub use hashing::{rescue_hash_leaf, rescue_hash_nodes};
pub use log::{LogCheckpoint, MerkleLog};
pub use proof::{
    parse_proof_steps, proof_depth, verify_compact, verify_inclusion, verify_inclusion_compact,
    verify_inclusion_compact_with, verify_inclusion_many, verify_inclusion_many_with,
    verify_inclusion_with, verify_multiproof, CompactMultiProof, InclusionProof,
    IndexedInclusionProof, MultiProof, ProofStep, SiblingSide,
};
#[cfg(feature = "zk-range")]
pub use range::{
    amount_in_range, generate_range_proof, verify_range_proof, RangeCheckCircuit, RangeProof,
    RangeProofError, RANGE_BITS, RANGE_K, RANGE_MAX,
};
#[cfg(feature = "merkle_sum")]
pub use solvency::{compare_liabilities, SolvencyError, SolvencyReport, TotalStatus};
#[cfg(feature = "merkle_sum")]
pub use sum::{
    commit_sum_root, parse_sum_absent_text, parse_sum_csv, parse_sum_multi_text,
    parse_sum_proof_text, sum_absent_to_text, sum_multi_to_text, sum_proof_to_text, AbsenceError,
    AccountId, MerkleSumTree, SumAbsenceNeighbor, SumAbsenceProof, SumBuildError, SumCsvError,
    SumInclusionProof, SumLeaf, SumMultiItem, SumMultiProof, SumNode, SumOverflow, SumProofError,
    SumProofStep, SumProofTextError,
};
pub use tree::{LeafInfo, MerkleRoot, MerkleTree};
