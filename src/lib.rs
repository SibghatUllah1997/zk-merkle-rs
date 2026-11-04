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

#![cfg_attr(not(feature = "std"), no_std)]

// When building without the `std` feature, pull Vec and String from `alloc`.
#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

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

pub use error::{try_array32, HexError, LengthError, ParseStepsError};
pub use hashing::{
    from_hex, hash_leaf, hash_nodes, to_hex, to_hex32, try_from_hex32, LEAF_PREFIX, NODE_PREFIX,
};
pub use proof::{
    parse_proof_steps, verify_inclusion, InclusionProof, IndexedInclusionProof, ProofStep,
    SiblingSide,
};

/// Minimal per-leaf metadata: the leaf's index and its hashed value.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafInfo {
    pub index: usize,
    pub hash: [u8; 32],
}

/// Newtype wrapper for a Merkle root hash (32 bytes).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MerkleRoot(pub [u8; 32]);

impl MerkleRoot {
    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encode the root as a lowercase string.
    pub fn to_hex(&self) -> String {
        to_hex32(&self.0)
    }

    /// Decode a 32-byte root from a hex string (optional `0x` prefix).
    pub fn from_hex(input: &str) -> Result<Self, HexError> {
        try_from_hex32(input).map(MerkleRoot)
    }
}

impl From<[u8; 32]> for MerkleRoot {
    fn from(value: [u8; 32]) -> Self {
        MerkleRoot(value)
    }
}

impl AsRef<[u8; 32]> for MerkleRoot {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<MerkleRoot> for [u8; 32] {
    fn from(value: MerkleRoot) -> [u8; 32] {
        value.0
    }
}

impl<'a> core::convert::TryFrom<&'a [u8]> for MerkleRoot {
    type Error = LengthError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        try_array32(value).map(MerkleRoot)
    }
}

impl<'a> core::convert::TryFrom<&'a str> for MerkleRoot {
    type Error = HexError;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        MerkleRoot::from_hex(value)
    }
}

impl core::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A Merkle tree built using SHA-256 with explicit domain separation.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// layers[0] = leaf layer (hashed); layers.last()[0] = root
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a new tree from raw leaf data items.
    pub fn from_leaves<I, T>(leaves: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let leaf_hashes: Vec<[u8; 32]> =
            leaves.into_iter().map(|x| hash_leaf(x.as_ref())).collect();
        let mut layers = Vec::new();
        if leaf_hashes.is_empty() {
            // Represent an empty tree as zero layers.
            return Self { layers };
        }
        layers.push(leaf_hashes);
        // Build up layers to the root.
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity((prev.len() + 1) / 2);
            let mut i = 0;
            while i < prev.len() {
                let left = prev[i];
                let right = if i + 1 < prev.len() {
                    prev[i + 1]
                } else {
                    prev[i]
                };
                next.push(hash_nodes(&left, &right));
                i += 2;
            }
            layers.push(next);
        }
        Self { layers }
    }

    /// Number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.layers.first().map(|v| v.len()).unwrap_or(0)
    }

    /// Root hash of the tree. Returns None for an empty tree.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.layers.last().and_then(|l| l.first().cloned())
    }

    /// Root hash wrapped in `MerkleRoot`. Returns None for an empty tree.
    pub fn root_typed(&self) -> Option<MerkleRoot> {
        self.root().map(MerkleRoot)
    }

    /// Root hash formatted as lowercase hex. Returns None for an empty tree.
    pub fn root_hex(&self) -> Option<String> {
        self.root().map(|r| to_hex32(&r))
    }

    /// Return the hashed leaf at index, if present.
    pub fn leaf_hash_at(&self, index: usize) -> Option<[u8; 32]> {
        self.layers.first().and_then(|l| l.get(index).cloned())
    }

    /// Return leaf metadata (index + hash) at `index`, if present.
    pub fn leaf_info(&self, index: usize) -> Option<LeafInfo> {
        self.leaf_hash_at(index)
            .map(|hash| LeafInfo { index, hash })
    }

    /// Return metadata for all leaves (index + hash).
    pub fn leaf_infos(&self) -> Vec<LeafInfo> {
        match self.layers.first() {
            Some(layer0) => layer0
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, hash)| LeafInfo { index, hash })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Convenience: leaf infos rendered as `(index, hex_hash)` tuples.
    pub fn leaf_infos_hex(&self) -> Vec<(usize, String)> {
        self.leaf_infos()
            .into_iter()
            .map(|li| (li.index, to_hex32(&li.hash)))
            .collect()
    }

    /// Generate an inclusion proof for the leaf at `index`.
    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        if self.layers.is_empty() {
            return None;
        }
        if index >= self.layers[0].len() {
            return None;
        }
        let mut steps = Vec::new();
        let mut idx = index;
        for level in 0..self.layers.len().saturating_sub(1) {
            let layer = &self.layers[level];
            let is_right = idx % 2 == 1;
            let sib_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = if sib_idx < layer.len() {
                layer[sib_idx]
            } else {
                // odd padding: duplicate last
                layer[idx]
            };
            let side = if is_right {
                SiblingSide::Left
            } else {
                SiblingSide::Right
            };
            steps.push(ProofStep { sibling, side });
            idx /= 2;
        }
        let leaf_hash = self.layers[0][index];
        Some(InclusionProof { leaf_hash, steps })
    }

    /// Generate an inclusion proof with the original leaf `index` as metadata.
    pub fn prove_indexed(&self, index: usize) -> Option<IndexedInclusionProof> {
        self.prove(index)
            .map(|proof| IndexedInclusionProof { index, proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::ToString};

    #[test]
    fn merkle_root_try_from_slice_and_from_array() {
        let arr = [9u8; 32];
        let mr_from = MerkleRoot::from(arr);
        assert_eq!(*mr_from.as_bytes(), arr);
        let mr_try = MerkleRoot::try_from(arr.as_slice()).expect("try_from ok");
        assert_eq!(*mr_try.as_bytes(), arr);
        // trait conversions
        let arr_back: [u8; 32] = mr_try.into();
        assert_eq!(arr_back, arr);
        let mr_ref_slice: &[u8; 32] = mr_from.as_ref();
        assert_eq!(mr_ref_slice, &arr);
        // Wrong length should error
        let bad = [0u8; 31];
        assert!(MerkleRoot::try_from(&bad[..]).is_err());
    }

    #[test]
    fn root_and_proofs_even_leaves() {
        let leaves = ["a", "b", "c", "d"].map(|s| s.as_bytes().to_vec());
        let tree = MerkleTree::from_leaves(leaves);
        let root = tree.root().expect("root");
        // Roundtrip proofs for all positions
        for i in 0..tree.leaf_count() {
            let proof = tree.prove(i).expect("proof");
            assert!(proof.verify(root), "proof failed at index {i}");
        }
        // Basic sanity: non-empty hex string
        assert!(!to_hex32(&root).is_empty());
    }

    #[test]
    fn odd_leaf_padding_duplicate_last() {
        let leaves = ["a", "b", "c"].map(|s| s.as_bytes().to_vec());
        let tree = MerkleTree::from_leaves(leaves);
        assert_eq!(tree.leaf_count(), 3);
        let root = tree.root().unwrap();
        // Verify one proof
        let proof2 = tree.prove(2).unwrap();
        assert!(proof2.verify(root));
        // Verify via helper using raw data
        assert!(verify_inclusion(b"c", &proof2.steps, root));
    }

    #[test]
    fn inclusion_proof_display_and_hex_helpers() {
        let tree = MerkleTree::from_leaves(["a", "b", "c"].map(|s| s.as_bytes()));
        let root_hex = tree.root_hex().expect("root hex");
        assert_eq!(root_hex.len(), 64);
        let proof = tree.prove(1).expect("proof for index 1");
        // Check leaf_hex and steps_hex
        let leaf_hex = proof.leaf_hex();
        assert_eq!(leaf_hex.len(), 64);
        let steps_hex = proof.steps_hex();
        assert!(!steps_hex.is_empty());
        for (side, h) in steps_hex {
            assert!(side == 'L' || side == 'R');
            assert_eq!(h.len(), 64);
        }
        // Display should include leaf= and steps=[
        let s = proof.to_string();
        assert!(s.contains("leaf=") && s.contains("steps=["));
    }

    #[test]
    fn leaf_info_helpers_return_expected_metadata() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"].map(|s| s.as_bytes()));
        // leaf_info
        let li2 = tree.leaf_info(2).expect("leaf info at 2");
        assert_eq!(li2.index, 2);
        assert_eq!(li2.hash, hash_leaf(b"c"));
        assert!(tree.leaf_info(99).is_none());
        // leaf_infos (all)
        let all = tree.leaf_infos();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].index, 0);
        assert_eq!(all[0].hash, hash_leaf(b"a"));
        assert_eq!(all[3].index, 3);
        assert_eq!(all[3].hash, hash_leaf(b"d"));
        // hex helpers
        let hexes = tree.leaf_infos_hex();
        assert_eq!(hexes.len(), 4);
        // hex strings should be 64 chars
        for (i, h) in hexes {
            assert!(i < 4);
            assert_eq!(h.len(), 64);
        }
    }

    #[test]
    fn indexed_proof_carries_index_and_verifies() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"].map(|s| s.as_bytes()));
        let root = tree.root().unwrap();
        let idx = 2usize;
        let ip = tree.prove_indexed(idx).expect("indexed proof");
        assert_eq!(ip.index, idx);
        assert!(ip.verify(root));
        // convenience methods
        assert_eq!(ip.leaf_hex().len(), 64);
        assert_eq!(ip.steps().len(), ip.proof.steps.len());
    }

    #[test]
    fn merkle_root_newtype_hex_and_bytes() {
        let tree = MerkleTree::from_leaves(["a", "b", "c"].map(|s| s.as_bytes()));
        let raw = tree.root().expect("root");
        let typed = tree.root_typed().expect("typed root");
        assert_eq!(raw, *typed.as_bytes());
        assert_eq!(typed.to_hex(), to_hex32(&raw));
        assert_eq!(typed.to_string(), to_hex32(&raw));
    }

    #[test]
    fn try_from_hex32_and_merkle_root_from_hex() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"].map(|s| s.as_bytes()));
        let raw = tree.root().expect("root");
        let hex = to_hex32(&raw);
        assert_eq!(try_from_hex32(&hex).expect("32"), raw);
        assert_eq!(MerkleRoot::from_hex(&hex).expect("root").0, raw);
        assert_eq!(MerkleRoot::try_from(hex.as_str()).expect("try_from").0, raw);
        assert_eq!(
            MerkleRoot::from_hex(&format!("0x{hex}")).expect("0x").0,
            raw
        );

        assert!(matches!(
            try_from_hex32("abcd"),
            Err(HexError::UnexpectedLen {
                expected: 32,
                found: 2
            })
        ));
        assert!(MerkleRoot::from_hex("not-hex").is_err());
    }

    #[test]
    fn proof_steps_spec_roundtrips_and_verifies() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"].map(|s| s.as_bytes()));
        let proof = tree.prove(2).expect("proof");
        let spec = proof.steps_spec();
        let parsed = parse_proof_steps(&spec).expect("parse steps");
        assert_eq!(parsed, proof.steps);
        assert_eq!(proof.steps[0].to_string(), spec.split(',').next().unwrap());

        let rebuilt = InclusionProof {
            leaf_hash: proof.leaf_hash,
            steps: parsed,
        };
        assert!(rebuilt.verify(tree.root().unwrap()));

        // whitespace, lowercase side, empty path
        let with_space = parse_proof_steps(&format!(" {} ", spec.replace(',', ", "))).unwrap();
        assert_eq!(with_space, proof.steps);
        let lower = spec.replace('R', "r").replace('L', "l");
        assert_eq!(parse_proof_steps(&lower).unwrap(), proof.steps);
        assert!(parse_proof_steps("").unwrap().is_empty());
        assert!(parse_proof_steps("   ").unwrap().is_empty());

        let single = MerkleTree::from_leaves(["only"].map(|s| s.as_bytes()));
        assert!(single.prove(0).unwrap().steps_spec().is_empty());
    }
}
