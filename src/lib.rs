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

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Encode bytes as lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Encode a 32-byte array as lowercase hex string.
pub fn to_hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Compute a leaf hash as H(0x00 || data).
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a parent/internal node hash as H(0x01 || left || right).
pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Direction of a sibling node in a proof step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingSide {
    Left,
    Right,
}

/// One step of an inclusion proof path: the sibling hash and its side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub side: SiblingSide,
}

/// Inclusion proof for a specific leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Hash of the original leaf data: H(0x00 || data)
    pub leaf_hash: [u8; 32],
    /// Ordered siblings from the leaf layer up to (but not including) the root.
    pub steps: Vec<ProofStep>,
}

impl InclusionProof {
    /// Verify this proof against an expected root.
    pub fn verify(&self, expected_root: [u8; 32]) -> bool {
        let mut acc = self.leaf_hash;
        for step in &self.steps {
            acc = match step.side {
                SiblingSide::Left => hash_nodes(&step.sibling, &acc),
                SiblingSide::Right => hash_nodes(&acc, &step.sibling),
            };
        }
        acc == expected_root
    }

    /// Leaf hash as lowercase hex.
    pub fn leaf_hex(&self) -> String {
        to_hex32(&self.leaf_hash)
    }

    /// Steps rendered as `Vec<(side, hex)>`, where side is `"L"` or `"R"`.
    pub fn steps_hex(&self) -> Vec<(char, String)> {
        self.steps
            .iter()
            .map(|s| {
                let side = match s.side {
                    SiblingSide::Left => 'L',
                    SiblingSide::Right => 'R',
                };
                (side, to_hex32(&s.sibling))
            })
            .collect()
    }
}

impl core::fmt::Display for InclusionProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "leaf={}, steps=[", to_hex32(&self.leaf_hash))?;
        for (i, step) in self.steps.iter().enumerate() {
            let side = match step.side {
                SiblingSide::Left => 'L',
                SiblingSide::Right => 'R',
            };
            write!(f, "{}:{}", side, to_hex32(&step.sibling))?;
            if i + 1 != self.steps.len() {
                write!(f, ", ")?;
            }
        }
        write!(f, "]")
    }
}

/// Minimal per-leaf metadata: the leaf's index and its hashed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafInfo {
    pub index: usize,
    pub hash: [u8; 32],
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
}

/// Verify an inclusion proof using the original leaf data and expected root.
pub fn verify_inclusion(leaf_data: &[u8], steps: &[ProofStep], expected_root: [u8; 32]) -> bool {
    let proof = InclusionProof {
        leaf_hash: hash_leaf(leaf_data),
        steps: steps.to_vec(),
    };
    proof.verify(expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    // Local helper retained for regression sanity.
    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(&mut s, "{:02x}", b).expect("write! to String never fails");
        }
        s
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
        assert!(!to_hex(&root).is_empty());
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
}
