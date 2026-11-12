//! Inclusion proofs: sibling steps, verification, and compact L/R hex encoding.
//!
//! A proof is the leaf hash plus the ordered sibling hashes from that leaf up
//! to (but not including) the root. Each step records whether the sibling sits
//! on the left or the right so the verifier can rebuild the same parent hashes.
//!
//! [`MultiProof`] is a naive bundle of those single-leaf paths. Overlapping
//! siblings are repeated. [`CompactMultiProof`] stores each shared sibling
//! once and records the tree's leaf count so a verifier can apply the same
//! duplicate-last padding the tree used.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::error::HashNotImplemented;
use crate::error::ParseStepsError;
use crate::hashing::{commit_root, to_hex32, try_from_hex32, HashAlgorithm, TreeHasher};

/// Direction of a sibling node in a proof step.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingSide {
    Left,
    Right,
}

impl SiblingSide {
    /// Compact label used in proof-step specs: `L` or `R`.
    pub const fn as_char(self) -> char {
        match self {
            SiblingSide::Left => 'L',
            SiblingSide::Right => 'R',
        }
    }

    /// Parse `L`/`l` or `R`/`r`.
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "L" | "l" => Some(SiblingSide::Left),
            "R" | "r" => Some(SiblingSide::Right),
            _ => None,
        }
    }
}

/// One step of an inclusion proof path: the sibling hash and its side.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub side: SiblingSide,
}

impl ProofStep {
    /// Parse a single `L:<32-byte hex>` or `R:<32-byte hex>` token.
    pub fn parse(token: &str) -> Result<Self, ParseStepsError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(ParseStepsError::EmptyToken);
        }
        let (side_str, hex_str) =
            token
                .split_once(':')
                .ok_or_else(|| ParseStepsError::MissingColon {
                    token: String::from(token),
                })?;
        let side = SiblingSide::from_label(side_str).ok_or_else(|| ParseStepsError::BadSide {
            found: String::from(side_str),
        })?;
        let sibling = try_from_hex32(hex_str)?;
        Ok(ProofStep { sibling, side })
    }
}

impl core::fmt::Display for ProofStep {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.side.as_char(), to_hex32(&self.sibling))
    }
}

/// Parse a comma-separated proof path such as `R:ab..cd,L:ef..`.
///
/// Empty input (after trim) is a valid empty path, matching a single-leaf tree.
pub fn parse_proof_steps(spec: &str) -> Result<Vec<ProofStep>, ParseStepsError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(Vec::new());
    }
    let mut steps = Vec::new();
    for token in spec.split(',') {
        steps.push(ProofStep::parse(token)?);
    }
    Ok(steps)
}

/// Number of steps in every inclusion proof for a tree of `leaf_count`
/// leaves: `ceil(log2(leaf_count))`, and zero for zero or one leaf.
///
/// ```
/// use merkle_tree::proof_depth;
///
/// assert_eq!(proof_depth(1), 0);
/// assert_eq!(proof_depth(2), 1);
/// assert_eq!(proof_depth(5), 3);
/// assert_eq!(proof_depth(8), 3);
/// ```
pub const fn proof_depth(leaf_count: usize) -> usize {
    if leaf_count <= 1 {
        0
    } else {
        (usize::BITS - (leaf_count - 1).leading_zeros()) as usize
    }
}

/// Inclusion proof for a specific leaf.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Hash of the original leaf data: H(0x00 || data)
    pub leaf_hash: [u8; 32],
    /// Ordered siblings from the leaf layer up to (but not including) the root.
    pub steps: Vec<ProofStep>,
}

impl InclusionProof {
    /// Verify this SHA-256 proof against an expected root.
    pub fn verify(&self, expected_root: [u8; 32]) -> bool {
        self.verify_inner(TreeHasher::Sha256, expected_root)
    }

    /// Verify this proof against `expected_root` using `algorithm`.
    ///
    /// Returns `Err` only for placeholder algorithms with no implementation.
    pub fn verify_with(
        &self,
        algorithm: HashAlgorithm,
        expected_root: [u8; 32],
    ) -> Result<bool, HashNotImplemented> {
        Ok(self.verify_inner(TreeHasher::new(algorithm)?, expected_root))
    }

    pub(crate) fn verify_inner(&self, hasher: TreeHasher, expected_root: [u8; 32]) -> bool {
        let mut acc = self.leaf_hash;
        for step in &self.steps {
            acc = match step.side {
                SiblingSide::Left => hasher.nodes(&step.sibling, &acc),
                SiblingSide::Right => hasher.nodes(&acc, &step.sibling),
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
            .map(|s| (s.side.as_char(), to_hex32(&s.sibling)))
            .collect()
    }

    /// Compact comma-separated step list, e.g. `R:ab..,L:cd..`.
    ///
    /// This is the inverse of [`parse_proof_steps`].
    pub fn steps_spec(&self) -> String {
        let mut out = String::new();
        for (i, step) in self.steps.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push(step.side.as_char());
            out.push(':');
            out.push_str(&to_hex32(&step.sibling));
        }
        out
    }
}

impl core::fmt::Display for InclusionProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "leaf={}, steps=[", to_hex32(&self.leaf_hash))?;
        for (i, step) in self.steps.iter().enumerate() {
            write!(f, "{step}")?;
            if i + 1 != self.steps.len() {
                write!(f, ", ")?;
            }
        }
        write!(f, "]")
    }
}

/// Inclusion proof carrying the original leaf index as metadata.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedInclusionProof {
    pub index: usize,
    pub proof: InclusionProof,
}

impl IndexedInclusionProof {
    /// Verify this SHA-256 proof against an expected root.
    pub fn verify(&self, expected_root: [u8; 32]) -> bool {
        self.proof.verify(expected_root)
    }

    /// Verify this proof against `expected_root` using `algorithm`.
    pub fn verify_with(
        &self,
        algorithm: HashAlgorithm,
        expected_root: [u8; 32],
    ) -> Result<bool, HashNotImplemented> {
        self.proof.verify_with(algorithm, expected_root)
    }

    /// Strictly verify this SHA-256 proof against a [`commit_root`]
    /// commitment for a tree of `leaf_count` leaves.
    ///
    /// On top of rebuilding the root, this checks that `index < leaf_count`,
    /// that the proof has exactly [`proof_depth`] steps, and that every
    /// step's side matches the bits of `index`. A proof for the right leaf
    /// therefore cannot be replayed at another position or with a padded
    /// copy of the last leaf.
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_leaves(["a", "b", "c"]);
    /// let commitment = tree.committed_root().expect("root");
    /// let proof = tree.prove_indexed(2).expect("proof");
    /// assert!(proof.verify_committed(commitment, 3));
    /// assert!(!proof.verify_committed(commitment, 4));
    /// ```
    pub fn verify_committed(&self, commitment: [u8; 32], leaf_count: usize) -> bool {
        self.verify_committed_inner(TreeHasher::Sha256, commitment, leaf_count)
    }

    /// Like [`Self::verify_committed`], hashing the path with `algorithm`.
    pub fn verify_committed_with(
        &self,
        algorithm: HashAlgorithm,
        commitment: [u8; 32],
        leaf_count: usize,
    ) -> Result<bool, HashNotImplemented> {
        Ok(self.verify_committed_inner(TreeHasher::new(algorithm)?, commitment, leaf_count))
    }

    fn verify_committed_inner(
        &self,
        hasher: TreeHasher,
        commitment: [u8; 32],
        leaf_count: usize,
    ) -> bool {
        if self.index >= leaf_count || self.proof.steps.len() != proof_depth(leaf_count) {
            return false;
        }
        let mut idx = self.index;
        let mut acc = self.proof.leaf_hash;
        for step in &self.proof.steps {
            let expected_side = if idx % 2 == 1 {
                SiblingSide::Left
            } else {
                SiblingSide::Right
            };
            if step.side != expected_side {
                return false;
            }
            acc = match step.side {
                SiblingSide::Left => hasher.nodes(&step.sibling, &acc),
                SiblingSide::Right => hasher.nodes(&acc, &step.sibling),
            };
            idx /= 2;
        }
        commit_root(&acc, leaf_count as u64) == commitment
    }

    /// Leaf hash as lowercase hex.
    pub fn leaf_hex(&self) -> String {
        self.proof.leaf_hex()
    }

    /// Borrow the ordered proof steps.
    pub fn steps(&self) -> &[ProofStep] {
        &self.proof.steps
    }
}

/// Naive multi-leaf inclusion proof: one independent path per requested leaf.
///
/// Sibling hashes are not shared across leaves. Verification is exactly
/// "every contained [`IndexedInclusionProof`] verifies against the same root".
/// Overlapping paths can be compressed later without changing this type's
/// meaning.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MultiProof {
    /// Per-leaf proofs, in the order the caller requested them.
    pub proofs: Vec<IndexedInclusionProof>,
}

impl MultiProof {
    /// Number of single-leaf proofs in this bundle.
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// `true` when no leaves were requested.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Leaf indices covered by this bundle, in caller order.
    pub fn indices(&self) -> Vec<usize> {
        self.proofs.iter().map(|item| item.index).collect()
    }

    /// Verify every contained proof against the same expected root.
    ///
    /// An empty bundle is treated as vacuously true for any root.
    pub fn verify(&self, expected_root: [u8; 32]) -> bool {
        self.verify_inner(TreeHasher::Sha256, expected_root)
    }

    /// Verify every contained proof against `expected_root` using `algorithm`.
    pub fn verify_with(
        &self,
        algorithm: HashAlgorithm,
        expected_root: [u8; 32],
    ) -> Result<bool, HashNotImplemented> {
        Ok(self.verify_inner(TreeHasher::new(algorithm)?, expected_root))
    }

    fn verify_inner(&self, hasher: TreeHasher, expected_root: [u8; 32]) -> bool {
        self.proofs
            .iter()
            .all(|item| item.proof.verify_inner(hasher, expected_root))
    }
}

impl core::fmt::Display for MultiProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "count={}, proofs=[", self.proofs.len())?;
        for (i, item) in self.proofs.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "index={}, {}", item.index, item.proof)?;
        }
        write!(f, "]")
    }
}

/// How a known node at one layer relates to its sibling.
///
/// Compact proof generation and verification walk layers with the same
/// pairing rule: sorted known indices, duplicate-last padding, and one
/// consumed sibling hash whenever the sibling is not already known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompactSibling {
    /// Odd last node: the missing sibling is a copy of this node.
    DuplicatePad,
    /// The next known index is this node's sibling; hash both together.
    KnownPair,
    /// The sibling is not among the known indices; it comes from the tree
    /// (prover) or from the compact sibling list (verifier).
    External,
}

/// Classify `index` against the next sorted known index at a layer of
/// `layer_len` hashes.
pub(crate) fn classify_compact_sibling(
    index: usize,
    next_known: Option<usize>,
    layer_len: usize,
) -> CompactSibling {
    let sibling = index ^ 1;
    if sibling >= layer_len {
        CompactSibling::DuplicatePad
    } else if next_known == Some(sibling) {
        CompactSibling::KnownPair
    } else {
        CompactSibling::External
    }
}

/// Sort `indices`, drop duplicates, and reject anything `>= leaf_count`.
pub(crate) fn unique_sorted_indices<I>(indices: I, leaf_count: usize) -> Option<Vec<usize>>
where
    I: IntoIterator<Item = usize>,
{
    let mut out: Vec<usize> = indices.into_iter().collect();
    for &index in &out {
        if index >= leaf_count {
            return None;
        }
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Compact multi-leaf inclusion proof: shared siblings stored once.
///
/// `indices` are unique and sorted. `leaves[i]` is the leaf hash at
/// `indices[i]`. `siblings` is the extra hashes a verifier needs, in the
/// order a bottom-up walk consumes them. `leaf_count` is the size of the
/// tree the proof was built from, so odd layers pad the same way.
///
/// An empty index list is a vacuous proof: it makes no claims. Proving every
/// leaf yields an empty sibling list, because every parent is determined by
/// the provided leaves.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompactMultiProof {
    /// Number of leaves in the tree this proof was generated from.
    pub leaf_count: usize,
    /// Sorted unique leaf indices covered by this proof.
    pub indices: Vec<usize>,
    /// Leaf hashes matching [`Self::indices`].
    pub leaves: Vec<[u8; 32]>,
    /// Sibling hashes consumed left-to-right, leaf layer toward the root.
    pub siblings: Vec<[u8; 32]>,
}

impl CompactMultiProof {
    /// Number of leaves covered by this proof.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// `true` when no leaves are claimed.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Borrow the sorted unique indices.
    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    /// Number of extra sibling hashes stored in this proof.
    pub fn sibling_count(&self) -> usize {
        self.siblings.len()
    }

    /// Leaf hashes as lowercase hex, in index order.
    pub fn leaves_hex(&self) -> Vec<String> {
        self.leaves.iter().map(to_hex32).collect()
    }

    /// Sibling hashes as lowercase hex, in consumption order.
    pub fn siblings_hex(&self) -> Vec<String> {
        self.siblings.iter().map(to_hex32).collect()
    }

    /// `true` when indices are unique, sorted, in range, and match `leaves`.
    fn structure_ok(&self) -> bool {
        if self.indices.len() != self.leaves.len() {
            return false;
        }
        for (i, &index) in self.indices.iter().enumerate() {
            if index >= self.leaf_count {
                return false;
            }
            if i > 0 && self.indices[i - 1] >= index {
                return false;
            }
        }
        true
    }

    /// Verify this SHA-256 compact proof against an expected root.
    ///
    /// An empty index list is treated as vacuously true for any root.
    pub fn verify(&self, expected_root: [u8; 32]) -> bool {
        self.verify_inner(TreeHasher::Sha256, expected_root)
    }

    /// Verify this compact proof against `expected_root` using `algorithm`.
    pub fn verify_with(
        &self,
        algorithm: HashAlgorithm,
        expected_root: [u8; 32],
    ) -> Result<bool, HashNotImplemented> {
        Ok(self.verify_inner(TreeHasher::new(algorithm)?, expected_root))
    }

    pub(crate) fn verify_inner(&self, hasher: TreeHasher, expected_root: [u8; 32]) -> bool {
        if !self.structure_ok() {
            return false;
        }
        if self.indices.is_empty() {
            return true;
        }

        let mut known_idx = self.indices.clone();
        let mut known_hash = self.leaves.clone();
        let mut sib_pos = 0usize;
        let mut layer_len = self.leaf_count;

        while layer_len > 1 {
            let mut parents_idx = Vec::with_capacity(known_idx.len());
            let mut parents_hash = Vec::with_capacity(known_idx.len());
            let mut i = 0;
            while i < known_idx.len() {
                let idx = known_idx[i];
                if idx >= layer_len {
                    return false;
                }
                let hash = known_hash[i];
                let next = known_idx.get(i + 1).copied();
                let parent_hash = match classify_compact_sibling(idx, next, layer_len) {
                    CompactSibling::DuplicatePad => hasher.nodes(&hash, &hash),
                    CompactSibling::KnownPair => {
                        let right = known_hash[i + 1];
                        i += 1;
                        hasher.nodes(&hash, &right)
                    }
                    CompactSibling::External => {
                        let Some(&sibling) = self.siblings.get(sib_pos) else {
                            return false;
                        };
                        sib_pos += 1;
                        if idx % 2 == 1 {
                            hasher.nodes(&sibling, &hash)
                        } else {
                            hasher.nodes(&hash, &sibling)
                        }
                    }
                };
                let parent = idx / 2;
                if parents_idx.last().copied() == Some(parent) {
                    return false;
                }
                parents_idx.push(parent);
                parents_hash.push(parent_hash);
                i += 1;
            }
            known_idx = parents_idx;
            known_hash = parents_hash;
            layer_len = (layer_len + 1) / 2;
        }

        sib_pos == self.siblings.len() && known_hash.len() == 1 && known_hash[0] == expected_root
    }
}

impl core::fmt::Display for CompactMultiProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "leaf_count={}, leaves={}, siblings={}, indices=[",
            self.leaf_count,
            self.leaves.len(),
            self.siblings.len()
        )?;
        for (i, index) in self.indices.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{index}")?;
        }
        write!(f, "]")
    }
}

/// Verify a naive multiproof against an expected root.
pub fn verify_multiproof(proof: &MultiProof, expected_root: [u8; 32]) -> bool {
    proof.verify(expected_root)
}

/// Verify a compact multiproof against an expected root.
pub fn verify_compact(proof: &CompactMultiProof, expected_root: [u8; 32]) -> bool {
    proof.verify(expected_root)
}

/// Verify that each `(index, leaf_data)` pair hashes to the compact proof's
/// claimed leaf and that the proof reconstructs `expected_root`.
///
/// Indices may arrive in any order. Duplicates, extras, missing leaves, or a
/// hash mismatch all fail. An empty iterator matches an empty proof.
pub fn verify_inclusion_compact<'a, I>(
    leaves: I,
    proof: &CompactMultiProof,
    expected_root: [u8; 32],
) -> bool
where
    I: IntoIterator<Item = (usize, &'a [u8])>,
{
    verify_inclusion_compact_inner(TreeHasher::Sha256, leaves, proof, expected_root)
}

/// Like [`verify_inclusion_compact`], but hashes leaves and nodes with `algorithm`.
pub fn verify_inclusion_compact_with<'a, I>(
    algorithm: HashAlgorithm,
    leaves: I,
    proof: &CompactMultiProof,
    expected_root: [u8; 32],
) -> Result<bool, HashNotImplemented>
where
    I: IntoIterator<Item = (usize, &'a [u8])>,
{
    let hasher = TreeHasher::new(algorithm)?;
    Ok(verify_inclusion_compact_inner(
        hasher,
        leaves,
        proof,
        expected_root,
    ))
}

fn verify_inclusion_compact_inner<'a, I>(
    hasher: TreeHasher,
    leaves: I,
    proof: &CompactMultiProof,
    expected_root: [u8; 32],
) -> bool
where
    I: IntoIterator<Item = (usize, &'a [u8])>,
{
    let mut provided: Vec<(usize, [u8; 32])> = leaves
        .into_iter()
        .map(|(index, data)| (index, hasher.leaf(data)))
        .collect();
    provided.sort_unstable_by_key(|(index, _)| *index);
    if provided.len() != proof.indices.len() {
        return false;
    }
    for (slot, (index, hash)) in provided.iter().enumerate() {
        if *index != proof.indices[slot] || *hash != proof.leaves[slot] {
            return false;
        }
    }
    proof.verify_inner(hasher, expected_root)
}

/// Verify that each `(index, leaf_data)` pair matches the corresponding
/// multiproof entry (same index and `hash_leaf`) and that the bundle
/// verifies against `expected_root`.
///
/// The iterator must yield the same number of items as `proof`, in the same
/// order. Extra, missing, or reordered items fail.
pub fn verify_inclusion_many<'a, I>(leaves: I, proof: &MultiProof, expected_root: [u8; 32]) -> bool
where
    I: IntoIterator<Item = (usize, &'a [u8])>,
{
    verify_inclusion_many_inner(TreeHasher::Sha256, leaves, proof, expected_root)
}

/// Like [`verify_inclusion_many`], but hashes leaves and nodes with `algorithm`.
pub fn verify_inclusion_many_with<'a, I>(
    algorithm: HashAlgorithm,
    leaves: I,
    proof: &MultiProof,
    expected_root: [u8; 32],
) -> Result<bool, HashNotImplemented>
where
    I: IntoIterator<Item = (usize, &'a [u8])>,
{
    let hasher = TreeHasher::new(algorithm)?;
    Ok(verify_inclusion_many_inner(
        hasher,
        leaves,
        proof,
        expected_root,
    ))
}

fn verify_inclusion_many_inner<'a, I>(
    hasher: TreeHasher,
    leaves: I,
    proof: &MultiProof,
    expected_root: [u8; 32],
) -> bool
where
    I: IntoIterator<Item = (usize, &'a [u8])>,
{
    let mut count = 0usize;
    for (index, data) in leaves {
        let entry = match proof.proofs.get(count) {
            Some(entry) => entry,
            None => return false,
        };
        if entry.index != index {
            return false;
        }
        if entry.proof.leaf_hash != hasher.leaf(data) {
            return false;
        }
        count += 1;
    }
    if count != proof.proofs.len() {
        return false;
    }
    proof.verify_inner(hasher, expected_root)
}

/// Verify an inclusion proof using the original leaf data and expected root.
pub fn verify_inclusion(leaf_data: &[u8], steps: &[ProofStep], expected_root: [u8; 32]) -> bool {
    verify_inclusion_inner(TreeHasher::Sha256, leaf_data, steps, expected_root)
}

/// Like [`verify_inclusion`], but hashes the leaf and path with `algorithm`.
pub fn verify_inclusion_with(
    algorithm: HashAlgorithm,
    leaf_data: &[u8],
    steps: &[ProofStep],
    expected_root: [u8; 32],
) -> Result<bool, HashNotImplemented> {
    let hasher = TreeHasher::new(algorithm)?;
    Ok(verify_inclusion_inner(
        hasher,
        leaf_data,
        steps,
        expected_root,
    ))
}

fn verify_inclusion_inner(
    hasher: TreeHasher,
    leaf_data: &[u8],
    steps: &[ProofStep],
    expected_root: [u8; 32],
) -> bool {
    let proof = InclusionProof {
        leaf_hash: hasher.leaf(leaf_data),
        steps: steps.to_vec(),
    };
    proof.verify_inner(hasher, expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::{hash_leaf, hash_nodes};
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, string::ToString, vec, vec::Vec};

    use crate::error::HexError;
    use crate::hashing::to_hex32;

    fn two_leaf_proof() -> (InclusionProof, [u8; 32]) {
        let left = hash_leaf(b"a");
        let right = hash_leaf(b"b");
        let root = hash_nodes(&left, &right);
        let proof = InclusionProof {
            leaf_hash: left,
            steps: vec![ProofStep {
                sibling: right,
                side: SiblingSide::Right,
            }],
        };
        (proof, root)
    }

    #[test]
    fn sibling_side_labels_roundtrip() {
        assert_eq!(SiblingSide::Left.as_char(), 'L');
        assert_eq!(SiblingSide::Right.as_char(), 'R');
        assert_eq!(SiblingSide::from_label("L"), Some(SiblingSide::Left));
        assert_eq!(SiblingSide::from_label("r"), Some(SiblingSide::Right));
        assert_eq!(SiblingSide::from_label("X"), None);
    }

    #[test]
    fn handmade_two_leaf_proof_verifies_and_rejects_tampering() {
        let (proof, root) = two_leaf_proof();
        assert!(proof.verify(root));
        assert!(verify_inclusion(b"a", &proof.steps, root));
        assert!(!verify_inclusion(b"nope", &proof.steps, root));

        let mut bad = proof.clone();
        bad.steps[0].sibling = hash_leaf(b"zzz");
        assert!(!bad.verify(root));

        let spec = proof.steps_spec();
        assert_eq!(parse_proof_steps(&spec).unwrap(), proof.steps);
        assert_eq!(proof.steps[0].to_string(), spec);
        assert!(proof.to_string().contains("leaf="));
        assert_eq!(proof.leaf_hex(), to_hex32(&proof.leaf_hash));
        assert_eq!(
            proof.steps_hex(),
            vec![('R', to_hex32(&proof.steps[0].sibling))]
        );
    }

    #[test]
    fn empty_path_is_the_single_leaf_root() {
        let leaf = hash_leaf(b"solo");
        let proof = InclusionProof {
            leaf_hash: leaf,
            steps: Vec::new(),
        };
        assert!(proof.verify(leaf));
        assert!(parse_proof_steps("").unwrap().is_empty());
        assert!(parse_proof_steps("   ").unwrap().is_empty());
        assert!(proof.steps_spec().is_empty());
    }

    #[test]
    fn parse_proof_steps_rejects_malformed_tokens() {
        assert!(matches!(
            parse_proof_steps(","),
            Err(ParseStepsError::EmptyToken)
        ));
        assert!(matches!(
            ProofStep::parse("no-colon"),
            Err(ParseStepsError::MissingColon { .. })
        ));
        assert!(matches!(
            ProofStep::parse("X:00"),
            Err(ParseStepsError::BadSide { .. })
        ));
        assert!(matches!(
            ProofStep::parse("L:abcd"),
            Err(ParseStepsError::Hex(HexError::UnexpectedLen { .. }))
        ));
        let msg = ParseStepsError::BadSide {
            found: String::from("X"),
        }
        .to_string();
        assert!(msg.contains('X'));
        let with_space = parse_proof_steps(&format!(" {} ", two_leaf_proof().0.steps_spec()));
        assert!(with_space.is_ok());
    }

    #[test]
    fn empty_multiproof_is_vacuous_and_displays() {
        let proof = MultiProof::default();
        assert!(proof.is_empty());
        assert_eq!(proof.len(), 0);
        assert!(proof.indices().is_empty());
        assert!(proof.verify([0u8; 32]));
        assert!(verify_multiproof(&proof, [0xff; 32]));
        assert_eq!(proof.to_string(), "count=0, proofs=[]");
    }

    #[test]
    fn handmade_multiproof_verifies_each_leaf() {
        let left = hash_leaf(b"a");
        let right = hash_leaf(b"b");
        let root = hash_nodes(&left, &right);
        let proof = MultiProof {
            proofs: vec![
                IndexedInclusionProof {
                    index: 0,
                    proof: InclusionProof {
                        leaf_hash: left,
                        steps: vec![ProofStep {
                            sibling: right,
                            side: SiblingSide::Right,
                        }],
                    },
                },
                IndexedInclusionProof {
                    index: 1,
                    proof: InclusionProof {
                        leaf_hash: right,
                        steps: vec![ProofStep {
                            sibling: left,
                            side: SiblingSide::Left,
                        }],
                    },
                },
            ],
        };
        assert_eq!(proof.len(), 2);
        assert_eq!(proof.indices(), vec![0, 1]);
        assert!(proof.verify(root));
        assert!(verify_multiproof(&proof, root));
        assert!(!proof.verify(hash_leaf(b"nope")));
        let shown = proof.to_string();
        assert!(shown.contains("count=2"));
        assert!(shown.contains("index=0"));
        assert!(shown.contains("index=1"));

        assert!(verify_inclusion_many(
            [(0usize, b"a".as_ref()), (1, b"b".as_ref())],
            &proof,
            root
        ));
        assert!(!verify_inclusion_many(
            [(0usize, b"a".as_ref())],
            &proof,
            root
        ));
        assert!(!verify_inclusion_many(
            [(1usize, b"a".as_ref()), (1, b"b".as_ref())],
            &proof,
            root
        ));
        assert!(!verify_inclusion_many(
            [(0usize, b"nope".as_ref()), (1, b"b".as_ref())],
            &proof,
            root
        ));
    }

    #[test]
    fn compact_sibling_classification_matches_padding_and_pairs() {
        assert_eq!(
            classify_compact_sibling(0, Some(1), 4),
            CompactSibling::KnownPair
        );
        assert_eq!(
            classify_compact_sibling(0, Some(2), 4),
            CompactSibling::External
        );
        assert_eq!(
            classify_compact_sibling(1, None, 4),
            CompactSibling::External
        );
        assert_eq!(
            classify_compact_sibling(2, None, 3),
            CompactSibling::DuplicatePad
        );
        assert_eq!(
            classify_compact_sibling(4, None, 5),
            CompactSibling::DuplicatePad
        );
    }

    #[test]
    fn unique_sorted_indices_dedups_and_rejects_oob() {
        assert_eq!(
            unique_sorted_indices([2, 0, 2, 1], 4).unwrap(),
            vec![0, 1, 2]
        );
        assert!(unique_sorted_indices([0, 4], 4).is_none());
        assert!(unique_sorted_indices([0], 0).is_none());
        assert!(unique_sorted_indices(core::iter::empty::<usize>(), 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn empty_compact_multiproof_displays() {
        let proof = CompactMultiProof::default();
        assert!(proof.is_empty());
        assert_eq!(proof.len(), 0);
        assert_eq!(proof.sibling_count(), 0);
        assert!(proof.indices().is_empty());
        assert!(proof.leaves_hex().is_empty());
        assert!(proof.siblings_hex().is_empty());
        assert_eq!(
            proof.to_string(),
            "leaf_count=0, leaves=0, siblings=0, indices=[]"
        );
        assert!(proof.verify([0u8; 32]));
        assert!(verify_compact(&proof, [0xff; 32]));
        assert!(verify_inclusion_compact(
            core::iter::empty::<(usize, &[u8])>(),
            &proof,
            [0u8; 32]
        ));
    }

    #[test]
    fn handmade_compact_two_leaf_proof_verifies_and_rejects_tampering() {
        let left = hash_leaf(b"a");
        let right = hash_leaf(b"b");
        let root = hash_nodes(&left, &right);
        let proof = CompactMultiProof {
            leaf_count: 2,
            indices: vec![0],
            leaves: vec![left],
            siblings: vec![right],
        };
        assert!(proof.verify(root));
        assert!(verify_compact(&proof, root));
        assert!(verify_inclusion_compact(
            [(0usize, b"a".as_ref())],
            &proof,
            root
        ));
        assert!(!verify_inclusion_compact(
            [(0usize, b"b".as_ref())],
            &proof,
            root
        ));
        assert!(!proof.verify(hash_leaf(b"nope")));

        let mut bad = proof.clone();
        bad.siblings[0] = hash_leaf(b"zzz");
        assert!(!bad.verify(root));

        let mut unsorted = proof.clone();
        unsorted.indices = vec![1, 0];
        unsorted.leaves = vec![right, left];
        assert!(!unsorted.verify(root));

        let mut extra = proof;
        extra.siblings.push(hash_leaf(b"extra"));
        assert!(!extra.verify(root));
    }
}
