//! Inclusion proofs: sibling steps, verification, and compact L/R hex encoding.
//!
//! A proof is the leaf hash plus the ordered sibling hashes from that leaf up
//! to (but not including) the root. Each step records whether the sibling sits
//! on the left or the right so the verifier can rebuild the same parent hashes.
//!
//! [`MultiProof`] is a naive bundle of those single-leaf paths. It does not
//! share overlapping siblings; a later format can compress that.
//!
//! [`MultiProof`] is a naive bundle of those single-leaf paths. It does not
//! share overlapping siblings; a later format can compress that.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::error::HashNotImplemented;
use crate::error::ParseStepsError;
use crate::hashing::{to_hex32, try_from_hex32, HashAlgorithm, TreeHasher};

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

/// Verify a naive multiproof against an expected root.
pub fn verify_multiproof(proof: &MultiProof, expected_root: [u8; 32]) -> bool {
    proof.verify(expected_root)
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
}
