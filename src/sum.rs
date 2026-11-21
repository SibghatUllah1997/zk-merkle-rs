//! Merkle sum tree building blocks for proof of reserves.
//!
//! A Merkle sum tree carries a running total next to every hash. Each leaf
//! commits to one account and its balance, and each parent commits to both
//! child hashes *and* both child sums. The root then pins a single
//! `(hash, total)` pair: the hash fixes every balance, and the total is the
//! liability figure an exchange publishes.
//!
//! Encoding (SHA-256, audited `sha2` crate):
//! - Leaf: `SHA-256(0x30 || account_id || amount as u128 big-endian)`
//! - Node: `SHA-256(0x31 || left.hash || left.sum_be || right.hash || right.sum_be)`
//!
//! The `0x30`/`0x31` tags never collide with the plain tree tags
//! (`0x00`/`0x01`/`0x02`), Poseidon (`0x10`/`0x11`), or Rescue (`0x20`/`0x21`),
//! so a sum-tree hash can never be replayed as a plain-tree hash.
//!
//! Account ids are fixed 32-byte values. An exchange should derive them from
//! a salted user id (for example `SHA-256(salt || user_id)`) so the published
//! tree does not leak who its customers are, and the fixed width keeps the
//! leaf encoding unambiguous without a length prefix.
//!
//! Parent sums use checked addition. A total that would overflow `u128`
//! returns [`SumOverflow`] instead of wrapping, because a wrapped total would
//! let a prover hide liabilities.
//!
//! ```
//! use merkle_tree::sum::{SumLeaf, SumNode};
//!
//! let alice = SumLeaf::new([1u8; 32], 40).node();
//! let bob = SumLeaf::new([2u8; 32], 2).node();
//! let parent = SumNode::parent(&alice, &bob).expect("no overflow");
//! assert_eq!(parent.sum, 42);
//! assert_ne!(parent.hash, alice.hash);
//! ```

#[cfg(not(feature = "std"))]
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::hashing::{to_hex32, try_from_hex32};
use crate::proof::SiblingSide;

/// Domain tag for a sum-tree leaf hash (`0x30`).
pub const SUM_LEAF_PREFIX: u8 = 0x30;

/// Domain tag for a sum-tree parent hash (`0x31`).
pub const SUM_NODE_PREFIX: u8 = 0x31;

/// Fixed-width account identifier committed in a sum-tree leaf.
pub type AccountId = [u8; 32];

/// One account balance in a Merkle sum tree.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SumLeaf {
    /// Salted, fixed-width account identifier.
    pub account_id: AccountId,
    /// Balance in the asset's smallest unit.
    pub amount: u128,
}

impl SumLeaf {
    /// Build a leaf from an account id and its balance.
    pub const fn new(account_id: AccountId, amount: u128) -> Self {
        Self { account_id, amount }
    }

    /// Leaf hash: `SHA-256(0x30 || account_id || amount_be)`.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([SUM_LEAF_PREFIX]);
        hasher.update(self.account_id);
        hasher.update(self.amount.to_be_bytes());
        hasher.finalize().into()
    }

    /// The `(hash, sum)` node this leaf contributes to the tree.
    pub fn node(&self) -> SumNode {
        SumNode {
            hash: self.hash(),
            sum: self.amount,
        }
    }
}

/// A sum-tree node: a hash plus the total of every leaf beneath it.
///
/// This is also the published root: a hash and a total liability.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SumNode {
    /// Domain-separated hash of the subtree.
    pub hash: [u8; 32],
    /// Sum of all leaf amounts in the subtree.
    pub sum: u128,
}

impl SumNode {
    /// Build a node from a hash and a subtree sum.
    pub const fn new(hash: [u8; 32], sum: u128) -> Self {
        Self { hash, sum }
    }

    /// Combine two children into their parent.
    ///
    /// The parent hash commits to both child hashes and both child sums, so
    /// changing any balance changes the root hash even if the total stays the
    /// same. Returns [`SumOverflow`] if the sums do not fit in `u128`.
    pub fn parent(left: &SumNode, right: &SumNode) -> Result<SumNode, SumOverflow> {
        let sum = left.sum.checked_add(right.sum).ok_or(SumOverflow {
            left: left.sum,
            right: right.sum,
        })?;
        Ok(SumNode {
            hash: hash_sum_nodes(left, right),
            sum,
        })
    }
}

/// Parent hash: `SHA-256(0x31 || left.hash || left.sum_be || right.hash || right.sum_be)`.
///
/// This only hashes; it does not check that the sums add up. Use
/// [`SumNode::parent`] to get the hash and a checked total together.
pub fn hash_sum_nodes(left: &SumNode, right: &SumNode) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([SUM_NODE_PREFIX]);
    hasher.update(left.hash);
    hasher.update(left.sum.to_be_bytes());
    hasher.update(right.hash);
    hasher.update(right.sum.to_be_bytes());
    hasher.finalize().into()
}

/// Two subtree sums whose total does not fit in `u128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SumOverflow {
    /// Left child sum.
    pub left: u128,
    /// Right child sum.
    pub right: u128,
}

impl core::fmt::Display for SumOverflow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "sum {} + {} overflows u128", self.left, self.right)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SumOverflow {}

/// Why a unique or sorted Merkle sum tree could not be built.
///
/// [`MerkleSumTree::from_leaves`] still accepts duplicate ids so existing
/// snapshots keep compiling. [`MerkleSumTree::from_unique_leaves`] is the
/// constructor that refuses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SumBuildError {
    /// A parent total overflowed `u128`.
    Overflow(SumOverflow),
    /// The same account id appeared at two leaf indices.
    Duplicate {
        /// Repeated account identifier.
        account_id: AccountId,
        /// First leaf that used this id.
        first: usize,
        /// Later leaf that reused it.
        second: usize,
    },
    /// Account ids are not strictly increasing at `index`.
    ///
    /// Equal neighbouring ids are [`Self::Duplicate`] instead. This variant
    /// means the id at `index` is smaller than the one before it.
    Unsorted {
        /// First index whose account id is smaller than the previous leaf.
        index: usize,
    },
}

impl core::fmt::Display for SumBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SumBuildError::Overflow(err) => write!(f, "{err}"),
            SumBuildError::Duplicate {
                account_id,
                first,
                second,
            } => write!(
                f,
                "account {} appears at index {first} and {second}",
                to_hex32(account_id)
            ),
            SumBuildError::Unsorted { index } => {
                write!(
                    f,
                    "account ids are not strictly increasing at index {index}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SumBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SumBuildError::Overflow(err) => Some(err),
            SumBuildError::Duplicate { .. } | SumBuildError::Unsorted { .. } => None,
        }
    }
}

impl From<SumOverflow> for SumBuildError {
    fn from(err: SumOverflow) -> Self {
        SumBuildError::Overflow(err)
    }
}

/// First repeated account id, if any, with the two indices that share it.
fn first_duplicate(leaves: &[SumLeaf]) -> Option<SumBuildError> {
    let mut seen = BTreeMap::new();
    for (index, leaf) in leaves.iter().enumerate() {
        if let Some(&first) = seen.get(&leaf.account_id) {
            return Some(SumBuildError::Duplicate {
                account_id: leaf.account_id,
                first,
                second: index,
            });
        }
        seen.insert(leaf.account_id, index);
    }
    None
}

/// First ordering problem in `leaves` when they must be strictly increasing.
fn first_sorted_error(leaves: &[SumLeaf]) -> Option<SumBuildError> {
    for i in 1..leaves.len() {
        match leaves[i].account_id.cmp(&leaves[i - 1].account_id) {
            core::cmp::Ordering::Greater => {}
            core::cmp::Ordering::Equal => {
                return Some(SumBuildError::Duplicate {
                    account_id: leaves[i].account_id,
                    first: i - 1,
                    second: i,
                });
            }
            core::cmp::Ordering::Less => {
                return Some(SumBuildError::Unsorted { index: i });
            }
        }
    }
    None
}

/// A problem reading Merkle sum leaves from CSV text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SumCsvError {
    /// No account rows after comments and an optional header.
    Empty,
    /// Line `line` (1-based) could not be parsed as `account_id,amount`.
    BadLine {
        /// 1-based source line.
        line: usize,
        /// Why the row failed.
        message: String,
    },
}

impl core::fmt::Display for SumCsvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SumCsvError::Empty => write!(f, "CSV has no account rows"),
            SumCsvError::BadLine { line, message } => {
                write!(f, "CSV line {line}: {message}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SumCsvError {}

fn parse_sum_csv_row(line: &str) -> Result<SumLeaf, String> {
    let mut parts = line.split(',');
    let id_raw = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| String::from("missing account id"))?;
    let amount_raw = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| String::from("missing amount"))?;
    if parts.next().is_some() {
        return Err(String::from("expected two columns: account_id,amount"));
    }
    let account_id = try_from_hex32(id_raw).map_err(|err| err.to_string())?;
    let amount = amount_raw
        .parse::<u128>()
        .map_err(|_| format!("invalid amount {amount_raw:?}"))?;
    Ok(SumLeaf::new(account_id, amount))
}

fn looks_like_csv_header(line: &str) -> bool {
    let first = line.split(',').next().unwrap_or("").trim();
    let lower = first.to_ascii_lowercase();
    lower.contains("account") || lower.contains("amount") || lower == "id"
}

/// Parse `account_id,amount` CSV into [`SumLeaf`] values.
///
/// `account_id` is 32-byte hex (optional `0x` prefix). `amount` is a decimal
/// `u128`. Empty lines and `#` comments are skipped. A header row is skipped
/// when it is the first non-empty line and is not itself a valid data row.
///
/// ```
/// use merkle_tree::sum::parse_sum_csv;
///
/// let leaves = parse_sum_csv(concat!(
///     "account_id,amount\n",
///     "1111111111111111111111111111111111111111111111111111111111111111,40\n",
///     "2222222222222222222222222222222222222222222222222222222222222222,2\n",
/// ))
/// .unwrap();
/// assert_eq!(leaves.len(), 2);
/// assert_eq!(leaves[0].amount, 40);
/// ```
pub fn parse_sum_csv(text: &str) -> Result<Vec<SumLeaf>, SumCsvError> {
    let mut leaves = Vec::new();
    let mut skipped_header = false;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_sum_csv_row(line) {
            Ok(leaf) => leaves.push(leaf),
            Err(_) if leaves.is_empty() && !skipped_header && looks_like_csv_header(line) => {
                skipped_header = true;
            }
            Err(message) => {
                return Err(SumCsvError::BadLine {
                    line: idx + 1,
                    message,
                });
            }
        }
    }
    if leaves.is_empty() {
        Err(SumCsvError::Empty)
    } else {
        Ok(leaves)
    }
}

/// A Merkle sum tree over [`SumLeaf`] values.
///
/// Built bottom-up with [`Self::from_leaves`]. An odd layer promotes the last
/// node unchanged instead of hashing it with a duplicate of itself: repeating
/// the last leaf would add its amount twice, so the root total would no longer
/// match the published liabilities. An empty tree has no root; a single-leaf
/// tree's root is that leaf's node.
///
/// ```
/// use merkle_tree::sum::{MerkleSumTree, SumLeaf};
///
/// let tree = MerkleSumTree::from_leaves([
///     SumLeaf::new([1u8; 32], 40),
///     SumLeaf::new([2u8; 32], 2),
///     SumLeaf::new([3u8; 32], 8),
/// ])
/// .expect("no overflow");
/// let (hash, total) = tree.root().expect("non-empty");
/// assert_eq!(total, 50);
/// assert_eq!(hash, tree.root_node().unwrap().hash);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleSumTree {
    leaves: Vec<SumLeaf>,
    /// Layer 0 is the leaf nodes; the last layer holds the root when the
    /// tree is not empty.
    layers: Vec<Vec<SumNode>>,
}

impl MerkleSumTree {
    /// Build a sum tree from leaves, in the given order.
    ///
    /// Returns [`SumOverflow`] if any parent total exceeds `u128`.
    pub fn from_leaves<I>(leaves: I) -> Result<Self, SumOverflow>
    where
        I: IntoIterator<Item = SumLeaf>,
    {
        let leaves: Vec<SumLeaf> = leaves.into_iter().collect();
        if leaves.is_empty() {
            return Ok(Self {
                leaves,
                layers: Vec::new(),
            });
        }

        let mut layer: Vec<SumNode> = leaves.iter().map(SumLeaf::node).collect();
        let mut layers = Vec::new();
        loop {
            if layer.len() <= 1 {
                layers.push(layer);
                break;
            }
            let mut next = Vec::with_capacity((layer.len() + 1) / 2);
            let mut pairs = layer.chunks_exact(2);
            for pair in pairs.by_ref() {
                next.push(SumNode::parent(&pair[0], &pair[1])?);
            }
            if let Some(odd) = pairs.remainder().first() {
                next.push(*odd);
            }
            layers.push(layer);
            layer = next;
        }

        Ok(Self { leaves, layers })
    }

    /// Build a sum tree, refusing any repeated account id.
    ///
    /// Duplicate ids let one balance be counted twice or split across two
    /// leaves, so a per-account inclusion proof no longer matches the total.
    /// [`Self::from_leaves`] still allows them; this constructor is the one
    /// an exchange should use before publishing.
    ///
    /// ```
    /// use merkle_tree::sum::{MerkleSumTree, SumBuildError, SumLeaf};
    ///
    /// let ok = MerkleSumTree::from_unique_leaves([
    ///     SumLeaf::new([1u8; 32], 40),
    ///     SumLeaf::new([2u8; 32], 2),
    /// ])
    /// .expect("unique");
    /// assert_eq!(ok.root().map(|r| r.1), Some(42));
    ///
    /// let err = MerkleSumTree::from_unique_leaves([
    ///     SumLeaf::new([1u8; 32], 40),
    ///     SumLeaf::new([1u8; 32], 2),
    /// ])
    /// .expect_err("duplicate");
    /// assert!(matches!(
    ///     err,
    ///     SumBuildError::Duplicate {
    ///         first: 0,
    ///         second: 1,
    ///         ..
    ///     }
    /// ));
    /// ```
    pub fn from_unique_leaves<I>(leaves: I) -> Result<Self, SumBuildError>
    where
        I: IntoIterator<Item = SumLeaf>,
    {
        let leaves: Vec<SumLeaf> = leaves.into_iter().collect();
        if let Some(err) = first_duplicate(&leaves) {
            return Err(err);
        }
        Self::from_leaves(leaves).map_err(SumBuildError::Overflow)
    }

    /// Build a sum tree whose account ids are strictly increasing.
    ///
    /// Strict order implies uniqueness, so this is a [`Self::from_unique_leaves`]
    /// tree that can also be binary-searched. The constructor does not sort:
    /// reordering leaves would change the published root.
    ///
    /// ```
    /// use merkle_tree::sum::{MerkleSumTree, SumBuildError, SumLeaf};
    ///
    /// let tree = MerkleSumTree::from_sorted_leaves([
    ///     SumLeaf::new([1u8; 32], 40),
    ///     SumLeaf::new([2u8; 32], 2),
    ///     SumLeaf::new([3u8; 32], 8),
    /// ])
    /// .expect("sorted");
    /// assert_eq!(tree.binary_search(&[2u8; 32]), Some(1));
    ///
    /// let err = MerkleSumTree::from_sorted_leaves([
    ///     SumLeaf::new([2u8; 32], 2),
    ///     SumLeaf::new([1u8; 32], 40),
    /// ])
    /// .expect_err("decreasing");
    /// assert_eq!(err, SumBuildError::Unsorted { index: 1 });
    /// ```
    pub fn from_sorted_leaves<I>(leaves: I) -> Result<Self, SumBuildError>
    where
        I: IntoIterator<Item = SumLeaf>,
    {
        let leaves: Vec<SumLeaf> = leaves.into_iter().collect();
        if let Some(err) = first_sorted_error(&leaves) {
            return Err(err);
        }
        Self::from_leaves(leaves).map_err(SumBuildError::Overflow)
    }

    /// True when account ids are strictly increasing (empty and single-leaf
    /// trees count as sorted).
    pub fn is_sorted_unique(&self) -> bool {
        self.leaves
            .windows(2)
            .all(|pair| pair[0].account_id < pair[1].account_id)
    }

    /// Index of `account_id` by binary search.
    ///
    /// The ids must be strictly increasing, as required by
    /// [`Self::from_sorted_leaves`]. On an unsorted tree this may return
    /// `None` even when the id is present; use [`Self::position`] then.
    pub fn binary_search(&self, account_id: &AccountId) -> Option<usize> {
        self.leaves
            .binary_search_by(|leaf| leaf.account_id.cmp(account_id))
            .ok()
    }

    /// Root hash and total, or `None` when the tree is empty.
    pub fn root(&self) -> Option<([u8; 32], u128)> {
        self.root_node().map(|node| (node.hash, node.sum))
    }

    /// Root node, or `None` when the tree is empty.
    pub fn root_node(&self) -> Option<SumNode> {
        self.layers.last().and_then(|layer| layer.first()).copied()
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// True when there are no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Leaves in insertion order.
    pub fn leaves(&self) -> &[SumLeaf] {
        &self.leaves
    }

    /// Number of stored layers, including the leaf layer and the root.
    ///
    /// Empty trees have zero layers.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Borrow the nodes of layer `level` (0 = leaves). `None` if out of range.
    ///
    /// Each node's `sum` is the total of the leaves beneath it. An odd leftover
    /// is promoted unchanged, so a parent never double-counts an amount.
    pub fn layer_nodes(&self, level: usize) -> Option<&[SumNode]> {
        self.layers.get(level).map(Vec::as_slice)
    }
}

/// Which sibling side each step of a proof for `index` must have, in a tree
/// of `leaf_count` leaves.
///
/// A level where the node is promoted (last node of an odd layer) has no
/// sibling and contributes no step, so the shape depends on both values.
fn expected_sides(mut index: usize, mut leaf_count: usize) -> Vec<SiblingSide> {
    let mut sides = Vec::new();
    while leaf_count > 1 {
        if index % 2 == 1 {
            sides.push(SiblingSide::Left);
        } else if index + 1 < leaf_count {
            sides.push(SiblingSide::Right);
        }
        index /= 2;
        leaf_count = (leaf_count + 1) / 2;
    }
    sides
}

/// One step of a sum-tree inclusion proof: the sibling `(hash, sum)` and the
/// side it sits on.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SumProofStep {
    /// Sibling subtree node, including its total.
    pub sibling: SumNode,
    /// Side of the sibling relative to the running node.
    pub side: SiblingSide,
}

/// Proof that one leaf is part of a [`MerkleSumTree`] and that its amount
/// counts toward the root total.
///
/// Each step carries the sibling's sum as well as its hash. The verifier
/// rebuilds every parent with [`SumNode::parent`], so the path is only valid
/// if the hashes chain to the root hash *and* the sums add up, with checked
/// arithmetic, to the root total.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumInclusionProof {
    /// Position of the leaf in the tree.
    pub leaf_index: usize,
    /// Number of leaves in the tree the proof was made for.
    ///
    /// This fixes the expected path shape. The root does not commit to the
    /// leaf count, so it is not a substitute for checking the published
    /// count separately.
    pub leaf_count: usize,
    /// Sibling nodes from the leaf layer up to just below the root.
    pub steps: Vec<SumProofStep>,
}

/// Why a [`SumInclusionProof`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SumProofError {
    /// `leaf_index` is not below `leaf_count`.
    IndexOutOfRange {
        /// Claimed leaf index.
        index: usize,
        /// Claimed leaf count.
        leaf_count: usize,
    },
    /// The proof has a different number of steps than the tree shape needs.
    PathLength {
        /// Steps needed for this index and leaf count.
        expected: usize,
        /// Steps in the proof.
        actual: usize,
    },
    /// A step's side does not match the leaf's position.
    WrongSide {
        /// Step number, counted from the leaf.
        step: usize,
    },
    /// Two sums on the path overflow `u128`.
    Overflow(SumOverflow),
    /// The rebuilt hash does not match the root hash.
    HashMismatch,
    /// The hash matched but the rebuilt total does not match the root total.
    SumMismatch {
        /// Total rebuilt from the leaf and sibling sums.
        computed: u128,
        /// Total claimed by the root.
        expected: u128,
    },
}

impl core::fmt::Display for SumProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SumProofError::IndexOutOfRange { index, leaf_count } => {
                write!(f, "leaf index {index} out of range for {leaf_count} leaves")
            }
            SumProofError::PathLength { expected, actual } => {
                write!(f, "proof has {actual} steps, expected {expected}")
            }
            SumProofError::WrongSide { step } => write!(f, "step {step} has the wrong side"),
            SumProofError::Overflow(err) => write!(f, "{err}"),
            SumProofError::HashMismatch => write!(f, "rebuilt hash does not match the root"),
            SumProofError::SumMismatch { computed, expected } => {
                write!(
                    f,
                    "rebuilt total {computed} does not match root total {expected}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SumProofError {}

impl From<SumOverflow> for SumProofError {
    fn from(err: SumOverflow) -> Self {
        SumProofError::Overflow(err)
    }
}

impl SumInclusionProof {
    /// Rebuild the root node from `leaf` and the proof steps.
    ///
    /// Checks the index, the path length, and every step's side against the
    /// tree shape before hashing, so a proof cannot be moved to another
    /// position or padded with extra steps.
    pub fn compute_root(&self, leaf: &SumLeaf) -> Result<SumNode, SumProofError> {
        if self.leaf_index >= self.leaf_count {
            return Err(SumProofError::IndexOutOfRange {
                index: self.leaf_index,
                leaf_count: self.leaf_count,
            });
        }
        let sides = expected_sides(self.leaf_index, self.leaf_count);
        if sides.len() != self.steps.len() {
            return Err(SumProofError::PathLength {
                expected: sides.len(),
                actual: self.steps.len(),
            });
        }

        let mut node = leaf.node();
        for (i, (step, side)) in self.steps.iter().zip(sides).enumerate() {
            if step.side != side {
                return Err(SumProofError::WrongSide { step: i });
            }
            node = match step.side {
                SiblingSide::Left => SumNode::parent(&step.sibling, &node)?,
                SiblingSide::Right => SumNode::parent(&node, &step.sibling)?,
            };
        }
        Ok(node)
    }

    /// Verify that `leaf` is in the tree with root `root` and that the
    /// sibling sums along the path add up to `root.sum`.
    pub fn verify(&self, leaf: &SumLeaf, root: &SumNode) -> Result<(), SumProofError> {
        let computed = self.compute_root(leaf)?;
        if computed.hash != root.hash {
            return Err(SumProofError::HashMismatch);
        }
        if computed.sum != root.sum {
            return Err(SumProofError::SumMismatch {
                computed: computed.sum,
                expected: root.sum,
            });
        }
        Ok(())
    }
}

/// One neighbouring leaf used in a [`SumAbsenceProof`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumAbsenceNeighbor {
    /// The neighbouring account and amount.
    pub leaf: SumLeaf,
    /// Inclusion proof for [`Self::leaf`] against the published root.
    pub proof: SumInclusionProof,
}

/// Proof that `query` is not among the leaves of a sorted unique sum tree.
///
/// The argument is two neighbouring inclusion proofs whose ids sandwich
/// `query`. Consecutive indices mean no leaf sits between them, so the
/// missing id cannot be in the tree. A query below the first leaf (or above
/// the last) uses only the right (or left) neighbour.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumAbsenceProof {
    /// Account id claimed to be missing.
    pub query: AccountId,
    /// Neighbour immediately below `query`, if any.
    pub left: Option<SumAbsenceNeighbor>,
    /// Neighbour immediately above `query`, if any.
    pub right: Option<SumAbsenceNeighbor>,
}

/// Why a [`SumAbsenceProof`] was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbsenceError {
    /// Neither neighbour was supplied.
    EmptyNeighbors,
    /// A neighbour inclusion proof did not verify.
    Inclusion(SumProofError),
    /// The two neighbours are not consecutive leaf indices.
    NotAdjacent {
        /// Left neighbour index.
        left: usize,
        /// Right neighbour index.
        right: usize,
    },
    /// A right-only proof whose neighbour is not leaf 0.
    NotFirst {
        /// Claimed index of the first leaf.
        index: usize,
    },
    /// A left-only proof whose neighbour is not the last leaf.
    NotLast {
        /// Claimed index of the last leaf.
        index: usize,
        /// Claimed leaf count.
        leaf_count: usize,
    },
    /// Neighbours disagree on how many leaves the tree has.
    LeafCountMismatch {
        /// Leaf count on the left proof.
        left: usize,
        /// Leaf count on the right proof.
        right: usize,
    },
    /// `query` is not strictly outside / between the neighbour account ids.
    NotBounded,
}

impl core::fmt::Display for AbsenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AbsenceError::EmptyNeighbors => write!(f, "absence proof has no neighbours"),
            AbsenceError::Inclusion(err) => write!(f, "neighbour inclusion failed: {err}"),
            AbsenceError::NotAdjacent { left, right } => {
                write!(f, "neighbours at {left} and {right} are not adjacent")
            }
            AbsenceError::NotFirst { index } => {
                write!(f, "right-only neighbour must be index 0, got {index}")
            }
            AbsenceError::NotLast { index, leaf_count } => write!(
                f,
                "left-only neighbour must be the last of {leaf_count} leaves, got {index}"
            ),
            AbsenceError::LeafCountMismatch { left, right } => {
                write!(f, "neighbours disagree on leaf count ({left} vs {right})")
            }
            AbsenceError::NotBounded => {
                write!(f, "query is not strictly bounded by the neighbour ids")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AbsenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AbsenceError::Inclusion(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SumProofError> for AbsenceError {
    fn from(err: SumProofError) -> Self {
        AbsenceError::Inclusion(err)
    }
}

impl SumAbsenceProof {
    /// Check that `query` sits in a gap of the tree with root `root`.
    ///
    /// Neighbour inclusion is verified first, then the indices must be
    /// consecutive (or the first / last leaf for an end gap) and the account
    /// ids must strictly sandwich `query`. Non-adjacent neighbours would let
    /// a skipped leaf hide in the gap.
    pub fn verify(&self, root: &SumNode) -> Result<(), AbsenceError> {
        match (&self.left, &self.right) {
            (None, None) => Err(AbsenceError::EmptyNeighbors),
            (Some(left), None) => {
                left.proof.verify(&left.leaf, root)?;
                if left.proof.leaf_index + 1 != left.proof.leaf_count {
                    return Err(AbsenceError::NotLast {
                        index: left.proof.leaf_index,
                        leaf_count: left.proof.leaf_count,
                    });
                }
                if left.leaf.account_id >= self.query {
                    return Err(AbsenceError::NotBounded);
                }
                Ok(())
            }
            (None, Some(right)) => {
                right.proof.verify(&right.leaf, root)?;
                if right.proof.leaf_index != 0 {
                    return Err(AbsenceError::NotFirst {
                        index: right.proof.leaf_index,
                    });
                }
                if self.query >= right.leaf.account_id {
                    return Err(AbsenceError::NotBounded);
                }
                Ok(())
            }
            (Some(left), Some(right)) => {
                left.proof.verify(&left.leaf, root)?;
                right.proof.verify(&right.leaf, root)?;
                if left.proof.leaf_count != right.proof.leaf_count {
                    return Err(AbsenceError::LeafCountMismatch {
                        left: left.proof.leaf_count,
                        right: right.proof.leaf_count,
                    });
                }
                if left.proof.leaf_index + 1 != right.proof.leaf_index {
                    return Err(AbsenceError::NotAdjacent {
                        left: left.proof.leaf_index,
                        right: right.proof.leaf_index,
                    });
                }
                if left.leaf.account_id >= self.query || self.query >= right.leaf.account_id {
                    return Err(AbsenceError::NotBounded);
                }
                Ok(())
            }
        }
    }
}

impl MerkleSumTree {
    /// Inclusion proof for the leaf at `index`, or `None` if out of range.
    ///
    /// ```
    /// use merkle_tree::sum::{MerkleSumTree, SumLeaf};
    ///
    /// let leaves = [
    ///     SumLeaf::new([1u8; 32], 40),
    ///     SumLeaf::new([2u8; 32], 2),
    ///     SumLeaf::new([3u8; 32], 8),
    /// ];
    /// let tree = MerkleSumTree::from_leaves(leaves).expect("no overflow");
    /// let root = tree.root_node().expect("non-empty");
    ///
    /// let proof = tree.prove(1).expect("in range");
    /// assert!(proof.verify(&leaves[1], &root).is_ok());
    /// // Claiming a different balance fails.
    /// assert!(proof.verify(&SumLeaf::new([2u8; 32], 3), &root).is_err());
    /// ```
    pub fn prove(&self, index: usize) -> Option<SumInclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut steps = Vec::new();
        let mut i = index;
        // The last layer is the root, which has no sibling.
        for layer in &self.layers[..self.layers.len() - 1] {
            if i % 2 == 1 {
                steps.push(SumProofStep {
                    sibling: layer[i - 1],
                    side: SiblingSide::Left,
                });
            } else if let Some(sibling) = layer.get(i + 1) {
                steps.push(SumProofStep {
                    sibling: *sibling,
                    side: SiblingSide::Right,
                });
            }
            i /= 2;
        }
        Some(SumInclusionProof {
            leaf_index: index,
            leaf_count: self.leaves.len(),
            steps,
        })
    }

    /// Non-inclusion proof for `account_id`, or `None` if it is present,
    /// the tree is empty, or the ids are not strictly increasing.
    ///
    /// ```
    /// use merkle_tree::sum::{MerkleSumTree, SumLeaf};
    ///
    /// let tree = MerkleSumTree::from_sorted_leaves([
    ///     SumLeaf::new([1u8; 32], 40),
    ///     SumLeaf::new([3u8; 32], 8),
    /// ])
    /// .expect("sorted");
    /// let root = tree.root_node().expect("non-empty");
    /// let proof = tree.prove_absent(&[2u8; 32]).expect("missing");
    /// assert!(proof.verify(&root).is_ok());
    /// assert!(tree.prove_absent(&[1u8; 32]).is_none());
    /// ```
    pub fn prove_absent(&self, account_id: &AccountId) -> Option<SumAbsenceProof> {
        if self.leaves.is_empty() || !self.is_sorted_unique() {
            return None;
        }
        match self
            .leaves
            .binary_search_by(|leaf| leaf.account_id.cmp(account_id))
        {
            Ok(_) => None,
            Err(insert_at) => {
                let left = insert_at.checked_sub(1).map(|index| SumAbsenceNeighbor {
                    leaf: self.leaves[index],
                    proof: self.prove(index).expect("in range"),
                });
                let right = if insert_at < self.leaves.len() {
                    Some(SumAbsenceNeighbor {
                        leaf: self.leaves[insert_at],
                        proof: self.prove(insert_at).expect("in range"),
                    })
                } else {
                    None
                };
                Some(SumAbsenceProof {
                    query: *account_id,
                    left,
                    right,
                })
            }
        }
    }
}

/// Why a sum-proof text file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SumProofTextError {
    /// Line `line` (1-based) is not a `key=value` pair this format knows.
    BadLine {
        /// 1-based source line.
        line: usize,
        /// Why the line failed.
        message: String,
    },
    /// A required key never appeared.
    Missing(&'static str),
    /// A key that may appear only once appeared twice.
    Duplicate(&'static str),
}

impl core::fmt::Display for SumProofTextError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SumProofTextError::BadLine { line, message } => {
                write!(f, "proof line {line}: {message}")
            }
            SumProofTextError::Missing(key) => write!(f, "proof is missing {key}="),
            SumProofTextError::Duplicate(key) => write!(f, "proof repeats {key}="),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SumProofTextError {}

/// Render `leaf` and `proof` as the line-based text the CLI exports.
///
/// ```text
/// account=<64 hex chars>
/// amount=<decimal u128>
/// index=<leaf index>
/// leaf_count=<leaves in the tree>
/// step=<L|R>:<sibling hash hex>:<sibling sum>
/// ```
///
/// One `step=` line per level, ordered from the leaf up. The root is left
/// out on purpose: a user must check the proof against the root the exchange
/// published, not against a value shipped inside the same file.
///
/// ```
/// use merkle_tree::sum::{parse_sum_proof_text, sum_proof_to_text, MerkleSumTree, SumLeaf};
///
/// let leaves = [SumLeaf::new([1u8; 32], 40), SumLeaf::new([2u8; 32], 2)];
/// let tree = MerkleSumTree::from_leaves(leaves).unwrap();
/// let proof = tree.prove(0).unwrap();
///
/// let text = sum_proof_to_text(&leaves[0], &proof);
/// let (leaf, parsed) = parse_sum_proof_text(&text).unwrap();
/// assert_eq!(leaf, leaves[0]);
/// assert!(parsed.verify(&leaf, &tree.root_node().unwrap()).is_ok());
/// ```
pub fn sum_proof_to_text(leaf: &SumLeaf, proof: &SumInclusionProof) -> String {
    let mut out = format!(
        "account={}\namount={}\nindex={}\nleaf_count={}\n",
        to_hex32(&leaf.account_id),
        leaf.amount,
        proof.leaf_index,
        proof.leaf_count
    );
    for step in &proof.steps {
        out.push_str(&format!(
            "step={}:{}:{}\n",
            step.side.as_char(),
            to_hex32(&step.sibling.hash),
            step.sibling.sum
        ));
    }
    out
}

fn parse_sum_step(value: &str) -> Result<SumProofStep, String> {
    let mut parts = value.split(':');
    let side_raw = parts.next().unwrap_or("");
    let hash_raw = parts
        .next()
        .ok_or_else(|| String::from("step needs side:hash:sum"))?;
    let sum_raw = parts
        .next()
        .ok_or_else(|| String::from("step needs side:hash:sum"))?;
    if parts.next().is_some() {
        return Err(String::from("step needs side:hash:sum"));
    }
    let side = SiblingSide::from_label(side_raw)
        .ok_or_else(|| format!("invalid step side {side_raw:?}"))?;
    let hash = try_from_hex32(hash_raw).map_err(|err| err.to_string())?;
    let sum = sum_raw
        .parse::<u128>()
        .map_err(|_| format!("invalid step sum {sum_raw:?}"))?;
    Ok(SumProofStep {
        sibling: SumNode::new(hash, sum),
        side,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &'static str) -> Result<(), SumProofTextError> {
    if slot.is_some() {
        return Err(SumProofTextError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// Parse text written by [`sum_proof_to_text`] back into a leaf and proof.
///
/// Blank lines and `#` comments are skipped. Unknown keys are rejected so a
/// typo cannot silently drop a field. Parsing does not verify anything; call
/// [`SumInclusionProof::verify`] with the published root afterwards.
pub fn parse_sum_proof_text(text: &str) -> Result<(SumLeaf, SumInclusionProof), SumProofTextError> {
    let mut account = None;
    let mut amount = None;
    let mut index = None;
    let mut leaf_count = None;
    let mut steps = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = |message: String| SumProofTextError::BadLine {
            line: idx + 1,
            message,
        };
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| bad(String::from("expected key=value")))?;
        let value = value.trim();
        match key.trim() {
            "account" => {
                let id = try_from_hex32(value).map_err(|err| bad(err.to_string()))?;
                set_once(&mut account, id, "account")?;
            }
            "amount" => {
                let v = value
                    .parse::<u128>()
                    .map_err(|_| bad(format!("invalid amount {value:?}")))?;
                set_once(&mut amount, v, "amount")?;
            }
            "index" => {
                let v = value
                    .parse::<usize>()
                    .map_err(|_| bad(format!("invalid index {value:?}")))?;
                set_once(&mut index, v, "index")?;
            }
            "leaf_count" => {
                let v = value
                    .parse::<usize>()
                    .map_err(|_| bad(format!("invalid leaf_count {value:?}")))?;
                set_once(&mut leaf_count, v, "leaf_count")?;
            }
            "step" => steps.push(parse_sum_step(value).map_err(bad)?),
            other => return Err(bad(format!("unknown key {other:?}"))),
        }
    }

    let leaf = SumLeaf::new(
        account.ok_or(SumProofTextError::Missing("account"))?,
        amount.ok_or(SumProofTextError::Missing("amount"))?,
    );
    let proof = SumInclusionProof {
        leaf_index: index.ok_or(SumProofTextError::Missing("index"))?,
        leaf_count: leaf_count.ok_or(SumProofTextError::Missing("leaf_count"))?,
        steps,
    };
    Ok((leaf, proof))
}

impl MerkleSumTree {
    /// Index of the first leaf whose account id is `account_id`.
    pub fn position(&self, account_id: &AccountId) -> Option<usize> {
        self.leaves
            .iter()
            .position(|leaf| &leaf.account_id == account_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::{
        LEAF_PREFIX, NODE_PREFIX, POSEIDON_LEAF_PREFIX, POSEIDON_NODE_PREFIX, RESCUE_LEAF_PREFIX,
        RESCUE_NODE_PREFIX, ROOT_COMMIT_PREFIX,
    };

    fn leaf(id: u8, amount: u128) -> SumLeaf {
        SumLeaf::new([id; 32], amount)
    }

    #[test]
    fn tags_do_not_collide_with_other_domains() {
        let others = [
            LEAF_PREFIX,
            NODE_PREFIX,
            ROOT_COMMIT_PREFIX,
            POSEIDON_LEAF_PREFIX,
            POSEIDON_NODE_PREFIX,
            RESCUE_LEAF_PREFIX,
            RESCUE_NODE_PREFIX,
        ];
        assert_ne!(SUM_LEAF_PREFIX, SUM_NODE_PREFIX);
        assert!(!others.contains(&SUM_LEAF_PREFIX));
        assert!(!others.contains(&SUM_NODE_PREFIX));
    }

    #[test]
    fn leaf_hash_matches_manual_encoding() {
        let l = leaf(7, 1_000);
        let mut buf = [0u8; 1 + 32 + 16];
        buf[0] = 0x30;
        buf[1..33].copy_from_slice(&[7u8; 32]);
        buf[33..].copy_from_slice(&1_000u128.to_be_bytes());
        let expected: [u8; 32] = Sha256::digest(buf).into();
        assert_eq!(l.hash(), expected);
        assert_eq!(l.node(), SumNode::new(expected, 1_000));
    }

    #[test]
    fn leaf_hash_differs_from_plain_leaf_hash() {
        let l = leaf(1, 5);
        let mut bytes = [0u8; 48];
        bytes[..32].copy_from_slice(&l.account_id);
        bytes[32..].copy_from_slice(&l.amount.to_be_bytes());
        assert_ne!(l.hash(), crate::hashing::hash_leaf(&bytes));
    }

    #[test]
    fn leaf_hash_binds_amount_and_account() {
        assert_ne!(leaf(1, 5).hash(), leaf(1, 6).hash());
        assert_ne!(leaf(1, 5).hash(), leaf(2, 5).hash());
    }

    #[test]
    fn parent_adds_sums_and_hashes_both_children() {
        let a = leaf(1, 30).node();
        let b = leaf(2, 12).node();
        let p = SumNode::parent(&a, &b).expect("fits");
        assert_eq!(p.sum, 42);
        assert_eq!(p.hash, hash_sum_nodes(&a, &b));

        let mut buf = [0u8; 1 + 48 + 48];
        buf[0] = 0x31;
        buf[1..33].copy_from_slice(&a.hash);
        buf[33..49].copy_from_slice(&30u128.to_be_bytes());
        buf[49..81].copy_from_slice(&b.hash);
        buf[81..].copy_from_slice(&12u128.to_be_bytes());
        let expected: [u8; 32] = Sha256::digest(buf).into();
        assert_eq!(p.hash, expected);
    }

    #[test]
    fn parent_is_order_sensitive() {
        let a = leaf(1, 30).node();
        let b = leaf(2, 12).node();
        let ab = SumNode::parent(&a, &b).expect("fits");
        let ba = SumNode::parent(&b, &a).expect("fits");
        assert_eq!(ab.sum, ba.sum);
        assert_ne!(ab.hash, ba.hash);
    }

    #[test]
    fn parent_hash_commits_to_sums_not_just_hashes() {
        let a = leaf(1, 30).node();
        let b = leaf(2, 12).node();
        // Same child hashes, sums shifted between children: total unchanged.
        let a2 = SumNode::new(a.hash, 31);
        let b2 = SumNode::new(b.hash, 11);
        let p = SumNode::parent(&a, &b).expect("fits");
        let p2 = SumNode::parent(&a2, &b2).expect("fits");
        assert_eq!(p.sum, p2.sum);
        assert_ne!(p.hash, p2.hash);
    }

    #[test]
    fn parent_rejects_overflow() {
        let a = leaf(1, u128::MAX).node();
        let b = leaf(2, 1).node();
        let err = SumNode::parent(&a, &b).expect_err("overflow");
        assert_eq!(
            err,
            SumOverflow {
                left: u128::MAX,
                right: 1
            }
        );
        assert!(SumNode::parent(&a, &leaf(3, 0).node()).is_ok());
    }

    #[test]
    fn frozen_vectors() {
        // Pin the encoding so future changes to the leaf/node layout are caught.
        let a = leaf(0xaa, 100).node();
        let b = leaf(0xbb, 250).node();
        let p = SumNode::parent(&a, &b).expect("fits");
        assert_eq!(p.sum, 350);
        assert_eq!(crate::hashing::to_hex32(&a.hash), A_HASH);
        assert_eq!(crate::hashing::to_hex32(&p.hash), P_HASH);
    }

    const A_HASH: &str = "2e6a6228c42bbad04e1a78a92398b943430843b4a91b7a821e2bb5bd61e9191c";
    const P_HASH: &str = "8eb6292d25aa2ac16bcb042f4174f807a8840e5b6d9a67016fe4cc683f658f52";

    #[test]
    fn empty_tree_has_no_root() {
        let tree = MerkleSumTree::from_leaves([]).expect("empty");
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.root(), None);
        assert_eq!(tree.root_node(), None);
        assert!(tree.leaves().is_empty());
        assert_eq!(tree.layer_count(), 0);
        assert_eq!(tree.layer_nodes(0), None);
    }

    #[test]
    fn single_leaf_root_is_the_leaf_node() {
        let leaf = leaf(1, 99);
        let tree = MerkleSumTree::from_leaves([leaf]).expect("fits");
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.root(), Some((leaf.hash(), 99)));
        assert_eq!(tree.root_node(), Some(leaf.node()));
        assert_eq!(tree.leaves(), &[leaf]);
        assert_eq!(tree.layer_count(), 1);
        assert_eq!(tree.layer_nodes(0), Some(&[leaf.node()][..]));
        assert_eq!(tree.layer_nodes(1), None);
    }

    #[test]
    fn two_leaf_root_matches_parent() {
        let a = leaf(1, 30);
        let b = leaf(2, 12);
        let tree = MerkleSumTree::from_leaves([a, b]).expect("fits");
        let parent = SumNode::parent(&a.node(), &b.node()).expect("fits");
        assert_eq!(tree.root(), Some((parent.hash, 42)));
        assert_eq!(tree.layer_count(), 2);
        assert_eq!(tree.layer_nodes(0), Some(&[a.node(), b.node()][..]));
        assert_eq!(tree.layer_nodes(1), Some(&[parent][..]));
    }

    #[test]
    fn odd_leaf_count_does_not_double_the_last_amount() {
        // A, B, C: the last node is promoted, so the total is 40+2+8=50,
        // not 40+2+8+8 as duplicate-last padding would produce.
        let leaves = [leaf(1, 40), leaf(2, 2), leaf(3, 8)];
        let tree = MerkleSumTree::from_leaves(leaves).expect("fits");
        let (hash, total) = tree.root().expect("non-empty");
        assert_eq!(total, 50);
        assert_eq!(total, leaves.iter().map(|l| l.amount).sum::<u128>());

        let ab = SumNode::parent(&leaves[0].node(), &leaves[1].node()).expect("fits");
        let expected = SumNode::parent(&ab, &leaves[2].node()).expect("fits");
        assert_eq!(hash, expected.hash);
        assert_eq!(total, expected.sum);

        let duplicated = SumNode::parent(&leaves[2].node(), &leaves[2].node()).expect("fits");
        let wrong = SumNode::parent(&ab, &duplicated).expect("fits");
        assert_ne!(total, wrong.sum);
        assert_ne!(hash, wrong.hash);
    }

    #[test]
    fn four_leaves_sum_and_hash_are_order_sensitive() {
        let leaves = [leaf(1, 10), leaf(2, 20), leaf(3, 30), leaf(4, 40)];
        let tree = MerkleSumTree::from_leaves(leaves).expect("fits");
        let (_, total) = tree.root().expect("non-empty");
        assert_eq!(total, 100);

        let mut swapped = leaves;
        swapped.swap(0, 1);
        let other = MerkleSumTree::from_leaves(swapped).expect("fits");
        assert_eq!(other.root().map(|r| r.1), Some(100));
        assert_ne!(tree.root().map(|r| r.0), other.root().map(|r| r.0));
    }

    #[test]
    fn from_leaves_rejects_overflow() {
        let err =
            MerkleSumTree::from_leaves([leaf(1, u128::MAX), leaf(2, 1)]).expect_err("overflow");
        assert_eq!(
            err,
            SumOverflow {
                left: u128::MAX,
                right: 1
            }
        );
    }

    #[test]
    fn from_unique_leaves_matches_from_leaves_when_ids_are_distinct() {
        let leaves = [leaf(1, 40), leaf(2, 2), leaf(3, 8)];
        let unique = MerkleSumTree::from_unique_leaves(leaves).expect("unique");
        let plain = MerkleSumTree::from_leaves(leaves).expect("fits");
        assert_eq!(unique, plain);
        assert_eq!(unique.root().map(|r| r.1), Some(50));
    }

    #[test]
    fn from_unique_leaves_rejects_a_repeated_account() {
        let err =
            MerkleSumTree::from_unique_leaves([leaf(1, 10), leaf(2, 20), leaf(1, 30), leaf(3, 40)])
                .expect_err("duplicate");
        assert_eq!(
            err,
            SumBuildError::Duplicate {
                account_id: [1u8; 32],
                first: 0,
                second: 2,
            }
        );
        assert!(err.to_string().contains(&to_hex32(&[1u8; 32])));
        assert!(err.to_string().contains("index 0 and 2"));
    }

    #[test]
    fn from_leaves_still_allows_duplicate_ids() {
        let tree =
            MerkleSumTree::from_leaves([leaf(7, 1), leaf(7, 2)]).expect("duplicates still build");
        assert_eq!(tree.len(), 2);
        assert_eq!(tree.root().map(|r| r.1), Some(3));
        assert_eq!(tree.position(&[7u8; 32]), Some(0));
    }

    #[test]
    fn from_unique_leaves_surfaces_overflow() {
        let err = MerkleSumTree::from_unique_leaves([leaf(1, u128::MAX), leaf(2, 1)])
            .expect_err("overflow");
        assert_eq!(
            err,
            SumBuildError::Overflow(SumOverflow {
                left: u128::MAX,
                right: 1
            })
        );
    }

    #[test]
    fn from_sorted_leaves_matches_unique_when_ids_increase() {
        let leaves = [leaf(1, 40), leaf(2, 2), leaf(3, 8)];
        let sorted = MerkleSumTree::from_sorted_leaves(leaves).expect("sorted");
        let unique = MerkleSumTree::from_unique_leaves(leaves).expect("unique");
        assert_eq!(sorted, unique);
        assert!(sorted.is_sorted_unique());
        assert_eq!(sorted.binary_search(&[1u8; 32]), Some(0));
        assert_eq!(sorted.binary_search(&[2u8; 32]), Some(1));
        assert_eq!(sorted.binary_search(&[3u8; 32]), Some(2));
        assert_eq!(sorted.binary_search(&[9u8; 32]), None);
    }

    #[test]
    fn from_sorted_leaves_rejects_a_decrease() {
        let err =
            MerkleSumTree::from_sorted_leaves([leaf(2, 2), leaf(1, 40)]).expect_err("decreasing");
        assert_eq!(err, SumBuildError::Unsorted { index: 1 });
        assert!(err.to_string().contains("index 1"));
    }

    #[test]
    fn from_sorted_leaves_rejects_adjacent_duplicates() {
        let err =
            MerkleSumTree::from_sorted_leaves([leaf(1, 10), leaf(1, 20)]).expect_err("duplicate");
        assert_eq!(
            err,
            SumBuildError::Duplicate {
                account_id: [1u8; 32],
                first: 0,
                second: 1,
            }
        );
    }

    #[test]
    fn empty_and_single_leaf_trees_are_sorted_unique() {
        let empty = MerkleSumTree::from_sorted_leaves([]).expect("empty");
        assert!(empty.is_sorted_unique());
        assert_eq!(empty.binary_search(&[1u8; 32]), None);

        let one = MerkleSumTree::from_sorted_leaves([leaf(4, 9)]).expect("one");
        assert!(one.is_sorted_unique());
        assert_eq!(one.binary_search(&[4u8; 32]), Some(0));
    }

    #[test]
    fn unsorted_ids_are_found_by_position_and_agree_after_sorting() {
        let tree = MerkleSumTree::from_leaves([leaf(3, 1), leaf(1, 1), leaf(2, 1)]).expect("fits");
        assert!(!tree.is_sorted_unique());
        assert_eq!(tree.position(&[1u8; 32]), Some(1));
        assert_eq!(tree.position(&[3u8; 32]), Some(0));

        let sorted = MerkleSumTree::from_sorted_leaves([leaf(1, 1), leaf(2, 1), leaf(3, 1)])
            .expect("sorted");
        for id in 1u8..=3 {
            assert_eq!(sorted.binary_search(&[id; 32]), sorted.position(&[id; 32]));
        }
        assert_eq!(sorted.binary_search(&[9u8; 32]), None);
    }

    #[test]
    fn prove_absent_verifies_a_gap_between_neighbours() {
        let tree = MerkleSumTree::from_sorted_leaves([leaf(1, 10), leaf(3, 20), leaf(5, 30)])
            .expect("sorted");
        let root = tree.root_node().unwrap();
        let proof = tree.prove_absent(&[2u8; 32]).expect("missing");
        assert_eq!(proof.query, [2u8; 32]);
        assert_eq!(proof.left.as_ref().unwrap().leaf.account_id, [1u8; 32]);
        assert_eq!(proof.right.as_ref().unwrap().leaf.account_id, [3u8; 32]);
        assert_eq!(proof.verify(&root), Ok(()));
        assert!(tree.prove_absent(&[3u8; 32]).is_none());
    }

    #[test]
    fn prove_absent_covers_below_first_and_above_last() {
        let tree = MerkleSumTree::from_sorted_leaves([leaf(2, 1), leaf(4, 1)]).expect("sorted");
        let root = tree.root_node().unwrap();

        let below = tree.prove_absent(&[1u8; 32]).expect("below");
        assert!(below.left.is_none());
        assert_eq!(below.right.as_ref().unwrap().proof.leaf_index, 0);
        assert_eq!(below.verify(&root), Ok(()));

        let above = tree.prove_absent(&[9u8; 32]).expect("above");
        assert!(above.right.is_none());
        assert_eq!(above.left.as_ref().unwrap().proof.leaf_index, 1);
        assert_eq!(above.verify(&root), Ok(()));
    }

    #[test]
    fn prove_absent_needs_a_non_empty_sorted_tree() {
        let empty = MerkleSumTree::from_sorted_leaves([]).expect("empty");
        assert!(empty.prove_absent(&[1u8; 32]).is_none());

        let unsorted = MerkleSumTree::from_leaves([leaf(3, 1), leaf(1, 1)]).expect("fits");
        assert!(unsorted.prove_absent(&[2u8; 32]).is_none());
    }

    #[test]
    fn shifting_value_between_leaves_changes_the_root_hash() {
        let a = MerkleSumTree::from_leaves([leaf(1, 30), leaf(2, 12)]).expect("fits");
        let b = MerkleSumTree::from_leaves([leaf(1, 31), leaf(2, 11)]).expect("fits");
        assert_eq!(a.root().map(|r| r.1), b.root().map(|r| r.1));
        assert_ne!(a.root().map(|r| r.0), b.root().map(|r| r.0));
    }

    fn leaves(n: u8) -> Vec<SumLeaf> {
        (0..n).map(|i| leaf(i, u128::from(i) * 7 + 1)).collect()
    }

    #[test]
    fn every_leaf_proof_verifies_for_many_sizes() {
        for n in 1..=17u8 {
            let ls = leaves(n);
            let tree = MerkleSumTree::from_leaves(ls.clone()).expect("fits");
            let root = tree.root_node().expect("non-empty");
            for (i, l) in ls.iter().enumerate() {
                let proof = tree.prove(i).expect("in range");
                assert_eq!(proof.compute_root(l), Ok(root), "n={n} i={i}");
                assert_eq!(proof.verify(l, &root), Ok(()), "n={n} i={i}");
            }
            assert_eq!(tree.prove(ls.len()), None);
        }
    }

    #[test]
    fn single_leaf_proof_has_no_steps() {
        let l = leaf(1, 5);
        let tree = MerkleSumTree::from_leaves([l]).expect("fits");
        let proof = tree.prove(0).expect("in range");
        assert!(proof.steps.is_empty());
        assert_eq!(proof.verify(&l, &l.node()), Ok(()));
    }

    #[test]
    fn promoted_leaf_skips_a_level() {
        // Five leaves: leaf 4 is promoted twice, then meets the left subtree.
        let ls = leaves(5);
        let tree = MerkleSumTree::from_leaves(ls).expect("fits");
        let proof = tree.prove(4).expect("in range");
        assert_eq!(proof.steps.len(), 1);
        assert_eq!(proof.steps[0].side, SiblingSide::Left);
    }

    #[test]
    fn sibling_sums_add_up_to_root_total() {
        let ls = leaves(6);
        let tree = MerkleSumTree::from_leaves(ls.clone()).expect("fits");
        let (_, total) = tree.root().expect("non-empty");
        let proof = tree.prove(2).expect("in range");
        let sibling_total: u128 = proof.steps.iter().map(|s| s.sibling.sum).sum();
        assert_eq!(ls[2].amount + sibling_total, total);
    }

    #[test]
    fn wrong_amount_fails() {
        let ls = leaves(4);
        let tree = MerkleSumTree::from_leaves(ls.clone()).expect("fits");
        let root = tree.root_node().expect("non-empty");
        let proof = tree.prove(1).expect("in range");
        let lie = SumLeaf::new(ls[1].account_id, ls[1].amount + 1);
        assert_eq!(proof.verify(&lie, &root), Err(SumProofError::HashMismatch));
    }

    #[test]
    fn tampered_sibling_sum_fails() {
        let ls = leaves(4);
        let tree = MerkleSumTree::from_leaves(ls.clone()).expect("fits");
        let root = tree.root_node().expect("non-empty");
        let mut proof = tree.prove(0).expect("in range");
        proof.steps[1].sibling.sum -= 1;
        assert_eq!(
            proof.verify(&ls[0], &root),
            Err(SumProofError::HashMismatch)
        );
    }

    #[test]
    fn wrong_root_total_fails_even_with_right_hash() {
        let ls = leaves(4);
        let tree = MerkleSumTree::from_leaves(ls.clone()).expect("fits");
        let root = tree.root_node().expect("non-empty");
        let proof = tree.prove(3).expect("in range");
        let inflated = SumNode::new(root.hash, root.sum + 1);
        assert_eq!(
            proof.verify(&ls[3], &inflated),
            Err(SumProofError::SumMismatch {
                computed: root.sum,
                expected: root.sum + 1
            })
        );
    }

    #[test]
    fn moved_or_resized_proof_fails() {
        let ls = leaves(4);
        let tree = MerkleSumTree::from_leaves(ls.clone()).expect("fits");
        let root = tree.root_node().expect("non-empty");

        let mut moved = tree.prove(0).expect("in range");
        moved.leaf_index = 1;
        assert_eq!(
            moved.verify(&ls[0], &root),
            Err(SumProofError::WrongSide { step: 0 })
        );

        let mut resized = tree.prove(0).expect("in range");
        resized.leaf_count = 2;
        assert_eq!(
            resized.verify(&ls[0], &root),
            Err(SumProofError::PathLength {
                expected: 1,
                actual: 2
            })
        );

        let mut out_of_range = tree.prove(0).expect("in range");
        out_of_range.leaf_index = 4;
        assert_eq!(
            out_of_range.verify(&ls[0], &root),
            Err(SumProofError::IndexOutOfRange {
                index: 4,
                leaf_count: 4
            })
        );
    }

    #[test]
    fn overflowing_path_is_rejected() {
        let proof = SumInclusionProof {
            leaf_index: 0,
            leaf_count: 2,
            steps: Vec::from([SumProofStep {
                sibling: SumNode::new([0u8; 32], u128::MAX),
                side: SiblingSide::Right,
            }]),
        };
        let root = SumNode::new([0u8; 32], 0);
        assert_eq!(
            proof.verify(&leaf(1, 1), &root),
            Err(SumProofError::Overflow(SumOverflow {
                left: 1,
                right: u128::MAX
            }))
        );
    }

    #[test]
    fn parse_sum_csv_reads_rows_and_skips_header() {
        let id_a = crate::hashing::to_hex32(&[1u8; 32]);
        let id_b = crate::hashing::to_hex32(&[2u8; 32]);
        let text = format!("account_id,amount\n{id_a},40\n#{id_b},99\n{id_b},2\n");
        let leaves = parse_sum_csv(&text).expect("csv");
        assert_eq!(leaves, [leaf(1, 40), leaf(2, 2)]);
    }

    #[test]
    fn parse_sum_csv_accepts_0x_ids_and_comments() {
        let id = crate::hashing::to_hex32(&[9u8; 32]);
        let text = format!("# balances\n0x{id}, 7 \n");
        let leaves = parse_sum_csv(&text).expect("csv");
        assert_eq!(leaves, [leaf(9, 7)]);
    }

    #[test]
    fn parse_sum_csv_rejects_empty_and_bad_rows() {
        assert_eq!(parse_sum_csv("").unwrap_err(), SumCsvError::Empty);
        assert_eq!(
            parse_sum_csv("account_id,amount\n").unwrap_err(),
            SumCsvError::Empty
        );
        let id = crate::hashing::to_hex32(&[1u8; 32]);
        let err = parse_sum_csv(&format!("{id},nope")).unwrap_err();
        match err {
            SumCsvError::BadLine { line, message } => {
                assert_eq!(line, 1);
                assert!(message.contains("amount"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let err = parse_sum_csv(&format!("{id},1,extra")).unwrap_err();
        assert!(matches!(err, SumCsvError::BadLine { line: 1, .. }));
    }

    #[test]
    fn parse_sum_csv_feeds_a_tree_with_the_printed_total() {
        let a = crate::hashing::to_hex32(&[1u8; 32]);
        let b = crate::hashing::to_hex32(&[2u8; 32]);
        let c = crate::hashing::to_hex32(&[3u8; 32]);
        let leaves = parse_sum_csv(&format!("{a},40\n{b},2\n{c},8\n")).unwrap();
        let tree = MerkleSumTree::from_leaves(leaves).unwrap();
        let (hash, total) = tree.root().unwrap();
        assert_eq!(total, 50);
        assert_eq!(hash, tree.root_node().unwrap().hash);
    }

    fn five_leaf_tree() -> (Vec<SumLeaf>, MerkleSumTree) {
        let leaves: Vec<SumLeaf> = (1..=5).map(|i| leaf(i, u128::from(i) * 10)).collect();
        let tree = MerkleSumTree::from_leaves(leaves.clone()).unwrap();
        (leaves, tree)
    }

    #[test]
    fn proof_text_round_trips_for_every_leaf() {
        let (leaves, tree) = five_leaf_tree();
        let root = tree.root_node().unwrap();
        for (i, l) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            let text = sum_proof_to_text(l, &proof);
            let (parsed_leaf, parsed) = parse_sum_proof_text(&text).unwrap();
            assert_eq!(&parsed_leaf, l);
            assert_eq!(parsed, proof);
            assert!(parsed.verify(&parsed_leaf, &root).is_ok());
        }
    }

    #[test]
    fn proof_text_has_one_step_line_per_level() {
        let (leaves, tree) = five_leaf_tree();
        // Leaf 4 is promoted twice in a 5-leaf tree, so it has one step.
        let text = sum_proof_to_text(&leaves[4], &tree.prove(4).unwrap());
        assert_eq!(text.lines().filter(|l| l.starts_with("step=")).count(), 1);
        assert!(text.contains("index=4\nleaf_count=5\n"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn proof_text_skips_comments_and_blank_lines() {
        let (leaves, tree) = five_leaf_tree();
        let text = sum_proof_to_text(&leaves[1], &tree.prove(1).unwrap());
        let noisy = format!("# exported proof\n\n{text}\n");
        assert_eq!(
            parse_sum_proof_text(&noisy).unwrap(),
            parse_sum_proof_text(&text).unwrap()
        );
    }

    #[test]
    fn edited_amount_in_proof_text_fails_verification() {
        let (leaves, tree) = five_leaf_tree();
        let root = tree.root_node().unwrap();
        let text = sum_proof_to_text(&leaves[2], &tree.prove(2).unwrap());
        let edited = text.replace("amount=30\n", "amount=31\n");
        let (l, proof) = parse_sum_proof_text(&edited).unwrap();
        assert_eq!(l.amount, 31);
        assert_eq!(proof.verify(&l, &root), Err(SumProofError::HashMismatch));
    }

    #[test]
    fn proof_text_rejects_bad_input() {
        let (leaves, tree) = five_leaf_tree();
        let text = sum_proof_to_text(&leaves[0], &tree.prove(0).unwrap());

        let mut without_amount = String::new();
        for line in text.lines().filter(|l| !l.starts_with("amount=")) {
            without_amount.push_str(line);
            without_amount.push('\n');
        }
        assert_eq!(
            parse_sum_proof_text(&without_amount).unwrap_err(),
            SumProofTextError::Missing("amount")
        );
        assert_eq!(
            parse_sum_proof_text(&format!("{text}index=1\n")).unwrap_err(),
            SumProofTextError::Duplicate("index")
        );
        let cases = [
            "colour=blue",
            "amount=-1",
            "account=abcd",
            "step=X:00:1",
            "step=L:00",
            "no equals sign",
        ];
        for bad in cases {
            let err = parse_sum_proof_text(&format!("{text}{bad}\n")).unwrap_err();
            assert!(
                matches!(err, SumProofTextError::BadLine { .. }),
                "{bad}: {err:?}"
            );
        }
        let hash = to_hex32(&[9u8; 32]);
        let err = parse_sum_proof_text(&format!("{text}step=L:{hash}:x\n")).unwrap_err();
        assert!(err.to_string().contains("invalid step sum"));
    }

    #[test]
    fn position_finds_the_first_matching_account() {
        let (_, tree) = five_leaf_tree();
        assert_eq!(tree.position(&[3u8; 32]), Some(2));
        assert_eq!(tree.position(&[9u8; 32]), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_is_implemented_for_sum_roots_and_proofs() {
        fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
        assert_serde::<SumLeaf>();
        assert_serde::<SumNode>();
        assert_serde::<SumProofStep>();
        assert_serde::<SumInclusionProof>();
        assert_serde::<SumAbsenceNeighbor>();
        assert_serde::<SumAbsenceProof>();
    }
}
