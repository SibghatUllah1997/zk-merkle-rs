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
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::proof::SiblingSide;

/// Domain tag for a sum-tree leaf hash (`0x30`).
pub const SUM_LEAF_PREFIX: u8 = 0x30;

/// Domain tag for a sum-tree parent hash (`0x31`).
pub const SUM_NODE_PREFIX: u8 = 0x31;

/// Fixed-width account identifier committed in a sum-tree leaf.
pub type AccountId = [u8; 32];

/// One account balance in a Merkle sum tree.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumInclusionProof {
    /// Position of the leaf in the tree.
    pub leaf_index: usize,
    /// Number of leaves in the tree the proof was made for.
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
    }

    #[test]
    fn single_leaf_root_is_the_leaf_node() {
        let leaf = leaf(1, 99);
        let tree = MerkleSumTree::from_leaves([leaf]).expect("fits");
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.root(), Some((leaf.hash(), 99)));
        assert_eq!(tree.root_node(), Some(leaf.node()));
        assert_eq!(tree.leaves(), &[leaf]);
    }

    #[test]
    fn two_leaf_root_matches_parent() {
        let a = leaf(1, 30);
        let b = leaf(2, 12);
        let tree = MerkleSumTree::from_leaves([a, b]).expect("fits");
        let parent = SumNode::parent(&a.node(), &b.node()).expect("fits");
        assert_eq!(tree.root(), Some((parent.hash, 42)));
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
    fn shifting_value_between_leaves_changes_the_root_hash() {
        let a = MerkleSumTree::from_leaves([leaf(1, 30), leaf(2, 12)]).expect("fits");
        let b = MerkleSumTree::from_leaves([leaf(1, 31), leaf(2, 11)]).expect("fits");
        assert_eq!(a.root().map(|r| r.1), b.root().map(|r| r.1));
        assert_ne!(a.root().map(|r| r.0), b.root().map(|r| r.0));
    }
}
