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

use sha2::{Digest, Sha256};

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
}
