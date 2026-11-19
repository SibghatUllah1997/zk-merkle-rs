//! Solvency checks: compare a published sum-tree commitment to an
//! independently computed liabilities snapshot (feature `merkle_sum`).
//!
//! An exchange publishes a root `(hash, total)`. An auditor takes their own
//! export of customer balances, rebuilds the sum tree, and compares:
//!
//! - **Total.** If the published total is *below* the snapshot total the
//!   exchange is understating liabilities, which is the failure proof of
//!   reserves exists to catch. A total *above* the snapshot is safe for users
//!   but still means the two data sets differ.
//! - **Root hash.** Equal totals with a different hash mean balances moved
//!   between accounts, accounts were swapped, or the leaf order differs.
//! - **Duplicate account ids.** The same id twice double-counts (or hides)
//!   a balance, so it is reported even when everything else matches.
//! - **Reserves (optional).** Reserves cover liabilities when they are at
//!   least the *snapshot* total; the auditor trusts their own figure, not the
//!   published one.
//!
//! The root depends on leaf order, so the snapshot must list accounts in the
//! publisher's order. Totals and duplicates do not depend on order.
//!
//! ```
//! use merkle_tree::solvency::{compare_liabilities, TotalStatus};
//! use merkle_tree::sum::{MerkleSumTree, SumLeaf};
//!
//! let snapshot = [SumLeaf::new([1u8; 32], 70), SumLeaf::new([2u8; 32], 30)];
//! let published = MerkleSumTree::from_leaves(snapshot).unwrap().root_node().unwrap();
//!
//! let report = compare_liabilities(&published, &snapshot).unwrap().with_reserves(120);
//! assert!(report.is_consistent());
//! assert_eq!(report.total_status(), TotalStatus::Match);
//! assert_eq!(report.reserve_shortfall(), Some(0));
//! ```

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use crate::sum::{AccountId, MerkleSumTree, SumLeaf, SumNode, SumOverflow};

/// Why a liabilities snapshot could not be compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolvencyError {
    /// The snapshot has no accounts, so there is no root to compare.
    EmptySnapshot,
    /// Snapshot amounts overflow `u128`.
    Overflow(SumOverflow),
}

impl core::fmt::Display for SolvencyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SolvencyError::EmptySnapshot => write!(f, "liabilities snapshot has no accounts"),
            SolvencyError::Overflow(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SolvencyError {}

impl From<SumOverflow> for SolvencyError {
    fn from(err: SumOverflow) -> Self {
        SolvencyError::Overflow(err)
    }
}

/// How the published total relates to the snapshot total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotalStatus {
    /// Published total equals the snapshot total.
    Match,
    /// Published total is lower than the snapshot by `by`: hidden liabilities.
    Understated {
        /// Snapshot total minus published total.
        by: u128,
    },
    /// Published total is higher than the snapshot by `by`.
    Overstated {
        /// Published total minus snapshot total.
        by: u128,
    },
}

impl TotalStatus {
    fn compare(published: u128, computed: u128) -> Self {
        match published.cmp(&computed) {
            core::cmp::Ordering::Equal => TotalStatus::Match,
            core::cmp::Ordering::Less => TotalStatus::Understated {
                by: computed - published,
            },
            core::cmp::Ordering::Greater => TotalStatus::Overstated {
                by: published - computed,
            },
        }
    }
}

/// Result of comparing a published commitment with a liabilities snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolvencyReport {
    published: SumNode,
    computed: SumNode,
    accounts: usize,
    duplicates: Vec<AccountId>,
    reserves: Option<u128>,
}

impl SolvencyReport {
    /// The `(hash, total)` the exchange published.
    pub fn published(&self) -> SumNode {
        self.published
    }

    /// The `(hash, total)` rebuilt from the snapshot.
    pub fn computed(&self) -> SumNode {
        self.computed
    }

    /// Number of rows in the snapshot, duplicates included.
    pub fn accounts(&self) -> usize {
        self.accounts
    }

    /// Account ids that appear more than once, sorted, each listed once.
    pub fn duplicates(&self) -> &[AccountId] {
        &self.duplicates
    }

    /// Published total compared with the snapshot total.
    pub fn total_status(&self) -> TotalStatus {
        TotalStatus::compare(self.published.sum, self.computed.sum)
    }

    /// Whether the published root hash equals the rebuilt one.
    pub fn root_matches(&self) -> bool {
        self.published.hash == self.computed.hash
    }

    /// Same root, same total, and no duplicate account ids.
    pub fn is_consistent(&self) -> bool {
        self.root_matches()
            && self.total_status() == TotalStatus::Match
            && self.duplicates.is_empty()
    }

    /// Attach the reserves figure to check coverage against.
    pub fn with_reserves(mut self, reserves: u128) -> Self {
        self.reserves = Some(reserves);
        self
    }

    /// Reserves attached with [`Self::with_reserves`], if any.
    pub fn reserves(&self) -> Option<u128> {
        self.reserves
    }

    /// How far reserves fall short of the snapshot total; `Some(0)` when
    /// covered, `None` when no reserves were attached.
    pub fn reserve_shortfall(&self) -> Option<u128> {
        self.reserves.map(|r| self.computed.sum.saturating_sub(r))
    }
}

/// Rebuild the sum tree from `snapshot` and compare it with `published`.
///
/// Fails only when the snapshot cannot be turned into a tree (empty or
/// overflowing). Every mismatch is reported in the [`SolvencyReport`].
pub fn compare_liabilities(
    published: &SumNode,
    snapshot: &[SumLeaf],
) -> Result<SolvencyReport, SolvencyError> {
    let tree = MerkleSumTree::from_leaves(snapshot.iter().copied())?;
    let computed = tree.root_node().ok_or(SolvencyError::EmptySnapshot)?;
    Ok(SolvencyReport {
        published: *published,
        computed,
        accounts: snapshot.len(),
        duplicates: duplicate_ids(snapshot),
        reserves: None,
    })
}

fn duplicate_ids(snapshot: &[SumLeaf]) -> Vec<AccountId> {
    let mut seen = BTreeSet::new();
    let mut dups = BTreeSet::new();
    for leaf in snapshot {
        if !seen.insert(leaf.account_id) {
            dups.insert(leaf.account_id);
        }
    }
    dups.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves() -> [SumLeaf; 3] {
        [
            SumLeaf::new([1; 32], 40),
            SumLeaf::new([2; 32], 2),
            SumLeaf::new([3; 32], 8),
        ]
    }

    fn root_of(leaves: &[SumLeaf]) -> SumNode {
        MerkleSumTree::from_leaves(leaves.iter().copied())
            .unwrap()
            .root_node()
            .unwrap()
    }

    #[test]
    fn identical_snapshot_is_consistent() {
        let snap = leaves();
        let report = compare_liabilities(&root_of(&snap), &snap).unwrap();
        assert!(report.is_consistent());
        assert_eq!(report.accounts(), 3);
        assert_eq!(report.computed().sum, 50);
        assert_eq!(report.reserve_shortfall(), None);
    }

    #[test]
    fn lower_published_total_is_understated() {
        let snap = leaves();
        let mut published = root_of(&snap);
        published.sum = 45;
        let report = compare_liabilities(&published, &snap).unwrap();
        assert_eq!(report.total_status(), TotalStatus::Understated { by: 5 });
        assert!(report.root_matches());
        assert!(!report.is_consistent());
    }

    #[test]
    fn higher_published_total_is_overstated() {
        let snap = leaves();
        let mut published = root_of(&snap);
        published.sum = 51;
        let report = compare_liabilities(&published, &snap).unwrap();
        assert_eq!(report.total_status(), TotalStatus::Overstated { by: 1 });
    }

    #[test]
    fn moved_balance_keeps_total_but_breaks_root() {
        let snap = leaves();
        let mut shifted = snap;
        shifted[0].amount -= 10;
        shifted[1].amount += 10;
        let report = compare_liabilities(&root_of(&shifted), &snap).unwrap();
        assert_eq!(report.total_status(), TotalStatus::Match);
        assert!(!report.root_matches());
        assert!(!report.is_consistent());
    }

    #[test]
    fn duplicate_ids_are_listed_once_and_sorted() {
        let snap = [
            SumLeaf::new([9; 32], 1),
            SumLeaf::new([2; 32], 1),
            SumLeaf::new([9; 32], 1),
            SumLeaf::new([2; 32], 1),
            SumLeaf::new([9; 32], 1),
        ];
        let report = compare_liabilities(&root_of(&snap), &snap).unwrap();
        assert_eq!(report.duplicates(), &[[2; 32], [9; 32]]);
        assert!(report.root_matches());
        assert!(!report.is_consistent());
    }

    #[test]
    fn reserves_are_checked_against_the_snapshot_total() {
        let snap = leaves();
        let mut published = root_of(&snap);
        published.sum = 30; // understated, so 40 would "cover" the published figure
        let report = compare_liabilities(&published, &snap)
            .unwrap()
            .with_reserves(40);
        assert_eq!(report.reserves(), Some(40));
        assert_eq!(report.reserve_shortfall(), Some(10));
        let covered = report.with_reserves(50);
        assert_eq!(covered.reserve_shortfall(), Some(0));
    }

    #[test]
    fn empty_and_overflowing_snapshots_are_errors() {
        let published = SumNode::new([0; 32], 0);
        assert_eq!(
            compare_liabilities(&published, &[]),
            Err(SolvencyError::EmptySnapshot)
        );
        let big = [SumLeaf::new([1; 32], u128::MAX), SumLeaf::new([2; 32], 1)];
        assert!(matches!(
            compare_liabilities(&published, &big),
            Err(SolvencyError::Overflow(_))
        ));
    }
}
