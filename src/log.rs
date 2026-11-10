//! Append-only log whose successive Merkle roots commit to every prefix.
//!
//! Each [`MerkleLog::append`] (or non-empty [`MerkleLog::extend`]) records a
//! [`LogCheckpoint`]: the Merkle root of all entries present at that moment.
//! Inclusion proofs are always against the *current* root. Historical roots
//! can be checked by rebuilding a prefix tree from the stored entries.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::hashing::to_hex32;
use crate::proof::{verify_inclusion, InclusionProof, IndexedInclusionProof};
use crate::tree::MerkleTree;

/// A published Merkle root together with how many log entries it covers.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogCheckpoint {
    /// Number of entries committed by [`Self::root`].
    pub leaf_count: usize,
    /// Merkle root of `entries[..leaf_count]`.
    pub root: [u8; 32],
}

impl LogCheckpoint {
    /// Root as lowercase hex.
    pub fn root_hex(&self) -> String {
        to_hex32(&self.root)
    }
}

impl core::fmt::Display for LogCheckpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "n={}, root={}", self.leaf_count, self.root_hex())
    }
}

/// An append-only sequence of entries committed by a Merkle tree.
///
/// Raw entry bytes are retained so a caller can re-prove inclusion and rebuild
/// any historical prefix. The tree itself stores only hashes, matching
/// [`MerkleTree`].
#[derive(Debug, Clone)]
pub struct MerkleLog {
    entries: Vec<Vec<u8>>,
    tree: MerkleTree,
    checkpoints: Vec<LogCheckpoint>,
}

impl MerkleLog {
    /// Empty log with no root and no checkpoints.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            tree: MerkleTree::from_leaves(core::iter::empty::<&[u8]>()),
            checkpoints: Vec::new(),
        }
    }

    /// Build a log from existing entries and record a single checkpoint.
    ///
    /// Empty input matches [`Self::new`].
    pub fn from_entries<I, T>(entries: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut log = Self::new();
        log.extend(entries);
        log
    }

    fn snapshot(&mut self) {
        if let Some(root) = self.tree.root() {
            self.checkpoints.push(LogCheckpoint {
                leaf_count: self.entries.len(),
                root,
            });
        }
    }

    /// Append one entry, snapshot the new root, and return the entry index.
    ///
    /// ```
    /// use merkle_tree::MerkleLog;
    ///
    /// let mut log = MerkleLog::new();
    /// assert_eq!(log.append("deposit 10"), 0);
    /// assert_eq!(log.append("withdraw 3"), 1);
    /// assert_eq!(log.checkpoints().len(), 2);
    /// assert!(log.verify_entry(0));
    /// assert!(log.history_matches());
    /// ```
    pub fn append<T: AsRef<[u8]>>(&mut self, entry: T) -> usize {
        let bytes = entry.as_ref();
        let index = self.entries.len();
        self.tree.append(bytes);
        self.entries.push(bytes.to_vec());
        self.snapshot();
        index
    }

    /// Append many entries and snapshot one root at the end of the batch.
    ///
    /// Empty input is a no-op and does not add a checkpoint.
    pub fn extend<I, T>(&mut self, entries: I)
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let start = self.entries.len();
        for entry in entries {
            self.entries.push(entry.as_ref().to_vec());
        }
        if self.entries.len() == start {
            return;
        }
        self.tree
            .extend(self.entries[start..].iter().map(|e| e.as_slice()));
        self.snapshot();
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no entries have been appended.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow the entry at `index`, if present.
    pub fn entry(&self, index: usize) -> Option<&[u8]> {
        self.entries.get(index).map(|e| e.as_slice())
    }

    /// All entries in append order.
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }

    /// Current Merkle root, if the log is non-empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.tree.root()
    }

    /// Current Merkle root as lowercase hex.
    pub fn root_hex(&self) -> Option<String> {
        self.tree.root_hex()
    }

    /// Recorded checkpoints, oldest first.
    pub fn checkpoints(&self) -> &[LogCheckpoint] {
        &self.checkpoints
    }

    /// Roots from each checkpoint, oldest first.
    pub fn root_history(&self) -> Vec<[u8; 32]> {
        self.checkpoints.iter().map(|cp| cp.root).collect()
    }

    /// Merkle root of the prefix `entries[..n]`, rebuilt from stored data.
    ///
    /// Returns `None` when `n` is zero or greater than the current length.
    pub fn prefix_root(&self, n: usize) -> Option<[u8; 32]> {
        if n == 0 || n > self.entries.len() {
            return None;
        }
        MerkleTree::from_leaves(self.entries[..n].iter().map(|e| e.as_slice())).root()
    }

    /// Inclusion proof for `index` against the current root.
    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        self.tree.prove(index)
    }

    /// Inclusion proof for `index` that also carries the leaf index.
    pub fn prove_indexed(&self, index: usize) -> Option<IndexedInclusionProof> {
        self.tree.prove_indexed(index)
    }

    /// Verify that stored entry `index` proves against the current root.
    pub fn verify_entry(&self, index: usize) -> bool {
        match (self.entry(index), self.prove(index), self.root()) {
            (Some(data), Some(proof), Some(root)) => verify_inclusion(data, &proof.steps, root),
            _ => false,
        }
    }

    /// Rebuild a prefix tree for every checkpoint and check the stored root.
    pub fn history_matches(&self) -> bool {
        self.checkpoints.iter().all(|cp| {
            self.prefix_root(cp.leaf_count) == Some(cp.root) && cp.leaf_count <= self.entries.len()
        })
    }
}

impl Default for MerkleLog {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: AsRef<[u8]>> core::iter::FromIterator<T> for MerkleLog {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from_entries(iter)
    }
}

impl<T: AsRef<[u8]>> core::iter::Extend<T> for MerkleLog {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        MerkleLog::extend(self, iter);
    }
}

impl core::fmt::Display for MerkleLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.root_hex() {
            Some(root) => write!(
                f,
                "entries={}, checkpoints={}, root={}",
                self.len(),
                self.checkpoints.len(),
                root
            ),
            None => write!(f, "entries=0, checkpoints=0, root=none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MerkleTree;
    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString, vec, vec::Vec};

    #[test]
    fn empty_log_has_no_root_or_proofs() {
        let log = MerkleLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.root().is_none());
        assert!(log.root_hex().is_none());
        assert!(log.checkpoints().is_empty());
        assert!(log.root_history().is_empty());
        assert!(log.prove(0).is_none());
        assert!(!log.verify_entry(0));
        assert!(log.history_matches());
        assert!(log.prefix_root(0).is_none());
        assert_eq!(log.to_string(), "entries=0, checkpoints=0, root=none");
        assert_eq!(MerkleLog::default().root(), None);
    }

    #[test]
    fn append_snapshots_a_root_per_entry() {
        let mut log = MerkleLog::new();
        assert_eq!(log.append("a"), 0);
        assert_eq!(log.append("b"), 1);
        assert_eq!(log.append("c"), 2);
        assert_eq!(log.len(), 3);
        assert_eq!(log.checkpoints().len(), 3);
        assert_eq!(log.checkpoints()[0].leaf_count, 1);
        assert_eq!(log.checkpoints()[1].leaf_count, 2);
        assert_eq!(log.checkpoints()[2].leaf_count, 3);
        assert_eq!(
            log.checkpoints()[0].root,
            MerkleTree::from_leaves(["a"]).root().unwrap()
        );
        assert_eq!(
            log.checkpoints()[1].root,
            MerkleTree::from_leaves(["a", "b"]).root().unwrap()
        );
        assert_eq!(log.root(), MerkleTree::from_leaves(["a", "b", "c"]).root());
        assert!(log.history_matches());
        assert_eq!(log.prefix_root(2), Some(log.checkpoints()[1].root));
        assert!(log.prefix_root(4).is_none());
    }

    #[test]
    fn from_entries_records_a_single_checkpoint() {
        let log = MerkleLog::from_entries(["x", "y", "z"]);
        assert_eq!(log.checkpoints().len(), 1);
        assert_eq!(log.checkpoints()[0].leaf_count, 3);
        assert_eq!(log.root(), MerkleTree::from_leaves(["x", "y", "z"]).root());
        let collected: MerkleLog = ["x", "y", "z"].into_iter().collect();
        assert_eq!(collected.root(), log.root());
        assert_eq!(collected.checkpoints(), log.checkpoints());
        assert!(log.history_matches());
    }

    #[test]
    fn extend_batches_one_checkpoint_and_ignores_empty() {
        let mut log = MerkleLog::from_entries(["a"]);
        let before = log.checkpoints().to_vec();
        log.extend(core::iter::empty::<&str>());
        assert_eq!(log.checkpoints(), before.as_slice());
        log.extend(["b", "c", "d"]);
        assert_eq!(log.len(), 4);
        assert_eq!(log.checkpoints().len(), 2);
        assert_eq!(log.checkpoints()[1].leaf_count, 4);
        assert_eq!(
            log.root(),
            MerkleTree::from_leaves(["a", "b", "c", "d"]).root()
        );
        <MerkleLog as core::iter::Extend<&str>>::extend(&mut log, ["e"]);
        assert_eq!(log.len(), 5);
        assert!(log.history_matches());
    }

    #[test]
    fn old_entries_still_prove_against_the_latest_root() {
        let mut log = MerkleLog::new();
        log.append("one");
        log.append("two");
        log.extend(["three", "four"]);
        let root = log.root().unwrap();
        for i in 0..log.len() {
            assert!(log.verify_entry(i), "entry {i}");
            let proof = log.prove(i).unwrap();
            assert!(proof.verify(root));
            let indexed = log.prove_indexed(i).unwrap();
            assert_eq!(indexed.index, i);
            assert_eq!(log.entry(i).unwrap(), log.entries()[i].as_slice());
        }
        assert!(!log.verify_entry(99));
        assert!(log.to_string().contains("entries=4"));
        assert_eq!(log.checkpoints()[0].root_hex().len(), 64);
        assert!(log.checkpoints()[0].to_string().contains("n=1"));
    }

    #[test]
    fn append_one_by_one_matches_fresh_prefix_trees() {
        let leaves = ["w", "x", "y", "z", "!"];
        let mut log = MerkleLog::new();
        for (i, leaf) in leaves.iter().enumerate() {
            log.append(leaf);
            let fresh = MerkleTree::from_leaves(leaves.iter().take(i + 1));
            assert_eq!(log.root(), fresh.root());
            assert_eq!(log.prefix_root(i + 1), fresh.root());
        }
        assert_eq!(log.root_history().len(), leaves.len());
        assert!(log.history_matches());
    }
}
