//! Cached parent and sibling positions for repeated proof generation.
//!
//! [`MerkleTree::prove`] works out each step with index arithmetic: halve the
//! index, look up the layer offset, flip the low bit for the sibling, and
//! check whether the layer was padded. That is cheap for one proof, but a
//! server that hands out thousands of proofs from the same tree repeats the
//! same arithmetic for every request.
//!
//! [`ProofIndexCache`] does that work once. For every position in the
//! tree's contiguous hash buffer it stores the position of the parent and of
//! the sibling. A proof is then a walk of plain table lookups from the leaf
//! to the root, with no per-step offset math or padding checks.
//!
//! The cache borrows the tree, so the borrow checker stops the tree from
//! being appended to (and the tables from going stale) while the cache is
//! alive.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::proof::{InclusionProof, IndexedInclusionProof, MultiProof, ProofStep, SiblingSide};
use crate::tree::MerkleTree;

/// Precomputed parent/sibling positions for one [`MerkleTree`].
///
/// Build it with [`MerkleTree::proof_index_cache`]. Proofs from the cache are
/// identical to [`MerkleTree::prove`]; only the way they are assembled
/// differs.
///
/// Memory cost is two `usize` per stored hash (16 bytes on 64-bit targets,
/// half the size of the hashes themselves), so it is opt-in rather than part
/// of every tree.
///
/// ```
/// use merkle_tree::MerkleTree;
///
/// let tree = MerkleTree::from_leaves(["a", "b", "c", "d", "e"]);
/// let cache = tree.proof_index_cache();
/// let root = tree.root().expect("root");
/// for i in 0..tree.leaf_count() {
///     let proof = cache.prove(i).expect("in range");
///     assert_eq!(Some(&proof), tree.prove(i).as_ref());
///     assert!(proof.verify(root));
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProofIndexCache<'a> {
    tree: &'a MerkleTree,
    /// `parent[p]` is the buffer position of the parent of position `p`.
    /// The root maps to itself, which is how a walk knows to stop.
    parent: Vec<usize>,
    /// `sibling[p]` is the buffer position of the sibling of `p`. When an odd
    /// layer is padded, the last node is its own sibling.
    sibling: Vec<usize>,
}

impl<'a> ProofIndexCache<'a> {
    pub(crate) fn new(tree: &'a MerkleTree) -> Self {
        let total = tree.hash_count();
        let mut parent = Vec::with_capacity(total);
        let mut sibling = Vec::with_capacity(total);
        let offsets = tree.layer_offsets();
        let layers = tree.layer_count();
        for level in 0..layers {
            let start = offsets[level];
            let end = offsets[level + 1];
            for pos in start..end {
                let local = pos - start;
                let sib_local = local ^ 1;
                sibling.push(if start + sib_local < end {
                    start + sib_local
                } else {
                    pos
                });
                parent.push(if level + 1 < layers {
                    offsets[level + 1] + local / 2
                } else {
                    pos
                });
            }
        }
        debug_assert_eq!(parent.len(), total);
        debug_assert_eq!(sibling.len(), total);
        Self {
            tree,
            parent,
            sibling,
        }
    }

    /// The tree these tables were built for.
    pub fn tree(&self) -> &'a MerkleTree {
        self.tree
    }

    /// Number of buffer positions covered (equals the tree's hash count).
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    /// `true` for the cache of an empty tree.
    pub fn is_empty(&self) -> bool {
        self.parent.is_empty()
    }

    /// Extra bytes held by the two position tables (not counting the tree).
    pub fn table_bytes(&self) -> usize {
        (self.parent.len() + self.sibling.len()) * core::mem::size_of::<usize>()
    }

    /// Buffer position of the parent of `position`. The root returns itself.
    /// `None` if `position` is out of range.
    pub fn parent_of(&self, position: usize) -> Option<usize> {
        self.parent.get(position).copied()
    }

    /// Buffer position of the sibling of `position`. A padded last node
    /// returns itself. `None` if `position` is out of range.
    pub fn sibling_of(&self, position: usize) -> Option<usize> {
        self.sibling.get(position).copied()
    }

    /// Buffer positions of every sibling on the path from leaf `index` to the
    /// root, bottom-up. `None` if `index` is out of range.
    pub fn sibling_positions(&self, index: usize) -> Option<Vec<usize>> {
        if index >= self.tree.leaf_count() {
            return None;
        }
        let mut out = Vec::with_capacity(self.tree.layer_count().saturating_sub(1));
        let mut pos = index;
        while self.parent[pos] != pos {
            out.push(self.sibling[pos]);
            pos = self.parent[pos];
        }
        Some(out)
    }

    /// Inclusion proof for leaf `index`, assembled from the cached tables.
    ///
    /// Returns the same value as [`MerkleTree::prove`].
    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.tree.leaf_count() {
            return None;
        }
        let hashes = self.tree.hash_buffer();
        let mut steps = Vec::with_capacity(self.tree.layer_count().saturating_sub(1));
        let mut pos = index;
        while self.parent[pos] != pos {
            let sib = self.sibling[pos];
            // A left child (or a padded node, whose sibling is itself) gets its
            // sibling on the right.
            let side = if sib < pos {
                SiblingSide::Left
            } else {
                SiblingSide::Right
            };
            steps.push(ProofStep {
                sibling: hashes[sib],
                side,
            });
            pos = self.parent[pos];
        }
        Some(InclusionProof {
            leaf_hash: hashes[index],
            steps,
        })
    }

    /// Like [`Self::prove`], with the leaf index kept as metadata.
    pub fn prove_indexed(&self, index: usize) -> Option<IndexedInclusionProof> {
        self.prove(index)
            .map(|proof| IndexedInclusionProof { index, proof })
    }

    /// Naive multiproof for `indices`, matching [`MerkleTree::prove_many`].
    pub fn prove_many<I>(&self, indices: I) -> Option<MultiProof>
    where
        I: IntoIterator<Item = usize>,
    {
        let mut proofs = Vec::new();
        for index in indices {
            proofs.push(self.prove_indexed(index)?);
        }
        Some(MultiProof { proofs })
    }

    /// Proofs for every leaf, matching [`MerkleTree::prove_all`].
    pub fn prove_all(&self) -> MultiProof {
        self.prove_many(0..self.tree.leaf_count())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec};

    fn tree_of(n: usize) -> MerkleTree {
        let leaves: Vec<String> = (0..n).map(|i| format!("leaf-{i}")).collect();
        MerkleTree::from_leaves(leaves.iter())
    }

    #[test]
    fn empty_tree_has_empty_cache() {
        let tree = tree_of(0);
        let cache = tree.proof_index_cache();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.table_bytes(), 0);
        assert!(cache.prove(0).is_none());
        assert!(cache.sibling_positions(0).is_none());
        assert!(cache.prove_all().is_empty());
        assert!(cache.parent_of(0).is_none());
        assert!(cache.sibling_of(0).is_none());
    }

    #[test]
    fn single_leaf_is_its_own_root() {
        let tree = tree_of(1);
        let cache = tree.proof_index_cache();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.parent_of(0), Some(0));
        assert_eq!(cache.sibling_of(0), Some(0));
        let proof = cache.prove(0).expect("proof");
        assert!(proof.steps.is_empty());
        assert_eq!(cache.sibling_positions(0), Some(vec![]));
    }

    #[test]
    fn three_leaf_tables_match_hand_layout() {
        // Buffer: [l0, l1, l2, p01, p22, root]
        let tree = tree_of(3);
        let cache = tree.proof_index_cache();
        assert_eq!(cache.parent, vec![3, 3, 4, 5, 5, 5]);
        assert_eq!(cache.sibling, vec![1, 0, 2, 4, 3, 5]);
        assert_eq!(cache.sibling_positions(2), Some(vec![2, 3]));
        assert_eq!(cache.table_bytes(), 12 * core::mem::size_of::<usize>());
    }

    #[test]
    fn cached_proofs_equal_direct_proofs() {
        for n in 0..=70 {
            let tree = tree_of(n);
            let cache = tree.proof_index_cache();
            assert_eq!(cache.len(), tree.hash_count());
            for i in 0..=n {
                assert_eq!(cache.prove(i), tree.prove(i), "n={n} i={i}");
                assert_eq!(cache.prove_indexed(i), tree.prove_indexed(i));
            }
            assert_eq!(cache.prove_all(), tree.prove_all());
        }
    }

    #[test]
    fn root_is_the_only_fixed_point() {
        for n in 1..=40 {
            let tree = tree_of(n);
            let cache = tree.proof_index_cache();
            let root_pos = tree.hash_count() - 1;
            for p in 0..cache.len() {
                let parent = cache.parent_of(p).unwrap();
                assert_eq!(parent == p, p == root_pos, "n={n} p={p}");
                assert!(parent >= p);
                let sib = cache.sibling_of(p).unwrap();
                assert_eq!(cache.parent_of(sib), Some(parent));
            }
        }
    }
}
