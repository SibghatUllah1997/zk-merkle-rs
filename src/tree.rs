//! Merkle tree construction, leaf metadata, and typed roots.
//!
//! Trees are built bottom-up. Odd layers duplicate the last hash so every
//! parent has two children. A single-leaf tree's root is exactly that leaf
//! hash; an empty tree has no root.
//!
//! All hashes live in one contiguous buffer. Layer 0 is the leaf hashes;
//! each later layer is the parents of the one below. A non-empty tree's root
//! is the last stored hash, so walking a proof only needs index arithmetic
//! inside that buffer instead of chasing a `Vec` per layer.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::cache::ProofIndexCache;
use crate::error::{try_array32, HashNotImplemented, HexError, LengthError};
use crate::hashing::{commit_root, to_hex32, try_from_hex32, HashAlgorithm, TreeHasher};
use crate::proof::{
    classify_compact_sibling, unique_sorted_indices, CompactMultiProof, CompactSibling,
    InclusionProof, IndexedInclusionProof, MultiProof, ProofStep, SiblingSide,
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

/// A Merkle tree with explicit domain separation.
///
/// SHA-256 is the default. With the `blake3` or `poseidon` features, trees can
/// also be built over those hashes via [`MerkleTree::try_from_leaves_with`];
/// the chosen algorithm is remembered so appends keep hashing the same way.
///
/// Hashes are stored leaf-to-root in a single `Vec`. `layer_offsets[i]` is the
/// start of layer `i` in that buffer; the last offset is the buffer length.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf hashes, then parent hashes, then the root. Empty iff the tree is empty.
    hashes: Vec<[u8; 32]>,
    /// `hashes[layer_offsets[i]..layer_offsets[i + 1]]` is layer `i`.
    /// Empty iff the tree is empty. Length is `layer_count() + 1` otherwise.
    layer_offsets: Vec<usize>,
    hasher: TreeHasher,
}

/// Exact number of hashes stored for a tree with `leaf_count` leaves, using
/// duplicate-last padding of odd layers (the padded sibling is not stored).
fn stored_hash_count(leaf_count: usize) -> usize {
    if leaf_count == 0 {
        return 0;
    }
    let mut n = leaf_count;
    let mut total = n;
    while n > 1 {
        n = (n + 1) / 2;
        total += n;
    }
    total
}

/// Number of layers (including the leaf layer) for `leaf_count` leaves.
fn stored_layer_count(leaf_count: usize) -> usize {
    if leaf_count == 0 {
        0
    } else {
        leaf_count.next_power_of_two().trailing_zeros() as usize + 1
    }
}

impl MerkleTree {
    /// Build a new tree from raw leaf data items.
    pub fn from_leaves<I, T>(leaves: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        Self::from_leaves_inner(TreeHasher::Sha256, leaves)
    }

    /// Build a tree from raw leaf data using `algorithm`.
    ///
    /// Fails with [`HashNotImplemented`] for placeholder algorithms such as
    /// Rescue. With [`HashAlgorithm::Sha256`] this equals [`Self::from_leaves`].
    ///
    /// ```
    /// use merkle_tree::{HashAlgorithm, MerkleTree};
    ///
    /// let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Sha256, ["a", "b"])?;
    /// assert_eq!(tree.root(), MerkleTree::from_leaves(["a", "b"]).root());
    /// assert_eq!(tree.algorithm(), HashAlgorithm::Sha256);
    /// # Ok::<(), merkle_tree::HashNotImplemented>(())
    /// ```
    pub fn try_from_leaves_with<I, T>(
        algorithm: HashAlgorithm,
        leaves: I,
    ) -> Result<Self, HashNotImplemented>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        Ok(Self::from_leaves_inner(TreeHasher::new(algorithm)?, leaves))
    }

    /// Build a tree from leaf hashes that were produced with `algorithm`
    /// (for example with [`crate::hash_leaf_with`]).
    pub fn try_from_hashed_leaves_with<I>(
        algorithm: HashAlgorithm,
        hashes: I,
    ) -> Result<Self, HashNotImplemented>
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let hasher = TreeHasher::new(algorithm)?;
        Ok(Self::from_leaf_hashes(hasher, hashes.into_iter().collect()))
    }

    fn from_leaves_inner<I, T>(hasher: TreeHasher, leaves: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let leaf_hashes: Vec<[u8; 32]> = leaves
            .into_iter()
            .map(|x| hasher.leaf(x.as_ref()))
            .collect();
        Self::from_leaf_hashes(hasher, leaf_hashes)
    }

    /// Hash algorithm used for every leaf and node in this tree.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.hasher.algorithm()
    }

    /// Build a tree from leaf hashes that are already domain-separated
    /// (`H(0x00 || data)`).
    ///
    /// Use this when callers hashed leaves themselves with [`crate::hash_leaf`] and do
    /// not need the raw preimage stored in the tree. Empty input yields an
    /// empty tree, matching [`Self::from_leaves`].
    ///
    /// ```
    /// use merkle_tree::{hash_leaf, MerkleTree};
    ///
    /// let hashes = [hash_leaf(b"a"), hash_leaf(b"b")];
    /// let from_raw = MerkleTree::from_leaves(["a", "b"]);
    /// let from_hashed = MerkleTree::from_hashed_leaves(hashes);
    /// assert_eq!(from_raw.root(), from_hashed.root());
    /// ```
    pub fn from_hashed_leaves<I>(hashes: I) -> Self
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        Self::from_leaf_hashes(TreeHasher::Sha256, hashes.into_iter().collect())
    }

    fn from_leaf_hashes(hasher: TreeHasher, mut hashes: Vec<[u8; 32]>) -> Self {
        if hashes.is_empty() {
            return Self {
                hashes,
                layer_offsets: Vec::new(),
                hasher,
            };
        }
        let leaf_count = hashes.len();
        hashes.reserve(stored_hash_count(leaf_count) - leaf_count);
        let mut layer_offsets = Vec::with_capacity(stored_layer_count(leaf_count) + 1);
        layer_offsets.push(0);
        let mut layer_start = 0;
        loop {
            let layer_end = hashes.len();
            layer_offsets.push(layer_end);
            let layer_len = layer_end - layer_start;
            if layer_len <= 1 {
                break;
            }
            let mut i = layer_start;
            while i < layer_end {
                let left = hashes[i];
                let right = if i + 1 < layer_end {
                    hashes[i + 1]
                } else {
                    hashes[i]
                };
                hashes.push(hasher.nodes(&left, &right));
                i += 2;
            }
            layer_start = layer_end;
        }
        hashes.shrink_to_fit();
        layer_offsets.shrink_to_fit();
        Self {
            hashes,
            layer_offsets,
            hasher,
        }
    }

    /// Append one raw leaf and return its index.
    ///
    /// The leaf is hashed as `H(0x00 || data)` with the tree's algorithm. Upper layers are rebuilt from
    /// the leaf layer, so each call costs O(n) hashes; use [`Extend`] to add
    /// many leaves with a single rebuild. The result always equals a tree
    /// built from scratch over the same leaves.
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let mut tree = MerkleTree::from_leaves(["a", "b"]);
    /// let index = tree.append("c");
    /// assert_eq!(index, 2);
    /// assert_eq!(tree.root(), MerkleTree::from_leaves(["a", "b", "c"]).root());
    /// ```
    pub fn append<T: AsRef<[u8]>>(&mut self, leaf: T) -> usize {
        self.append_hashed(self.hasher.leaf(leaf.as_ref()))
    }

    /// Append one already-hashed leaf (`H(0x00 || data)`) and return its index.
    pub fn append_hashed(&mut self, hash: [u8; 32]) -> usize {
        let index = self.leaf_count();
        self.extend_hashed(core::iter::once(hash));
        index
    }

    /// Append many already-hashed leaves with a single rebuild.
    ///
    /// Truncates the buffer back to the leaf layer in place so the existing
    /// allocation can hold the new parents, then rebuilds upper layers.
    pub fn extend_hashed<I>(&mut self, hashes: I)
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let n = self.leaf_count();
        self.hashes.truncate(n);
        self.hashes.extend(hashes);
        let leaf_hashes = core::mem::take(&mut self.hashes);
        *self = Self::from_leaf_hashes(self.hasher, leaf_hashes);
    }

    /// `true` when the tree was built from no leaves.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Number of hash layers, including the leaf layer. Zero for an empty tree.
    pub fn layer_count(&self) -> usize {
        self.layer_offsets.len().saturating_sub(1)
    }

    /// Number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        match self.layer_offsets.get(1) {
            Some(&end) => end,
            None => 0,
        }
    }

    /// Exact number of hashes a tree with `leaf_count` leaves stores, including
    /// internal nodes and the root.
    ///
    /// Odd layers hash the last node twice for the missing sibling, but the
    /// duplicate is not stored. For a power-of-two leaf count this is `2n - 1`;
    /// otherwise it is a little larger because those padded parents exist.
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
    /// assert_eq!(tree.hash_count(), MerkleTree::stored_hash_count(4));
    /// assert_eq!(MerkleTree::stored_hash_count(4), 7);
    /// assert_eq!(MerkleTree::stored_hash_count(3), 6);
    /// ```
    pub fn stored_hash_count(leaf_count: usize) -> usize {
        stored_hash_count(leaf_count)
    }

    /// Total number of stored hashes, including internal nodes and the root.
    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }

    /// Bytes occupied by stored hashes (`32 * hash_count`).
    ///
    /// This is the payload size of the contiguous buffer, not `Vec` capacity
    /// overhead or the small offset table.
    pub fn storage_bytes(&self) -> usize {
        self.hash_count() * 32
    }

    /// Number of hashes at `level` (0 = leaves). `None` if out of range.
    pub fn layer_len(&self, level: usize) -> Option<usize> {
        let start = self.layer_offsets.get(level).copied()?;
        let end = self.layer_offsets.get(level + 1).copied()?;
        Some(end - start)
    }

    /// Borrow the hashes of layer `level` (0 = leaves). `None` if out of range.
    ///
    /// Layers are adjacent slices of the same buffer: the end of layer `i` is
    /// the start of layer `i + 1`, and the last layer is the single root hash.
    pub fn layer_hashes(&self, level: usize) -> Option<&[[u8; 32]]> {
        let start = *self.layer_offsets.get(level)?;
        let end = *self.layer_offsets.get(level + 1)?;
        Some(&self.hashes[start..end])
    }

    /// Root hash of the tree. Returns None for an empty tree.
    ///
    /// The root is the last hash in the contiguous buffer.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.hashes.last().copied()
    }

    /// Root hash wrapped in `MerkleRoot`. Returns None for an empty tree.
    pub fn root_typed(&self) -> Option<MerkleRoot> {
        self.root().map(MerkleRoot)
    }

    /// Root bound to this tree's leaf count via [`commit_root`]. Returns
    /// None for an empty tree.
    ///
    /// Publish this instead of [`Self::root`] when verifiers should not
    /// accept a tree that differs only by a duplicated last leaf.
    pub fn committed_root(&self) -> Option<[u8; 32]> {
        self.root()
            .map(|root| commit_root(&root, self.leaf_count() as u64))
    }

    /// Root hash formatted as lowercase hex. Returns None for an empty tree.
    pub fn root_hex(&self) -> Option<String> {
        self.root().map(|r| to_hex32(&r))
    }

    /// Return the hashed leaf at index, if present.
    pub fn leaf_hash_at(&self, index: usize) -> Option<[u8; 32]> {
        if index >= self.leaf_count() {
            return None;
        }
        self.hashes.get(index).copied()
    }

    /// Return leaf metadata (index + hash) at `index`, if present.
    pub fn leaf_info(&self, index: usize) -> Option<LeafInfo> {
        self.leaf_hash_at(index)
            .map(|hash| LeafInfo { index, hash })
    }

    /// Return metadata for all leaves (index + hash).
    pub fn leaf_infos(&self) -> Vec<LeafInfo> {
        self.hashes
            .iter()
            .take(self.leaf_count())
            .copied()
            .enumerate()
            .map(|(index, hash)| LeafInfo { index, hash })
            .collect()
    }

    /// Convenience: leaf infos rendered as `(index, hex_hash)` tuples.
    pub fn leaf_infos_hex(&self) -> Vec<(usize, String)> {
        self.leaf_infos()
            .into_iter()
            .map(|li| (li.index, to_hex32(&li.hash)))
            .collect()
    }

    /// Whole contiguous hash buffer, leaf layer first and root last.
    pub(crate) fn hash_buffer(&self) -> &[[u8; 32]] {
        &self.hashes
    }

    /// Layer start offsets into [`Self::hash_buffer`], plus the final length.
    pub(crate) fn layer_offsets(&self) -> &[usize] {
        &self.layer_offsets
    }

    /// Precompute parent and sibling positions for fast repeated proofs.
    ///
    /// Building the cache is one pass over the buffer. Afterwards every proof
    /// is a chain of table lookups; see [`ProofIndexCache`]. The cache
    /// borrows `self`, so the tree cannot change while it is alive.
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_leaves(["a", "b", "c"]);
    /// let cache = tree.proof_index_cache();
    /// assert_eq!(cache.prove_all(), tree.prove_all());
    /// ```
    pub fn proof_index_cache(&self) -> ProofIndexCache<'_> {
        ProofIndexCache::new(self)
    }

    /// Slice of hashes at `level` (0 = leaves). Panics if `level` is out of range.
    fn layer(&self, level: usize) -> &[[u8; 32]] {
        let start = self.layer_offsets[level];
        let end = self.layer_offsets[level + 1];
        &self.hashes[start..end]
    }

    /// Generate an inclusion proof for the leaf at `index`.
    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaf_count() {
            return None;
        }
        let mut steps = Vec::new();
        let mut idx = index;
        let last_level = self.layer_count().saturating_sub(1);
        for level in 0..last_level {
            let layer = self.layer(level);
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
        let leaf_hash = self.hashes[index];
        Some(InclusionProof { leaf_hash, steps })
    }

    /// Generate an inclusion proof with the original leaf `index` as metadata.
    pub fn prove_indexed(&self, index: usize) -> Option<IndexedInclusionProof> {
        self.prove(index)
            .map(|proof| IndexedInclusionProof { index, proof })
    }

    /// Generate a naive multiproof for `indices`.
    ///
    /// Each index is proved independently: overlapping siblings are repeated,
    /// and duplicate indices each get their own copy of the same path. Returns
    /// `None` if any index is out of range. An empty `indices` list yields an
    /// empty [`MultiProof`], including on an empty tree.
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
    /// let root = tree.root().expect("root");
    /// let multi = tree.prove_many([0, 3]).expect("in range");
    /// assert_eq!(multi.indices(), vec![0, 3]);
    /// assert!(multi.verify(root));
    /// ```
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

    /// Naive multiproof covering every leaf, in index order.
    ///
    /// Always succeeds: an empty tree yields an empty bundle.
    pub fn prove_all(&self) -> MultiProof {
        self.prove_many(0..self.leaf_count()).unwrap_or_default()
    }

    /// Generate a compact multiproof for `indices`.
    ///
    /// Indices are sorted and de-duplicated. A sibling that sits on more than
    /// one proved path is stored once. Returns `None` if any index is out of
    /// range. An empty `indices` list yields an empty [`CompactMultiProof`],
    /// including on an empty tree.
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
    /// let compact = tree.prove_compact([0, 1]).expect("in range");
    /// assert_eq!(compact.indices(), &[0, 1]);
    /// assert_eq!(compact.sibling_count(), 1);
    /// assert!(compact.verify(tree.root().expect("root")));
    /// ```
    pub fn prove_compact<I>(&self, indices: I) -> Option<CompactMultiProof>
    where
        I: IntoIterator<Item = usize>,
    {
        let leaf_count = self.leaf_count();
        let indices = unique_sorted_indices(indices, leaf_count)?;
        if indices.is_empty() {
            return Some(CompactMultiProof {
                leaf_count,
                indices,
                leaves: Vec::new(),
                siblings: Vec::new(),
            });
        }

        let leaves: Vec<[u8; 32]> = indices.iter().map(|&i| self.hashes[i]).collect();
        let mut siblings = Vec::new();
        let mut known = indices.clone();
        let mut layer_len = leaf_count;
        let last_level = self.layer_count().saturating_sub(1);

        for level in 0..last_level {
            let layer = self.layer(level);
            let mut parents = Vec::with_capacity(known.len());
            let mut i = 0;
            while i < known.len() {
                let idx = known[i];
                let next = known.get(i + 1).copied();
                match classify_compact_sibling(idx, next, layer_len) {
                    CompactSibling::DuplicatePad => {}
                    CompactSibling::KnownPair => {
                        i += 1;
                    }
                    CompactSibling::External => {
                        siblings.push(layer[idx ^ 1]);
                    }
                }
                let parent = idx / 2;
                if parents.last().copied() != Some(parent) {
                    parents.push(parent);
                }
                i += 1;
            }
            known = parents;
            layer_len = (layer_len + 1) / 2;
        }

        Some(CompactMultiProof {
            leaf_count,
            indices,
            leaves,
            siblings,
        })
    }

    /// Compact multiproof covering every leaf, in index order.
    ///
    /// Always succeeds. Because every leaf is provided, the sibling list is
    /// empty: each parent is determined by the claimed leaves (and padding).
    pub fn prove_compact_all(&self) -> CompactMultiProof {
        self.prove_compact(0..self.leaf_count()).unwrap_or_default()
    }
}

impl<T: AsRef<[u8]>> core::iter::FromIterator<T> for MerkleTree {
    /// Hash each item as a leaf and build the tree, matching [`Self::from_leaves`].
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from_leaves(iter)
    }
}

impl<T: AsRef<[u8]>> core::iter::Extend<T> for MerkleTree {
    /// Hash each item as a leaf and append it, rebuilding the upper layers once.
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let hasher = self.hasher;
        self.extend_hashed(iter.into_iter().map(|x| hasher.leaf(x.as_ref())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_leaf;
    use crate::proof::{parse_proof_steps, verify_inclusion};
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, string::ToString, vec};

    #[test]
    fn contiguous_buffer_matches_layer_sizes() {
        for n in 0..=17usize {
            let leaves: Vec<String> = (0..n).map(|i| format!("l{i}")).collect();
            let tree = MerkleTree::from_leaves(leaves.iter());
            assert_eq!(tree.hashes.len(), stored_hash_count(n));
            assert_eq!(tree.layer_count(), stored_layer_count(n));
            if n == 0 {
                assert!(tree.hashes.is_empty());
                assert!(tree.layer_offsets.is_empty());
                continue;
            }
            assert_eq!(tree.layer_offsets.first().copied(), Some(0));
            assert_eq!(tree.layer_offsets.last().copied(), Some(tree.hashes.len()));
            assert_eq!(tree.layer_offsets.len(), tree.layer_count() + 1);
            let mut expected_len = n;
            for level in 0..tree.layer_count() {
                let start = tree.layer_offsets[level];
                let end = tree.layer_offsets[level + 1];
                assert_eq!(end - start, expected_len, "n={n} level={level}");
                assert_eq!(tree.layer(level).len(), expected_len);
                expected_len = (expected_len + 1) / 2;
            }
            assert_eq!(tree.root(), tree.hashes.last().copied());
            assert_eq!(tree.hashes.capacity(), tree.hashes.len());
            assert_eq!(tree.hash_count(), stored_hash_count(n));
            assert_eq!(tree.hash_count(), MerkleTree::stored_hash_count(n));
            assert_eq!(tree.storage_bytes(), tree.hash_count() * 32);
            assert_eq!(tree.layer_len(tree.layer_count()), None);
            assert_eq!(tree.layer_hashes(tree.layer_count()), None);
            if n >= 1 {
                let leaves = tree.layer_hashes(0).expect("leaf layer");
                assert_eq!(leaves.len(), n);
                assert_eq!(tree.layer_len(0), Some(n));
                let root_layer = tree.layer_hashes(tree.layer_count() - 1).expect("root");
                assert_eq!(root_layer, core::slice::from_ref(&tree.root().unwrap()));
                for (i, leaf) in leaves.iter().enumerate() {
                    assert_eq!(tree.leaf_hash_at(i).as_ref(), Some(leaf));
                }
            }
        }
        assert_eq!(MerkleTree::stored_hash_count(0), 0);
        assert_eq!(MerkleTree::stored_hash_count(1), 1);
        assert_eq!(MerkleTree::stored_hash_count(2), 3);
        assert_eq!(MerkleTree::stored_hash_count(8), 15);
        let empty = MerkleTree::from_leaves(core::iter::empty::<&[u8]>());
        assert_eq!(empty.hash_count(), 0);
        assert_eq!(empty.storage_bytes(), 0);
        assert_eq!(empty.layer_len(0), None);
        assert_eq!(empty.layer_hashes(0), None);
    }

    #[test]
    fn append_matches_fresh_build_and_returns_index() {
        let mut tree = MerkleTree::from_leaves(core::iter::empty::<&[u8]>());
        for (i, leaf) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            assert_eq!(tree.append(leaf), i);
            let fresh = MerkleTree::from_leaves(["a", "b", "c", "d", "e"].iter().take(i + 1));
            assert_eq!(tree.root(), fresh.root());
            assert_eq!(tree.layer_count(), fresh.layer_count());
        }
    }

    #[test]
    fn proofs_stay_valid_after_append() {
        let mut tree = MerkleTree::from_leaves(["a", "b", "c"]);
        tree.append("d");
        tree.append_hashed(hash_leaf(b"e"));
        let root = tree.root().expect("root");
        for i in 0..tree.leaf_count() {
            assert!(tree.prove(i).expect("proof").verify(root));
        }
        assert_eq!(tree.leaf_count(), 5);
    }

    #[test]
    fn extend_adds_many_and_empty_extend_is_a_noop() {
        let mut tree = MerkleTree::from_leaves(["a", "b"]);
        let before = tree.root();
        tree.extend(core::iter::empty::<&str>());
        assert_eq!(tree.root(), before);
        tree.extend(["c", "d", "e"]);
        assert_eq!(
            tree.root(),
            MerkleTree::from_leaves(["a", "b", "c", "d", "e"]).root()
        );
        let mut empty = MerkleTree::from_leaves(core::iter::empty::<&str>());
        empty.extend(core::iter::empty::<&str>());
        assert!(empty.is_empty());
    }

    #[test]
    fn merkle_root_try_from_slice_and_from_array() {
        let arr = [9u8; 32];
        let mr_from = MerkleRoot::from(arr);
        assert_eq!(*mr_from.as_bytes(), arr);
        let mr_try = MerkleRoot::try_from(arr.as_slice()).expect("try_from ok");
        assert_eq!(*mr_try.as_bytes(), arr);
        let arr_back: [u8; 32] = mr_try.into();
        assert_eq!(arr_back, arr);
        let mr_ref_slice: &[u8; 32] = mr_from.as_ref();
        assert_eq!(mr_ref_slice, &arr);
        let bad = [0u8; 31];
        assert!(MerkleRoot::try_from(&bad[..]).is_err());
    }

    #[test]
    fn empty_tree_has_no_root_or_proofs() {
        let tree = MerkleTree::from_leaves(core::iter::empty::<&[u8]>());
        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.layer_count(), 0);
        assert!(tree.root().is_none());
        assert!(tree.root_typed().is_none());
        assert!(tree.root_hex().is_none());
        assert!(tree.prove(0).is_none());
        assert!(tree.prove_indexed(0).is_none());
        assert!(tree.leaf_infos().is_empty());
    }

    #[test]
    fn single_leaf_root_is_the_leaf_hash() {
        let tree = MerkleTree::from_leaves(["only"].map(|s| s.as_bytes()));
        assert!(!tree.is_empty());
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.layer_count(), 1);
        let leaf = hash_leaf(b"only");
        assert_eq!(tree.root(), Some(leaf));
        let proof = tree.prove(0).expect("proof");
        assert!(proof.steps.is_empty());
        assert!(proof.verify(leaf));
        assert!(tree.prove(1).is_none());
    }

    #[test]
    fn root_and_proofs_even_leaves() {
        let leaves = ["a", "b", "c", "d"].map(|s| s.as_bytes().to_vec());
        let tree = MerkleTree::from_leaves(leaves);
        let root = tree.root().expect("root");
        for i in 0..tree.leaf_count() {
            let proof = tree.prove(i).expect("proof");
            assert!(proof.verify(root), "proof failed at index {i}");
        }
        assert!(!to_hex32(&root).is_empty());
        assert_eq!(tree.layer_count(), 3);
    }

    #[test]
    fn odd_leaf_padding_duplicate_last() {
        let leaves = ["a", "b", "c"].map(|s| s.as_bytes().to_vec());
        let tree = MerkleTree::from_leaves(leaves);
        assert_eq!(tree.leaf_count(), 3);
        let root = tree.root().unwrap();
        let proof2 = tree.prove(2).unwrap();
        assert!(proof2.verify(root));
        assert!(verify_inclusion(b"c", &proof2.steps, root));
    }

    #[test]
    fn inclusion_proof_display_and_hex_helpers() {
        let tree = MerkleTree::from_leaves(["a", "b", "c"].map(|s| s.as_bytes()));
        let root_hex = tree.root_hex().expect("root hex");
        assert_eq!(root_hex.len(), 64);
        let proof = tree.prove(1).expect("proof for index 1");
        let leaf_hex = proof.leaf_hex();
        assert_eq!(leaf_hex.len(), 64);
        let steps_hex = proof.steps_hex();
        assert!(!steps_hex.is_empty());
        for (side, h) in steps_hex {
            assert!(side == 'L' || side == 'R');
            assert_eq!(h.len(), 64);
        }
        let s = proof.to_string();
        assert!(s.contains("leaf=") && s.contains("steps=["));
    }

    #[test]
    fn leaf_info_helpers_return_expected_metadata() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"].map(|s| s.as_bytes()));
        let li2 = tree.leaf_info(2).expect("leaf info at 2");
        assert_eq!(li2.index, 2);
        assert_eq!(li2.hash, hash_leaf(b"c"));
        assert!(tree.leaf_info(99).is_none());
        let all = tree.leaf_infos();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].index, 0);
        assert_eq!(all[0].hash, hash_leaf(b"a"));
        assert_eq!(all[3].index, 3);
        assert_eq!(all[3].hash, hash_leaf(b"d"));
        let hexes = tree.leaf_infos_hex();
        assert_eq!(hexes.len(), 4);
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

        let with_space = parse_proof_steps(&format!(" {} ", spec.replace(',', ", "))).unwrap();
        assert_eq!(with_space, proof.steps);
        let lower = spec.replace('R', "r").replace('L', "l");
        assert_eq!(parse_proof_steps(&lower).unwrap(), proof.steps);
        assert!(parse_proof_steps("").unwrap().is_empty());
        assert!(parse_proof_steps("   ").unwrap().is_empty());

        let single = MerkleTree::from_leaves(["only"].map(|s| s.as_bytes()));
        assert!(single.prove(0).unwrap().steps_spec().is_empty());
    }

    #[test]
    fn from_hashed_leaves_matches_from_leaves() {
        let leaves = ["a", "b", "c", "d"];
        let hashes = leaves.map(|s| hash_leaf(s.as_bytes()));
        let from_raw = MerkleTree::from_leaves(leaves);
        let from_hashed = MerkleTree::from_hashed_leaves(hashes);
        assert_eq!(from_hashed.root(), from_raw.root());
        assert_eq!(from_hashed.leaf_count(), from_raw.leaf_count());
        assert_eq!(from_hashed.leaf_infos(), from_raw.leaf_infos());
        let root = from_hashed.root().expect("root");
        for (i, expected_hash) in hashes.iter().enumerate() {
            let proof = from_hashed.prove(i).expect("proof");
            assert!(proof.verify(root));
            assert_eq!(proof.leaf_hash, *expected_hash);
        }
    }

    #[test]
    fn from_hashed_leaves_empty_and_single() {
        let empty = MerkleTree::from_hashed_leaves(core::iter::empty::<[u8; 32]>());
        assert!(empty.is_empty());
        assert!(empty.root().is_none());
        assert!(empty.prove(0).is_none());

        let only = hash_leaf(b"only");
        let single = MerkleTree::from_hashed_leaves([only]);
        assert_eq!(single.leaf_count(), 1);
        assert_eq!(single.layer_count(), 1);
        assert_eq!(single.root(), Some(only));
        let proof = single.prove(0).expect("proof");
        assert!(proof.steps.is_empty());
        assert!(proof.verify(only));
    }

    #[test]
    fn collect_from_strs_matches_from_leaves() {
        let expected = MerkleTree::from_leaves(["a", "b", "c", "d"]);
        let collected: MerkleTree = ["a", "b", "c", "d"].into_iter().collect();
        assert_eq!(collected.root(), expected.root());
        assert_eq!(collected.leaf_count(), expected.leaf_count());
        assert_eq!(collected.leaf_infos(), expected.leaf_infos());
    }

    #[test]
    fn collect_from_byte_slices_vecs_and_strings() {
        let from_slices: MerkleTree = [b"a".as_ref(), b"b".as_ref(), b"c".as_ref()]
            .into_iter()
            .collect();
        let from_vecs: MerkleTree = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
            .into_iter()
            .collect();
        let from_owned: MerkleTree = [String::from("a"), String::from("b"), String::from("c")]
            .into_iter()
            .collect();
        let expected = MerkleTree::from_leaves(["a", "b", "c"]);
        assert_eq!(from_slices.root(), expected.root());
        assert_eq!(from_vecs.root(), expected.root());
        assert_eq!(from_owned.root(), expected.root());
    }

    #[test]
    fn collect_empty_iterator_is_empty_tree() {
        let tree: MerkleTree = core::iter::empty::<&[u8]>().collect();
        assert!(tree.is_empty());
        assert!(tree.root().is_none());
    }

    #[test]
    fn prove_many_preserves_order_and_duplicates() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
        let root = tree.root().expect("root");
        let multi = tree.prove_many([2, 0, 2]).expect("in range");
        assert_eq!(multi.indices(), vec![2, 0, 2]);
        assert_eq!(multi.len(), 3);
        assert!(multi.verify(root));
        assert_eq!(multi.proofs[0].proof.leaf_hash, hash_leaf(b"c"));
        assert_eq!(multi.proofs[1].proof.leaf_hash, hash_leaf(b"a"));
        assert_eq!(multi.proofs[0], multi.proofs[2]);
        assert!(tree.prove_many([0, 99]).is_none());
        assert!(tree.prove_many([4]).is_none());
    }

    #[test]
    fn prove_many_empty_request_and_empty_tree() {
        let empty = MerkleTree::from_leaves(core::iter::empty::<&[u8]>());
        let none = empty
            .prove_many(core::iter::empty::<usize>())
            .expect("empty");
        assert!(none.is_empty());
        assert!(empty.prove_many([0]).is_none());
        assert!(empty.prove_all().is_empty());

        let tree = MerkleTree::from_leaves(["a", "b", "c"]);
        let root = tree.root().expect("root");
        let none = tree
            .prove_many(core::iter::empty::<usize>())
            .expect("empty");
        assert!(none.is_empty());
        assert!(none.verify(root));

        let all = tree.prove_all();
        assert_eq!(all.indices(), vec![0, 1, 2]);
        assert!(all.verify(root));
        for (i, item) in all.proofs.iter().enumerate() {
            assert_eq!(item.index, i);
            assert_eq!(item.proof, tree.prove(i).unwrap());
        }
    }

    #[test]
    fn prove_many_odd_leaf_count_matches_single_proofs() {
        let tree = MerkleTree::from_leaves(["a", "b", "c"]);
        let root = tree.root().expect("root");
        let multi = tree.prove_many([0, 2]).expect("in range");
        assert!(multi.verify(root));
        assert_eq!(multi.proofs[0].proof, tree.prove(0).unwrap());
        assert_eq!(multi.proofs[1].proof, tree.prove(2).unwrap());
    }

    #[test]
    fn prove_compact_sorts_dedups_and_matches_leaf_hashes() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
        let compact = tree.prove_compact([2, 0, 2]).expect("in range");
        assert_eq!(compact.leaf_count, 4);
        assert_eq!(compact.indices(), &[0, 2]);
        assert_eq!(compact.leaves, vec![hash_leaf(b"a"), hash_leaf(b"c")]);
        assert_eq!(compact.leaves_hex().len(), 2);
        assert!(tree.prove_compact([0, 99]).is_none());
        assert!(tree.prove_compact([4]).is_none());
    }

    #[test]
    fn prove_compact_all_has_no_siblings() {
        for n in 0..=9usize {
            let leaves: Vec<String> = (0..n).map(|i| format!("l{i}")).collect();
            let tree = MerkleTree::from_leaves(leaves.iter());
            let compact = tree.prove_compact_all();
            assert_eq!(compact.leaf_count, n);
            assert_eq!(compact.indices, (0..n).collect::<Vec<_>>());
            assert!(compact.siblings.is_empty(), "n={n}");
            if n == 0 {
                assert!(compact.is_empty());
                assert!(compact.verify([0u8; 32]));
            } else {
                assert!(compact.verify(tree.root().unwrap()), "n={n}");
            }
        }
    }

    #[test]
    fn prove_compact_adjacent_pair_stores_one_sibling() {
        let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
        let compact = tree.prove_compact([0, 1]).expect("in range");
        assert_eq!(compact.sibling_count(), 1);
        assert!(compact.verify(tree.root().unwrap()));
        let naive = tree.prove_many([0, 1]).expect("in range");
        let naive_hashes: usize = naive.proofs.iter().map(|p| p.proof.steps.len()).sum();
        assert!(compact.sibling_count() < naive_hashes);
        let shown = compact.to_string();
        assert!(shown.contains("leaf_count=4"));
        assert!(shown.contains("indices=[0, 1]"));
    }

    #[test]
    fn try_from_leaves_with_sha256_matches_default_constructors() {
        let leaves = ["a", "b", "c"];
        let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Sha256, leaves).expect("sha");
        assert_eq!(tree.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(tree.root(), MerkleTree::from_leaves(leaves).root());
        assert_eq!(
            MerkleTree::from_leaves(leaves).algorithm(),
            HashAlgorithm::Sha256
        );
        let hashed = MerkleTree::try_from_hashed_leaves_with(
            HashAlgorithm::Sha256,
            leaves.map(|l| hash_leaf(l.as_bytes())),
        )
        .expect("sha");
        assert_eq!(hashed.root(), tree.root());
    }

    #[cfg(feature = "rescue")]
    #[test]
    fn placeholder_algorithms_cannot_build_trees() {
        let err = MerkleTree::try_from_leaves_with(HashAlgorithm::Rescue, ["a"]).expect_err("stub");
        assert_eq!(err, HashNotImplemented::new("rescue"));
        let empty: [[u8; 32]; 0] = [];
        assert!(MerkleTree::try_from_hashed_leaves_with(HashAlgorithm::Rescue, empty).is_err());
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn poseidon_tree_keeps_its_algorithm_across_appends() {
        let mut tree =
            MerkleTree::try_from_leaves_with(HashAlgorithm::Poseidon, ["a"]).expect("poseidon");
        assert_eq!(tree.root(), Some(crate::hashing::poseidon_hash_leaf(b"a")));
        tree.append("b");
        let expected = crate::hashing::poseidon_hash_nodes(
            &crate::hashing::poseidon_hash_leaf(b"a"),
            &crate::hashing::poseidon_hash_leaf(b"b"),
        );
        assert_eq!(tree.root(), Some(expected));
        tree.extend(["c", "d", "e"]);
        let rebuilt =
            MerkleTree::try_from_leaves_with(HashAlgorithm::Poseidon, ["a", "b", "c", "d", "e"])
                .expect("poseidon");
        assert_eq!(tree.root(), rebuilt.root());
        assert_eq!(tree.algorithm(), HashAlgorithm::Poseidon);
        assert_ne!(
            tree.root(),
            MerkleTree::from_leaves(["a", "b", "c", "d", "e"]).root()
        );
        let compact = tree.prove_compact([0, 4]).expect("in range");
        assert_eq!(
            compact.verify_with(HashAlgorithm::Poseidon, tree.root().unwrap()),
            Ok(true)
        );
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_tree_keeps_its_algorithm_across_appends() {
        use crate::hashing::{blake3_hash_leaf, blake3_hash_nodes};
        let mut tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, ["a"]).expect("b3");
        assert_eq!(tree.root(), Some(blake3_hash_leaf(b"a")));
        tree.append("b");
        let expected = blake3_hash_nodes(&blake3_hash_leaf(b"a"), &blake3_hash_leaf(b"b"));
        assert_eq!(tree.root(), Some(expected));
        tree.extend(["c", "d", "e"]);
        let rebuilt =
            MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, ["a", "b", "c", "d", "e"])
                .expect("b3");
        assert_eq!(tree.root(), rebuilt.root());
        assert_eq!(tree.algorithm(), HashAlgorithm::Blake3);
        assert_ne!(
            tree.root(),
            MerkleTree::from_leaves(["a", "b", "c", "d", "e"]).root()
        );
    }
}
