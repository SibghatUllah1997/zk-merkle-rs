# Tree variants

"Merkle tree" is a family of layouts, not one data structure. This crate
implements one of them: a binary tree over an ordered list of leaves, with
duplicate-last padding, a contiguous hash buffer, and optional hash
algorithms. Other layouts exist for other jobs. This chapter says which
one you have and which ones you do not.

## What this crate is

- **Shape.** Leaves sit in a sequence. Each layer hashes adjacent pairs.
  Odd layers duplicate the last hash for that parent only
  ([Padding](padding.md)).
- **Root.** One 32-byte digest, or a count-bound commitment
  (`committed_root`).
- **Proofs.** A path of siblings from one leaf to the root, a naive bundle
  of those paths, or a compact bundle that stores shared siblings once.
- **Growth.** `append` / `extend` rebuild the upper layers from the leaf
  buffer. The result matches a tree built from scratch over the same
  leaves. Each single append is O(n) hashes.
- **Hash.** SHA-256 by default. BLAKE3 and Poseidon are feature-gated
  alternatives with the same pairing rule. Rescue is a named stub.

Use it when you have an ordered list (file chunks, log entries, a static
set of keys) and you want inclusion proofs against a published root.

## Nearby layouts this crate does not implement

**Power-of-two trees with empty or zero fillers.** Some designs pad the
leaf list to `2^k` with empty leaves or zero hashes, then only hash even
pairs. Proofs are a uniform depth, but the extra fillers change the root
for every non-power-of-two size. `tests/padding.rs` shows that those
roots do not match this crate.

**Unbalanced / promote-odd trees.** An odd leftover is copied up instead
of hashed with itself. Proofs for that leaf are shorter. The root for
three leaves is `H(H(ab), H(c))`, not `H(H(ab), H(c,c))`.

**Sparse Merkle trees.** Every possible index in a huge keyspace (often
`2^256`) has a place. Absent keys hash to a well-known empty subtree, so
you can prove *non*-inclusion. This crate only proves that a leaf is
present in a finite list. Empty slots are not first-class.

**Merkle mountain ranges.** An append-only list of peaks, each a perfect
binary tree. Appending is O(log n) and historical peaks stay stable
without rebuilding. `MerkleLog` in this crate snapshots a full-tree root
after each append; it is an audit log, not an MMR.

**Incremental / lazy trees.** Some implementations hash a parent only when
a proof asks for it. This crate hashes every parent at construction time
and stores them in one buffer.

**Merkle sum trees.** Each node carries a hash *and* a numeric sum of its
leaves, used for proofs of solvency. That is the next roadmap phase, not
this crate today. The current leaf type is opaque bytes.

## Choosing a hash is not choosing a variant

`HashAlgorithm` picks the compression function (SHA-256, BLAKE3, Poseidon).
The pairing rule, padding, and proof format stay the same. A Poseidon tree
is still this variant; it is not a sparse tree or a sum tree. Mixing
algorithms is a domain mismatch ([Domains](domains.md)), not a layout
mismatch.

## When to pick something else

- You need a non-inclusion proof for an unused key: a sparse tree.
- You append constantly and cannot afford an O(n) rebuild: an MMR or a
  similar peak structure.
- You must commit to balances and their total: a sum tree.
- You must match an existing root from another system: copy *that*
  system's padding and domain tags, do not assume this crate's.

If none of those apply, the binary duplicate-last tree here is the usual
choice: small API, explicit domains, and proofs that a second implementation
can check from the published rules alone.
