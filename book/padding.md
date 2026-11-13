# Padding

Every parent in this crate has two children. When a layer has an odd number
of hashes, the last hash is used twice for that parent and is **not** stored
a second time. That rule is *duplicate-last padding*.

## What a three-leaf tree actually stores

Leaves `a, b, c` produce:

```text
H(a)   H(b)   H(c)
  \     /       |
   H(ab)     H(c,c)     <- last leaf hashed with itself
       \     /
        root
```

Six hashes sit in the buffer: three leaves, two parents, one root. The
duplicated `H(c)` is only re-read when the parent is computed.
`MerkleTree::layer_widths(3)` is `[3, 2, 1]`. `layer_is_padded(3)` is
true; `layer_is_padded(2)` is false.

A single-leaf tree is not padded. Its root **is** the leaf hash, and
`parent_count(1)` is zero.

## Why this crate uses it

- Proofs stay `ceil(log2(n))` steps, including odd `n`.
- The extra sibling is not stored, so `stored_hash_count(3)` is 6 rather
  than 7.
- Compact multiproofs can replay the same rule because they carry
  `leaf_count`.

The cost is an ambiguity: `[a, b, c]` and `[a, b, c, c]` share a plain
root. A proof for the "ghost" leaf at index 3 verifies against the
three-leaf root. If the protocol cares about the exact leaf set, publish
`committed_root()` instead of the plain digest:

```rust,ignore
use merkle_tree::MerkleTree;

let three = MerkleTree::from_leaves(["a", "b", "c"]);
let four = MerkleTree::from_leaves(["a", "b", "c", "c"]);
assert_eq!(three.root(), four.root());
assert_ne!(three.committed_root(), four.committed_root());
```

`commit_root(root, n)` is `SHA-256(0x02 || n as u64 big-endian || root)`.
See [Security notes](security.md) for `verify_committed`.

## Alternatives this crate does not use

Callers sometimes want a different odd-layer rule. The tests in
`tests/padding.rs` build those trees by hand so the difference stays
checked.

**Empty-leaf power-of-two padding.** Hash each real leaf, then fill the
bottom layer with `H(0x00 || "")` out to the next power of two. For three
leaves the extra empty hash changes every parent above it, so the root
differs. For four leaves both schemes agree, because the bottom layer is
already even.

**Promote an odd leftover unchanged.** Hash pairs, and if one node remains,
copy it to the next layer without a parent hash. Three leaves then produce
`H(H(a)||H(b), H(c))` instead of `H(H(a)||H(b), H(c,c))`. Proofs for the
promoted leaf are shorter than proofs for its siblings, which this crate
avoids.

Neither alternative is "wrong". They are different commitments. A verifier
must use the same rule the prover used; mixing them fails the root check.

## Helpers

| Function | Meaning |
| --- | --- |
| `MerkleTree::parent_count(len)` | Parents emitted from a layer of `len` nodes |
| `MerkleTree::layer_is_padded(len)` | Whether that layer hashes the last node with itself |
| `MerkleTree::layer_widths(n)` | Width of every layer from `n` leaves up to the root |
| `proof_depth(n)` | Steps in every inclusion proof for `n` leaves |

`layer_widths(n)` summed is `stored_hash_count(n)`. On a live tree the
same numbers appear as `layer_len(i)`.
