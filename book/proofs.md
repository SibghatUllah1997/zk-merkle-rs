# Inclusion proofs

A proof is the leaf hash plus the sibling hashes from that leaf up to, but
not including, the root. Each step records whether the sibling sits on the
left or the right so the verifier can rebuild the same parents.

## Single-leaf proofs

```rust,ignore
use merkle_tree::{verify_inclusion, MerkleTree};

let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
let root = tree.root().expect("root");
let proof = tree.prove(2).expect("index 2 is c");

assert!(proof.verify(root));
assert!(verify_inclusion(b"c", &proof.steps, root));
assert!(!verify_inclusion(b"nope", &proof.steps, root));
```

`prove` returns `None` when the index is out of range or the tree is empty.
`prove_indexed` wraps the same path with the original index as metadata.
A single-leaf tree produces a proof with an empty step list: the leaf hash
*is* the root.

Steps can be printed and parsed as `L:<64 hex>` / `R:<64 hex>` tokens,
comma-separated. That is the form the `merkle` CLI `verify` command accepts.

## Multiproofs

`prove_many` and `prove_all` bundle independent per-leaf paths. Overlapping
siblings are repeated; the type does not compress shared nodes yet. Verify
with `MultiProof::verify` or `verify_inclusion_many` when you also want to
check the original leaf bytes against each entry, in the same order.

An empty bundle is vacuously true for any root. That matches "no claims were
made", not "the tree is empty".

## Many proofs from one tree

`prove` re-derives every step with index arithmetic: halve the index, find
the layer offset, flip the low bit, and check for a padded layer. When one
tree serves many proof requests, `proof_index_cache()` does that work once:

```rust,ignore
let tree = MerkleTree::from_leaves(["a", "b", "c", "d", "e"]);
let cache = tree.proof_index_cache();
let proof = cache.prove(4).expect("in range");
assert_eq!(Some(proof), tree.prove(4));
```

The cache keeps two tables, one entry per stored hash: the buffer position
of each node's parent and of its sibling. A padded last node is its own
sibling, and the root is its own parent, which is where a walk stops.

- Proofs are byte-for-byte the same as `prove`; only assembly changes.
- Cost is two `usize` per stored hash (`table_bytes()`), so it is opt-in.
- The cache borrows the tree. `append` / `extend` need `&mut`, so the
  compiler rejects a stale cache; build a new one after the tree changes.
- The gain is modest: the hashes are already in one flat buffer, so the
  main win is skipping per-step arithmetic in hot loops like `prove_all`.
