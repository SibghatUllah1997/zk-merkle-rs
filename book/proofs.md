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
