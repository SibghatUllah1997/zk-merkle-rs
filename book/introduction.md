# Introduction

`merkle-tree` is a small Rust library for SHA-256 Merkle trees with explicit
domain separation and inclusion proofs. It is meant to be easy to read, easy
to test, and usable from `no_std` crates that still have an allocator.

This book is the long-form companion to the crate docs. It covers the hashing
rules, how trees are built and padded, how proofs are checked, and how hashes
are stored so large trees stay in one buffer. Later chapters compare this
binary duplicate-last layout to other Merkle variants, spell out the odd-layer
padding rule, and list every domain tag the crate reserves.

## Install

Until the crate is published, depend on the git repo:

```toml
[dependencies]
merkle-tree = { git = "https://github.com/SibghatUllah1997/zk-merkle-rs" }
```

Disable default features for `no_std`:

```toml
merkle-tree = { git = "https://github.com/SibghatUllah1997/zk-merkle-rs", default-features = false }
```

## Quickstart

```rust,ignore
use merkle_tree::{verify_inclusion, MerkleTree};

let leaves = [b"a".as_ref(), b"b", b"c", b"d"];
let tree = MerkleTree::from_leaves(leaves);
let root = tree.root().expect("root");

let proof = tree.prove(2).expect("proof");
assert!(proof.verify(root));
assert!(verify_inclusion(b"c", &proof.steps, root));
```

`cargo doc --open` still has the API reference. This book is for the *why*:
why leaves and nodes use different prefixes, why odd layers duplicate the last
hash, and why the tree keeps every digest in one `Vec`. Start with
[Tree variants](variants.md) if you are matching another system's root,
[Padding](padding.md) for the odd-layer rule, and [Domain tags](domains.md)
for the prefix registry. The [CLI runbook](runbook.md) walks through `merkle`
commands and the browser verifier. [Threat model](threat-model.md) lists
what a published root still does not prove.
