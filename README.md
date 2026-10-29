# merkle-tree (educational)

Rust library implementing a SHA-256 Merkle tree with inclusion proofs, intended for learning and portfolio purposes. It starts with a simple, audited-hash (sha2) design and will grow toward zk-friendly hashes in future days.

Important: This crate is educational. Do not use it for production security-critical applications without a thorough review.

## What it does

- Builds a Merkle tree from arbitrary leaf byte slices
- Computes the Merkle root
- Generates and verifies inclusion proofs
- Uses `sha2::Sha256` (audited; no hand-rolled crypto)
- Clear domain separation:
  - Leaf hash: H(0x00 || data)
  - Internal node hash: H(0x01 || left || right)
  - Odd layers are padded by duplicating the last element

## Quickstart

```rust
use merkle_tree::{MerkleTree, verify_inclusion};

let leaves = [b\"a\".as_ref(), b\"b\", b\"c\", b\"d\"];
let tree = MerkleTree::from_leaves(leaves);
let root = tree.root().expect(\"root\");

// Create and verify a proof for leaf at index 2 (\"c\")
let proof = tree.prove(2).expect(\"proof\");
assert!(proof.verify(root));

// Or verify with the helper using raw leaf data:
assert!(verify_inclusion(b\"c\", &proof.steps, root));
```

## Roadmap

See `ROADMAP.md` for the 30-day plan as this grows toward zk-friendly hashes and richer features.

## License

MIT. See `LICENSE` for details.
# zk-merkle-rs
