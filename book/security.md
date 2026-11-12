# Security notes

This chapter lists what the tree guarantees, what it relies on, and where a
caller still has to be careful.

## What the hash must provide

| Property | Meaning here | Who provides it |
| --- | --- | --- |
| Preimage resistance | From a root you cannot recover the leaves | SHA-256 / BLAKE3 / Poseidon |
| Second-preimage resistance | Given a tree, you cannot find other data with the same root | The hash, plus domain separation |
| Collision resistance | Nobody can build two different trees with one root | The hash |

The crate never implements these primitives itself. SHA-256 comes from
`sha2`, BLAKE3 from `blake3`, and Poseidon from `light-poseidon-nostd` over
`ark-bn254`.

**Preimage resistance does not hide low-entropy leaves.** If a leaf is a
small number, a yes/no flag, or a known email address, anyone holding its
leaf hash can guess and check. Mix a random salt into such leaves before
hashing if they must stay private.

## Second preimages and domain separation

Without prefixes, the 64 bytes `H0 || H1` hash to the same value as a leaf
and as the parent of `H0` and `H1`. An attacker can then claim those 64 bytes
are a leaf one level up and present a valid-looking proof. The crate blocks
this by hashing leaves as `H(0x00 || data)` and parents as
`H(0x01 || left || right)`; Poseidon uses its own `0x10`/`0x11` domain
tags. `tests/security.rs` runs the forgery against an unprefixed tree, where
it works, and against this crate, where it fails.

## Padding ambiguity and `commit_root`

Odd layers duplicate their last hash. That keeps proofs short, but it means
`[a, b, c]` and `[a, b, c, c]` have the same plain root, and a proof for the
"ghost" leaf at index 3 verifies against the 3-leaf root.

If your protocol cares about the exact leaf set, publish the committed root:

```rust
use merkle_tree::MerkleTree;

let tree = MerkleTree::from_leaves(["a", "b", "c"]);
let commitment = tree.committed_root().expect("non-empty");
let proof = tree.prove_indexed(2).expect("in range");
assert!(proof.verify_committed(commitment, 3));
```

`commit_root(root, n)` is `SHA-256(0x02 || n as u64 big-endian || root)`. It
is always SHA-256, even for BLAKE3 or Poseidon trees, because it wraps the
finished root outside any circuit.

`verify_committed` is stricter than `verify`. It also checks that:

- the claimed index is below the leaf count,
- the proof has exactly `proof_depth(leaf_count)` steps, and
- every step's left/right side matches the bits of the index.

So an honest proof cannot be replayed at another index, padded, or cut short.

## What is still on the caller

- **Trusting the root.** A proof only shows a leaf is under *some* root. Get
  the root (or commitment) from a source you trust.
- **Plain `verify` is position-free.** It checks that the path rebuilds the
  root and nothing else. Use `verify_committed` when the index matters.
- **Hashed-leaf constructors.** `from_hashed_leaves` takes 32-byte values as
  is. If those are not `hash_leaf` outputs, domain separation is up to you.
- **Algorithm agreement.** A verifier must use the same `HashAlgorithm` the
  tree was built with. Mixing them fails closed: proofs simply do not verify.
- **Constant time.** Verification compares public data, so it is not written
  to run in constant time. Do not use it to compare secrets.
- **Rescue.** It is still a placeholder and returns `HashNotImplemented`.
