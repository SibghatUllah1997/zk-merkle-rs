# Hashing and domain separation

Every digest this crate stores is 32 bytes. SHA-256 is always available.
BLAKE3 is optional behind the `blake3` feature. Poseidon and Rescue names
exist as feature-gated placeholders and return `HashNotImplemented` until a
real binding lands.

## Prefixes

A Merkle tree hashes two kinds of payload that can look alike: raw leaf bytes
and a pair of 32-byte child hashes. Without a tag, `H(data)` and
`H(left || right)` can collide if `data` happens to be 64 bytes that match
two children.

The crate therefore prepends a one-byte domain:

| Kind | Input | Digest |
| --- | --- | --- |
| Leaf | `0x00 \|\| data` | 32 bytes |
| Internal node | `0x01 \|\| left \|\| right` | 32 bytes |

`left` and `right` are always 32-byte hashes, so a node input is always 65
bytes (`1 + 32 + 32`). A leaf can be any length, including empty.

The constants are `LEAF_PREFIX` (`0x00`) and `NODE_PREFIX` (`0x01`). Poseidon
and Rescue reserve `0x10`/`0x11` and `0x20`/`0x21` so a later binding does not
reuse the SHA-256 tags.

## Choosing an algorithm

`HashAlgorithm` is the public selector. SHA-256 is the default for
`MerkleTree::from_leaves` and `InclusionProof::verify`. To hash with BLAKE3:

```rust,ignore
use merkle_tree::{HashAlgorithm, MerkleTree};

let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, ["a", "b"])?;
let root = tree.root().expect("root");
let proof = tree.prove(0).expect("proof");
assert!(proof.verify_with(HashAlgorithm::Blake3, root)?);
# Ok::<(), merkle_tree::HashNotImplemented>(())
```

The tree remembers the algorithm, so `append` keeps hashing the same way.
A BLAKE3 proof will not verify as SHA-256, and the reverse is also true:
the prefix scheme is shared, but the digest function is not.

## What the prefixes do not do

They do not make SHA-256 into a zk-friendly hash. They only keep leaf hashes
and parent hashes in separate domains *inside one algorithm*. Two trees that
use different algorithms already diverge because the compression function
differs.
