# Building a tree

A tree is built from the leaves up. Each layer is hashed in pairs. If a layer
has an odd number of hashes, the last hash is used twice for that parent and
is **not** stored a second time.

## Construction

```text
leaves:   H(a)   H(b)   H(c)   H(d)
            \     /       \     /
parents:     H(ab)         H(cd)
                 \         /
root:              H(abcd)
```

- `from_leaves` hashes each item as `H(0x00 || data)` then builds parents.
- `from_hashed_leaves` skips that step when the caller already hashed with
  the matching algorithm.
- A single-leaf tree's root **is** the leaf hash. There is no dummy parent.
- An empty tree has no root and no proofs.

Odd counts duplicate the last element only for the parent hash. Three leaves
`a, b, c` produce parents `H(ab)` and `H(c, c)`, then a root over those two.

## Growing a tree

`append`, `append_hashed`, and `Extend` add leaves and rebuild the upper
layers once. The result always matches a tree built from scratch over the
same sequence. Each single `append` is O(n) hashes; batching with `extend`
is cheaper when many leaves arrive together.

```rust,ignore
use merkle_tree::MerkleTree;

let mut tree = MerkleTree::from_leaves(["a", "b"]);
tree.append("c");
tree.extend(["d", "e"]);
assert_eq!(
    tree.root(),
    MerkleTree::from_leaves(["a", "b", "c", "d", "e"]).root()
);
```

## Metadata

`leaf_count`, `layer_count`, `leaf_hash_at`, and `leaf_info` read the leaf
layer without re-hashing. `root`, `root_typed`, and `root_hex` expose the
same 32-byte digest as bytes, a newtype, or lowercase hex.
