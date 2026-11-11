# Memory layout

Hashes live in one contiguous `Vec<[u8; 32]>`. Layer 0 is the leaf hashes;
each later layer is the parents of the one below. A small offset table marks
where each layer starts. The last stored hash is the root.

## Why flatten

The first version of the tree kept `Vec<Vec<[u8; 32]>>`: one allocation per
layer. A tree of `n` leaves has about `log2(n)` layers, so a large tree paid
for many small allocations and jumped between them on every proof step.

A single buffer:

- allocates once for the hashes (plus a tiny offset `Vec`)
- writes parent hashes in place while building, with capacity reserved up front
- keeps sibling lookups sequential inside one array
- truncates back to the leaf layer on `append` / `extend` so the same
  allocation can hold the rebuilt parents

The padded sibling used for an odd layer is **not** stored. It is only
re-read from the last hash of that layer when the parent is computed.

## Sizes

`MerkleTree::stored_hash_count(n)` is the exact number of 32-byte hashes a
tree with `n` leaves keeps. For a power-of-two `n` that is `2n - 1`. Odd
counts store a few extra parents (the duplicate is hashed, not stored), so
three leaves occupy six hashes rather than five.

On a live tree:

- `hash_count()` — length of the buffer
- `storage_bytes()` — `32 * hash_count()`, not `Vec` spare capacity
- `layer_len(i)` / `layer_hashes(i)` — size or slice of layer `i` (0 = leaves)

Layer slices are adjacent: the end of layer `i` is the start of layer `i + 1`.
The last layer always has length 1 and equals `root()`.
