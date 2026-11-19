# Merkle sum trees

Proof of reserves needs more than "this account is in the set". A user also
wants to know that their balance counted toward the total the exchange
published. A Merkle sum tree carries that total next to every hash.

Enable it with the `merkle_sum` feature. Types live in `merkle_tree::sum`.

## Leaves

A `SumLeaf` is `(account_id: [u8; 32], amount: u128)`:

```text
leaf.hash = SHA-256(0x30 || account_id || amount_be16)
leaf.sum  = amount
```

The account id is fixed width, so no length prefix is needed. Derive it from a
salted user id (for example `SHA-256(salt || user_id)`) so the published tree
does not reveal customer identities. Amounts are in the asset's smallest unit.

## Nodes

A `SumNode` is `(hash, sum)`. Two children fold into a parent:

```text
parent.hash = SHA-256(0x31 || L.hash || L.sum_be16 || R.hash || R.sum_be16)
parent.sum  = L.sum + R.sum   (checked; overflow is an error)
```

Hashing the child sums matters. If only hashes were hashed, a prover could
shift value from one subtree to another while keeping the root hash, and a
user checking their path would see sibling sums that do not match what the
root committed to.

## Domain tags

| Tag    | Use               |
|--------|-------------------|
| `0x30` | Sum-tree leaf     |
| `0x31` | Sum-tree parent   |

These do not overlap the plain tree (`0x00`-`0x02`), Poseidon (`0x10`/`0x11`),
or Rescue (`0x20`/`0x21`) tags.

## Building the tree

`MerkleSumTree::from_leaves` builds the tree bottom-up and returns the
`(hash, total)` root through `root()`. An empty tree has no root; a
single-leaf tree's root is that leaf's node.

Odd layers promote the last node unchanged. The plain tree's duplicate-last
padding would hash the last leaf with itself and add its amount twice, so the
root total would no longer match the liabilities. Promoting keeps
`root().sum` equal to the sum of the leaves.

```rust
# #[cfg(feature = "merkle_sum")]
# {
use merkle_tree::sum::{MerkleSumTree, SumLeaf};

let tree = MerkleSumTree::from_leaves([
    SumLeaf::new([1u8; 32], 40),
    SumLeaf::new([2u8; 32], 2),
    SumLeaf::new([3u8; 32], 8),
])
.expect("no overflow");
let (_hash, total) = tree.root().expect("non-empty");
assert_eq!(total, 50);
# }
```

A parent whose sums do not fit in `u128` returns `SumOverflow` instead of
wrapping.

`layer_count` and `layer_nodes` expose that layout. Layer 0 is the leaves;
each parent sum is the checked total of its children, and a leftover node is
copied up unchanged. The published root total is therefore the sum of the
leaves. Property tests in `tests/proptest_sum.rs` check this for random
trees, and they check that a changed leaf or sibling amount fails
`SumInclusionProof::verify`.

## Inclusion proofs

`MerkleSumTree::prove(index)` returns a `SumInclusionProof`: the leaf index,
the leaf count, and one `(sibling hash, sibling sum, side)` step per level.
A promoted node has no sibling at that level, so it adds no step.

`verify(&leaf, &root)` rebuilds each parent with `SumNode::parent`, so the
hashes and the sums are checked together:

- the index must be below the leaf count, and the number of steps and each
  step's side must match that position, so a proof cannot be moved or padded
- sums are added with checked arithmetic, so a sibling cannot wrap the total
- the rebuilt hash must equal the root hash, and the rebuilt total must equal
  the root total

Because each parent hash commits to its children's sums, a sibling whose sum
was edited no longer hashes to the root. A user's own amount plus the sibling
sums on their path equals the published total.

```rust
# #[cfg(feature = "merkle_sum")]
# {
use merkle_tree::sum::{MerkleSumTree, SumLeaf};

let leaves = [
    SumLeaf::new([1u8; 32], 40),
    SumLeaf::new([2u8; 32], 2),
    SumLeaf::new([3u8; 32], 8),
];
let tree = MerkleSumTree::from_leaves(leaves).expect("no overflow");
let root = tree.root_node().expect("non-empty");
let proof = tree.prove(2).expect("in range");
assert!(proof.verify(&leaves[2], &root).is_ok());
# }
```

The root does not commit to the leaf count. The count in a proof only fixes
the expected path shape; check it against the published count separately.

## Serde

With the `serde` feature, `SumLeaf`, `SumNode` (the published root),
`SumProofStep`, and `SumInclusionProof` serialize and deserialize. A proof
that round-trips through JSON still verifies against the same root.

## CSV and the CLI

`parse_sum_csv` reads `account_id,amount` rows. Account ids are 32-byte hex
(optional `0x`); amounts are decimal `u128`. Comments (`#`) and a header row
are skipped.

`merkle sum-build <file>` (needs `std` and `merkle_sum`) builds that tree and
prints:

```text
root=<64 hex>
sum=<total>
```

The total is the sum of the CSV amounts. Odd layers still promote the last
node, so the last amount is not counted twice.

## Exporting and checking one account's proof

`merkle sum-prove <file> --account <hex>` rebuilds the tree from the same CSV
and prints the proof for that account as plain `key=value` lines:

```text
account=<64 hex>
amount=<decimal>
index=<leaf index>
leaf_count=<leaves in the tree>
step=<L|R>:<sibling hash hex>:<sibling sum>
```

There is one `step=` line per level, from the leaf up. `sum_proof_to_text`
and `parse_sum_proof_text` write and read the same format from the library,
so it works without `serde`.

`merkle sum-verify <proof-file> --root <hex> --sum <total>` checks it. It
prints `ok` with the account and amount, or exits with code 1 and says
whether the hash or the total did not match.

The proof file does not carry the root. The user should pass the root and
total the exchange published, so a proof file cannot vouch for itself.

## Range proofs

`u128` already rules out negative amounts in the leaf encoding. The `zk-range`
feature additionally proves `0 <= amount < 2^64` with a Halo 2 circuit, so a
published balance cannot hide a wrap by using more than 64 bits. See
[Range proofs](range.md).
