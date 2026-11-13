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

## What is not here yet

Tree building, inclusion proofs, and range proofs for non-negative balances
come in later roadmap steps. `u128` already rules out negative amounts in the
leaf encoding; the range proof will let a user check that without seeing
other balances.
