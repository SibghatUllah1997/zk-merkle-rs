# Range proofs

A Merkle sum tree commits to every account amount, but the leaf encoding is a
`u128`. That cannot be negative; it can still be larger than a 64-bit
balance. The `zk-range` feature proves `0 <= amount < 2^64` with a Halo 2
circuit from the audited `halo2_proofs` crate.

Enable it together with `std` (Halo 2 needs the standard library):

```toml
merkle-tree = { git = "https://github.com/SibghatUllah1997/zk-merkle-rs", features = ["zk-range"] }
```

## Circuit

The amount is decomposed into 64 little-endian bits. Each bit is constrained
to `{0, 1}`. A running sum reconstructs `sum bit_i * 2^i` and is
copy-constrained to a public instance, so a verifier who already knows the
amount can check that it really is a 64-bit value.

`RANGE_K` is 7 (`128` rows): 64 bit rows plus Halo 2's blinding rows.

## Prove and verify

```rust,ignore
use merkle_tree::{generate_range_proof, verify_range_proof};

let proof = generate_range_proof(42).expect("fits in 64 bits");
assert!(verify_range_proof(42, &proof).is_ok());
assert!(generate_range_proof(1u128 << 64).is_err());
```

`generate_range_proof` returns `RangeProofError::OutOfRange` when the amount
needs more than 64 bits, before any proving. A proof for one amount does not
verify against another, and a flipped transcript byte fails verification.

The amount is a public instance. The proof does not hide it; it only shows
the published figure fits in 64 bits. Proving uses a fixed RNG seed so tests
can pin a frozen transcript for amount 42.
