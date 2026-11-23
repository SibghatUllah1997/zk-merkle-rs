# CLI runbook

The `merkle` binary is a small demo of the library. It needs the default
`std` feature. Sum-tree commands also need `merkle_sum`. The commands are
`merkle build`, `merkle prove`, `merkle verify`, and with `merkle_sum`,
`merkle sum-build`, `merkle sum-prove`, `merkle sum-verify`,
`merkle sum-absent`, `merkle sum-verify-absent`, and `merkle solvency`.

```bash
cargo run --bin merkle -- help
cargo run --features merkle_sum --bin merkle -- help
```

Leaves are UTF-8 strings hashed as `H(0x00 || bytes)`. Hex is lowercase;
a `0x` prefix is accepted on roots and account ids.

## Build a tree and print the root

```bash
cargo run --bin merkle -- build a b c d
```

Prints one 64-character hex line: the SHA-256 Merkle root. An empty argument
list is a usage error (exit 2). A single leaf's root is that leaf hash.

## Prove inclusion

```bash
cargo run --bin merkle -- prove --index 2 a b c d
```

`--index` can also be a bare integer before the leaves. Output:

```text
root=<64 hex>
index=<n>
leaf_hash=<64 hex>
steps=R:<hex>,L:<hex>
```

`steps` is empty for a one-leaf tree. The index must be in range (exit 1).

## Verify a proof

```bash
cargo run --bin merkle -- verify --leaf c --root <root-hex> --steps <L|R:hex,...>
```

`--leaf` is the original UTF-8 leaf, not the leaf hash. `--steps` may be
omitted for a single-leaf tree. Prints `ok` or exits 1 with
`verification failed`. A parse error (bad hex, unknown side) also exits 1.

The root must come from a source you trust. The CLI does not fetch it.

## Merkle sum tree from CSV

Needs `--features merkle_sum`. CSV is `account_id,amount`: 32-byte hex ids
and decimal `u128` amounts. Comments (`#`) and a header row are skipped.

```bash
cargo run --features merkle_sum --bin merkle -- sum-build balances.csv
```

Prints:

```text
root=<64 hex>
sum=<total>
```

`sum` is the sum of the CSV amounts. Odd layers promote the last node, so
the last amount is not counted twice. An unreadable file or empty CSV exits
1 (empty CSV is treated as a usage problem, exit 2).

## Export one account's proof

```bash
cargo run --features merkle_sum --bin merkle -- sum-prove balances.csv --account <id-hex>
```

Prints `key=value` lines (account, amount, index, leaf_count, one `step=`
per level). Redirect that to a file. The file does **not** contain the root.

An unknown account id exits 1.

## Verify a sum-tree proof

```bash
cargo run --features merkle_sum --bin merkle -- sum-verify proof.txt --root <hex> --sum <total>
```

Pass the root and total the exchange published. Prints `ok` with the account
and amount, or exits 1 and says whether the hash or the total failed.

## Prove an account id is missing

The CSV must be strictly sorted by account id. A present id exits 1.

```bash
cargo run --features merkle_sum --bin merkle -- sum-absent balances.csv --account <id-hex>
```

Prints `kind=absent` plus the neighbouring inclusion proofs. Redirect that
to a file. Then:

```bash
cargo run --features merkle_sum --bin merkle -- sum-verify-absent absent.txt --root <hex> --sum <total>
```

Prints `ok` with the query account, or exits 1 if the neighbours do not
bound the query or fail inclusion.

## Solvency check against your own snapshot

```bash
cargo run --features merkle_sum --bin merkle -- solvency liabilities.csv --root <hex> --sum <total> [--reserves <amount>]
```

Rebuilds the tree from *your* CSV and compares it with the published pair.
`--reserves` is optional and is checked against the snapshot total, not the
published one. Any mismatch prints a report on stderr and exits 1.

The root depends on leaf order, so the snapshot must use the publisher's
order.

## Browser verifier

The `wasm` feature exports `verifyInclusionProof`, `verifySumProof`, and
`verifySumAbsent` for a static page. Build a `cdylib` as in
[Verifying in the browser](wasm.md), then serve `demo/`:

```bash
rustup target add wasm32-unknown-unknown
cargo rustc --lib --release --target wasm32-unknown-unknown \
  --no-default-features --features wasm --crate-type cdylib
wasm-bindgen --target web --out-dir demo/pkg \
  target/wasm32-unknown-unknown/release/merkle_tree.wasm
python3 -m http.server --directory demo 8080
```

Paste CLI output into the forms. `verifyRangeProof` needs `--features wasm,zk-range`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, or `help` |
| 1 | Verification failed, I/O error, unknown account, solvency mismatch |
| 2 | Usage: missing args, unknown flags, empty leaf list, empty CSV |

A valid inclusion proof still does not cover valuation, omitted accounts,
or the time between snapshot and verification. See
[Proof-of-reserves threat model](threat-model.md).
