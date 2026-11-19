<div align="center">

# merkle-tree

Fast, tiny, no_std-friendly SHA-256 Merkle tree with inclusion proofs and a clean API.

[![CI](https://github.com/SibghatUllah1997/zk-merkle-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SibghatUllah1997/zk-merkle-rs/actions/workflows/ci.yml)
![MSRV](https://img.shields.io/badge/MSRV-1.64%2B-blue)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

</div>

### Why it matters
- Merkle trees are a foundational building block for integrity, inclusion proofs, and commitments in distributed systems and blockchains.
- This crate focuses on correctness and clarity with explicit domain separation and a small surface area suitable for audits and teaching.

### Features
- Proofs: generate and verify inclusion proofs
- Indexed proofs: carry original leaf index alongside the proof
- Multiproofs: naive bundle of independent per-leaf paths, plus compact proofs that store shared siblings once (`prove_compact`)
- serde support: optional `serde` derive on proof/root types, including Merkle sum leaves, roots, and proofs
- no_std: works without `std` (uses `alloc`) via feature flags
- BLAKE3: the `blake3` feature adds `BLAKE3(0x00 || data)` / `BLAKE3(0x01 || l || r)` trees via `MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, ..)` and `verify_with`
- Merkle sum tree: the `merkle_sum` feature adds `MerkleSumTree::from_leaves`, `root() -> (hash, total)`, inclusion proofs, and `parse_sum_csv` / `merkle sum-build` for account-amount CSV, `merkle sum-prove` / `sum-verify` for per-account proofs, built on `SumLeaf` / `SumNode` with `SHA-256(0x30 || id || amount)` leaves and sum-committing `0x31` parents
- Range check: the `zk-range` feature adds `range::RangeCheckCircuit`, a `halo2_proofs` circuit that proves an amount fits in 64 bits (checked with `MockProver`; real proof helpers come next)
- Poseidon: the `poseidon` feature hashes with circom-compatible BN254 Poseidon (`0x10`/`0x11` domain tags) via `try_from_leaves_with(HashAlgorithm::Poseidon, ..)`
- Hash placeholder: the `rescue` feature still returns `HashNotImplemented`
- Chunking: split buffers or `Read` streams into fixed-size leaves (`chunk_bytes`, `chunk_reader`)
- Append-only log: `MerkleLog` records a root checkpoint after each append or batch
- Contiguous layout: all hashes sit in one buffer; `hash_count`, `storage_bytes`, and `layer_hashes` expose it
- Security: `committed_root` binds a root to its leaf count, and `verify_committed` checks index, depth, and sides; see `book/security.md`
- Domain tags: `DomainKind` names the `0x00`/`0x01`/`0x02` prefixes and the reserved Poseidon/Rescue values
- Feature flags: `merkle_tree::features` reports which optional hashes this build compiled with
- Book: `mdbook build` / `mdbook serve` from the repo root (source in `book/`, including variants, padding, and domains)
- Clear domain separation:
  - Leaf hash: H(0x00 || data)
  - Internal node hash: H(0x01 || left || right)
  - Odd layers are padded by duplicating the last element (single-leaf root = leaf hash)

### Install
Add to your `Cargo.toml` (git until published):

```toml
[dependencies]
merkle-tree = { git = "https://github.com/SibghatUllah1997/zk-merkle-rs", features = ["serde"] }
```

no_std users can disable `std`:
```toml
merkle-tree = { git = "https://github.com/SibghatUllah1997/zk-merkle-rs", default-features = false, features = ["serde"] }
```

### CLI demo
Build the `merkle` binary (needs the default `std` feature) to print roots and check proofs:

```bash
cargo run --bin merkle -- build a b c d
cargo run --bin merkle -- prove --index 2 a b c d
cargo run --bin merkle -- verify --leaf c --root <root-hex> --steps <L|R:hex,...>
cargo run --features merkle_sum --bin merkle -- sum-build balances.csv
cargo run --features merkle_sum --bin merkle -- sum-prove balances.csv --account <id-hex> > proof.txt
cargo run --features merkle_sum --bin merkle -- sum-verify proof.txt --root <root-hex> --sum <total>
```

`build` prints a 64-character lowercase hex root. `prove` prints `root`, `index`, `leaf_hash`, and compact `steps` that `verify` consumes. `sum-build` (needs `merkle_sum`) reads `account_id,amount` CSV and prints `root` and `sum`. `sum-prove` exports one account's proof as `key=value` lines, and `sum-verify` checks that file against the published root and total.

### Examples
Chunk a file (or a bundled sample) into leaves and prove the last chunk:

```bash
cargo run --example file_chunking
cargo run --example file_chunking -- README.md
```

Grow an append-only log and print the root after each mutation:

```bash
cargo run --example append_only_log
```

Show why a count-bound root is needed when odd layers duplicate the last hash:

```bash
cargo run --example committed_root
```

### Usage
This example compiles and is also covered by doctests in the crate:

```rust
use merkle_tree::{verify_inclusion, MerkleTree};

let leaves = [b"a".as_ref(), b"b", b"c", b"d"];
let tree = MerkleTree::from_leaves(leaves);
let root = tree.root().expect("root");

// Create and verify a proof for the leaf at index 2 ("c")
let proof = tree.prove(2).expect("proof");
assert!(proof.verify(root));

// Or verify using the free function with raw leaf data:
assert!(verify_inclusion(b"c", &proof.steps, root));

// Naive multiproof: independent paths, no sibling sharing
let multi = tree.prove_many([0, 2]).expect("in range");
assert!(multi.verify(root));

// Compact multiproof: overlapping siblings stored once
let compact = tree.prove_compact([0, 2]).expect("in range");
assert!(compact.verify(root));
```

### Benchmarks (micro, one-shot)
Numbers from `cargo bench` on this repo (wall-clock, single run per size):

| n    | build (one-shot) | prove(3 positions) |
|------|-------------------|--------------------|
| 8    | 5.814µs           | 1.61µs             |
| 64   | 12.596µs          | 1.664µs            |
| 512  | 106.09µs          | 2.211µs            |
| 4096 | 716.38µs          | 536ns              |

Your results will vary with hardware and toolchain.

### Diagram (mermaid)
```mermaid
graph TD
    A["leaf a (H(0x00||a))"] --> N1["H(0x01||A||B)"]
    B["leaf b (H(0x00||b))"] --> N1
    C["leaf c (H(0x00||c))"] --> N2["H(0x01||C||D)"]
    D["leaf d (H(0x00||d))"] --> N2
    N1 --> R["root = H(0x01||N1||N2)"]
    N2 --> R
```

### Testing
- Run unit tests and doctests: `cargo test`
- Property tests: `cargo test --test proptest_hashing --test proptest_tree` and `cargo test --features merkle_sum --test proptest_sum`
- Fuzzing (nightly): see `fuzz/README.md` (`cargo +nightly fuzz run tree_prove`)
- no_std surface: `cargo test --no-default-features` and `cargo test --no-default-features --features serde`
- Bare-metal no_std check: `rustup target add thumbv7em-none-eabihf`, then `cargo build --lib --target thumbv7em-none-eabihf --no-default-features`; the `ci/no-std-smoke` crate builds the same way and runs its checks on the host with `cargo test`
- Poseidon: `cargo test --features poseidon` and `cargo test --no-default-features --features poseidon`
- Rescue stub: `cargo test --features rescue` (functions return `HashNotImplemented`)
- BLAKE3: `cargo test --features blake3` and `cargo test --no-default-features --features blake3`
- Merkle sum: `cargo test --features merkle_sum` and `cargo test --features merkle_sum,serde`
- Format and lints: `cargo fmt --all --check` and `cargo clippy --all-targets --all-features -D warnings`
- Docs: `cargo doc --no-deps` for the API, `mdbook build` for the longer-form book (`book/`, including variants, padding, and domain tags)

### Roadmap
See `ROADMAP.md` for milestones and upcoming work.

### License
Licensed under either of
- Apache License, Version 2.0, (`LICENSE-APACHE` or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license (`LICENSE-MIT` or <http://opensource.org/licenses/MIT>)

at your option.
