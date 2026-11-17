# Changelog

## 2026-11-17 (sum serde and CSV)

- Optional serde on Merkle sum leaves, roots (`SumNode`), and inclusion proofs
- `merkle sum-build` reads `account_id,amount` CSV and prints the root hash and total
- The printed total is the sum of the CSV amounts; odd layers still promote the last node

## 2026-11-17

- Add `MerkleSumTree::prove` and `SumInclusionProof::verify` behind the `merkle_sum` feature
- Verification rebuilds each parent from hash and sum, so the path must hash to the root and the sums must add up to the root total
- Index, path length, and step sides are checked against the leaf position; overflow and mismatches return `SumProofError`

## 2026-11-16

- Add `MerkleSumTree::from_leaves` behind the `merkle_sum` feature, with `root()` returning `(hash, total)`
- Odd layers promote the last node instead of duplicating it, so the root total stays equal to the sum of the leaves
- A parent that would overflow `u128` still returns `SumOverflow`

## 2026-11-13 (merkle sum types)

- Add a `merkle_sum` feature with `SumLeaf (account_id, amount: u128)` and `SumNode (hash, sum)` for proof of reserves
- Parent hashes commit to both child hashes and both child sums under new `0x30`/`0x31` domain tags; totals use checked addition
- Book chapter on sum trees; CI checks the feature in the matrix and on bare metal

## 2026-11-13

- Name domain tags and hash algorithms, and expose helpers for duplicate-last padding
- Add book chapters on tree variants, padding, and domain tags
- 1.0 polish: committed-root example, feature-flag module, extra benches, version 1.0.0

## 2026-11-12 (security notes)

- Add `commit_root` and `MerkleTree::committed_root` so a root is bound to its leaf count, which removes the duplicate-last padding ambiguity
- Add `verify_committed`, which also checks the index, path length, and step sides
- New security chapter in the book and attack tests for second preimages, padding, and moved proofs

## 2026-11-12

- Compact multiproofs store shared siblings once and still reconstruct the same root
- Poseidon is a real hash behind the `poseidon` feature: leaves, nodes, trees, and proofs
- Rescue stays a stub; SHA-256 remains the default

## 2026-11-11 (proof cache)

- Add `ProofIndexCache`: parent and sibling positions precomputed once per tree, so each proof is a walk of table lookups
- Cached proofs are identical to `prove`, checked across tree sizes and with property tests
- Bench compares direct and cached `prove_all`; the book explains the memory trade-off

## 2026-11-11

- Store every Merkle hash in one contiguous buffer, with helpers for hash count, byte cost, and per-layer slices
- Add an mdBook site covering hashing, padding, proofs, and that layout; CI builds the book on every push

## 2026-11-10 (no_std CI)

- Add a CI job that builds the library for a bare-metal target with no std, across feature combos
- Add a small `#![no_std]` smoke crate that uses trees, proofs, multiproofs, the log, and chunking
- The smoke crate also runs as host tests, so the no_std path is checked for correct results too

## 2026-11-10

- Split files and byte buffers into fixed-size Merkle leaves, including a streaming reader
- Add an append-only log that snapshots a root after each append or batch
- Examples show chunking a file and growing a log while old entries still prove

## 2026-11-09 (blake3)

- Add an optional `blake3` feature with domain-separated BLAKE3 leaf and node hashing
- Build trees with a chosen algorithm and verify proofs and multiproofs with `verify_with`
- Trees remember their algorithm, so appends keep hashing the same way; SHA-256 stays the default

## 2026-11-09

- Add a naive multiproof API that bundles per-leaf inclusion paths without sharing siblings
- Callers can prove several indices at once and check the original leaf bytes against that bundle
- Poseidon and Rescue hash hooks sit behind feature flags and return a clear not-implemented error until a real binding lands

## 2026-11-05 (append)

- Add `MerkleTree::append`, `append_hashed`, and `extend_hashed` for growing a tree in place
- Implement `Extend` so many leaves can be added with a single rebuild
- Appended trees always match a tree built from scratch over the same leaves

## 2026-11-05

- Build trees from already-hashed leaves, matching the raw-data constructor
- Add proptest coverage for hashing, tree construction, and inclusion proofs
- Add cargo-fuzz targets for prove/verify and proof-step parsing

## 2026-11-04

- Split hashing, errors, proofs, and the tree into dedicated modules
- Collect leaves into a MerkleTree via FromIterator for byte slices and strings
- Crate-root exports stay the same, so existing callers keep compiling

## 2026-11-03

- Add a `merkle` demo CLI to build a tree, print the root, and prove/verify inclusion
- Decode hex roots and compact L/R proof-step lists for copy-paste verification
- Run CI across std and no_std feature combinations (with and without serde)

## 2026-11-02

- Add no_std (alloc) support behind a crate feature; default remains std
- Introduce length-safe [u8; 32] conversions and TryFrom for MerkleRoot

## 2026-11-01

- Add leaf metadata helpers (LeafInfo) and indexed inclusion proofs
- Introduce optional serde support for proofs and a typed MerkleRoot wrapper

## 2026-10-31

- Add harness-free microbench to time tree build and proof steps
- Validate and document odd-leaf padding; note common alternative strategies

## 2026-10-30

- Add crate-level docs with a quickstart doctest and formatting cleanups
- Introduce hex helpers and `root_hex()` for formatted roots
- Implement `Display` for inclusion proofs and add hex-oriented proof helpers

## Day 1

- Initialize Rust library crate: `merkle-tree`
- Add README, MIT LICENSE, `.gitignore`, ROADMAP, and CI workflow
- Implement SHA-256 Merkle tree with inclusion proof generation and verification
