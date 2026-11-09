# Changelog

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
