# Changelog

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
