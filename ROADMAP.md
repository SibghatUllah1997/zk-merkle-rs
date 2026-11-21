# 30-Day Roadmap

This project will evolve from a simple educational Merkle tree to a more featureful library with zk-friendly hash options and tooling.

1. Initialize crate, README, LICENSE, CI, basic SHA-256 tree [x]
2. Add API docs and crate-level docs with examples [x]
3. Add hex/Display helpers for roots and proofs [x]
4. Benchmarks: build and proof generation microbench (criterion) [x]
5. Validate odd-leaf padding choices and document alternatives [x]
6. Add optional leaf indexing and metadata helpers [x]
7. Add serde (optional) for proofs and roots [x]
8. Add no_std (alloc) support feature-flag [x]
9. Add `TryFrom` and safe conversions for byte arrays [x]
10. Add a simple CLI demo (build tree, print root, verify proof) [x]
11. Add cargo `--features` matrix to CI (std/no_std) [x]
12. Split modules: hashing, tree, proof, errors [x]
13. Add `FromIterator` impls for MerkleTree [x]
14. Add `Arbitrary`/quickcheck-style property tests [x]
15. Fuzz basic operations (cargo-fuzz) [x]
16. Add incremental append (rebuild-on-append) API [x]
17. Provide multiproof skeleton (no optimization) [x]
18. Add Poseidon/Rescue skeletons behind feature flags (no impl yet) [x]
19. Integrate blake3 as an alternative hash (feature flag) [x]
20. Add `no_std` CI job [x]
21. Add documentation site (mdbook) scaffold [x]
22. Add example: file chunking into leaves [x]
23. Add example: simple append-only log with roots [x]
24. Optimize memory layout for large trees [x]
25. Optimize proof generation by caching parent indices [x]
26. Add multiproof format and verifier [x]
27. Add zk-friendly hash implementation (Poseidon) via audited crate [x]
28. Add preimage resistance considerations and security notes [x]
29. [x] Add advanced docs: tree variants, padding, and domains
30. [x] 1.0 polish pass: docs, examples, benches, feature flags, release

## Phase 2: Proof of Reserves

Goal: allow an exchange to publish a commitment to all user balances and let each user verify inclusion and non-negativity of their balance, plus demonstrate aggregate solvency vs total liabilities.

Each item is one small, shippable step. Hashing and range proofs must use audited crates only (existing tree hashes, plus `halo2` for the range-check circuit). Do not hand-roll cryptographic primitives.

31. [x] Define the Merkle sum leaf `(account_id, amount: u128)` and domain-separated node hash `(hash, subtree_sum)` types and docs
32. [x] Implement a feature-gated `merkle_sum` tree with `from_leaves` and `root() -> (hash, sum)`
33. [x] Add an inclusion proof that checks path hashing and that sibling sums aggregate to the root sum
34. [x] Add optional serde support for sum-tree proofs and roots
35. [x] Add a CLI command to build a sum tree from CSV and print `(root_hash, total_sum)`
36. [x] Add CLI commands to export a per-account inclusion proof and to verify one
37. [x] Add property tests that subtree sums equal the sum of leaves and that tampered amounts fail verification
38. [x] Add a `zk-range` feature with a 64-bit range-check circuit in the audited `halo2` crate (`0 <= amount < 2^64`)
39. [x] Expose `generate_range_proof` and `verify_range_proof`, with tests against a frozen vector
40. [x] Add solvency tooling that compares a published `total_sum` to an independently computed liabilities snapshot
41. [x] Add a `wasm-bindgen` verifier for inclusion proofs and, optionally, range proofs
42. [x] Add a small demo page, CLI runbook, and threat-model notes (valuation, excluded accounts, timing)

## Phase 3: Sorted uniqueness and non-inclusion

Inclusion shows that one account is in the published tree. It does not show
that some other account id is absent. That needs unique, strictly sorted
ids so two neighbouring leaves can bound a missing id.

43. [x] Reject duplicate account ids when building with `from_unique_leaves`
44. [x] Add `from_sorted_leaves`, binary search, and a non-inclusion proof for a missing account
