# 30-Day Roadmap

This project will evolve from a simple educational Merkle tree to a more featureful library with zk-friendly hash options and tooling.

1. Initialize crate, README, LICENSE, CI, basic SHA-256 tree
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
19. Integrate blake3 as an alternative hash (feature flag)
20. Add `no_std` CI job
21. Add documentation site (mdbook) scaffold
22. Add example: file chunking into leaves
23. Add example: simple append-only log with roots
24. Optimize memory layout for large trees
25. Optimize proof generation by caching parent indices
26. Add multiproof format and verifier
27. Add zk-friendly hash implementation (Poseidon) via audited crate
28. Add preimage resistance considerations and security notes
29. Add advanced docs: tree variants, padding, and domains
30. 1.0 polish pass: docs, examples, benches, feature flags, release

## Milestone: Proof of Reserves

Goal: allow an exchange to publish a commitment to all user balances and let each user verify inclusion and non-negativity of their balance, plus demonstrate aggregate solvency vs total liabilities.

Order of work (small, incremental items):

1. Define Merkle sum leaf format
   - Leaf = `(account_id, amount)` with `amount: u128`
   - Internal node carries `(hash, subtree_sum)` where `subtree_sum = left.sum + right.sum`
   - Domain-separate sum-tree hashing from regular tree
2. Implement Merkle sum tree
   - New `merkle_sum` module feature-gated (default off)
   - API: `from_leaves`, `root() -> (hash, sum)`, `prove(index) -> SumInclusionProof`
   - serde support for proofs (optional)
3. Inclusion proof for a user's balance
   - Verify both path hashing and that sibling sums aggregate to root sum
   - Provide example: verify `(account_id, amount)` appears with correct contribution
4. ZK range proofs for non-negative balances
   - Choose `halo2` (PSE) for a 64-bit range-check gadget (audited and widely used)
   - Build a tiny circuit: witness `amount`, prove `0 <= amount < 2^64`
   - Expose `generate_range_proof(amount)` and `verify_range_proof(proof)`
   - Feature-gate as `zk-range` with optional `std` dependency for prover
5. Solvency proof vs total liabilities
   - Publish `(root_hash, total_sum)` from the Merkle sum tree
   - Provide tooling to compare published `total_sum` vs independently computed liabilities snapshot
   - Document assumptions (asset valuation, excluded accounts, timing)
6. WASM verifier for users
   - `wasm-bindgen` crate: verify inclusion proof and (optionally) range proof in browser
   - Small demo page: input account id + amount + proof JSON → verify
7. Operational docs and examples
   - CLI flow: build tree from CSV → publish `(root_hash, total_sum)` → export proofs
   - Threat model notes and limitations
