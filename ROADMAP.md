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
10. Add a simple CLI demo (build tree, print root, verify proof)
11. Add cargo `--features` matrix to CI (std/no_std)
12. Split modules: hashing, tree, proof, errors
13. Add `FromIterator` impls for MerkleTree
14. Add `Arbitrary`/quickcheck-style property tests
15. Fuzz basic operations (cargo-fuzz)
16. Add incremental append (rebuild-on-append) API
17. Provide multiproof skeleton (no optimization)
18. Add Poseidon/Rescue skeletons behind feature flags (no impl yet)
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
