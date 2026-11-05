# Fuzz targets

A standalone Cargo package so the library crate can stay on stable Rust.

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run tree_prove
cargo +nightly fuzz run parse_proof
```

- `tree_prove` splits random bytes into leaves, builds a tree, and checks that
  every generated inclusion proof verifies (including the hashed-leaf constructor).
- `parse_proof` feeds arbitrary text to `parse_proof_steps` and the hex helpers.
  Any input that parses must round-trip through `InclusionProof::steps_spec`.
