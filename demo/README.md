# Verifier demo

A small static page that calls `verifyInclusionProof`, `verifySumProof`,
and `verifySumAbsent` from the `wasm` feature. It does not reimplement
hashing in JavaScript.

## Build the wasm module

From the repo root, with a `wasm-bindgen-cli` that matches the crate's
`wasm-bindgen` version:

```bash
rustup target add wasm32-unknown-unknown
cargo rustc --lib --release --target wasm32-unknown-unknown \
  --no-default-features --features wasm --crate-type cdylib
wasm-bindgen --target web --out-dir demo/pkg \
  target/wasm32-unknown-unknown/release/merkle_tree.wasm
```

To also export `verifyRangeProof`:

```bash
cargo rustc --lib --release --target wasm32-unknown-unknown \
  --no-default-features --features wasm,zk-range --crate-type cdylib
wasm-bindgen --target web --out-dir demo/pkg \
  target/wasm32-unknown-unknown/release/merkle_tree.wasm
```

## Serve the page

Browsers block `file://` wasm. From the repo root:

```bash
python3 -m http.server --directory demo 8080
```

Then open <http://localhost:8080/>. See [Verifying in the browser](../book/wasm.md)
and the [CLI runbook](../book/runbook.md).
