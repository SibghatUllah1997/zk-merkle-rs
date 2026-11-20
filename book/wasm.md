# Verifying in the browser

Most users will never install a CLI to check a proof of reserves. The `wasm`
feature exposes two `wasm-bindgen` functions so a static page can do the
check client side, with nothing sent back to the exchange.

```js
const v = verifySumProof(proofText, publishedRootHex, publishedTotal);
if (v.ok) {
  show(`account ${v.account} with ${v.amount} is included`);
} else {
  show(`proof rejected: ${v.reason}`);
}
v.free();
```

- `verifySumProof(proofText, rootHex, totalSum)` takes the text printed by
  `merkle sum-prove`, plus the root hash and total the exchange published.
- `verifyInclusionProof(leaf, steps, rootHex)` checks a plain-tree proof in
  the CLI's `R:<hex>,L:<hex>` path format.

Both return a `Verdict` with `ok`, `reason`, `account`, and `amount`. They
never throw: bad hex, a malformed file, and a mismatched proof all come back
as `ok = false` with a short reason.

## Building

The crate stays an `rlib` so the `no_std` and native builds are unchanged.
Ask for a `cdylib` only for the browser build, then generate the JS glue
with a `wasm-bindgen-cli` that matches the `wasm-bindgen` version in
`Cargo.lock`:

```sh
rustup target add wasm32-unknown-unknown
cargo rustc --lib --release --target wasm32-unknown-unknown \
  --no-default-features --features wasm --crate-type cdylib
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/merkle_tree.wasm
```

## Design notes

- Inputs are strings. Balances are `u128`, which a JavaScript number cannot
  hold exactly, and hex/decimal text survives copy and paste.
- The root and total are always arguments, never read from the proof file,
  so a forged file cannot vouch for itself.
- A failed sum-tree check still reports the account and amount it parsed, so
  the page can say which balance did not match.
- Range proofs are not exposed yet. The Halo 2 prover and its parameters add
  a lot of weight to a browser bundle for a check the auditor can run with
  the CLI; inclusion is what each user needs to check for themselves.
