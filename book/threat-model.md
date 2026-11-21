# Proof-of-reserves threat model

A Merkle sum tree plus an inclusion proof shows that *one published tree*
contains a given account and that sibling sums add up to the published
total. It does not show that the exchange is solvent in the real world.
This chapter lists the gaps that still sit with the publisher, the
auditor, and the user.

## What a user actually checks

With `merkle sum-verify` or the wasm helper:

- their `(account_id, amount)` leaf hashes under the published root
- sibling sums along that path add up to the published total
- optionally, `0 <= amount < 2^64` if a Halo 2 range proof is attached

They do **not** check that every liability is in the tree, that the
amounts are in a currency they care about, or that the publisher still
holds matching assets an hour later.

## Valuation

The tree stores integer amounts. Someone still has to say *which asset*
and *at which price*.

- A tree of satoshis is not a tree of dollars. Mixing assets in one `u128`
  column without a published unit is undefined.
- Stale or self-chosen prices can make an insolvent book look covered.
  Reserves checked with `--reserves` are in the same unit as the snapshot;
  they are not a mark-to-market.
- Haircuts, yield-bearing wrappers, and IOUs can share a ticker with the
  asset users think they hold. The hash does not know the difference.

Publish the asset, the unit, and (if you convert) the price source and
time next to the root. Users should refuse a root that has none of that.

## Excluded accounts

The root only commits to the leaves that were hashed. Anything left out
is invisible:

- Internal or "house" accounts omitted so the published total is smaller
  than true liabilities
- Negative or bankrupt accounts dropped instead of being shown (the leaf
  encoding cannot be negative; exclusion is the cheat)
- Cold-wallet or insurance-fund balances that users would count as
  reserves but that never appear as leaves
- Accounts created after the snapshot, or closed accounts that still have
  a claim

`merkle solvency` catches a mismatch only if the auditor's own CSV is
complete. If both the published tree and the auditor snapshot omit the
same accounts, they will agree and still be wrong. A non-inclusion proof
shows that one id is absent from *this* tree, not that every real
customer was listed. Users should treat "not in the tree" as "not
proven", not as "zero".

## Timing

A root is a snapshot. Solvency can change the moment after it is hashed.

- Intra-day trading, withdrawals, and loans can empty reserves between
  snapshot and publication
- A publisher can pick a quiet second, hash, then resume an insolvent
  book
- Reusing an old root after a bank run is a valid-looking proof of a
  past state
- Inclusion proofs do not expire; a user verifying last week's proof
  against last week's root learns nothing about now

Publish the snapshot time, and prefer frequent roots (or a live log of
roots) over a single quarterly PDF. `committed_root` binds a plain tree
to its leaf count; it does not bind a sum tree to a timestamp. Put the
time next to the hex in the announcement, not only inside a proof file.

## Other limits that still apply

- **Trust the root.** A valid proof for an attacker-chosen root is
  worthless. Get the hex from a page or signature you already trust.
- **Order.** Sum-tree hashes depend on leaf order. An auditor CSV in a
  different order will mismatch even when the balances are the same.
- **Identities.** Account ids should be salted hashes, not emails. A
  published tree otherwise leaks who is a customer and how much they
  hold.
- **Range proofs do not hide amounts.** The Halo 2 circuit takes the
  amount as a public instance. It only shows the figure fits in 64 bits.
- **No asset proof.** This crate does not attest that hot or cold wallets
  hold the published reserves. That is a separate, usually on-chain,
  statement.

For hashing and padding attacks on the plain tree, see
[Security notes](security.md).
