# Domain tags

A Merkle tree hashes two kinds of payload that can look alike: raw leaf bytes
and a pair of 32-byte child hashes. Without a tag, `H(data)` and
`H(left || right)` collide whenever `data` is the 64-byte concatenation of
two children. An attacker can then present those 64 bytes as a leaf one
level up and still rebuild the root.

This crate keeps those cases in separate domains. The public `DomainKind`
type names them so callers do not copy magic numbers.

## SHA-256 and BLAKE3 prefixes

SHA-256 (always) and BLAKE3 (the `blake3` feature) prepend a one-byte
prefix:

| Domain | Constant | Byte | Input |
| --- | --- | --- | --- |
| Leaf | `LEAF_PREFIX` | `0x00` | `0x00 \|\| data` |
| Internal node | `NODE_PREFIX` | `0x01` | `0x01 \|\| left \|\| right` |
| Root commitment | `ROOT_COMMIT_PREFIX` | `0x02` | `0x02 \|\| leaf_count_be64 \|\| root` |

`left` and `right` are always 32-byte hashes, so a node input is always 65
bytes. A leaf can be any length, including empty. `DomainKind::prefix()`
returns the same bytes the hash functions consume.

The prefixes only separate leaves from nodes *inside one algorithm*. A
BLAKE3 tree already diverges from a SHA-256 tree because the compression
function differs; the `0x00`/`0x01` bytes are not a second hash.

## Poseidon and Rescue tags

Poseidon (the `poseidon` feature) does not prepend a leading byte. It mixes
a domain value into the capacity slot of a circom-compatible BN254
permutation:

| Domain | Constant | Tag |
| --- | --- | --- |
| Leaf | `POSEIDON_LEAF_PREFIX` | `0x10` |
| Internal node | `POSEIDON_NODE_PREFIX` | `0x11` |

`DomainKind::poseidon_tag()` returns those values for leaf and node, and
`None` for a root commitment. Root commitments are always SHA-256, even
when the tree itself used Poseidon: they wrap a finished 32-byte root
outside any circuit.

Rescue is still a placeholder. The reserved tags `0x20` (leaf) and `0x21`
(node) are public so a later binding can occupy them without colliding with
SHA-256 or Poseidon. `hash_leaf_with(HashAlgorithm::Rescue, …)` returns
`HashNotImplemented`.

The reserved tags are exported even when the matching crate feature is off.
That is the domain *registry*; the hash functions stay behind their flags.

## What the tags do not do

- They do not make SHA-256 zk-friendly.
- They do not hide low-entropy leaves. Guessable data still needs a salt.
- They do not bind a root to its leaf count. That is `0x02` via
  `commit_root`, described in [Padding](padding.md).
- They do not replace algorithm agreement. A verifier must use the same
  `HashAlgorithm` the tree was built with; mixed algorithms fail closed.

Parse algorithm names with `HashAlgorithm::from_name("sha256")` (also
`"sha-256"` and `"sha2"`). Names whose crate feature is off are unknown in
that build, matching the enum variants that do not exist there.
`HashAlgorithm::is_implemented()` is `false` only for the Rescue
placeholder.
