//! Domain-separated SHA-256 hashing used by the Merkle tree.
//!
//! Every digest in this crate is SHA-256 with an explicit one-byte prefix:
//!
//! - Leaves: `SHA-256(0x00 || data)`
//! - Internal nodes: `SHA-256(0x01 || left || right)`
//!
//! The prefixes stop a leaf hash from colliding with a two-child node hash of
//! the same 32-byte payload. Hex helpers live here so roots and proof hashes
//! can be printed and parsed without pulling in a second public type.
//!
//! Alternative hashes can be selected through [`HashAlgorithm`]. SHA-256 is
//! always implemented. BLAKE3 is implemented behind the `blake3` feature and
//! uses the same `0x00`/`0x01` prefixes. Poseidon (the `poseidon` feature) is
//! circom-compatible BN254 x^5 via `light-poseidon-nostd`, with its own
//! `0x10`/`0x11` domain tags. Rescue remains a placeholder that returns
//! [`crate::error::HashNotImplemented`].
//!
//! [`DomainKind`] names the three SHA-256/BLAKE3 prefixes and the reserved
//! Poseidon/Rescue tags so callers can document the registry without copying
//! magic numbers.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use sha2::{Digest, Sha256};

use crate::error::{HashNotImplemented, HexError, UnknownAlgorithm};

#[cfg(feature = "poseidon")]
use ark_bn254::Fr;
#[cfg(feature = "poseidon")]
use ark_ff::{BigInteger, PrimeField};
#[cfg(feature = "poseidon")]
use light_poseidon_nostd::{Poseidon, PoseidonHasher};

/// Domain-separation prefix prepended to raw leaf data before hashing.
pub const LEAF_PREFIX: u8 = 0x00;

/// Domain-separation prefix prepended to concatenated child hashes.
pub const NODE_PREFIX: u8 = 0x01;

/// Domain-separation prefix for a root bound to its leaf count, see
/// [`commit_root`].
pub const ROOT_COMMIT_PREFIX: u8 = 0x02;

/// Domain tag mixed into Poseidon leaf hashes (`0x10`).
///
/// Reserved even when the `poseidon` feature is off so the domain registry
/// stays visible without enabling the hash.
pub const POSEIDON_LEAF_PREFIX: u8 = 0x10;

/// Domain tag mixed into Poseidon parent-node hashes (`0x11`).
pub const POSEIDON_NODE_PREFIX: u8 = 0x11;

/// Bytes packed into one BN254 field element. 31 bytes is always smaller
/// than the 254-bit modulus, so packing is lossless.
#[cfg(feature = "poseidon")]
const POSEIDON_FIELD_CHUNK: usize = 31;

/// Reserved leaf prefix for a future Rescue binding (not hashed yet).
pub const RESCUE_LEAF_PREFIX: u8 = 0x20;

/// Reserved parent-node prefix for a future Rescue binding.
pub const RESCUE_NODE_PREFIX: u8 = 0x21;

/// Which payload a domain-separation tag is hashing.
///
/// SHA-256 and BLAKE3 prepend [`Self::prefix`] as a leading byte. Poseidon
/// mixes [`Self::poseidon_tag`] into the capacity slot instead. Root
/// commitments are always SHA-256, even when the tree itself used another
/// hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainKind {
    /// Raw leaf bytes: `H(0x00 || data)`.
    Leaf,
    /// Two child hashes: `H(0x01 || left || right)`.
    Node,
    /// Root bound to its leaf count: `SHA-256(0x02 || n_be || root)`.
    RootCommit,
}

impl DomainKind {
    /// Stable lowercase name (`leaf`, `node`, `root-commit`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Node => "node",
            Self::RootCommit => "root-commit",
        }
    }

    /// SHA-256 / BLAKE3 leading-byte prefix for this domain.
    pub const fn prefix(self) -> u8 {
        match self {
            Self::Leaf => LEAF_PREFIX,
            Self::Node => NODE_PREFIX,
            Self::RootCommit => ROOT_COMMIT_PREFIX,
        }
    }

    /// Poseidon capacity-slot tag, if this domain is used inside Poseidon.
    ///
    /// Root commitments are a SHA-256 wrap of a finished root, so they have
    /// no Poseidon tag.
    pub const fn poseidon_tag(self) -> Option<u8> {
        match self {
            Self::Leaf => Some(POSEIDON_LEAF_PREFIX),
            Self::Node => Some(POSEIDON_NODE_PREFIX),
            Self::RootCommit => None,
        }
    }

    /// Reserved Rescue tag, if this domain would be used by a Rescue binding.
    pub const fn rescue_tag(self) -> Option<u8> {
        match self {
            Self::Leaf => Some(RESCUE_LEAF_PREFIX),
            Self::Node => Some(RESCUE_NODE_PREFIX),
            Self::RootCommit => None,
        }
    }

    /// The three domains this crate actually hashes today.
    pub const fn all() -> [Self; 3] {
        [Self::Leaf, Self::Node, Self::RootCommit]
    }
}

impl core::fmt::Display for DomainKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Which digest a caller asked for. SHA-256 is always available.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// Domain-separated SHA-256 used by [`hash_leaf`] and [`hash_nodes`].
    Sha256,
    /// Domain-separated BLAKE3 (`blake3` feature), see [`blake3_hash_leaf`].
    #[cfg(feature = "blake3")]
    Blake3,
    /// Circom-compatible Poseidon over BN254; enable the `poseidon` feature.
    #[cfg(feature = "poseidon")]
    Poseidon,
    /// Rescue placeholder; enable the `rescue` feature to name it.
    #[cfg(feature = "rescue")]
    Rescue,
}

impl HashAlgorithm {
    /// Stable lowercase name for errors and logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            #[cfg(feature = "blake3")]
            Self::Blake3 => "blake3",
            #[cfg(feature = "poseidon")]
            Self::Poseidon => "poseidon",
            #[cfg(feature = "rescue")]
            Self::Rescue => "rescue",
        }
    }

    /// Parse a stable name such as `"sha256"` or `"blake3"`.
    ///
    /// Matching is ASCII-case-insensitive and ignores surrounding whitespace.
    /// Names for algorithms whose crate feature is off are unknown in that
    /// build, matching the variants that do not exist on the enum.
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.eq_ignore_ascii_case("sha256")
            || name.eq_ignore_ascii_case("sha-256")
            || name.eq_ignore_ascii_case("sha2")
        {
            return Some(Self::Sha256);
        }
        #[cfg(feature = "blake3")]
        if name.eq_ignore_ascii_case("blake3") {
            return Some(Self::Blake3);
        }
        #[cfg(feature = "poseidon")]
        if name.eq_ignore_ascii_case("poseidon") {
            return Some(Self::Poseidon);
        }
        #[cfg(feature = "rescue")]
        if name.eq_ignore_ascii_case("rescue") {
            return Some(Self::Rescue);
        }
        None
    }

    /// `true` when this algorithm has a real hash implementation in this build.
    ///
    /// SHA-256 is always implemented. BLAKE3 and Poseidon are implemented when
    /// their features are on. Rescue is a named placeholder and returns
    /// `false`.
    pub const fn is_implemented(self) -> bool {
        match self {
            Self::Sha256 => true,
            #[cfg(feature = "blake3")]
            Self::Blake3 => true,
            #[cfg(feature = "poseidon")]
            Self::Poseidon => true,
            #[cfg(feature = "rescue")]
            Self::Rescue => false,
        }
    }
}

impl core::str::FromStr for HashAlgorithm {
    type Err = UnknownAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or(UnknownAlgorithm)
    }
}

impl core::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Compute a leaf hash as `SHA-256(0x00 || data)`.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a parent hash as `SHA-256(0x01 || left || right)`.
pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Bind a Merkle root to the number of leaves it was built from:
/// `SHA-256(0x02 || leaf_count as u64 big-endian || root)`.
///
/// Duplicate-last padding means `[a, b, c]` and `[a, b, c, c]` share a plain
/// root. Publishing this commitment instead removes that ambiguity, because a
/// verifier must also agree on `leaf_count`. The commitment is always SHA-256,
/// whatever algorithm built the tree: the root already differs per algorithm,
/// and this final wrap happens outside any circuit.
///
/// ```
/// use merkle_tree::{commit_root, MerkleTree};
///
/// let three = MerkleTree::from_leaves(["a", "b", "c"]);
/// let four = MerkleTree::from_leaves(["a", "b", "c", "c"]);
/// assert_eq!(three.root(), four.root());
/// let root = three.root().expect("root");
/// assert_ne!(commit_root(&root, 3), commit_root(&root, 4));
/// ```
pub fn commit_root(root: &[u8; 32], leaf_count: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([ROOT_COMMIT_PREFIX]);
    hasher.update(leaf_count.to_be_bytes());
    hasher.update(root);
    hasher.finalize().into()
}

/// A digest backend that is actually implemented.
///
/// Trees and proof verifiers hold one of these instead of a raw
/// [`HashAlgorithm`], so placeholder algorithms are rejected once at the
/// boundary and the hot hashing loops stay infallible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeHasher {
    Sha256,
    #[cfg(feature = "blake3")]
    Blake3,
    #[cfg(feature = "poseidon")]
    Poseidon,
}

impl TreeHasher {
    /// Pick the backend for `algorithm`, or report that it has no code yet.
    pub(crate) fn new(algorithm: HashAlgorithm) -> Result<Self, HashNotImplemented> {
        match algorithm {
            HashAlgorithm::Sha256 => Ok(Self::Sha256),
            #[cfg(feature = "blake3")]
            HashAlgorithm::Blake3 => Ok(Self::Blake3),
            #[cfg(feature = "poseidon")]
            HashAlgorithm::Poseidon => Ok(Self::Poseidon),
            #[allow(unreachable_patterns)]
            other => Err(HashNotImplemented::new(other.name())),
        }
    }

    /// The public algorithm this backend implements.
    pub(crate) const fn algorithm(self) -> HashAlgorithm {
        match self {
            Self::Sha256 => HashAlgorithm::Sha256,
            #[cfg(feature = "blake3")]
            Self::Blake3 => HashAlgorithm::Blake3,
            #[cfg(feature = "poseidon")]
            Self::Poseidon => HashAlgorithm::Poseidon,
        }
    }

    /// Domain-separated leaf hash.
    pub(crate) fn leaf(self, data: &[u8]) -> [u8; 32] {
        match self {
            Self::Sha256 => hash_leaf(data),
            #[cfg(feature = "blake3")]
            Self::Blake3 => blake3_hash_leaf(data),
            #[cfg(feature = "poseidon")]
            Self::Poseidon => poseidon_hash_leaf(data),
        }
    }

    /// Domain-separated parent hash.
    pub(crate) fn nodes(self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        match self {
            Self::Sha256 => hash_nodes(left, right),
            #[cfg(feature = "blake3")]
            Self::Blake3 => blake3_hash_nodes(left, right),
            #[cfg(feature = "poseidon")]
            Self::Poseidon => poseidon_hash_nodes(left, right),
        }
    }
}

/// Hash a leaf with `algorithm`. SHA-256 always succeeds.
pub fn hash_leaf_with(
    algorithm: HashAlgorithm,
    data: &[u8],
) -> Result<[u8; 32], HashNotImplemented> {
    match algorithm {
        HashAlgorithm::Sha256 => Ok(hash_leaf(data)),
        #[cfg(feature = "blake3")]
        HashAlgorithm::Blake3 => Ok(blake3_hash_leaf(data)),
        #[cfg(feature = "poseidon")]
        HashAlgorithm::Poseidon => Ok(poseidon_hash_leaf(data)),
        #[cfg(feature = "rescue")]
        HashAlgorithm::Rescue => rescue_hash_leaf(data),
    }
}

/// Hash two child nodes with `algorithm`. SHA-256 always succeeds.
pub fn hash_nodes_with(
    algorithm: HashAlgorithm,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32], HashNotImplemented> {
    match algorithm {
        HashAlgorithm::Sha256 => Ok(hash_nodes(left, right)),
        #[cfg(feature = "blake3")]
        HashAlgorithm::Blake3 => Ok(blake3_hash_nodes(left, right)),
        #[cfg(feature = "poseidon")]
        HashAlgorithm::Poseidon => Ok(poseidon_hash_nodes(left, right)),
        #[cfg(feature = "rescue")]
        HashAlgorithm::Rescue => rescue_hash_nodes(left, right),
    }
}

/// Compute a BLAKE3 leaf hash as `BLAKE3(0x00 || data)`.
///
/// Uses the audited `blake3` crate in its default 32-byte output mode. The
/// prefixes match SHA-256 because the digest function itself already keeps
/// SHA-256 and BLAKE3 trees apart; the prefix only separates leaves from nodes.
#[cfg(feature = "blake3")]
pub fn blake3_hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a BLAKE3 parent hash as `BLAKE3(0x01 || left || right)`.
#[cfg(feature = "blake3")]
pub fn blake3_hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Two-to-one circom Poseidon with `domain` in the capacity slot.
#[cfg(feature = "poseidon")]
fn poseidon2(domain: Fr, left: Fr, right: Fr) -> Fr {
    let mut hasher = match Poseidon::<Fr>::with_domain_tag_circom(2, domain) {
        Ok(hasher) => hasher,
        Err(_) => unreachable!("circom Poseidon width 2 is in the published parameter set"),
    };
    match hasher.hash(&[left, right]) {
        Ok(digest) => digest,
        Err(_) => unreachable!("two inputs match width 2"),
    }
}

/// Encode a field element as 32 big-endian bytes.
#[cfg(feature = "poseidon")]
fn poseidon_field_to_bytes(element: Fr) -> [u8; 32] {
    let bytes = element.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    debug_assert!(bytes.len() <= 32);
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

/// Pack at most [`POSEIDON_FIELD_CHUNK`] bytes as a big-endian field element.
#[cfg(feature = "poseidon")]
fn poseidon_chunk_to_field(chunk: &[u8]) -> Fr {
    debug_assert!(!chunk.is_empty());
    debug_assert!(chunk.len() <= POSEIDON_FIELD_CHUNK);
    let mut buf = [0u8; 32];
    buf[32 - chunk.len()..].copy_from_slice(chunk);
    Fr::from_be_bytes_mod_order(&buf)
}

/// Poseidon leaf hash: absorb `len` then 31-byte chunks under the leaf domain.
///
/// Empty input still mixes length with a zero chunk so it does not collide
/// with a missing absorption. The permutation is circom-compatible Poseidon
/// over BN254 (`light-poseidon-nostd`).
#[cfg(feature = "poseidon")]
pub fn poseidon_hash_leaf(data: &[u8]) -> [u8; 32] {
    let domain = Fr::from(u64::from(POSEIDON_LEAF_PREFIX));
    let mut acc = Fr::from(data.len() as u64);
    if data.is_empty() {
        return poseidon_field_to_bytes(poseidon2(domain, acc, Fr::from(0u64)));
    }
    let mut offset = 0;
    while offset < data.len() {
        let end = core::cmp::min(offset + POSEIDON_FIELD_CHUNK, data.len());
        acc = poseidon2(domain, acc, poseidon_chunk_to_field(&data[offset..end]));
        offset = end;
    }
    poseidon_field_to_bytes(acc)
}

/// Poseidon parent hash of two 32-byte children under the node domain tag.
///
/// Each child is reduced into a BN254 field element (Poseidon outputs already
/// sit below the modulus, so this round-trips for hashes this function produces).
#[cfg(feature = "poseidon")]
pub fn poseidon_hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let domain = Fr::from(u64::from(POSEIDON_NODE_PREFIX));
    let left_f = Fr::from_be_bytes_mod_order(left);
    let right_f = Fr::from_be_bytes_mod_order(right);
    poseidon_field_to_bytes(poseidon2(domain, left_f, right_f))
}

/// Rescue leaf hash placeholder. Always returns [`HashNotImplemented`].
///
/// A later binding will absorb `data` as field elements and use
/// [`RESCUE_LEAF_PREFIX`] so leaves stay distinct from parent nodes.
#[cfg(feature = "rescue")]
pub fn rescue_hash_leaf(_data: &[u8]) -> Result<[u8; 32], HashNotImplemented> {
    Err(HashNotImplemented::new(HashAlgorithm::Rescue.name()))
}

/// Rescue parent-node hash placeholder. Always returns [`HashNotImplemented`].
#[cfg(feature = "rescue")]
pub fn rescue_hash_nodes(
    _left: &[u8; 32],
    _right: &[u8; 32],
) -> Result<[u8; 32], HashNotImplemented> {
    Err(HashNotImplemented::new(HashAlgorithm::Rescue.name()))
}

fn hex_nibble(byte: u8, index: usize) -> Result<u8, HexError> {
    let value = match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => {
            return Err(HexError::InvalidDigit {
                index,
                digit: char::from(byte),
            });
        }
    };
    Ok(value)
}

/// Decode a hex string into bytes.
///
/// Accepts optional `0x`/`0X` prefixes and both lower- and upper-case digits.
/// Surrounding whitespace is ignored; interior whitespace is not.
pub fn from_hex(input: &str) -> Result<Vec<u8>, HexError> {
    let trimmed = input.trim();
    let hex_body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_body.len() % 2 != 0 {
        return Err(HexError::OddLength {
            chars: hex_body.len(),
        });
    }
    let bytes = hex_body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_nibble(bytes[index], index)?;
        let lo = hex_nibble(bytes[index + 1], index + 1)?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

/// Decode a hex string into a 32-byte array.
pub fn try_from_hex32(input: &str) -> Result<[u8; 32], HexError> {
    let bytes = from_hex(input)?;
    if bytes.len() != 32 {
        return Err(HexError::UnexpectedLen {
            expected: 32,
            found: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode bytes as a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Encode a 32-byte array as a lowercase hex string.
pub fn to_hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "poseidon")]
    use super::{poseidon2, poseidon_chunk_to_field, poseidon_field_to_bytes};
    use crate::error::UnknownAlgorithm;
    #[cfg(all(feature = "blake3", not(feature = "std")))]
    use alloc::vec;
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::ToString, vec::Vec};
    #[cfg(feature = "poseidon")]
    use ark_bn254::Fr;
    #[cfg(feature = "poseidon")]
    use ark_ff::PrimeField;

    /// SHA-256(0x00 || "") — stable test vector for the empty leaf.
    const EMPTY_LEAF_HEX: &str = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
    /// SHA-256(0x00 || "abc")
    const ABC_LEAF_HEX: &str = "609f6e36d2405585188d5cfd761f407c7cc46a7d3f314c88270469dde315fcd1";
    /// SHA-256(0x00 || "a")
    const A_LEAF_HEX: &str = "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c";
    /// SHA-256(0x00 || "b")
    const B_LEAF_HEX: &str = "57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31";
    /// SHA-256(0x01 || H(a) || H(b))
    const AB_NODE_HEX: &str = "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb";

    #[test]
    fn prefixes_are_distinct() {
        assert_eq!(LEAF_PREFIX, 0x00);
        assert_eq!(NODE_PREFIX, 0x01);
        assert_ne!(LEAF_PREFIX, NODE_PREFIX);
        assert_eq!(ROOT_COMMIT_PREFIX, 0x02);
        assert_ne!(ROOT_COMMIT_PREFIX, LEAF_PREFIX);
        assert_ne!(ROOT_COMMIT_PREFIX, NODE_PREFIX);
        assert_eq!(POSEIDON_LEAF_PREFIX, 0x10);
        assert_eq!(POSEIDON_NODE_PREFIX, 0x11);
        assert_ne!(POSEIDON_LEAF_PREFIX, POSEIDON_NODE_PREFIX);
        assert_ne!(POSEIDON_LEAF_PREFIX, LEAF_PREFIX);
        assert_ne!(POSEIDON_NODE_PREFIX, NODE_PREFIX);
        assert_eq!(RESCUE_LEAF_PREFIX, 0x20);
        assert_eq!(RESCUE_NODE_PREFIX, 0x21);
        assert_ne!(RESCUE_LEAF_PREFIX, RESCUE_NODE_PREFIX);
        assert_ne!(RESCUE_LEAF_PREFIX, LEAF_PREFIX);
        assert_ne!(RESCUE_NODE_PREFIX, NODE_PREFIX);
        assert_ne!(RESCUE_LEAF_PREFIX, POSEIDON_LEAF_PREFIX);
        assert_ne!(RESCUE_NODE_PREFIX, POSEIDON_NODE_PREFIX);
        let prefixes = [
            LEAF_PREFIX,
            NODE_PREFIX,
            ROOT_COMMIT_PREFIX,
            POSEIDON_LEAF_PREFIX,
            POSEIDON_NODE_PREFIX,
            RESCUE_LEAF_PREFIX,
            RESCUE_NODE_PREFIX,
        ];
        for (i, a) in prefixes.iter().enumerate() {
            for b in prefixes.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn domain_kind_matches_prefix_constants() {
        assert_eq!(DomainKind::Leaf.prefix(), LEAF_PREFIX);
        assert_eq!(DomainKind::Node.prefix(), NODE_PREFIX);
        assert_eq!(DomainKind::RootCommit.prefix(), ROOT_COMMIT_PREFIX);
        assert_eq!(DomainKind::Leaf.poseidon_tag(), Some(POSEIDON_LEAF_PREFIX));
        assert_eq!(DomainKind::Node.poseidon_tag(), Some(POSEIDON_NODE_PREFIX));
        assert_eq!(DomainKind::RootCommit.poseidon_tag(), None);
        assert_eq!(DomainKind::Leaf.rescue_tag(), Some(RESCUE_LEAF_PREFIX));
        assert_eq!(DomainKind::Node.rescue_tag(), Some(RESCUE_NODE_PREFIX));
        assert_eq!(DomainKind::RootCommit.rescue_tag(), None);
        assert_eq!(DomainKind::Leaf.name(), "leaf");
        assert_eq!(DomainKind::Node.to_string(), "node");
        assert_eq!(DomainKind::RootCommit.name(), "root-commit");
        assert_eq!(
            DomainKind::all(),
            [DomainKind::Leaf, DomainKind::Node, DomainKind::RootCommit]
        );
        // Hash functions must consume the same bytes DomainKind advertises.
        let mut hasher = Sha256::new();
        hasher.update([DomainKind::Leaf.prefix()]);
        hasher.update(b"abc");
        let from_kind: [u8; 32] = hasher.finalize().into();
        assert_eq!(from_kind, hash_leaf(b"abc"));
    }

    #[test]
    fn hash_algorithm_from_name_and_is_implemented() {
        assert_eq!(
            HashAlgorithm::from_name("sha256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_name(" SHA-256 "),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_name("sha2"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            "sha256".parse::<HashAlgorithm>().expect("name"),
            HashAlgorithm::Sha256
        );
        assert_eq!("nope".parse::<HashAlgorithm>(), Err(UnknownAlgorithm));
        assert!(HashAlgorithm::Sha256.is_implemented());
        assert!(HashAlgorithm::from_name("").is_none());
        #[cfg(feature = "blake3")]
        {
            assert_eq!(
                HashAlgorithm::from_name("BLAKE3"),
                Some(HashAlgorithm::Blake3)
            );
            assert!(HashAlgorithm::Blake3.is_implemented());
        }
        #[cfg(not(feature = "blake3"))]
        assert!(HashAlgorithm::from_name("blake3").is_none());
        #[cfg(feature = "poseidon")]
        {
            assert_eq!(
                HashAlgorithm::from_name("poseidon"),
                Some(HashAlgorithm::Poseidon)
            );
            assert!(HashAlgorithm::Poseidon.is_implemented());
        }
        #[cfg(feature = "rescue")]
        {
            assert_eq!(
                HashAlgorithm::from_name("rescue"),
                Some(HashAlgorithm::Rescue)
            );
            assert!(!HashAlgorithm::Rescue.is_implemented());
        }
        #[cfg(not(feature = "rescue"))]
        assert!(HashAlgorithm::from_name("rescue").is_none());
    }

    #[test]
    fn hash_leaf_with_sha256_matches_hash_leaf() {
        let data = b"abc";
        assert_eq!(
            hash_leaf_with(HashAlgorithm::Sha256, data).expect("sha256"),
            hash_leaf(data)
        );
        let left = hash_leaf(b"a");
        let right = hash_leaf(b"b");
        assert_eq!(
            hash_nodes_with(HashAlgorithm::Sha256, &left, &right).expect("sha256"),
            hash_nodes(&left, &right)
        );
        assert_eq!(HashAlgorithm::Sha256.name(), "sha256");
        assert_eq!(HashAlgorithm::Sha256.to_string(), "sha256");
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_hashes_match_prefixed_one_shot_and_differ_from_sha256() {
        let mut leaf_input = vec![LEAF_PREFIX];
        leaf_input.extend_from_slice(b"abc");
        let expected_leaf: [u8; 32] = blake3::hash(&leaf_input).into();
        assert_eq!(blake3_hash_leaf(b"abc"), expected_leaf);
        assert_ne!(blake3_hash_leaf(b"abc"), hash_leaf(b"abc"));

        let left = blake3_hash_leaf(b"a");
        let right = blake3_hash_leaf(b"b");
        let mut node_input = vec![NODE_PREFIX];
        node_input.extend_from_slice(&left);
        node_input.extend_from_slice(&right);
        let expected_node: [u8; 32] = blake3::hash(&node_input).into();
        assert_eq!(blake3_hash_nodes(&left, &right), expected_node);
        assert_ne!(
            blake3_hash_nodes(&left, &right),
            blake3_hash_nodes(&right, &left)
        );
        // Leaf and node domains stay apart on the same 64-byte payload.
        let payload = [0x22u8; 64];
        let mut as_node = vec![NODE_PREFIX];
        as_node.extend_from_slice(&payload);
        let as_node: [u8; 32] = blake3::hash(&as_node).into();
        assert_ne!(blake3_hash_leaf(&payload), as_node);
    }

    #[test]
    fn tree_hasher_accepts_implemented_algorithms_only() {
        let sha = TreeHasher::new(HashAlgorithm::Sha256).expect("sha256");
        assert_eq!(sha.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(sha.leaf(b"abc"), hash_leaf(b"abc"));
        #[cfg(feature = "blake3")]
        {
            let b3 = TreeHasher::new(HashAlgorithm::Blake3).expect("blake3");
            assert_eq!(b3.algorithm(), HashAlgorithm::Blake3);
            assert_eq!(b3.leaf(b"abc"), blake3_hash_leaf(b"abc"));
            let (l, r) = (b3.leaf(b"a"), b3.leaf(b"b"));
            assert_eq!(b3.nodes(&l, &r), blake3_hash_nodes(&l, &r));
        }
        #[cfg(feature = "poseidon")]
        {
            let poseidon = TreeHasher::new(HashAlgorithm::Poseidon).expect("poseidon");
            assert_eq!(poseidon.algorithm(), HashAlgorithm::Poseidon);
            assert_eq!(poseidon.leaf(b"abc"), poseidon_hash_leaf(b"abc"));
            let (l, r) = (poseidon.leaf(b"a"), poseidon.leaf(b"b"));
            assert_eq!(poseidon.nodes(&l, &r), poseidon_hash_nodes(&l, &r));
        }
        #[cfg(feature = "rescue")]
        assert_eq!(
            TreeHasher::new(HashAlgorithm::Rescue),
            Err(HashNotImplemented::new("rescue"))
        );
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn hash_with_blake3_dispatches_to_blake3() {
        assert_eq!(
            hash_leaf_with(HashAlgorithm::Blake3, b"abc").expect("blake3"),
            blake3_hash_leaf(b"abc")
        );
        let left = blake3_hash_leaf(b"a");
        let right = blake3_hash_leaf(b"b");
        assert_eq!(
            hash_nodes_with(HashAlgorithm::Blake3, &left, &right).expect("blake3"),
            blake3_hash_nodes(&left, &right)
        );
        assert_eq!(HashAlgorithm::Blake3.name(), "blake3");
        assert_eq!(HashAlgorithm::Blake3.to_string(), "blake3");
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn poseidon_hashes_are_deterministic_ordered_and_domain_separated() {
        assert_eq!(HashAlgorithm::Poseidon.name(), "poseidon");
        assert_eq!(HashAlgorithm::Poseidon.to_string(), "poseidon");
        assert_eq!(poseidon_hash_leaf(b"abc"), poseidon_hash_leaf(b"abc"));
        assert_ne!(poseidon_hash_leaf(b"abc"), poseidon_hash_leaf(b"abd"));
        assert_ne!(poseidon_hash_leaf(b"abc"), hash_leaf(b"abc"));
        assert_eq!(
            hash_leaf_with(HashAlgorithm::Poseidon, b"abc").expect("poseidon"),
            poseidon_hash_leaf(b"abc")
        );

        let left = poseidon_hash_leaf(b"a");
        let right = poseidon_hash_leaf(b"b");
        assert_ne!(
            poseidon_hash_nodes(&left, &right),
            poseidon_hash_nodes(&right, &left)
        );
        assert_eq!(
            hash_nodes_with(HashAlgorithm::Poseidon, &left, &right).expect("poseidon"),
            poseidon_hash_nodes(&left, &right)
        );

        // Same 32-byte payload must not hash the same as a leaf and as a node.
        let payload = [0x22u8; 32];
        assert_ne!(
            poseidon_hash_leaf(&payload),
            poseidon_hash_nodes(&payload, &payload)
        );
        assert_ne!(poseidon_hash_leaf(b""), poseidon_hash_leaf(&[0u8]));
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn poseidon_leaf_matches_manual_length_and_chunk_fold() {
        let data = b"abcdefghijklmnopqrstuvwxyz0123456789";
        assert!(data.len() > POSEIDON_FIELD_CHUNK);
        let domain = Fr::from(u64::from(POSEIDON_LEAF_PREFIX));
        let mut acc = Fr::from(data.len() as u64);
        let mut offset = 0;
        while offset < data.len() {
            let end = core::cmp::min(offset + POSEIDON_FIELD_CHUNK, data.len());
            acc = poseidon2(domain, acc, poseidon_chunk_to_field(&data[offset..end]));
            offset = end;
        }
        assert_eq!(poseidon_hash_leaf(data), poseidon_field_to_bytes(acc));
    }

    #[cfg(feature = "poseidon")]
    #[test]
    fn poseidon_nodes_match_direct_permutation_call() {
        let left = poseidon_hash_leaf(b"left");
        let right = poseidon_hash_leaf(b"right");
        let domain = Fr::from(u64::from(POSEIDON_NODE_PREFIX));
        let expected = poseidon2(
            domain,
            Fr::from_be_bytes_mod_order(&left),
            Fr::from_be_bytes_mod_order(&right),
        );
        assert_eq!(
            poseidon_hash_nodes(&left, &right),
            poseidon_field_to_bytes(expected)
        );
        assert_eq!(
            Fr::from_be_bytes_mod_order(&poseidon_hash_nodes(&left, &right)),
            expected
        );
    }

    #[cfg(feature = "rescue")]
    #[test]
    fn rescue_stubs_return_not_implemented() {
        let err = rescue_hash_leaf(b"abc").expect_err("stub");
        assert_eq!(err.algorithm, "rescue");
        assert_eq!(err.to_string(), "rescue hashing is not implemented yet");
        assert_eq!(
            rescue_hash_nodes(&[1u8; 32], &[2u8; 32]).expect_err("stub"),
            err
        );
        assert_eq!(
            hash_leaf_with(HashAlgorithm::Rescue, b"abc").expect_err("stub"),
            err
        );
        assert_eq!(
            hash_nodes_with(HashAlgorithm::Rescue, &[1u8; 32], &[2u8; 32]).expect_err("stub"),
            err
        );
        assert_eq!(HashAlgorithm::Rescue.name(), "rescue");
        assert_eq!(HashAlgorithm::Rescue.to_string(), "rescue");
        assert_ne!(err, HashNotImplemented::new("poseidon"));
    }

    #[test]
    fn commit_root_matches_manual_layout_and_binds_count() {
        let root = hash_nodes(&hash_leaf(b"a"), &hash_leaf(b"b"));
        let mut hasher = Sha256::new();
        hasher.update([ROOT_COMMIT_PREFIX]);
        hasher.update(2u64.to_be_bytes());
        hasher.update(root);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(commit_root(&root, 2), expected);
        assert_ne!(commit_root(&root, 2), commit_root(&root, 3));
        assert_ne!(commit_root(&root, 2), root);
        // A commitment is not a valid node hash over the same bytes.
        assert_ne!(commit_root(&root, 2), hash_nodes(&root, &root));
    }

    #[test]
    fn hash_leaf_matches_known_vectors() {
        assert_eq!(to_hex32(&hash_leaf(b"")), EMPTY_LEAF_HEX);
        assert_eq!(to_hex32(&hash_leaf(b"abc")), ABC_LEAF_HEX);
        assert_eq!(to_hex32(&hash_leaf(b"a")), A_LEAF_HEX);
        assert_eq!(to_hex32(&hash_leaf(b"b")), B_LEAF_HEX);
    }

    #[test]
    fn hash_nodes_matches_known_vector_and_is_ordered() {
        let left = hash_leaf(b"a");
        let right = hash_leaf(b"b");
        assert_eq!(to_hex32(&hash_nodes(&left, &right)), AB_NODE_HEX);
        // Swapping children must change the parent unless the children are equal.
        assert_ne!(hash_nodes(&left, &right), hash_nodes(&right, &left));
        assert_eq!(hash_nodes(&left, &left), hash_nodes(&left, &left));
    }

    #[test]
    fn leaf_and_node_domains_do_not_collide_on_the_same_payload() {
        let payload = [0x11u8; 64];
        let as_leaf = hash_leaf(&payload);
        // Hash the same 64 bytes as if they were two concatenated children, but
        // through the leaf path — the prefix is the only difference.
        let mut hasher = Sha256::new();
        hasher.update([NODE_PREFIX]);
        hasher.update(payload);
        let as_node_prefixed: [u8; 32] = hasher.finalize().into();
        assert_ne!(as_leaf, as_node_prefixed);
    }

    #[test]
    fn from_hex_roundtrips_and_rejects_bad_input() {
        let original = [0x00, 0xab, 0xcd, 0xef, 0x12, 0x34];
        let encoded = to_hex(&original);
        assert_eq!(from_hex(&encoded).expect("decode"), original);
        assert_eq!(from_hex("00ABCDEF1234").expect("upper"), original);
        assert_eq!(from_hex("  0x00abcdef1234  ").expect("prefix"), original);
        assert_eq!(from_hex("0X00abcdef1234").expect("0X"), original);
        assert_eq!(from_hex("").expect("empty"), Vec::<u8>::new());

        assert!(matches!(
            from_hex("abc"),
            Err(HexError::OddLength { chars: 3 })
        ));
        assert!(matches!(
            from_hex("zz"),
            Err(HexError::InvalidDigit {
                index: 0,
                digit: 'z'
            })
        ));
        assert!(matches!(
            from_hex("0x0g"),
            Err(HexError::InvalidDigit {
                index: 1,
                digit: 'g'
            })
        ));
    }

    #[test]
    fn try_from_hex32_accepts_64_hex_chars_only() {
        let digest = hash_leaf(b"abc");
        let hex = to_hex32(&digest);
        assert_eq!(try_from_hex32(&hex).expect("32"), digest);
        assert_eq!(try_from_hex32(&format!("0x{hex}")).expect("0x"), digest);
        assert!(matches!(
            try_from_hex32("abcd"),
            Err(HexError::UnexpectedLen {
                expected: 32,
                found: 2
            })
        ));
    }
}
