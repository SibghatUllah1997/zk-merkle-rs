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

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use sha2::{Digest, Sha256};

use crate::error::HexError;

/// Domain-separation prefix prepended to raw leaf data before hashing.
pub const LEAF_PREFIX: u8 = 0x00;

/// Domain-separation prefix prepended to concatenated child hashes.
pub const NODE_PREFIX: u8 = 0x01;

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
    #[cfg(not(feature = "std"))]
    use alloc::{format, vec::Vec};

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
