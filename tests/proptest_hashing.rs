//! Property tests for domain-separated hashing and hex helpers.

use merkle_tree::{
    from_hex, hash_leaf, hash_nodes, to_hex, to_hex32, try_from_hex32, HexError, MerkleRoot,
    LEAF_PREFIX, NODE_PREFIX,
};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

fn cfg() -> ProptestConfig {
    ProptestConfig {
        cases: 64,
        max_shrink_iters: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn hex_encode_decode_roundtrip(bytes in prop::collection::vec(any::<u8>(), 0..=96)) {
        let encoded = to_hex(&bytes);
        prop_assert_eq!(from_hex(&encoded).expect("lower"), bytes.clone());
        prop_assert_eq!(from_hex(&encoded.to_ascii_uppercase()).expect("upper"), bytes.clone());
        prop_assert_eq!(from_hex(&format!("0x{encoded}")).expect("0x"), bytes.clone());
        prop_assert_eq!(from_hex(&format!("0X{encoded}")).expect("0X"), bytes.clone());
        prop_assert_eq!(from_hex(&format!("  {encoded}  ")).expect("trim"), bytes);
    }

    #[test]
    fn try_from_hex32_and_root_roundtrip(bytes in any::<[u8; 32]>()) {
        let encoded = to_hex32(&bytes);
        prop_assert_eq!(encoded.len(), 64);
        prop_assert_eq!(try_from_hex32(&encoded).expect("32"), bytes);
        prop_assert_eq!(MerkleRoot::from_hex(&encoded).expect("root").0, bytes);
        prop_assert_eq!(MerkleRoot::try_from(encoded.as_str()).expect("try_from").0, bytes);
        let typed = MerkleRoot::from(bytes);
        prop_assert_eq!(typed.to_hex(), encoded);
        prop_assert_eq!(typed.to_string(), typed.to_hex());
        prop_assert_eq!(*typed.as_bytes(), bytes);
    }

    #[test]
    fn odd_length_hex_is_rejected(
        bytes in prop::collection::vec(any::<u8>(), 0..=40),
        extra in "[0-9a-f]"
    ) {
        let mut s = to_hex(&bytes);
        s.push_str(&extra);
        match from_hex(&s) {
            Err(HexError::OddLength { chars }) => prop_assert_eq!(chars, s.len()),
            other => prop_assert!(false, "expected OddLength, got {other:?}"),
        }
    }

    #[test]
    fn invalid_hex_digit_is_rejected(index in 0usize..8, digit in "[g-z]") {
        // Avoid a leading "0x"/"0X" after substitution; that would be a valid prefix.
        let mut chars = *b"11223344";
        chars[index] = digit.as_bytes()[0];
        let s = String::from_utf8(chars.to_vec()).unwrap();
        match from_hex(&s) {
            Err(HexError::InvalidDigit { index: found, digit: ch }) => {
                prop_assert_eq!(found, index);
                prop_assert_eq!(ch, digit.chars().next().unwrap());
            }
            other => prop_assert!(false, "expected InvalidDigit, got {other:?}"),
        }
    }

    #[test]
    fn try_from_hex32_rejects_non_32_byte_payloads(bytes in prop::collection::vec(any::<u8>(), 0..=48)) {
        prop_assume!(bytes.len() != 32);
        let encoded = to_hex(&bytes);
        match try_from_hex32(&encoded) {
            Err(HexError::UnexpectedLen { expected, found }) => {
                prop_assert_eq!(expected, 32);
                prop_assert_eq!(found, bytes.len());
            }
            other => prop_assert!(false, "expected UnexpectedLen, got {other:?}"),
        }
    }

    #[test]
    fn hash_nodes_is_ordered(left in any::<[u8; 32]>(), right in any::<[u8; 32]>()) {
        let ab = hash_nodes(&left, &right);
        let ba = hash_nodes(&right, &left);
        if left == right {
            prop_assert_eq!(ab, ba);
        } else {
            prop_assert_ne!(ab, ba);
        }
        prop_assert_eq!(ab, hash_nodes(&left, &right));
    }

    #[test]
    fn leaf_hash_differs_from_parent_of_two_copies(data in prop::collection::vec(any::<u8>(), 0..=80)) {
        prop_assert_ne!(LEAF_PREFIX, NODE_PREFIX);
        let leaf = hash_leaf(&data);
        let parent = hash_nodes(&leaf, &leaf);
        // Domain prefixes plus the extra child bytes make a collision with the
        // leaf hash vanishingly unlikely under SHA-256.
        prop_assert_ne!(leaf, parent);
    }
}
