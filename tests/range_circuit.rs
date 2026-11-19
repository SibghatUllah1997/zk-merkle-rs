//! Public API tests for the `zk-range` bitness circuit.
#![cfg(feature = "zk-range")]

use merkle_tree::{amount_in_range, features, RangeCheckCircuit, RANGE_BITS, RANGE_MAX};

#[test]
fn feature_flag_is_on() {
    assert!(features::enabled().contains(&"zk-range"));
    assert_eq!(
        features::enabled().contains(&"zk-range"),
        features::ZK_RANGE
    );
}

#[test]
fn public_constants_describe_a_64_bit_range() {
    assert_eq!(RANGE_BITS, 64);
    assert_eq!(RANGE_MAX, u64::MAX as u128);
    assert!(amount_in_range(1u128 << 63));
    assert!(!amount_in_range(1u128 << 64));
}

#[test]
fn circuit_constructor_mirrors_the_range_check() {
    let circuit = RangeCheckCircuit::try_from_amount(1_000).expect("fits");
    assert_eq!(circuit.amount, Some(1_000));
    assert_eq!(RangeCheckCircuit::new(7).amount, Some(7));
    assert!(RangeCheckCircuit::try_from_amount(u128::MAX).is_none());
}
