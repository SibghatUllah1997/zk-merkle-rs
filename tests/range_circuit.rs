//! MockProver checks for the 64-bit range circuit.
#![cfg(feature = "zk-range")]

use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use merkle_tree::range::{amount_to_field, RangeCheckCircuit, RANGE_CIRCUIT_K};
use proptest::prelude::*;

fn verifies(amount: u128, public: Fp) -> bool {
    let circuit = RangeCheckCircuit::new(amount);
    let prover = MockProver::run(RANGE_CIRCUIT_K, &circuit, vec![vec![public]]).expect("synthesis");
    prover.verify().is_ok()
}

fn honest(amount: u128) -> bool {
    verifies(amount, amount_to_field(amount))
}

#[test]
fn edge_amounts_in_range_pass() {
    for amount in [
        0u128,
        1,
        2,
        255,
        1 << 32,
        (1 << 63) - 1,
        1 << 63,
        u64::MAX as u128,
    ] {
        assert!(honest(amount), "{amount}");
    }
}

#[test]
fn amounts_at_or_above_two_pow_64_fail() {
    for amount in [
        1u128 << 64,
        (1 << 64) + 1,
        (1 << 64) + 5,
        1 << 100,
        u128::MAX,
    ] {
        assert!(!honest(amount), "{amount}");
    }
}

#[test]
fn wrong_public_amount_fails() {
    assert!(!verifies(5, amount_to_field(6)));
    assert!(!verifies(0, Fp::one()));
}

#[test]
fn negative_amount_as_field_element_fails() {
    // -1 mod p is a huge field element; no 64-bit witness can reach it.
    assert!(!verifies(u64::MAX as u128, -Fp::one()));
}

#[test]
fn public_inputs_hold_the_amount() {
    let circuit = RangeCheckCircuit::new(42);
    assert_eq!(circuit.public_inputs(), vec![Fp::from(42)]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn any_u64_passes(amount in any::<u64>()) {
        prop_assert!(honest(amount as u128));
    }

    #[test]
    fn any_value_above_u64_fails(high in 1u64.., low in any::<u64>()) {
        let amount = ((high as u128) << 64) | low as u128;
        prop_assert!(!honest(amount));
    }
}
