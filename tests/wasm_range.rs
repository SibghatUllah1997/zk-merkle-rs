//! Host tests for the optional wasm Halo 2 range-proof verifier.
//!
//! JavaScript passes a decimal amount and hex transcript. The helper returns
//! the same [`merkle_tree::wasm::Verdict`] as the inclusion checkers.

use merkle_tree::wasm::verify_range_proof_js;
use merkle_tree::{generate_range_proof, to_hex, RANGE_MAX};

fn proof_hex(amount: u128) -> String {
    let proof = generate_range_proof(amount).expect("fits in 64 bits");
    to_hex(&proof.bytes)
}

#[test]
fn a_fresh_proof_verifies_for_in_range_amounts() {
    for amount in [0u128, 1, 42, u64::MAX as u128] {
        let hex = proof_hex(amount);
        let verdict = verify_range_proof_js(&amount.to_string(), &hex);
        assert!(verdict.ok(), "amount={amount}: {}", verdict.reason());
        assert_eq!(verdict.amount(), amount.to_string());
    }
}

#[test]
fn a_proof_for_one_amount_does_not_verify_another() {
    let hex = proof_hex(42);
    assert!(verify_range_proof_js("42", &hex).ok());
    let wrong = verify_range_proof_js("43", &hex);
    assert!(!wrong.ok());
    assert_eq!(wrong.amount(), "43");
    assert!(!verify_range_proof_js("0", &hex).ok());
}

#[test]
fn a_tampered_transcript_fails_closed() {
    let mut hex = proof_hex(42);
    let last = hex.pop().expect("non-empty");
    hex.push(if last == '0' { '1' } else { '0' });
    let verdict = verify_range_proof_js("42", &hex);
    assert!(!verdict.ok());
    assert_eq!(verdict.amount(), "42");
    assert!(!verify_range_proof_js("42", "").ok());
}

#[test]
fn out_of_range_and_parse_errors_carry_a_reason() {
    let too_big = verify_range_proof_js(&(RANGE_MAX + 1).to_string(), "00");
    assert!(!too_big.ok());
    assert!(
        too_big.reason().contains("outside 0..2^64"),
        "{}",
        too_big.reason()
    );
    assert_eq!(too_big.amount(), (RANGE_MAX + 1).to_string());

    let bad_amount = verify_range_proof_js("xyz", "00");
    assert!(!bad_amount.ok());
    assert!(bad_amount.reason().contains("invalid amount"));
    assert!(bad_amount.amount().is_empty());

    let bad_hex = verify_range_proof_js("1", "gg");
    assert!(!bad_hex.ok());
    assert!(
        bad_hex.reason().contains("invalid hex"),
        "{}",
        bad_hex.reason()
    );
}
