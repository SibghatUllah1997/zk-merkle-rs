//! 64-bit range-check circuit behind the `zk-range` feature.
//!
//! A Merkle-sum leaf stores an amount as `u128`. That encoding cannot be
//! negative; this circuit additionally proves `0 <= amount < 2^64` using the
//! audited [`halo2_proofs`] crate (Zcash Halo 2 over Pasta).
//!
//! This module assigns the 64 little-endian bits of the amount and constrains
//! each bit to `{0, 1}`. Reconstructing the amount from those bits and
//! exposing it as a public input is the next step.

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

/// Width of the range check, in bits. Amounts must satisfy `0 <= a < 2^64`.
pub const RANGE_BITS: usize = 64;

/// Circuit size parameter: the circuit uses `2^RANGE_K` rows.
///
/// 64 bit rows plus Halo 2's blinding rows fit in `2^7 = 128`.
pub const RANGE_K: u32 = 7;

/// Largest amount the circuit accepts (`2^64 - 1`).
pub const RANGE_MAX: u128 = u64::MAX as u128;

/// True when `amount` is in `0..2^64`.
///
/// ```
/// use merkle_tree::range::amount_in_range;
///
/// assert!(amount_in_range(0));
/// assert!(amount_in_range(u64::MAX as u128));
/// assert!(!amount_in_range((u64::MAX as u128) + 1));
/// ```
pub const fn amount_in_range(amount: u128) -> bool {
    amount <= RANGE_MAX
}

/// Halo 2 circuit that witnesses `amount` as 64 boolean bits.
///
/// ```
/// use merkle_tree::range::RangeCheckCircuit;
///
/// let circuit = RangeCheckCircuit::try_from_amount(42).expect("fits");
/// assert_eq!(circuit.amount, Some(42));
/// assert!(RangeCheckCircuit::try_from_amount(1u128 << 64).is_none());
/// ```
#[derive(Clone, Debug, Default)]
pub struct RangeCheckCircuit {
    /// Private amount. `None` during key generation.
    pub amount: Option<u64>,
}

impl RangeCheckCircuit {
    /// Circuit for a 64-bit amount.
    pub const fn new(amount: u64) -> Self {
        Self {
            amount: Some(amount),
        }
    }

    /// Empty circuit used for key generation.
    pub const fn empty() -> Self {
        Self { amount: None }
    }

    /// Build a circuit from a `u128`, or `None` if it does not fit in 64 bits.
    pub const fn try_from_amount(amount: u128) -> Option<Self> {
        if amount_in_range(amount) {
            Some(Self::new(amount as u64))
        } else {
            None
        }
    }
}

/// Columns and selectors for [`RangeCheckCircuit`].
#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    bit: Column<Advice>,
    s_bit: Selector,
}

impl Circuit<Fp> for RangeCheckCircuit {
    type Config = RangeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let bit = meta.advice_column();
        let s_bit = meta.selector();

        // s * bit * (1 - bit) = 0  =>  bit ∈ {0, 1} on selected rows.
        meta.create_gate("bitness", |meta| {
            let s = meta.query_selector(s_bit);
            let bit = meta.query_advice(bit, Rotation::cur());
            vec![s * bit.clone() * (Expression::Constant(Fp::ONE) - bit)]
        });

        RangeCheckConfig { bit, s_bit }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "range bits",
            |mut region| {
                for i in 0..RANGE_BITS {
                    config.s_bit.enable(&mut region, i)?;
                    let bit_val = match self.amount {
                        Some(a) => Value::known(Fp::from((a >> i) & 1)),
                        None => Value::unknown(),
                    };
                    region.assign_advice(|| "bit", config.bit, i, || bit_val)?;
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn mock_ok(amount: u64) {
        let circuit = RangeCheckCircuit::new(amount);
        let prover = MockProver::run(RANGE_K, &circuit, vec![]).expect("rows");
        prover.verify().expect("satisfied");
    }

    #[test]
    fn constants_match_the_64_bit_bound() {
        assert_eq!(RANGE_BITS, 64);
        assert_eq!(RANGE_MAX, (1u128 << 64) - 1);
        assert_eq!(RANGE_K, 7);
        assert!(amount_in_range(0));
        assert!(amount_in_range(RANGE_MAX));
        assert!(!amount_in_range(RANGE_MAX + 1));
        assert!(!amount_in_range(u128::MAX));
    }

    #[test]
    fn try_from_amount_rejects_values_that_need_more_than_64_bits() {
        assert_eq!(
            RangeCheckCircuit::try_from_amount(0).unwrap().amount,
            Some(0)
        );
        assert_eq!(
            RangeCheckCircuit::try_from_amount(RANGE_MAX)
                .unwrap()
                .amount,
            Some(u64::MAX)
        );
        assert!(RangeCheckCircuit::try_from_amount(RANGE_MAX + 1).is_none());
        assert!(RangeCheckCircuit::empty().amount.is_none());
    }

    #[test]
    fn mock_prover_accepts_in_range_amounts() {
        for amount in [0, 1, 42, 255, (1u64 << 32) - 1, 1u64 << 63, u64::MAX] {
            mock_ok(amount);
        }
    }

    #[test]
    fn k_is_large_enough_for_64_bits_and_blinding() {
        let circuit = RangeCheckCircuit::new(1);
        MockProver::run(RANGE_K, &circuit, vec![]).expect("k=7 has enough rows");
        let too_small = MockProver::run(6, &circuit, vec![]);
        assert!(too_small.is_err(), "k=6 should be short of blinding rows");
    }

    #[test]
    fn without_witnesses_clears_the_amount() {
        let circuit = RangeCheckCircuit::new(99);
        assert!(circuit.without_witnesses().amount.is_none());
    }
}
