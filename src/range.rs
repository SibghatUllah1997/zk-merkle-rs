//! 64-bit range-check circuit for Merkle sum leaf amounts (feature `zk-range`).
//!
//! The circuit proves that a public amount `v` satisfies `0 <= v < 2^64`.
//! It is written against the audited `halo2_proofs` crate over the Pallas
//! scalar field; no proving-system or field arithmetic lives in this crate.
//!
//! Layout (one region, 65 rows):
//!
//! | row | `bit`   | `acc`                  | `q_step` |
//! |-----|---------|------------------------|----------|
//! | 0   | –       | 0 (fixed constant)     | 0        |
//! | i   | `b_i`   | `2 * acc[i-1] + b_i`   | 1        |
//! | 64  | `b_64`  | `v` (= public input 0) | 1        |
//!
//! Bits are fed most significant first. The `step` gate enforces that each
//! `b_i` is 0 or 1 and that the accumulator doubles and adds the bit. After
//! 64 steps the accumulator is at most `2^64 - 1`, far below the field
//! modulus, so it cannot wrap. Copying it to the instance column ties that
//! value to the public amount.
//!
//! The amount is public here. Binding it to a hidden leaf commitment is left
//! to later roadmap steps.
//!
//! ```
//! use merkle_tree::range::{RangeCheckCircuit, RANGE_CIRCUIT_K};
//! use halo2_proofs::dev::MockProver;
//!
//! let amount = 1_000_000u128;
//! let circuit = RangeCheckCircuit::new(amount);
//! let prover = MockProver::run(RANGE_CIRCUIT_K, &circuit, vec![circuit.public_inputs()]).unwrap();
//! assert!(prover.verify().is_ok());
//! ```

use std::vec;
use std::vec::Vec;

use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

/// Number of bits the circuit decomposes the amount into.
pub const RANGE_BITS: usize = 64;

/// Circuit size parameter: `2^7 = 128` rows fit the 65 used rows plus blinding.
pub const RANGE_CIRCUIT_K: u32 = 7;

/// Converts an amount to a Pallas scalar without truncation.
pub fn amount_to_field(amount: u128) -> Fp {
    let lo = Fp::from(amount as u64);
    let hi = Fp::from((amount >> 64) as u64);
    // 2^64 as a field element: (2^32)^2 avoids a u128 constructor.
    let two_32 = Fp::from(1u64 << 32);
    lo + hi * two_32 * two_32
}

/// Low 64 bits of `amount`, most significant first.
///
/// Higher bits are dropped on purpose: for `amount >= 2^64` the circuit's
/// accumulator then differs from the public input and verification fails.
pub fn bits_msb_first(amount: u128) -> [bool; RANGE_BITS] {
    let low = amount as u64;
    let mut out = [false; RANGE_BITS];
    for (i, bit) in out.iter_mut().enumerate() {
        *bit = (low >> (RANGE_BITS - 1 - i)) & 1 == 1;
    }
    out
}

/// Columns and selector used by [`RangeCheckCircuit`].
#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    bit: Column<Advice>,
    acc: Column<Advice>,
    instance: Column<Instance>,
    q_step: Selector,
}

impl RangeCheckConfig {
    /// Allocates columns and registers the boolean and accumulator gate.
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let bit = meta.advice_column();
        let acc = meta.advice_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();
        let q_step = meta.selector();

        meta.enable_equality(acc);
        meta.enable_equality(instance);
        meta.enable_constant(constant);

        meta.create_gate("range step", |meta| {
            let q = meta.query_selector(q_step);
            let b = meta.query_advice(bit, Rotation::cur());
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let acc_prev = meta.query_advice(acc, Rotation::prev());
            let one = Expression::Constant(Fp::one());
            let two = Expression::Constant(Fp::from(2));

            vec![
                // b is a bit: b * (1 - b) == 0
                q.clone() * b.clone() * (one - b.clone()),
                // acc[i] == 2 * acc[i-1] + b
                q * (acc_cur - (acc_prev * two + b)),
            ]
        });

        Self {
            bit,
            acc,
            instance,
            q_step,
        }
    }

    /// Lays out the decomposition and returns the final accumulator cell.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        bits: [Value<Fp>; RANGE_BITS],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "range decomposition",
            |mut region| {
                let mut acc =
                    region.assign_advice_from_constant(|| "acc 0", self.acc, 0, Fp::zero())?;
                for (i, b) in bits.iter().enumerate() {
                    let row = i + 1;
                    self.q_step.enable(&mut region, row)?;
                    region.assign_advice(|| "bit", self.bit, row, || *b)?;
                    let next = acc.value().zip(*b).map(|(a, b)| a + a + b);
                    acc = region.assign_advice(|| "acc", self.acc, row, || next)?;
                }
                Ok(acc)
            },
        )
    }

    /// Constrains `cell` to equal public input row `row`.
    pub fn expose(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.instance, row)
    }
}

/// Proves `0 <= amount < 2^64` for a public amount.
#[derive(Clone, Debug, Default)]
pub struct RangeCheckCircuit {
    amount: Value<u128>,
}

impl RangeCheckCircuit {
    /// Circuit with a known witness amount.
    pub fn new(amount: u128) -> Self {
        Self {
            amount: Value::known(amount),
        }
    }

    /// Public inputs for the single instance column: `[amount]`.
    ///
    /// Panics if the circuit was built without a witness.
    pub fn public_inputs(&self) -> Vec<Fp> {
        let mut out = Vec::with_capacity(1);
        self.amount.map(|a| out.push(amount_to_field(a)));
        assert_eq!(out.len(), 1, "public_inputs needs a known amount");
        out
    }
}

impl Circuit<Fp> for RangeCheckCircuit {
    type Config = RangeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        RangeCheckConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let bits: [Value<Fp>; RANGE_BITS] = core::array::from_fn(|i| {
            self.amount
                .map(|a| Fp::from(u64::from(bits_msb_first(a)[i])))
        });
        let last = config.assign(layouter.namespace(|| "decompose"), bits)?;
        config.expose(layouter.namespace(|| "public amount"), &last, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    /// Assigns arbitrary field values as "bits" to probe the gate.
    struct RawBits(pub [u64; RANGE_BITS]);

    impl Circuit<Fp> for RawBits {
        type Config = RangeCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            RawBits([0; RANGE_BITS])
        }
        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            RangeCheckConfig::configure(meta)
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let bits = self.0.map(|b| Value::known(Fp::from(b)));
            let last = config.assign(layouter.namespace(|| "decompose"), bits)?;
            config.expose(layouter.namespace(|| "public amount"), &last, 0)
        }
    }

    #[test]
    fn non_boolean_bit_is_rejected_even_when_sum_matches() {
        // Last "bit" = 2 makes the accumulator 2, matching the public input,
        // so only the boolean constraint can catch it.
        let mut bits = [0u64; RANGE_BITS];
        bits[RANGE_BITS - 1] = 2;
        let prover = MockProver::run(RANGE_CIRCUIT_K, &RawBits(bits), vec![vec![Fp::from(2)]])
            .expect("synthesis");
        assert!(prover.verify().is_err());
    }

    #[test]
    fn honest_raw_bits_pass() {
        let mut bits = [0u64; RANGE_BITS];
        bits[RANGE_BITS - 2] = 1; // value 2
        let prover = MockProver::run(RANGE_CIRCUIT_K, &RawBits(bits), vec![vec![Fp::from(2)]])
            .expect("synthesis");
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn bits_are_msb_first() {
        let bits = bits_msb_first(1);
        assert!(bits[RANGE_BITS - 1]);
        assert!(bits[..RANGE_BITS - 1].iter().all(|b| !b));
        assert!(bits_msb_first(1u128 << 63)[0]);
        assert!(bits_msb_first(1u128 << 64).iter().all(|b| !b));
    }

    #[test]
    fn amount_to_field_matches_u64_path() {
        assert_eq!(amount_to_field(u64::MAX as u128), Fp::from(u64::MAX));
        assert_eq!(amount_to_field(1u128 << 64), Fp::from(u64::MAX) + Fp::one());
    }
}
