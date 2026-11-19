//! 64-bit range-check circuit behind the `zk-range` feature.
//!
//! A Merkle-sum leaf stores an amount as `u128`. That encoding cannot be
//! negative; this circuit additionally proves `0 <= amount < 2^64` using the
//! audited [`halo2_proofs`] crate (Zcash Halo 2 over Pasta).
//!
//! Each of the 64 little-endian bits is constrained to `{0, 1}`. A running
//! sum reconstructs `sum_i bit_i * 2^i` and is copy-constrained to a public
//! instance, so a verifier who knows `amount` can check it is a 64-bit value.
//! [`generate_range_proof`] and [`verify_range_proof`] wrap Halo 2 proving.

use std::sync::Mutex;

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Expression, Fixed, Instance, ProvingKey, Selector, SingleVerifier,
    },
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::StdRng;
use rand::SeedableRng;

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

    /// Public Halo 2 instance for `amount`: one Pasta field element.
    pub fn instance(amount: u64) -> Vec<Vec<Fp>> {
        vec![vec![Fp::from(amount)]]
    }
}

/// Columns and selectors for [`RangeCheckCircuit`].
#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    bit: Column<Advice>,
    acc: Column<Advice>,
    pow2: Column<Fixed>,
    instance: Column<Instance>,
    s_bit: Selector,
    s_start: Selector,
    s_acc: Selector,
}

impl Circuit<Fp> for RangeCheckCircuit {
    type Config = RangeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let bit = meta.advice_column();
        let acc = meta.advice_column();
        let pow2 = meta.fixed_column();
        let instance = meta.instance_column();
        let s_bit = meta.selector();
        let s_start = meta.selector();
        let s_acc = meta.selector();

        meta.enable_equality(acc);
        meta.enable_equality(instance);

        // s_bit * bit * (1 - bit) = 0  =>  bit ∈ {0, 1} on selected rows.
        meta.create_gate("bitness", |meta| {
            let s = meta.query_selector(s_bit);
            let bit = meta.query_advice(bit, Rotation::cur());
            vec![s * bit.clone() * (Expression::Constant(Fp::ONE) - bit)]
        });

        // First row: acc = bit * 2^0.
        meta.create_gate("start", |meta| {
            let s = meta.query_selector(s_start);
            let bit = meta.query_advice(bit, Rotation::cur());
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let pow = meta.query_fixed(pow2);
            vec![s * (acc_cur - bit * pow)]
        });

        // Later rows: acc = acc_prev + bit * 2^i.
        meta.create_gate("accumulate", |meta| {
            let s = meta.query_selector(s_acc);
            let bit = meta.query_advice(bit, Rotation::cur());
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let acc_prev = meta.query_advice(acc, Rotation::prev());
            let pow = meta.query_fixed(pow2);
            vec![s * (acc_cur - acc_prev - bit * pow)]
        });

        RangeCheckConfig {
            bit,
            acc,
            pow2,
            instance,
            s_bit,
            s_start,
            s_acc,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let amount_cell: AssignedCell<Fp, Fp> = layouter.assign_region(
            || "range bits",
            |mut region| {
                let mut acc = Value::known(Fp::ZERO);
                let mut last = None;
                for i in 0..RANGE_BITS {
                    config.s_bit.enable(&mut region, i)?;
                    if i == 0 {
                        config.s_start.enable(&mut region, i)?;
                    } else {
                        config.s_acc.enable(&mut region, i)?;
                    }

                    let pow = Fp::from(1u64 << i);
                    region.assign_fixed(|| "pow2", config.pow2, i, || Value::known(pow))?;

                    let bit_v = match self.amount {
                        Some(a) => Value::known(Fp::from((a >> i) & 1)),
                        None => Value::unknown(),
                    };
                    region.assign_advice(|| "bit", config.bit, i, || bit_v)?;

                    acc = acc + bit_v * Value::known(pow);
                    last = Some(region.assign_advice(|| "acc", config.acc, i, || acc)?);
                }
                Ok(last.expect("RANGE_BITS > 0"))
            },
        )?;

        layouter.constrain_instance(amount_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}

/// Seed for the prover RNG.
///
/// The amount is a public instance, so the proof is not hiding it. A fixed
/// seed makes [`generate_range_proof`] deterministic for test vectors.
pub const PROOF_RNG_SEED: [u8; 32] = [7u8; 32];

/// Serialized Halo 2 proof that `amount` fits in 64 bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProof {
    /// Transcript bytes from `halo2_proofs::create_proof`.
    pub bytes: Vec<u8>,
}

impl RangeProof {
    /// Wrap already-serialized proof bytes.
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Why [`generate_range_proof`] or [`verify_range_proof`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeProofError {
    /// `amount` is `2^64` or larger.
    OutOfRange {
        /// The amount that did not fit.
        amount: u128,
    },
    /// Halo 2 proving failed.
    Prove,
    /// The proof did not verify for this amount.
    Verify,
}

impl core::fmt::Display for RangeProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RangeProofError::OutOfRange { amount } => {
                write!(f, "amount {amount} is outside 0..2^64")
            }
            RangeProofError::Prove => write!(f, "range-proof proving failed"),
            RangeProofError::Verify => write!(f, "range-proof verification failed"),
        }
    }
}

impl std::error::Error for RangeProofError {}

struct Artifacts {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

fn artifacts() -> &'static Artifacts {
    static CELL: Mutex<Option<&'static Artifacts>> = Mutex::new(None);
    let mut guard = CELL.lock().expect("range-check keys");
    if guard.is_none() {
        let params = Params::new(RANGE_K);
        let empty = RangeCheckCircuit::empty();
        let vk = keygen_vk(&params, &empty).expect("range-check keygen_vk");
        let pk = keygen_pk(&params, vk, &empty).expect("range-check keygen_pk");
        *guard = Some(Box::leak(Box::new(Artifacts { params, pk })));
    }
    guard.expect("initialized")
}

/// Prove that `amount` satisfies `0 <= amount < 2^64`.
///
/// ```
/// use merkle_tree::range::{generate_range_proof, verify_range_proof};
///
/// let proof = generate_range_proof(42).expect("fits");
/// assert!(verify_range_proof(42, &proof).is_ok());
/// assert!(generate_range_proof(1u128 << 64).is_err());
/// ```
pub fn generate_range_proof(amount: u128) -> Result<RangeProof, RangeProofError> {
    let amount_u64 = u64::try_from(amount).map_err(|_| RangeProofError::OutOfRange { amount })?;
    let circuit = RangeCheckCircuit::new(amount_u64);
    let keys = artifacts();
    let mut rng = StdRng::from_seed(PROOF_RNG_SEED);
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(Vec::new());
    let instance = Fp::from(amount_u64);
    create_proof(
        &keys.params,
        &keys.pk,
        &[circuit],
        &[&[&[instance]]],
        &mut rng,
        &mut transcript,
    )
    .map_err(|_| RangeProofError::Prove)?;
    Ok(RangeProof::from_bytes(transcript.finalize()))
}

/// Check a proof from [`generate_range_proof`] against a public `amount`.
pub fn verify_range_proof(amount: u128, proof: &RangeProof) -> Result<(), RangeProofError> {
    let amount_u64 = u64::try_from(amount).map_err(|_| RangeProofError::OutOfRange { amount })?;
    let keys = artifacts();
    let strategy = SingleVerifier::new(&keys.params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof.bytes.as_slice());
    let instance = Fp::from(amount_u64);
    verify_proof(
        &keys.params,
        keys.pk.get_vk(),
        strategy,
        &[&[&[instance]]],
        &mut transcript,
    )
    .map_err(|_| RangeProofError::Verify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn mock_ok(amount: u64) {
        let circuit = RangeCheckCircuit::new(amount);
        let prover =
            MockProver::run(RANGE_K, &circuit, RangeCheckCircuit::instance(amount)).expect("rows");
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
        MockProver::run(RANGE_K, &circuit, RangeCheckCircuit::instance(1))
            .expect("k=7 has enough rows");
        let too_small = MockProver::run(6, &circuit, RangeCheckCircuit::instance(1));
        assert!(too_small.is_err(), "k=6 should be short of blinding rows");
    }

    #[test]
    fn without_witnesses_clears_the_amount() {
        let circuit = RangeCheckCircuit::new(99);
        assert!(circuit.without_witnesses().amount.is_none());
    }

    #[test]
    fn reconstructed_amount_must_match_the_public_instance() {
        let circuit = RangeCheckCircuit::new(42);
        let prover =
            MockProver::run(RANGE_K, &circuit, RangeCheckCircuit::instance(42)).expect("rows");
        prover.verify().expect("42 is in range");

        let wrong =
            MockProver::run(RANGE_K, &circuit, RangeCheckCircuit::instance(43)).expect("rows");
        assert!(
            wrong.verify().is_err(),
            "a different public amount must fail"
        );
    }

    #[test]
    fn endpoints_of_the_64_bit_range_match_the_instance() {
        mock_ok(0);
        mock_ok(u64::MAX);
        let circuit = RangeCheckCircuit::new(0);
        let swapped = MockProver::run(RANGE_K, &circuit, RangeCheckCircuit::instance(u64::MAX))
            .expect("rows");
        assert!(swapped.verify().is_err());
    }

    #[test]
    fn generate_and_verify_round_trip() {
        for amount in [0u128, 1, 42, u64::MAX as u128] {
            let proof = generate_range_proof(amount).expect("fits");
            assert!(!proof.bytes.is_empty());
            assert_eq!(verify_range_proof(amount, &proof), Ok(()));
        }
    }

    #[test]
    fn generate_rejects_amounts_outside_64_bits() {
        let amount = RANGE_MAX + 1;
        assert_eq!(
            generate_range_proof(amount),
            Err(RangeProofError::OutOfRange { amount })
        );
        assert_eq!(
            verify_range_proof(amount, &RangeProof::from_bytes(Vec::new())),
            Err(RangeProofError::OutOfRange { amount })
        );
    }

    #[test]
    fn verify_rejects_a_wrong_amount_or_a_tampered_proof() {
        let proof = generate_range_proof(42).expect("fits");
        assert_eq!(verify_range_proof(43, &proof), Err(RangeProofError::Verify));

        let mut mangled = proof.clone();
        let last = mangled.bytes.last_mut().expect("non-empty");
        *last ^= 0xff;
        assert_eq!(
            verify_range_proof(42, &mangled),
            Err(RangeProofError::Verify)
        );
        assert_eq!(
            verify_range_proof(42, &RangeProof::from_bytes(Vec::new())),
            Err(RangeProofError::Verify)
        );
    }

    #[test]
    fn generate_is_deterministic_for_the_fixed_seed() {
        let a = generate_range_proof(42).expect("fits");
        let b = generate_range_proof(42).expect("fits");
        assert_eq!(a, b);
    }
}
