//! Frozen Halo 2 range-proof vector for amount 42.
//!
//! Bytes come from `generate_range_proof(42)` with the crate's fixed prover
//! seed. A change to the circuit, `RANGE_K`, that seed, or halo2_proofs 0.3.5
//! will miss this vector.
#![cfg(feature = "zk-range")]

use merkle_tree::{
    from_hex, generate_range_proof, verify_range_proof, RangeProof, RangeProofError,
};

/// Public amount pinned by this vector.
const FROZEN_AMOUNT: u128 = 42;

/// Transcript bytes from `generate_range_proof(42)` (1440 bytes).
const FROZEN_PROOF_HEX: &str = concat!(
    "efc34698ca33b1866dba0a55fad9bf8f14055706d4cd77b57b13de5d633db188",
    "a13852f0da4958a20b77ecdba2d6b22d3716627366416fa4a70c9a940842c23b",
    "23061cccf1f3bce63a098e3e127209f8bf4429dca4a5442f17f75869d0691a38",
    "0174a240cd2e3417797dcb4955a65f9056c364c6b13b6db0f3bbe38dae1ea51a",
    "d9de10992c0706a157ff1c458a3688cc69dcace12704fa7bf154fe71a8dc08bf",
    "f4c4c6af0d6a733ca35ab651ec2aad6c533ea49405b8221854cb6cfbd2002299",
    "e0f051a2f55962de0c33888723eca3bb281a15e06d1ea458695fdd2788133432",
    "e3cfaa2ea020e5265447a2283dd3ae03b82992cc297d2124a1e97f9f160de53f",
    "a2958276565a1e0b2eca85eed4cc15b9681b346c13cd5120799cb54a36ed643e",
    "d6281901df43b69705607d5ba0cbef901e95396d12cebb20b1c29305c772cf29",
    "64d6b508ae169a6b1b3d0c296fbff334f9d7081c7abd1cd78f35f5180a4f2210",
    "c0d87d5024df81c3e0ef1f7e84e01fbd564c1dda3de0a0119383e76bbc850e1f",
    "45e5ebc777cbdd58a5c01f59ffa5c2ab6201a873b450477431e9ab28abad272b",
    "9eafeb74edb5b3de44430e09dce87aca9ce8de84e2fc0c8df19da7ba8c4f3c0f",
    "a73500538a152a7a607d115023bd47e1c518c9eed1533ae73f4b046e1e5eeb1b",
    "fcbf4b71b57735eb0f0afb7eddc7cbe40ad0ae3c1eab58f7963856e733b49421",
    "52fc7af219b26f52f041561ce7633998a1e083d6f09d9e2fb50a486bd2187027",
    "5eb9ab4b1263903ab5387c029e019e13842defbf73f60e8bf2945b5aebe03e04",
    "b6288fcaa97d3415c0c700701c9dddac791267f160a6e8044715e1b9c4d11f30",
    "92308968fcb7fe6e908d70e20b424e493cae0f59f6e7ea469405f3554e756726",
    "e779ac7a32c15f521b19f4f8912752908c22723beec2143ac90bf4ebcace1517",
    "cc8a2ebcccbd373bbd11b9017a2fb0555d61e7186ecdb92165ba9067d7fe4d2b",
    "4a5474ee27981a6c793b74d710510b46cb1854cccd34bd515236749f4b19fe11",
    "36493cc6be0b07c43b1b7373ac56c6a55b54d08ac6d93ec185e2f2fe44ac4e35",
    "249b451640c05d21c28745be3c4ccd9d769e229612a7ee061037989d0e214822",
    "83569af5a2edbb2a650fed2da9d22675c67c937e0bfca50ce4fe34e8b0732a3e",
    "88459f036f2ac98211288e29ad2e5be44b23a12aa68e591a3dd10bd96ca75b36",
    "fb8bdd5b25f68dde69bdc9574a8c4d350a6864c00128f5ea11215c449991d23a",
    "82d9bd2ef92600020ca94ebfaf1f8f4aa000b7601a971cd35431518306ab6625",
    "85e542474bb5cc3592b7e5225ef487c83cc95808cf39d0e911d0bad340742684",
    "5fe54dcf9718829ad6f7b56e156a621904ad7af557e2d3a73985558fef3c5da7",
    "5d0afcef9eb5756dbc7dbe711c960ff7e19555d0994e3e584b1795c348a2c439",
    "6612034a705515cbaedf00b7ad2331fa37e3665a233156a5af0ded33b46973b3",
    "8d65ef03f61ae61c438b9d9ab9402b2788cd6a9d3735d5d7880b6c4183aac5b2",
    "da5e0ce576ddbd9c7ed3a733f3210b96ed26e511a3242fa6e4ad0f4d7a8618a1",
    "2c6cb94ccf23b602d84482a58e4794e3d6e9f9ea9998eacac21f26ca9e6edc81",
    "f40f6746222689bc26f3f7b447408b0826b217c7316e201a5516b57bd6e51212",
    "d94b30ac62750e29b07e3d5c33bda27c93453162e1099dd4f2d3f8e239bea819",
    "b4f75205c6b122023384663cd9ab44ea0e989585ba621761e50d174a6a413eab",
    "3a9b2e9cb57bd41edb6ce7fcdc3db46dd565ce827ebb420270f6cd849fc9cf89",
    "0a039d44227c6cbf83092e4592cdb90bcabc7071a081bbe184e774018bc66630",
    "318d785565b78605ab17136aeb2ed595572e336abd5b20703982e5b50f95b23e",
    "bb6bceb1e2361ed8a9bb75992c4a83bffae605673692d53c81b3cc03c8865196",
    "1d596341fa0ec1510fa25fe4a2fc7057dd3adda311b6e53e82b8e38c2235d32c",
    "3fa669b1ee90359fc0a0132d412285e37562f1cba9b3f8201e7107b1f4769e3e"
);

fn frozen_proof() -> RangeProof {
    let bytes = from_hex(FROZEN_PROOF_HEX).expect("frozen hex");
    assert_eq!(bytes.len(), 1440);
    RangeProof::from_bytes(bytes)
}

#[test]
fn frozen_vector_still_verifies() {
    let proof = frozen_proof();
    assert_eq!(verify_range_proof(FROZEN_AMOUNT, &proof), Ok(()));
}

#[test]
fn prover_still_emits_the_frozen_bytes() {
    let proof = generate_range_proof(FROZEN_AMOUNT).expect("fits");
    assert_eq!(proof, frozen_proof());
}

#[test]
fn frozen_vector_rejects_a_different_amount() {
    let proof = frozen_proof();
    assert_eq!(
        verify_range_proof(FROZEN_AMOUNT + 1, &proof),
        Err(RangeProofError::Verify)
    );
}

#[test]
fn frozen_vector_rejects_a_flipped_byte() {
    let mut proof = frozen_proof();
    proof.bytes[0] ^= 0x01;
    assert_eq!(
        verify_range_proof(FROZEN_AMOUNT, &proof),
        Err(RangeProofError::Verify)
    );
}
