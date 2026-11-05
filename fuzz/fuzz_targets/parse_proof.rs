#![no_main]

use libfuzzer_sys::fuzz_target;
use merkle_tree::{from_hex, parse_proof_steps, InclusionProof, MerkleRoot};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = from_hex(text.as_ref());
    let _ = MerkleRoot::from_hex(text.as_ref());
    let _ = MerkleRoot::try_from(text.as_ref());

    if let Ok(steps) = parse_proof_steps(text.as_ref()) {
        let spec = InclusionProof {
            leaf_hash: [0u8; 32],
            steps: steps.clone(),
        }
        .steps_spec();
        let again = parse_proof_steps(&spec).expect("canonical spec parses");
        assert_eq!(again, steps);
    }
});
