//! Attacks the hashing and proof rules are meant to stop, written as tests.

use merkle_tree::{
    commit_root, hash_leaf, hash_nodes, proof_depth, verify_inclusion, IndexedInclusionProof,
    MerkleTree, ProofStep, SiblingSide,
};
use sha2::{Digest, Sha256};

fn leaves(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("leaf-{i}")).collect()
}

fn tree_of(items: &[String]) -> MerkleTree {
    MerkleTree::from_leaves(items.iter().map(|s| s.as_bytes()))
}

/// Plain SHA-256 with no domain prefix, used only to show the attack the
/// prefixes block.
fn raw(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[test]
fn unprefixed_tree_admits_a_second_preimage_that_ours_rejects() {
    // Unprefixed tree over four leaves: root = H(H(H0 || H1) || H(H2 || H3)).
    let items = leaves(4);
    let h: Vec<[u8; 32]> = items.iter().map(|s| raw(s.as_bytes())).collect();
    let pair = |l: &[u8; 32], r: &[u8; 32]| {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(l);
        buf[32..].copy_from_slice(r);
        buf
    };
    let n01 = raw(&pair(&h[0], &h[1]));
    let n23 = raw(&pair(&h[2], &h[3]));
    let raw_root = raw(&pair(&n01, &n23));
    // Forgery: claim the 64 bytes H0 || H1 are a leaf one level up.
    let forged_leaf = pair(&h[0], &h[1]);
    assert_eq!(raw(&pair(&raw(&forged_leaf), &n23)), raw_root);

    // The same trick against this crate: hash the two real leaf hashes as
    // leaf data and use the real sibling from level 1.
    let tree = tree_of(&items);
    let root = tree.root().expect("root");
    let level0 = tree.layer_hashes(0).expect("leaves");
    let level1 = tree.layer_hashes(1).expect("level 1");
    let forged = pair(&level0[0], &level0[1]);
    let steps = [ProofStep {
        sibling: level1[1],
        side: SiblingSide::Right,
    }];
    assert!(!verify_inclusion(&forged, &steps, root));
    // Only the honest parent hash rebuilds the root.
    assert_eq!(hash_nodes(&level1[0], &level1[1]), root);
    assert_ne!(hash_leaf(&forged), level1[0]);
}

#[test]
fn duplicate_last_padding_is_ambiguous_until_the_count_is_committed() {
    let three = leaves(3);
    let mut four = three.clone();
    four.push(three[2].clone());
    let t3 = tree_of(&three);
    let t4 = tree_of(&four);
    assert_eq!(t3.root(), t4.root(), "padding makes these roots equal");
    assert_ne!(t3.committed_root(), t4.committed_root());

    // The padded copy proves at index 3 against the plain root...
    let ghost = t4.prove_indexed(3).expect("proof");
    assert!(ghost.verify(t3.root().expect("root")));
    // ...but not against the 3-leaf commitment.
    let c3 = t3.committed_root().expect("root");
    assert!(!ghost.verify_committed(c3, 3));
    assert!(ghost.verify_committed(t4.committed_root().expect("root"), 4));
}

#[test]
fn committed_verification_accepts_every_honest_proof() {
    for n in 1..=33 {
        let items = leaves(n);
        let tree = tree_of(&items);
        let commitment = tree.committed_root().expect("root");
        assert_eq!(
            commitment,
            commit_root(&tree.root().expect("root"), n as u64)
        );
        for i in 0..n {
            let proof = tree.prove_indexed(i).expect("proof");
            assert_eq!(proof.steps().len(), proof_depth(n), "n={n} i={i}");
            assert!(proof.verify_committed(commitment, n), "n={n} i={i}");
            assert!(!proof.verify_committed(commitment, n + 1), "n={n} i={i}");
        }
    }
}

#[test]
fn committed_verification_binds_the_claimed_index() {
    let tree = tree_of(&leaves(8));
    let commitment = tree.committed_root().expect("root");
    let honest = tree.prove_indexed(5).expect("proof");

    let mut moved = honest.clone();
    moved.index = 4;
    assert!(!moved.verify_committed(commitment, 8));

    let out_of_range = IndexedInclusionProof {
        index: 8,
        proof: honest.proof.clone(),
    };
    assert!(!out_of_range.verify_committed(commitment, 8));

    let mut flipped = honest.clone();
    flipped.proof.steps[0].side = SiblingSide::Right;
    assert!(!flipped.verify_committed(commitment, 8));
}

#[test]
fn committed_verification_rejects_wrong_length_paths() {
    let tree = tree_of(&leaves(4));
    let commitment = tree.committed_root().expect("root");
    let honest = tree.prove_indexed(0).expect("proof");

    let mut short = honest.clone();
    short.proof.steps.pop();
    assert!(!short.verify_committed(commitment, 4));

    let mut long = honest.clone();
    long.proof.steps.push(ProofStep {
        sibling: [0u8; 32],
        side: SiblingSide::Right,
    });
    assert!(!long.verify_committed(commitment, 4));

    // A single-leaf tree takes zero steps, and its root is the leaf hash.
    let one = tree_of(&leaves(1));
    let p = one.prove_indexed(0).expect("proof");
    assert!(p.steps().is_empty());
    assert!(p.verify_committed(one.committed_root().expect("root"), 1));
}

#[test]
fn proof_depth_edges() {
    assert_eq!(proof_depth(0), 0);
    assert_eq!(proof_depth(1), 0);
    assert_eq!(proof_depth(2), 1);
    assert_eq!(proof_depth(3), 2);
    assert_eq!(proof_depth(1024), 10);
    assert_eq!(proof_depth(1025), 11);
    assert_eq!(proof_depth(usize::MAX), usize::BITS as usize);
}

#[cfg(feature = "blake3")]
#[test]
fn committed_verification_with_blake3() {
    use merkle_tree::HashAlgorithm;
    let tree =
        MerkleTree::try_from_leaves_with(HashAlgorithm::Blake3, leaves(5).iter()).expect("blake3");
    let commitment = tree.committed_root().expect("root");
    let proof = tree.prove_indexed(4).expect("proof");
    assert!(proof
        .verify_committed_with(HashAlgorithm::Blake3, commitment, 5)
        .expect("blake3"));
    assert!(!proof.verify_committed(commitment, 5));
}

#[cfg(feature = "poseidon")]
#[test]
fn committed_verification_with_poseidon() {
    use merkle_tree::HashAlgorithm;
    let tree = MerkleTree::try_from_leaves_with(HashAlgorithm::Poseidon, leaves(3).iter())
        .expect("poseidon");
    let commitment = tree.committed_root().expect("root");
    let proof = tree.prove_indexed(1).expect("proof");
    assert!(proof
        .verify_committed_with(HashAlgorithm::Poseidon, commitment, 3)
        .expect("poseidon"));
    assert!(!proof.verify_committed(commitment, 3));
}

#[cfg(feature = "rescue")]
#[test]
fn committed_verification_with_rescue_is_not_implemented() {
    use merkle_tree::HashAlgorithm;
    let tree = tree_of(&leaves(2));
    let proof = tree.prove_indexed(0).expect("proof");
    assert!(proof
        .verify_committed_with(HashAlgorithm::Rescue, [0u8; 32], 2)
        .is_err());
}
