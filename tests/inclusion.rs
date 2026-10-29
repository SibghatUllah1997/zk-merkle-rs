use merkle_tree::{verify_inclusion, MerkleTree};

#[test]
fn inclusion_proofs_roundtrip_various_sizes() {
    for n in 1..=7 {
        let leaves = (0..n).map(|i| format!("leaf-{i}")).collect::<Vec<_>>();
        let tree = MerkleTree::from_leaves(leaves.iter().map(|s| s.as_bytes()));
        let root = tree.root().expect("root");
        for (i, leaf) in leaves.iter().enumerate().take(n) {
            let proof = tree.prove(i).expect("proof");
            assert!(proof.verify(root), "method verify failed for n={n}, i={i}");
            assert!(
                verify_inclusion(leaf.as_bytes(), &proof.steps, root),
                "free verify_inclusion failed for n={n}, i={i}"
            );
        }
    }
}
