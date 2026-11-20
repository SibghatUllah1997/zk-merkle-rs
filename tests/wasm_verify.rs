//! The browser verifier must accept exactly what the CLI accepts.

use merkle_tree::hashing::to_hex32;
use merkle_tree::sum::{sum_proof_to_text, MerkleSumTree, SumLeaf};
use merkle_tree::wasm::{verify_inclusion_proof, verify_sum_proof};
use merkle_tree::MerkleTree;
use std::process::Command;

fn leaves(n: u8) -> Vec<SumLeaf> {
    (1..=n)
        .map(|i| SumLeaf::new([i; 32], u128::from(i) * 1_000))
        .collect()
}

#[test]
fn every_sum_leaf_verifies_for_odd_and_even_trees() {
    for n in [1u8, 2, 5, 8, 13] {
        let leaves = leaves(n);
        let tree = MerkleSumTree::from_leaves(leaves.clone()).expect("no overflow");
        let root = tree.root_node().expect("non-empty");
        let root_hex = to_hex32(&root.hash);
        let total = root.sum.to_string();
        for (i, leaf) in leaves.iter().enumerate() {
            let text = sum_proof_to_text(leaf, &tree.prove(i).expect("in range"));
            let verdict = verify_sum_proof(&text, &root_hex, &total);
            assert!(verdict.ok(), "n={n} i={i}: {}", verdict.reason());
            assert_eq!(verdict.amount(), leaf.amount.to_string());
        }
    }
}

#[test]
fn tampered_amount_or_foreign_root_is_rejected() {
    let leaves = leaves(5);
    let tree = MerkleSumTree::from_leaves(leaves.clone()).expect("no overflow");
    let root = tree.root_node().expect("non-empty");
    let text = sum_proof_to_text(&leaves[3], &tree.prove(3).expect("in range"));
    let root_hex = to_hex32(&root.hash);
    let total = root.sum.to_string();

    let bumped = text.replace("amount=4000", "amount=4001");
    assert_ne!(bumped, text);
    assert!(!verify_sum_proof(&bumped, &root_hex, &total).ok());

    let other = MerkleSumTree::from_leaves(leaves[..4].to_vec()).expect("no overflow");
    let other_hex = to_hex32(&other.root_node().expect("non-empty").hash);
    assert!(!verify_sum_proof(&text, &other_hex, &total).ok());
}

#[test]
fn cli_sum_prove_output_verifies_in_the_browser_verifier() {
    let path = std::env::temp_dir().join("zk-merkle-wasm-verify.csv");
    let mut csv = String::from("account_id,amount\n");
    for leaf in leaves(3) {
        csv.push_str(&format!("{},{}\n", to_hex32(&leaf.account_id), leaf.amount));
    }
    std::fs::write(&path, csv).expect("write csv");

    let out = Command::new(env!("CARGO_BIN_EXE_merkle"))
        .args([
            "sum-prove",
            path.to_str().unwrap(),
            "--account",
            &to_hex32(&[2u8; 32]),
        ])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("utf-8");

    let tree = MerkleSumTree::from_leaves(leaves(3)).expect("no overflow");
    let root = tree.root_node().expect("non-empty");
    let verdict = verify_sum_proof(&text, &to_hex32(&root.hash), &root.sum.to_string());
    assert!(verdict.ok(), "{}", verdict.reason());
    assert_eq!(verdict.account(), to_hex32(&[2u8; 32]));
}

#[test]
fn every_plain_leaf_verifies() {
    let data = ["a", "b", "c", "d", "e"];
    let tree = MerkleTree::from_leaves(data);
    let root = to_hex32(&tree.root().expect("root"));
    for (i, leaf) in data.iter().enumerate() {
        let proof = tree.prove(i).expect("proof");
        let steps: Vec<String> = proof.steps.iter().map(ToString::to_string).collect();
        let verdict = verify_inclusion_proof(leaf, &steps.join(","), &root);
        assert!(verdict.ok(), "i={i}: {}", verdict.reason());
    }
}
