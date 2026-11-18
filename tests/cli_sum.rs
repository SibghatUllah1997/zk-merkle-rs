//! End-to-end check of `merkle sum-build` (needs `std` and `merkle_sum`).

use merkle_tree::hashing::to_hex32;
use merkle_tree::sum::{MerkleSumTree, SumLeaf};
use std::process::Command;

fn merkle() -> Command {
    Command::new(env!("CARGO_BIN_EXE_merkle"))
}

#[test]
fn sum_build_prints_root_hash_and_total() {
    let dir = std::env::temp_dir();
    let path = dir.join("zk-merkle-cli-sum-build.csv");
    let id_a = to_hex32(&[1u8; 32]);
    let id_b = to_hex32(&[2u8; 32]);
    let id_c = to_hex32(&[3u8; 32]);
    std::fs::write(
        &path,
        format!("account_id,amount\n{id_a},40\n{id_b},2\n{id_c},8\n"),
    )
    .expect("write csv");

    let out = merkle()
        .args(["sum-build", path.to_str().unwrap()])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8(out.stdout).expect("utf-8");

    let tree = MerkleSumTree::from_leaves([
        SumLeaf::new([1u8; 32], 40),
        SumLeaf::new([2u8; 32], 2),
        SumLeaf::new([3u8; 32], 8),
    ])
    .unwrap();
    let (hash, total) = tree.root().unwrap();
    assert_eq!(printed, format!("root={}\nsum={total}\n", to_hex32(&hash)));
    assert_eq!(total, 50);
}

#[test]
fn sum_build_missing_file_exits_nonzero() {
    let out = merkle()
        .args(["sum-build", "/no/such/sum-tree.csv"])
        .output()
        .expect("run merkle");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed to read"));
}

#[test]
fn help_mentions_sum_build() {
    let out = merkle().arg("help").output().expect("run merkle");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("merkle sum-build"));
}

fn write_balances(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(name);
    let rows: String = (1u8..=5)
        .map(|i| format!("{},{}\n", to_hex32(&[i; 32]), u128::from(i) * 100))
        .collect();
    std::fs::write(&path, format!("account_id,amount\n{rows}")).expect("write csv");
    path
}

#[test]
fn sum_prove_exports_a_proof_that_sum_verify_accepts() {
    let csv = write_balances("zk-merkle-cli-sum-prove.csv");
    let proof_path = std::env::temp_dir().join("zk-merkle-cli-sum-prove.txt");
    let account = to_hex32(&[4u8; 32]);

    let out = merkle()
        .args(["sum-prove", csv.to_str().unwrap(), "--account", &account])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&csv);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(&proof_path, &out.stdout).expect("write proof");

    let leaves: Vec<SumLeaf> = (1u8..=5)
        .map(|i| SumLeaf::new([i; 32], u128::from(i) * 100))
        .collect();
    let tree = MerkleSumTree::from_leaves(leaves).unwrap();
    let (hash, total) = tree.root().unwrap();
    let root = to_hex32(&hash);

    let ok = merkle()
        .args(["sum-verify", proof_path.to_str().unwrap(), "--root", &root])
        .args(["--sum", &total.to_string()])
        .output()
        .expect("run merkle");
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(
        String::from_utf8(ok.stdout).unwrap(),
        format!("ok\naccount={account}\namount=400\n")
    );

    let wrong_root = to_hex32(&[0u8; 32]);
    let bad = merkle()
        .args(["sum-verify", proof_path.to_str().unwrap()])
        .args(["--root", &wrong_root, "--sum", &total.to_string()])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&proof_path);
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("verification failed"));
}

#[test]
fn sum_verify_rejects_a_proof_with_an_edited_amount() {
    let csv = write_balances("zk-merkle-cli-sum-edit.csv");
    let proof_path = std::env::temp_dir().join("zk-merkle-cli-sum-edit.txt");
    let out = merkle()
        .args(["sum-prove", csv.to_str().unwrap()])
        .args(["--account", &to_hex32(&[2u8; 32])])
        .output()
        .expect("run merkle");
    let build = merkle()
        .args(["sum-build", csv.to_str().unwrap()])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&csv);
    let text = String::from_utf8(out.stdout).unwrap();
    std::fs::write(&proof_path, text.replace("amount=200\n", "amount=900\n")).unwrap();

    let built = String::from_utf8(build.stdout).unwrap();
    let mut lines = built.lines();
    let root = lines.next().unwrap().trim_start_matches("root=");
    let sum = lines.next().unwrap().trim_start_matches("sum=");

    let bad = merkle()
        .args(["sum-verify", proof_path.to_str().unwrap()])
        .args(["--root", root, "--sum", sum])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&proof_path);
    assert_eq!(bad.status.code(), Some(1));
}

#[test]
fn sum_prove_unknown_account_exits_nonzero() {
    let csv = write_balances("zk-merkle-cli-sum-unknown.csv");
    let out = merkle()
        .args(["sum-prove", csv.to_str().unwrap()])
        .args(["--account", &to_hex32(&[42u8; 32])])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&csv);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not in the CSV"));
}

#[test]
fn help_mentions_sum_prove_and_verify() {
    let out = merkle().arg("help").output().expect("run merkle");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("merkle sum-prove"));
    assert!(text.contains("merkle sum-verify"));
}
