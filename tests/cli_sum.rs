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
    let mut rows = String::new();
    for i in 1u8..=5 {
        rows.push_str(&format!("{},{}\n", to_hex32(&[i; 32]), u128::from(i) * 100));
    }
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
    assert!(text.contains("merkle sum-absent"));
    assert!(text.contains("merkle sum-verify-absent"));
}

#[test]
fn sum_absent_then_verify_absent_via_the_binary() {
    let csv = write_balances("zk-merkle-cli-sum-absent.csv");
    let proof_path = std::env::temp_dir().join("zk-merkle-cli-sum-absent.txt");
    let missing = to_hex32(&[9u8; 32]);

    let out = merkle()
        .args(["sum-absent", csv.to_str().unwrap(), "--account", &missing])
        .output()
        .expect("run merkle");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(&proof_path, &out.stdout).expect("write proof");

    let present = merkle()
        .args([
            "sum-absent",
            csv.to_str().unwrap(),
            "--account",
            &to_hex32(&[2u8; 32]),
        ])
        .output()
        .expect("run merkle");
    assert_eq!(present.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&present.stderr).contains("use sum-prove"));

    let root = balances_root();
    let ok = merkle()
        .args([
            "sum-verify-absent",
            proof_path.to_str().unwrap(),
            "--root",
            &root,
            "--sum",
            "1500",
        ])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&csv);
    let _ = std::fs::remove_file(&proof_path);
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let printed = String::from_utf8(ok.stdout).unwrap();
    assert!(printed.contains("absent"));
    assert!(printed.contains(&missing));
}

/// Root and total that `sum-build` prints for `write_balances` (sum 1500).
fn balances_root() -> String {
    let tree =
        MerkleSumTree::from_leaves((1u8..=5).map(|i| SumLeaf::new([i; 32], u128::from(i) * 100)))
            .unwrap();
    to_hex32(&tree.root().unwrap().0)
}

#[test]
fn solvency_matching_snapshot_with_reserves_exits_zero() {
    let csv = write_balances("zk-merkle-cli-solvency-ok.csv");
    let out = merkle()
        .args(["solvency", csv.to_str().unwrap()])
        .args([
            "--root",
            &balances_root(),
            "--sum",
            "1500",
            "--reserves",
            "2000",
        ])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&csv);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("status=ok\naccounts=5\npublished_sum=1500\ncomputed_sum=1500\n"));
    assert!(text.ends_with("duplicates=0\nsorted=yes\nreserves=2000\nreserve_shortfall=0\n"));
}

#[test]
fn solvency_understated_total_exits_one() {
    let csv = write_balances("zk-merkle-cli-solvency-under.csv");
    let out = merkle()
        .args(["solvency", csv.to_str().unwrap()])
        .args(["--root", &balances_root(), "--sum", "1400"])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&csv);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("status=mismatch"));
    assert!(err.contains("total=understated by 100"));
    assert!(err.contains("root=match"));
}

#[test]
fn solvency_flags_duplicate_accounts() {
    let path = std::env::temp_dir().join("zk-merkle-cli-solvency-dup.csv");
    let id = to_hex32(&[1u8; 32]);
    std::fs::write(&path, format!("{id},10\n{id},10\n")).unwrap();
    let tree =
        MerkleSumTree::from_leaves([SumLeaf::new([1; 32], 10), SumLeaf::new([1; 32], 10)]).unwrap();
    let out = merkle()
        .args(["solvency", path.to_str().unwrap()])
        .args(["--root", &to_hex32(&tree.root().unwrap().0), "--sum", "20"])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("root=match"));
    assert!(err.contains(&format!("duplicates=1\nduplicate={id}")));
    assert!(err.contains("sorted=no"));
}

#[test]
fn solvency_flags_unsorted_unique_accounts() {
    let path = std::env::temp_dir().join("zk-merkle-cli-solvency-unsorted.csv");
    let id_hi = to_hex32(&[3u8; 32]);
    let id_lo = to_hex32(&[1u8; 32]);
    std::fs::write(&path, format!("{id_hi},8\n{id_lo},40\n")).unwrap();
    let tree =
        MerkleSumTree::from_leaves([SumLeaf::new([3; 32], 8), SumLeaf::new([1; 32], 40)]).unwrap();
    let out = merkle()
        .args(["solvency", path.to_str().unwrap()])
        .args(["--root", &to_hex32(&tree.root().unwrap().0), "--sum", "48"])
        .output()
        .expect("run merkle");
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("status=mismatch"));
    assert!(err.contains("root=match"));
    assert!(err.contains("total=match"));
    assert!(err.contains("duplicates=0"));
    assert!(err.contains("sorted=no"));
}
