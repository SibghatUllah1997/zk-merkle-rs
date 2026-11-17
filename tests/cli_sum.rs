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
