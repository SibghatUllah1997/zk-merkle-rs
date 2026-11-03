//! End-to-end checks of the `merkle` demo binary.

use merkle_tree::MerkleTree;
use std::process::Command;

fn merkle() -> Command {
    Command::new(env!("CARGO_BIN_EXE_merkle"))
}

fn stdout(cmd: &mut Command) -> String {
    let out = cmd.output().expect("run merkle");
    assert!(
        out.status.success(),
        "merkle failed: status={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout utf-8")
}

#[test]
fn build_prints_library_root() {
    let tree = MerkleTree::from_leaves(["a", "b", "c", "d"].map(|s| s.as_bytes()));
    let printed = stdout(merkle().args(["build", "a", "b", "c", "d"]));
    assert_eq!(printed, format!("{}\n", tree.root_hex().unwrap()));
}

#[test]
fn prove_then_verify_via_the_binary() {
    let prove = stdout(merkle().args(["prove", "--index", "1", "w", "x", "y"]));
    let root = prove
        .lines()
        .find_map(|line| line.strip_prefix("root="))
        .expect("root");
    let steps = prove
        .lines()
        .find_map(|line| line.strip_prefix("steps="))
        .expect("steps");

    let verified =
        stdout(merkle().args(["verify", "--leaf", "x", "--root", root, "--steps", steps]));
    assert_eq!(verified, "ok\n");
}

#[test]
fn verify_mismatch_exits_nonzero() {
    let root = stdout(merkle().args(["build", "a", "b"]));
    let out = merkle()
        .args(["verify", "--leaf", "zzz", "--root", root.trim()])
        .output()
        .expect("run merkle");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "verification failed"
    );
}

#[test]
fn help_exits_zero_and_names_commands() {
    let out = merkle().arg("help").output().expect("run merkle");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("merkle build"));
    assert!(text.contains("merkle prove"));
    assert!(text.contains("merkle verify"));
}

#[test]
fn usage_error_exits_two() {
    let out = merkle().arg("build").output().expect("run merkle");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("expected at least one leaf"));
}
