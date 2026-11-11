use merkle_tree::MerkleTree;
use std::time::{Duration, Instant};

fn generate_leaves(count: usize) -> Vec<Vec<u8>> {
    // Deterministic, non-random leaves with varying sizes to avoid easy constant folding.
    // Each leaf is "leaf-{i}" repeated (i % 4 + 1) times.
    (0..count)
        .map(|i| {
            let base = format!("leaf-{i}");
            let reps = (i % 4) + 1;
            base.repeat(reps).into_bytes()
        })
        .collect()
}

fn bench_once_build(n: usize) -> Duration {
    let leaves = generate_leaves(n);
    let start = Instant::now();
    let tree = MerkleTree::from_leaves(leaves.iter().map(|v| v.as_slice()));
    // Prevent potential optimization by using the root value.
    let _ = tree.root();
    start.elapsed()
}

fn bench_once_prove(n: usize) -> Duration {
    let leaves = generate_leaves(n);
    let tree = MerkleTree::from_leaves(leaves.iter().map(|v| v.as_slice()));
    let start = Instant::now();
    // Prove a few positions to exercise the path code.
    let _ = tree.prove(0);
    let _ = tree.prove(n / 2);
    let _ = tree.prove(n.saturating_sub(1));
    start.elapsed()
}

fn bench_prove_all(n: usize) -> (Duration, Duration) {
    let leaves = generate_leaves(n);
    let tree = MerkleTree::from_leaves(leaves.iter().map(|v| v.as_slice()));

    let start = Instant::now();
    let direct = tree.prove_all();
    let direct_time = start.elapsed();

    let start = Instant::now();
    let cache = tree.proof_index_cache();
    let cached = cache.prove_all();
    let cached_time = start.elapsed();

    assert_eq!(direct, cached);
    (direct_time, cached_time)
}

fn run_microbenches() {
    let sizes = [8usize, 64, 512, 4096];
    println!("Microbenchmarks (wall-clock, one-shot):");
    for &n in &sizes {
        let tb = bench_once_build(n);
        let tp = bench_once_prove(n);
        println!("  n={:<5} build={:?} prove(3 positions)={:?}", n, tb, tp);
    }
    println!("prove_all: direct vs cached (cache build included):");
    for &n in &sizes {
        let (direct, cached) = bench_prove_all(n);
        println!("  n={:<5} direct={:?} cached={:?}", n, direct, cached);
    }
}

fn main() {
    run_microbenches();
}
