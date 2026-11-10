//! Grow an append-only log and print the Merkle root after each mutation.
//!
//! Historical checkpoints commit to prefixes. Inclusion proofs are always
//! checked against the latest root, so older entries remain auditable as the
//! log grows.
//!
//! ```text
//! cargo run --example append_only_log
//! ```

use std::io::{self, Write};
use std::process::ExitCode;

use merkle_tree::MerkleLog;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> io::Result<()> {
    let mut log = MerkleLog::new();
    let events = [
        "acct-1 credit 40",
        "acct-2 credit 15",
        "acct-1 debit 7",
        "acct-3 credit 100",
        "acct-2 debit 3",
    ];

    for event in events {
        let index = log.append(event);
        writeln!(
            io::stdout(),
            "append index={index} n={} root={}",
            log.len(),
            log.root_hex().expect("non-empty")
        )?;
    }

    log.extend(["acct-4 credit 8", "acct-1 credit 2"]);
    writeln!(
        io::stdout(),
        "batch n={} checkpoints={} root={}",
        log.len(),
        log.checkpoints().len(),
        log.root_hex().expect("non-empty")
    )?;

    assert!(
        log.history_matches(),
        "every checkpoint must match its prefix"
    );
    assert!(log.verify_entry(0), "first event must still prove");
    let first = log.prove_indexed(0).expect("first");
    writeln!(
        io::stdout(),
        "proved_index={} leaf={} steps={}",
        first.index,
        first.leaf_hex(),
        first.proof.steps_spec()
    )?;
    writeln!(io::stdout(), "{log}")?;
    Ok(())
}
