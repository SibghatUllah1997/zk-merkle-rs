//! Demo binary: build a SHA-256 Merkle tree, print the root, and verify proofs.

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match merkle_tree::cli::run_from_args(&args) {
        Ok(output) => match write_stdout(&output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("failed to write stdout: {err}");
                ExitCode::from(1)
            }
        },
        Err(err) => {
            if err.exit_code() == 0 {
                let _ = writeln!(io::stdout(), "{err}");
            } else {
                let _ = writeln!(io::stderr(), "{err}");
            }
            ExitCode::from(err.exit_code() as u8)
        }
    }
}

fn write_stdout(output: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    stdout.flush()
}
