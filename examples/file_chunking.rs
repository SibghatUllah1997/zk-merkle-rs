//! Chunk a file into Merkle leaves and prove one piece of it.
//!
//! With no arguments this uses a bundled sample buffer. Pass a path to hash a
//! real file in 256-byte leaves:
//!
//! ```text
//! cargo run --example file_chunking
//! cargo run --example file_chunking -- README.md
//! ```

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

use merkle_tree::{chunk_bytes_owned, chunk_reader, verify_inclusion, MerkleTree};

const SAMPLE: &[u8] = b"The quick brown fox jumps over the lazy dog. \
Merkle trees hash fixed-size chunks so a verifier can check one piece \
without downloading the rest of the file.";
const CHUNK_SIZE: usize = 256;

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
    let path = env::args().nth(1);
    let (source, chunks) = load_chunks(path.as_deref())?;
    if chunks.is_empty() {
        writeln!(io::stdout(), "source={source} chunks=0 (empty input)")?;
        return Ok(());
    }

    let tree = MerkleTree::from_leaves(chunks.iter());
    let root = tree.root().expect("non-empty");
    let last = chunks.len() - 1;
    let proof = tree.prove(last).expect("in range");
    assert!(
        verify_inclusion(&chunks[last], &proof.steps, root),
        "last-chunk proof must verify"
    );

    writeln!(io::stdout(), "source={source}")?;
    writeln!(io::stdout(), "chunk_size={CHUNK_SIZE}")?;
    writeln!(io::stdout(), "chunks={}", chunks.len())?;
    writeln!(io::stdout(), "root={}", tree.root_hex().expect("root"))?;
    writeln!(
        io::stdout(),
        "proved_index={last} steps={}",
        proof.steps_spec()
    )?;
    Ok(())
}

fn load_chunks(path: Option<&str>) -> io::Result<(String, Vec<Vec<u8>>)> {
    match path {
        Some(path) => {
            let chunks = chunk_reader(File::open(path)?, CHUNK_SIZE)?;
            Ok((path.to_string(), chunks))
        }
        None => {
            let chunks = chunk_bytes_owned(SAMPLE, CHUNK_SIZE)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            Ok((String::from("sample"), chunks))
        }
    }
}
