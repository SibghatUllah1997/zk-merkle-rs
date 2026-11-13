//! Show why a count-bound root is needed when odd layers duplicate the last hash.
//!
//! Three leaves and the same three plus a copied last leaf share a plain root.
//! `committed_root` binds the digest to the leaf count so a verifier can reject
//! the extra copy.
//!
//! ```text
//! cargo run --example committed_root
//! ```

use std::io::{self, Write};
use std::process::ExitCode;

use merkle_tree::{DomainKind, MerkleTree};

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
    let three = MerkleTree::from_leaves(["a", "b", "c"]);
    let four = MerkleTree::from_leaves(["a", "b", "c", "c"]);

    writeln!(
        io::stdout(),
        "plain_root_three={} plain_root_four={}",
        three.root_hex().expect("non-empty"),
        four.root_hex().expect("non-empty")
    )?;
    assert_eq!(
        three.root(),
        four.root(),
        "duplicate-last padding makes these plain roots equal"
    );

    let c3 = three.committed_root().expect("non-empty");
    let c4 = four.committed_root().expect("non-empty");
    writeln!(
        io::stdout(),
        "committed_three={} committed_four={}",
        merkle_tree::to_hex32(&c3),
        merkle_tree::to_hex32(&c4)
    )?;
    assert_ne!(c3, c4);
    writeln!(
        io::stdout(),
        "domain={} prefix={:#04x} widths_three={:?}",
        DomainKind::RootCommit,
        DomainKind::RootCommit.prefix(),
        MerkleTree::layer_widths(3)
    )?;

    let ghost = four.prove_indexed(3).expect("copied leaf");
    assert!(ghost.verify(three.root().expect("root")));
    assert!(
        !ghost.verify_committed(c3, 3),
        "ghost leaf must fail the three-leaf commitment"
    );
    assert!(ghost.verify_committed(c4, 4));
    writeln!(
        io::stdout(),
        "ghost_index=3 verifies_plain_three=true verifies_committed_three=false"
    )?;
    Ok(())
}
