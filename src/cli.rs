//! Small SHA-256 Merkle tree demo used by the `merkle` binary.
//!
//! Leaves are UTF-8 strings hashed as `H(0x00 || bytes)`. Proof steps use the
//! crate's compact `L:<hex>,R:<hex>` form (see [`crate::parse_proof_steps`]).

use crate::{
    parse_proof_steps, verify_inclusion, HexError, MerkleTree, ParseStepsError, ProofStep,
};

/// Parsed invocation of the demo CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Build {
        leaves: Vec<Vec<u8>>,
    },
    Prove {
        index: usize,
        leaves: Vec<Vec<u8>>,
    },
    Verify {
        leaf: Vec<u8>,
        root: [u8; 32],
        steps: Vec<ProofStep>,
    },
}

/// Recoverable CLI failure, including usage requests that should print help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    Help,
    Usage(String),
    UnknownCommand(String),
    UnknownFlag(String),
    MissingValue(&'static str),
    InvalidIndex(String),
    EmptyLeaves,
    IndexOutOfRange { index: usize, leaf_count: usize },
    Hex(HexError),
    Steps(ParseStepsError),
    VerificationFailed,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Help => write!(f, "{}", usage()),
            CliError::Usage(msg) => write!(f, "{msg}\n\n{}", usage()),
            CliError::UnknownCommand(cmd) => {
                write!(f, "unknown command {cmd:?}\n\n{}", usage())
            }
            CliError::UnknownFlag(flag) => write!(f, "unknown flag {flag:?}\n\n{}", usage()),
            CliError::MissingValue(name) => write!(f, "missing value for {name}"),
            CliError::InvalidIndex(raw) => write!(f, "invalid leaf index {raw:?}"),
            CliError::EmptyLeaves => write!(f, "expected at least one leaf"),
            CliError::IndexOutOfRange { index, leaf_count } => {
                write!(f, "index {index} is out of range for {leaf_count} leaves")
            }
            CliError::Hex(err) => write!(f, "{err}"),
            CliError::Steps(err) => write!(f, "{err}"),
            CliError::VerificationFailed => write!(f, "verification failed"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Hex(err) => Some(err),
            CliError::Steps(err) => Some(err),
            _ => None,
        }
    }
}

impl CliError {
    /// Process exit code: 0 for help, 2 for usage problems, 1 otherwise.
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Help => 0,
            CliError::Usage(_)
            | CliError::UnknownCommand(_)
            | CliError::UnknownFlag(_)
            | CliError::MissingValue(_)
            | CliError::InvalidIndex(_)
            | CliError::EmptyLeaves => 2,
            _ => 1,
        }
    }
}

/// User-facing help text for the `merkle` binary.
pub fn usage() -> &'static str {
    concat!(
        "merkle - SHA-256 Merkle tree demo\n\n",
        "USAGE:\n",
        "    merkle build <leaf>...\n",
        "    merkle prove [--index] <index> <leaf>...\n",
        "    merkle verify --leaf <data> --root <hex> [--steps <L|R:hex,...>]\n",
        "    merkle help\n\n",
        "Leaves are UTF-8 strings. Proof steps are comma-separated L:/R: hex tokens."
    )
}

/// Parse argv *without* `argv[0]` into a [`Command`].
pub fn parse_args<I, S>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    let command = match args.next() {
        None => return Err(CliError::Help),
        Some(cmd) => cmd,
    };
    match command.as_ref() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "build" => parse_build(args),
        "prove" => parse_prove(args),
        "verify" => parse_verify(args),
        other => Err(CliError::UnknownCommand(String::from(other))),
    }
}

fn parse_build<I, S>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut leaves = Vec::new();
    for arg in args {
        let arg = arg.as_ref();
        if arg == "-h" || arg == "--help" {
            return Ok(Command::Help);
        }
        if arg.starts_with('-') {
            return Err(CliError::UnknownFlag(String::from(arg)));
        }
        leaves.push(arg.as_bytes().to_vec());
    }
    if leaves.is_empty() {
        return Err(CliError::EmptyLeaves);
    }
    Ok(Command::Build { leaves })
}

fn parse_index(raw: &str) -> Result<usize, CliError> {
    raw.parse::<usize>()
        .map_err(|_| CliError::InvalidIndex(String::from(raw)))
}

fn parse_prove<I, S>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut index = None;
    let mut leaves = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref();
        if arg == "-h" || arg == "--help" {
            return Ok(Command::Help);
        }
        if arg == "--index" {
            let value = args.next().ok_or(CliError::MissingValue("--index"))?;
            index = Some(parse_index(value.as_ref())?);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--index=") {
            index = Some(parse_index(value)?);
            continue;
        }
        if arg.starts_with('-') {
            return Err(CliError::UnknownFlag(String::from(arg)));
        }
        if index.is_none() && leaves.is_empty() && arg.bytes().all(|b| b.is_ascii_digit()) {
            index = Some(parse_index(arg)?);
            continue;
        }
        leaves.push(arg.as_bytes().to_vec());
    }
    let index = index.ok_or(CliError::MissingValue("--index"))?;
    if leaves.is_empty() {
        return Err(CliError::EmptyLeaves);
    }
    Ok(Command::Prove { index, leaves })
}

fn parse_verify<I, S>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut leaf = None;
    let mut root = None;
    let mut steps = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref();
        if arg == "-h" || arg == "--help" {
            return Ok(Command::Help);
        }
        if arg == "--leaf" || arg == "--leaf-data" {
            let value = args.next().ok_or(CliError::MissingValue("--leaf"))?;
            leaf = Some(value.as_ref().as_bytes().to_vec());
            continue;
        }
        if let Some(value) = arg.strip_prefix("--leaf=") {
            leaf = Some(value.as_bytes().to_vec());
            continue;
        }
        if arg == "--root" {
            let value = args.next().ok_or(CliError::MissingValue("--root"))?;
            root = Some(parse_root(value.as_ref())?);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--root=") {
            root = Some(parse_root(value)?);
            continue;
        }
        if arg == "--steps" {
            let value = args.next().ok_or(CliError::MissingValue("--steps"))?;
            steps = Some(parse_steps(value.as_ref())?);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--steps=") {
            steps = Some(parse_steps(value)?);
            continue;
        }
        if arg.starts_with('-') {
            return Err(CliError::UnknownFlag(String::from(arg)));
        }
        return Err(CliError::Usage(format!(
            "unexpected argument {arg:?}; verify takes --leaf, --root, and optional --steps"
        )));
    }
    let leaf = leaf.ok_or(CliError::MissingValue("--leaf"))?;
    let root = root.ok_or(CliError::MissingValue("--root"))?;
    Ok(Command::Verify {
        leaf,
        root,
        steps: steps.unwrap_or_default(),
    })
}

fn parse_root(raw: &str) -> Result<[u8; 32], CliError> {
    crate::try_from_hex32(raw).map_err(CliError::Hex)
}

fn parse_steps(raw: &str) -> Result<Vec<ProofStep>, CliError> {
    parse_proof_steps(raw).map_err(CliError::Steps)
}

/// Execute a parsed command and return stdout text (always newline-terminated,
/// except the empty string is never returned).
pub fn run(command: Command) -> Result<String, CliError> {
    match command {
        Command::Help => Ok(format!("{}\n", usage())),
        Command::Build { leaves } => run_build(&leaves),
        Command::Prove { index, leaves } => run_prove(index, &leaves),
        Command::Verify { leaf, root, steps } => run_verify(&leaf, root, &steps),
    }
}

/// Parse argv *without* `argv[0]` and execute it.
pub fn run_from_args<I, S>(args: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    run(parse_args(args)?)
}

fn run_build(leaves: &[Vec<u8>]) -> Result<String, CliError> {
    if leaves.is_empty() {
        return Err(CliError::EmptyLeaves);
    }
    let tree = MerkleTree::from_leaves(leaves);
    let hex = tree.root_hex().expect("non-empty tree has a root");
    Ok(format!("{hex}\n"))
}

fn run_prove(index: usize, leaves: &[Vec<u8>]) -> Result<String, CliError> {
    if leaves.is_empty() {
        return Err(CliError::EmptyLeaves);
    }
    let tree = MerkleTree::from_leaves(leaves);
    let proof = tree.prove(index).ok_or(CliError::IndexOutOfRange {
        index,
        leaf_count: tree.leaf_count(),
    })?;
    let root = tree.root_hex().expect("non-empty tree has a root");
    Ok(format!(
        "root={root}\nindex={index}\nleaf_hash={}\nsteps={}\n",
        proof.leaf_hex(),
        proof.steps_spec()
    ))
}

fn run_verify(leaf: &[u8], root: [u8; 32], steps: &[ProofStep]) -> Result<String, CliError> {
    if verify_inclusion(leaf, steps, root) {
        Ok(String::from("ok\n"))
    } else {
        Err(CliError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_leaf, to_hex32};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| String::from(*s)).collect()
    }

    #[test]
    fn parse_build_and_help() {
        assert_eq!(parse_args(args(&[])).unwrap_err(), CliError::Help);
        assert_eq!(parse_args(args(&["help"])).unwrap(), Command::Help);
        assert_eq!(parse_args(args(&["--help"])).unwrap(), Command::Help);
        assert_eq!(
            parse_args(args(&["build", "a", "b"])).unwrap(),
            Command::Build {
                leaves: vec![b"a".to_vec(), b"b".to_vec()],
            }
        );
        assert!(matches!(
            parse_args(args(&["build"])).unwrap_err(),
            CliError::EmptyLeaves
        ));
        assert!(matches!(
            parse_args(args(&["wat"])).unwrap_err(),
            CliError::UnknownCommand(_)
        ));
        assert!(matches!(
            parse_args(args(&["build", "--oops"])).unwrap_err(),
            CliError::UnknownFlag(_)
        ));
    }

    #[test]
    fn parse_prove_index_forms() {
        let expected = Command::Prove {
            index: 2,
            leaves: vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()],
        };
        assert_eq!(
            parse_args(args(&["prove", "2", "a", "b", "c", "d"])).unwrap(),
            expected
        );
        assert_eq!(
            parse_args(args(&["prove", "--index", "2", "a", "b", "c", "d"])).unwrap(),
            expected
        );
        assert_eq!(
            parse_args(args(&["prove", "--index=2", "a", "b", "c", "d"])).unwrap(),
            expected
        );
        assert!(matches!(
            parse_args(args(&["prove", "a", "b"])).unwrap_err(),
            CliError::MissingValue("--index")
        ));
        assert!(matches!(
            parse_args(args(&["prove", "--index", "nope", "a"])).unwrap_err(),
            CliError::InvalidIndex(_)
        ));
        assert!(matches!(
            parse_args(args(&["prove", "0"])).unwrap_err(),
            CliError::EmptyLeaves
        ));
    }

    #[test]
    fn parse_verify_flags() {
        let root = [0xab; 32];
        let root_hex = to_hex32(&root);
        let cmd = parse_args(args(&["verify", "--leaf", "c", "--root", &root_hex])).unwrap();
        match cmd {
            Command::Verify {
                leaf,
                root: parsed_root,
                steps,
            } => {
                assert_eq!(leaf, b"c");
                assert_eq!(parsed_root, root);
                assert!(steps.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }

        let err = parse_args(args(&["verify", "--leaf", "c"])).unwrap_err();
        assert!(matches!(err, CliError::MissingValue("--root")));

        let err = parse_args(args(&["verify", "--leaf", "c", "--root", "zz"])).unwrap_err();
        assert!(matches!(err, CliError::Hex(_)));
    }

    #[test]
    fn run_build_matches_library_root() {
        let leaves = ["a", "b", "c", "d"];
        let tree = MerkleTree::from_leaves(leaves.map(|s| s.as_bytes()));
        let expected = format!("{}\n", tree.root_hex().unwrap());
        let out = run_from_args(args(&["build", "a", "b", "c", "d"])).unwrap();
        assert_eq!(out, expected);
        assert_eq!(out.trim().len(), 64);
    }

    #[test]
    fn run_prove_then_verify_roundtrip() {
        let prove = run_from_args(args(&["prove", "2", "a", "b", "c", "d"])).unwrap();
        let mut root = None;
        let mut steps = None;
        for line in prove.lines() {
            if let Some(value) = line.strip_prefix("root=") {
                root = Some(value.to_string());
            }
            if let Some(value) = line.strip_prefix("steps=") {
                steps = Some(value.to_string());
            }
            if let Some(value) = line.strip_prefix("leaf_hash=") {
                assert_eq!(value, to_hex32(&hash_leaf(b"c")));
            }
            if let Some(value) = line.strip_prefix("index=") {
                assert_eq!(value, "2");
            }
        }
        let root = root.expect("root line");
        let steps = steps.expect("steps line");
        let out = run_from_args(args(&[
            "verify", "--leaf", "c", "--root", &root, "--steps", &steps,
        ]))
        .unwrap();
        assert_eq!(out, "ok\n");

        let bad = run_from_args(args(&[
            "verify", "--leaf", "nope", "--root", &root, "--steps", &steps,
        ]))
        .unwrap_err();
        assert_eq!(bad, CliError::VerificationFailed);
        assert_eq!(bad.exit_code(), 1);
        assert_eq!(bad.to_string(), "verification failed");
    }

    #[test]
    fn run_prove_rejects_out_of_range_index() {
        let err = run_from_args(args(&["prove", "9", "a", "b"])).unwrap_err();
        assert_eq!(
            err,
            CliError::IndexOutOfRange {
                index: 9,
                leaf_count: 2
            }
        );
    }

    #[test]
    fn single_leaf_verify_with_empty_steps() {
        let root = run_from_args(args(&["build", "solo"])).unwrap();
        let out = run_from_args(args(&[
            "verify",
            "--leaf=solo",
            &format!("--root={}", root.trim()),
        ]))
        .unwrap();
        assert_eq!(out, "ok\n");
    }
}
