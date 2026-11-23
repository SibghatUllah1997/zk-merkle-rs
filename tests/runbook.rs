//! Keep the CLI runbook aligned with the public `merkle` commands.

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn runbook_names_the_cli_commands() {
    let book = read("book/runbook.md");
    for needle in [
        "merkle build",
        "merkle prove",
        "merkle verify",
        "sum-build",
        "sum-prove",
        "sum-verify",
        "sum-absent",
        "sum-verify-absent",
        "solvency",
        "verifyInclusionProof",
        "verifySumProof",
        "verifySumAbsent",
    ] {
        assert!(book.contains(needle), "runbook missing {needle:?}");
    }
}
