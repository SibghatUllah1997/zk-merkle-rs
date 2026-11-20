//! Keep the threat-model chapter covering the three named PoR gaps.

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn threat_model_covers_valuation_exclusion_and_timing() {
    let book = read("book/threat-model.md");
    for heading in ["## Valuation", "## Excluded accounts", "## Timing"] {
        assert!(book.contains(heading), "threat model missing {heading}");
    }
    assert!(book.contains("published unit"));
    assert!(book.contains("not in the tree"));
    assert!(book.contains("snapshot"));
}

#[test]
fn changelog_records_the_demo_and_threat_model() {
    let log = read("CHANGELOG.md");
    assert!(log.contains("## 2026-11-20 (demo and threat model)"));
    assert!(log.contains("verifyRangeProof"));
    assert!(log.contains("Threat-model"));
}

#[test]
fn roadmap_ticks_the_demo_runbook_and_threat_model() {
    let roadmap = read("ROADMAP.md");
    assert!(roadmap.contains("42. [x] Add a small demo page, CLI runbook, and threat-model notes"));
}
