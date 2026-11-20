//! Keep the demo page aligned with the public wasm export names.

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn demo_page_calls_the_wasm_export_names() {
    let html = read("demo/index.html");
    for name in ["verifyInclusionProof", "verifySumProof", "verifyRangeProof"] {
        assert!(html.contains(name), "demo page missing {name}");
    }
    assert!(html.contains("./pkg/merkle_tree.js"));
}

#[test]
fn demo_readme_uses_the_cdylib_build() {
    let readme = read("demo/README.md");
    assert!(readme.contains("--crate-type cdylib"));
    assert!(readme.contains("wasm-bindgen"));
}
