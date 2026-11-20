//! Browser-facing verifiers built with `wasm-bindgen`.
//!
//! A user who downloads their proof of reserves should not have to install a
//! CLI to check it. These functions take the same text the `merkle` CLI
//! prints and answer with a [`Verdict`](crate::wasm::Verdict), so a static page can verify a proof
//! entirely client side.
//!
//! Every input is a string on purpose: hex roots and decimal totals survive a
//! copy and paste, and `u128` balances do not fit in a JavaScript number.
//!
//! Nothing here throws. A bad hex string, a malformed proof, and a proof that
//! simply does not match all come back as `ok = false` with a reason, which
//! keeps the JavaScript side to a single `if`.
//!
//! ```
//! use merkle_tree::sum::{sum_proof_to_text, MerkleSumTree, SumLeaf};
//! use merkle_tree::wasm::verify_sum_proof;
//!
//! let leaves = [SumLeaf::new([1u8; 32], 40), SumLeaf::new([2u8; 32], 2)];
//! let tree = MerkleSumTree::from_leaves(leaves).expect("no overflow");
//! let root = tree.root_node().expect("non-empty");
//! let text = sum_proof_to_text(&leaves[1], &tree.prove(1).expect("in range"));
//!
//! let verdict = verify_sum_proof(&text, &merkle_tree::to_hex32(&root.hash), "42");
//! assert!(verdict.ok());
//! assert_eq!(verdict.amount(), "2");
//!
//! let wrong_total = verify_sum_proof(&text, &merkle_tree::to_hex32(&root.hash), "41");
//! assert!(!wrong_total.ok());
//! ```

use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "zk-range")]
use crate::hashing::from_hex;
use crate::hashing::{to_hex32, try_from_hex32};
use crate::proof::{parse_proof_steps, verify_inclusion};
use crate::sum::{parse_sum_proof_text, SumNode};

/// Result of a browser-side verification.
///
/// `account` and `amount` are filled only for a sum-tree proof that parsed,
/// so a page can show which balance was checked even when the check fails.
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    ok: bool,
    reason: String,
    account: String,
    amount: String,
}

impl Verdict {
    fn pass() -> Self {
        Self {
            ok: true,
            reason: String::new(),
            account: String::new(),
            amount: String::new(),
        }
    }

    fn fail(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            reason: reason.into(),
            account: String::new(),
            amount: String::new(),
        }
    }
}

#[wasm_bindgen]
impl Verdict {
    /// `true` only when the proof matched the published root.
    #[wasm_bindgen(getter)]
    pub fn ok(&self) -> bool {
        self.ok
    }

    /// Why verification failed; empty when [`Verdict::ok`] is `true`.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.reason.clone()
    }

    /// Account id from a sum-tree proof as 64 hex characters, or empty.
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> String {
        self.account.clone()
    }

    /// Balance from a sum-tree proof as a decimal string, or empty.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> String {
        self.amount.clone()
    }
}

/// Verify a sum-tree proof written by `merkle sum-prove`.
///
/// `root_hex` and `total_sum` are the values the exchange published. The
/// proof text never carries them, so a forged file cannot vouch for itself.
#[wasm_bindgen(js_name = verifySumProof)]
pub fn verify_sum_proof(proof_text: &str, root_hex: &str, total_sum: &str) -> Verdict {
    let hash = match try_from_hex32(root_hex.trim()) {
        Ok(hash) => hash,
        Err(err) => return Verdict::fail(format!("root: {err}")),
    };
    let total = total_sum.trim();
    let sum = match total.parse::<u128>() {
        Ok(sum) => sum,
        Err(_) => return Verdict::fail(format!("total: invalid sum {total:?}")),
    };
    let (leaf, proof) = match parse_sum_proof_text(proof_text) {
        Ok(parsed) => parsed,
        Err(err) => return Verdict::fail(format!("proof: {err}")),
    };

    let mut verdict = match proof.verify(&leaf, &SumNode::new(hash, sum)) {
        Ok(()) => Verdict::pass(),
        Err(err) => Verdict::fail(err.to_string()),
    };
    verdict.account = to_hex32(&leaf.account_id);
    verdict.amount = leaf.amount.to_string();
    verdict
}

/// Verify a plain-tree inclusion proof for `leaf` (UTF-8 bytes, as in the CLI).
///
/// `steps` uses the CLI path format, `R:<hex>,L:<hex>`; an empty string is the
/// path of a single-leaf tree.
#[wasm_bindgen(js_name = verifyInclusionProof)]
pub fn verify_inclusion_proof(leaf: &str, steps: &str, root_hex: &str) -> Verdict {
    let root = match try_from_hex32(root_hex.trim()) {
        Ok(root) => root,
        Err(err) => return Verdict::fail(format!("root: {err}")),
    };
    let steps = match parse_proof_steps(steps) {
        Ok(steps) => steps,
        Err(err) => return Verdict::fail(format!("steps: {err}")),
    };
    if verify_inclusion(leaf.as_bytes(), &steps, root) {
        Verdict::pass()
    } else {
        Verdict::fail("proof does not match the root")
    }
}

/// Verify a Halo 2 range proof that `amount` fits in 64 bits.
///
/// `amount` is a decimal `u128`. `proof_hex` is the transcript from
/// [`crate::generate_range_proof`]. The amount is a public instance; this
/// does not hide it. Needs the `zk-range` feature in addition to `wasm`.
#[cfg(feature = "zk-range")]
#[wasm_bindgen(js_name = verifyRangeProof)]
pub fn verify_range_proof_js(amount: &str, proof_hex: &str) -> Verdict {
    use crate::range::{verify_range_proof, RangeProof};

    let amount_raw = amount.trim();
    let parsed = match amount_raw.parse::<u128>() {
        Ok(parsed) => parsed,
        Err(_) => return Verdict::fail(format!("amount: invalid amount {amount_raw:?}")),
    };
    let bytes = match from_hex(proof_hex) {
        Ok(bytes) => bytes,
        Err(err) => return Verdict::fail(format!("proof: {err}")),
    };
    let mut verdict = match verify_range_proof(parsed, &RangeProof::from_bytes(bytes)) {
        Ok(()) => Verdict::pass(),
        Err(err) => Verdict::fail(err.to_string()),
    };
    verdict.amount = parsed.to_string();
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sum::{sum_proof_to_text, MerkleSumTree, SumLeaf};
    use crate::MerkleTree;

    fn sum_fixture() -> (String, String) {
        let leaves = [
            SumLeaf::new([1u8; 32], 40),
            SumLeaf::new([2u8; 32], 2),
            SumLeaf::new([3u8; 32], 8),
        ];
        let tree = MerkleSumTree::from_leaves(leaves).expect("no overflow");
        let root = tree.root_node().expect("non-empty");
        let text = sum_proof_to_text(&leaves[2], &tree.prove(2).expect("in range"));
        (text, to_hex32(&root.hash))
    }

    #[test]
    fn sum_proof_passes_and_reports_the_leaf() {
        let (text, root) = sum_fixture();
        let verdict = verify_sum_proof(&text, &root, "50");
        assert!(verdict.ok(), "{}", verdict.reason());
        assert!(verdict.reason().is_empty());
        assert_eq!(verdict.account(), to_hex32(&[3u8; 32]));
        assert_eq!(verdict.amount(), "8");
    }

    #[test]
    fn sum_proof_tolerates_pasted_whitespace() {
        let (text, root) = sum_fixture();
        let verdict = verify_sum_proof(&text, &format!("  {root}\n"), " 50 ");
        assert!(verdict.ok(), "{}", verdict.reason());
    }

    #[test]
    fn wrong_total_fails_but_still_names_the_leaf() {
        let (text, root) = sum_fixture();
        let verdict = verify_sum_proof(&text, &root, "49");
        assert!(!verdict.ok());
        assert!(verdict.reason().contains("49"), "{}", verdict.reason());
        assert_eq!(verdict.amount(), "8");
    }

    #[test]
    fn bad_inputs_fail_without_leaf_fields() {
        let (text, root) = sum_fixture();
        for verdict in [
            verify_sum_proof(&text, "zz", "50"),
            verify_sum_proof(&text, &root, "-1"),
            verify_sum_proof("amount=1\n", &root, "50"),
        ] {
            assert!(!verdict.ok());
            assert!(!verdict.reason().is_empty());
            assert!(verdict.account().is_empty());
            assert!(verdict.amount().is_empty());
        }
    }

    #[test]
    fn plain_proof_round_trip() {
        let tree = MerkleTree::from_leaves(["a", "b", "c"]);
        let root = to_hex32(&tree.root().expect("root"));
        let proof = tree.prove(1).expect("proof");
        let steps: Vec<String> = proof.steps.iter().map(|s| s.to_string()).collect();
        let steps = steps.join(",");

        assert!(verify_inclusion_proof("b", &steps, &root).ok());
        let wrong = verify_inclusion_proof("c", &steps, &root);
        assert!(!wrong.ok());
        assert_eq!(wrong.reason(), "proof does not match the root");
        assert!(!verify_inclusion_proof("b", "X:00", &root).ok());
    }

    #[test]
    fn single_leaf_tree_has_an_empty_path() {
        let tree = MerkleTree::from_leaves(["only"]);
        let root = to_hex32(&tree.root().expect("root"));
        assert!(verify_inclusion_proof("only", "", &root).ok());
    }

    #[cfg(feature = "zk-range")]
    #[test]
    fn range_proof_rejects_a_non_numeric_amount() {
        let verdict = verify_range_proof_js("nope", "00");
        assert!(!verdict.ok());
        assert!(
            verdict.reason().contains("invalid amount"),
            "{}",
            verdict.reason()
        );
        assert!(verdict.amount().is_empty());
    }
}
