//! Append-only log: successive roots commit to prefixes of the same entries.

use merkle_tree::{verify_inclusion, MerkleLog, MerkleTree};

#[test]
fn successive_roots_match_fresh_prefix_trees() {
    let events = [
        "acct-1 credit 40",
        "acct-2 credit 15",
        "acct-1 debit 7",
        "acct-3 credit 100",
        "acct-2 debit 3",
    ];
    let mut log = MerkleLog::new();
    for (i, event) in events.iter().enumerate() {
        log.append(event);
        let fresh = MerkleTree::from_leaves(events.iter().take(i + 1));
        assert_eq!(log.root(), fresh.root());
        assert_eq!(log.checkpoints()[i].leaf_count, i + 1);
        assert_eq!(log.checkpoints()[i].root, fresh.root().unwrap());
    }
    assert!(log.history_matches());

    let root = log.root().unwrap();
    for (i, event) in events.iter().enumerate() {
        let proof = log.prove(i).unwrap();
        assert!(verify_inclusion(event.as_bytes(), &proof.steps, root));
    }
}

#[test]
fn batch_extend_adds_one_checkpoint() {
    let mut log = MerkleLog::from_entries(["open", "credit"]);
    assert_eq!(log.checkpoints().len(), 1);
    log.extend(["debit", "close"]);
    assert_eq!(log.len(), 4);
    assert_eq!(log.checkpoints().len(), 2);
    assert_eq!(
        log.root(),
        MerkleTree::from_leaves(["open", "credit", "debit", "close"]).root()
    );
    assert!(log.verify_entry(0));
    assert!(log.verify_entry(3));
    assert!(log.history_matches());
}
