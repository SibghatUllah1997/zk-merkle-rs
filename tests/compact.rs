//! Integration tests for compact multi-leaf proof generation.

use merkle_tree::{hash_leaf, hash_nodes, MerkleTree};

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

#[test]
fn compact_empty_request_and_empty_tree() {
    let empty = MerkleTree::from_leaves(core::iter::empty::<&[u8]>());
    let none = empty
        .prove_compact(core::iter::empty::<usize>())
        .expect("empty");
    assert!(none.is_empty());
    assert_eq!(none.leaf_count, 0);
    assert!(empty.prove_compact([0]).is_none());
    assert!(empty.prove_compact_all().is_empty());

    let tree = MerkleTree::from_leaves(["a", "b", "c"]);
    let none = tree
        .prove_compact(core::iter::empty::<usize>())
        .expect("empty");
    assert!(none.is_empty());
    assert_eq!(none.leaf_count, 3);
    assert!(none.siblings.is_empty());
}

#[test]
fn compact_single_leaf_has_no_siblings() {
    let tree = MerkleTree::from_leaves(["solo"]);
    let compact = tree.prove_compact([0]).expect("in range");
    assert_eq!(compact.leaf_count, 1);
    assert_eq!(compact.indices(), &[0]);
    assert_eq!(compact.leaves, vec![hash_leaf(b"solo")]);
    assert!(compact.siblings.is_empty());
}

#[test]
fn compact_four_leaf_shapes() {
    let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
    let ha = hash_leaf(b"a");
    let hb = hash_leaf(b"b");
    let hc = hash_leaf(b"c");
    let hd = hash_leaf(b"d");
    let ncd = hash_nodes(&hc, &hd);

    let pair = tree.prove_compact([0, 1]).expect("in range");
    assert_eq!(pair.leaves, vec![ha, hb]);
    assert_eq!(pair.siblings, vec![ncd]);

    let split = tree.prove_compact([0, 2]).expect("in range");
    assert_eq!(split.leaves, vec![ha, hc]);
    assert_eq!(split.siblings, vec![hb, hd]);

    let all = tree.prove_compact_all();
    assert_eq!(all.leaves, vec![ha, hb, hc, hd]);
    assert!(all.siblings.is_empty());
}

#[test]
fn compact_odd_leaf_count_pads_without_storing_the_duplicate() {
    let tree = MerkleTree::from_leaves(["a", "b", "c"]);
    let ha = hash_leaf(b"a");
    let hb = hash_leaf(b"b");
    let hc = hash_leaf(b"c");
    let nab = hash_nodes(&ha, &hb);

    let only_last = tree.prove_compact([2]).expect("in range");
    assert_eq!(only_last.leaves, vec![hc]);
    assert_eq!(only_last.siblings, vec![nab]);

    let first_and_last = tree.prove_compact([0, 2]).expect("in range");
    assert_eq!(first_and_last.leaves, vec![ha, hc]);
    assert_eq!(first_and_last.siblings, vec![hb]);
}

#[test]
fn compact_uses_fewer_hashes_than_naive_on_overlapping_paths() {
    for n in 2..=12 {
        let data = leaves(n);
        let tree = MerkleTree::from_leaves(data.iter().map(|v| v.as_slice()));
        let compact = tree.prove_compact([0, 1]).expect("in range");
        let naive = tree.prove_many([0, 1]).expect("in range");
        let naive_steps: usize = naive.proofs.iter().map(|p| p.proof.steps.len()).sum();
        assert!(
            compact.sibling_count() < naive_steps,
            "n={n}: compact {} vs naive {naive_steps}",
            compact.sibling_count()
        );
        assert_eq!(compact.indices(), &[0, 1]);
        assert_eq!(compact.leaf_count, n);
    }
}

#[test]
fn compact_hex_helpers_match_stored_hashes() {
    let tree = MerkleTree::from_leaves(["a", "b", "c", "d"]);
    let compact = tree.prove_compact([0, 3]).expect("in range");
    assert_eq!(compact.leaves_hex().len(), 2);
    assert_eq!(compact.siblings_hex().len(), compact.siblings.len());
    for (hex, hash) in compact.leaves_hex().iter().zip(compact.leaves.iter()) {
        assert_eq!(hex.len(), 64);
        assert_eq!(*hex, merkle_tree::to_hex32(hash));
    }
}
