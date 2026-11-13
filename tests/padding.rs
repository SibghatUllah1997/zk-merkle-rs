//! Duplicate-last padding versus common alternatives.

use merkle_tree::{hash_leaf, hash_nodes, MerkleTree};

fn labels(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("leaf-{i}")).collect()
}

/// Build a root by padding hashed leaves with empty-leaf hashes out to the
/// next power of two, then hashing pairs with no further padding.
fn empty_leaf_padded_root(items: &[String]) -> [u8; 32] {
    let mut hashes: Vec<[u8; 32]> = items.iter().map(|s| hash_leaf(s.as_bytes())).collect();
    let target = hashes.len().next_power_of_two();
    let filler = hash_leaf(b"");
    hashes.resize(target, filler);
    MerkleTree::from_hashed_leaves(hashes)
        .root()
        .expect("non-empty")
}

/// Build a root by hashing pairs and promoting an odd leftover unchanged
/// instead of hashing it with itself.
fn promote_odd_root(items: &[String]) -> [u8; 32] {
    let mut layer: Vec<[u8; 32]> = items.iter().map(|s| hash_leaf(s.as_bytes())).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0;
        while i + 1 < layer.len() {
            next.push(hash_nodes(&layer[i], &layer[i + 1]));
            i += 2;
        }
        if i < layer.len() {
            next.push(layer[i]);
        }
        layer = next;
    }
    layer[0]
}

#[test]
fn odd_leaf_padding_equivalence_to_single_duplicate() {
    // For several odd sizes, duplicating the last leaf at the bottom layer
    // yields the same root as the implementation that duplicates at each odd layer.
    for n in (3..=15).filter(|x| x % 2 == 1) {
        let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let mut dup = leaves.clone();
        // Duplicate the last leaf once to make the bottom layer even.
        dup.push(dup.last().expect("non-empty").clone());

        let t_impl = MerkleTree::from_leaves(leaves.iter().map(|v| v.as_slice()));
        let t_dup = MerkleTree::from_leaves(dup.iter().map(|v| v.as_slice()));
        assert_eq!(
            t_impl.root(),
            t_dup.root(),
            "roots differ for n={n} with single-duplicate bottom padding"
        );
    }
}

#[test]
fn parent_count_and_padding_flags() {
    assert_eq!(MerkleTree::parent_count(0), 0);
    assert_eq!(MerkleTree::parent_count(1), 0);
    assert_eq!(MerkleTree::parent_count(2), 1);
    assert_eq!(MerkleTree::parent_count(3), 2);
    assert_eq!(MerkleTree::parent_count(4), 2);
    assert_eq!(MerkleTree::parent_count(5), 3);
    assert!(!MerkleTree::layer_is_padded(0));
    assert!(!MerkleTree::layer_is_padded(1));
    assert!(!MerkleTree::layer_is_padded(2));
    assert!(MerkleTree::layer_is_padded(3));
    assert!(!MerkleTree::layer_is_padded(4));
    assert!(MerkleTree::layer_is_padded(5));
}

#[test]
fn layer_widths_match_a_live_tree() {
    assert!(MerkleTree::layer_widths(0).is_empty());
    assert_eq!(MerkleTree::layer_widths(1), vec![1]);
    for n in 0..=33usize {
        let items = labels(n);
        let tree = MerkleTree::from_leaves(items.iter());
        let widths = MerkleTree::layer_widths(n);
        assert_eq!(widths.len(), tree.layer_count());
        assert_eq!(
            widths.iter().copied().sum::<usize>(),
            MerkleTree::stored_hash_count(n)
        );
        for (level, width) in widths.iter().copied().enumerate() {
            assert_eq!(tree.layer_len(level), Some(width), "n={n} level={level}");
            if level + 1 < widths.len() {
                assert_eq!(
                    MerkleTree::parent_count(width),
                    widths[level + 1],
                    "n={n} level={level}"
                );
            }
            let padded = MerkleTree::layer_is_padded(width);
            if padded {
                assert_eq!(width % 2, 1);
                assert!(width >= 3);
            }
        }
        if n > 0 {
            assert_eq!(*widths.last().expect("root width"), 1);
        }
    }
}

#[test]
fn empty_leaf_power_of_two_padding_differs_on_odd_counts() {
    for n in [3usize, 5, 6, 7, 9] {
        let items = labels(n);
        let ours = MerkleTree::from_leaves(items.iter())
            .root()
            .expect("non-empty");
        let padded = empty_leaf_padded_root(&items);
        assert_ne!(ours, padded, "n={n} should not match empty-leaf padding");
    }
    let four = labels(4);
    assert_eq!(
        MerkleTree::from_leaves(four.iter()).root(),
        Some(empty_leaf_padded_root(&four))
    );
}

#[test]
fn promoting_an_odd_node_unchanged_differs_from_duplicate_last() {
    for n in [3usize, 5, 6, 7, 9] {
        let items = labels(n);
        let ours = MerkleTree::from_leaves(items.iter())
            .root()
            .expect("non-empty");
        let promoted = promote_odd_root(&items);
        assert_ne!(ours, promoted, "n={n} should not match promote-odd");
    }
    // Two leaves: one pair, no leftover, both schemes match.
    let two = labels(2);
    assert_eq!(
        MerkleTree::from_leaves(two.iter()).root(),
        Some(promote_odd_root(&two))
    );
}

#[test]
fn three_leaf_parents_are_pair_and_self_hash() {
    let tree = MerkleTree::from_leaves(["a", "b", "c"]);
    let leaves = tree.layer_hashes(0).expect("leaves");
    let parents = tree.layer_hashes(1).expect("parents");
    assert_eq!(parents.len(), 2);
    assert_eq!(parents[0], hash_nodes(&leaves[0], &leaves[1]));
    assert_eq!(parents[1], hash_nodes(&leaves[2], &leaves[2]));
    assert_eq!(tree.root(), Some(hash_nodes(&parents[0], &parents[1])));
}
