//! Contiguous hash-buffer layout: layer sizes, byte cost, and adjacency.

use merkle_tree::MerkleTree;

fn expected_layer_lens(leaf_count: usize) -> Vec<usize> {
    if leaf_count == 0 {
        return Vec::new();
    }
    let mut lens = Vec::new();
    let mut n = leaf_count;
    loop {
        lens.push(n);
        if n == 1 {
            break;
        }
        n = (n + 1) / 2;
    }
    lens
}

#[test]
fn stored_hash_count_matches_sum_of_layer_sizes() {
    for n in 0..=64 {
        let lens = expected_layer_lens(n);
        let sum: usize = lens.iter().sum();
        assert_eq!(MerkleTree::stored_hash_count(n), sum, "n={n}");
        if n > 0 && n.is_power_of_two() {
            assert_eq!(MerkleTree::stored_hash_count(n), 2 * n - 1, "perfect n={n}");
        }
    }
    assert_eq!(MerkleTree::stored_hash_count(3), 6);
    assert_eq!(MerkleTree::stored_hash_count(5), 11);
}

#[test]
fn empty_tree_has_no_layers_or_storage() {
    let tree = MerkleTree::from_leaves(core::iter::empty::<&[u8]>());
    assert_eq!(tree.hash_count(), 0);
    assert_eq!(tree.storage_bytes(), 0);
    assert!(tree.layer_hashes(0).is_none());
    assert!(tree.layer_len(0).is_none());
    assert_eq!(MerkleTree::stored_hash_count(0), 0);
}

#[test]
fn layer_slices_are_adjacent_in_one_buffer() {
    for n in 1..=33 {
        let leaves: Vec<Vec<u8>> = (0..n).map(|i| (i as u32).to_le_bytes().to_vec()).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let lens = expected_layer_lens(n);
        assert_eq!(tree.layer_count(), lens.len());
        assert_eq!(tree.hash_count(), lens.iter().sum());
        assert_eq!(tree.storage_bytes(), tree.hash_count() * 32);

        let mut previous_end: Option<usize> = None;
        for (level, &len) in lens.iter().enumerate() {
            let slice = tree.layer_hashes(level).expect("layer");
            assert_eq!(slice.len(), len);
            assert_eq!(tree.layer_len(level), Some(len));
            let start = slice.as_ptr() as usize;
            if let Some(end) = previous_end {
                assert_eq!(start, end, "layer {level} should follow the previous slice");
            }
            previous_end = Some(start + slice.len() * 32);
        }

        let root = tree.root().unwrap();
        assert_eq!(
            tree.layer_hashes(lens.len() - 1),
            Some(core::slice::from_ref(&root))
        );
        assert!(tree.layer_hashes(lens.len()).is_none());
        assert!(tree.layer_len(lens.len()).is_none());
    }
}

#[test]
fn append_keeps_layout_in_sync_with_a_fresh_tree() {
    let mut tree = MerkleTree::from_leaves(["a", "b"]);
    tree.append("c");
    tree.extend(["d", "e", "f"]);
    let fresh = MerkleTree::from_leaves(["a", "b", "c", "d", "e", "f"]);
    assert_eq!(tree.root(), fresh.root());
    assert_eq!(tree.hash_count(), fresh.hash_count());
    assert_eq!(tree.storage_bytes(), fresh.storage_bytes());
    assert_eq!(tree.layer_count(), fresh.layer_count());
    for level in 0..tree.layer_count() {
        assert_eq!(tree.layer_hashes(level), fresh.layer_hashes(level));
    }
}
