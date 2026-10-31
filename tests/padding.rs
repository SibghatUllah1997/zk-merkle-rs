use merkle_tree::MerkleTree;

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
