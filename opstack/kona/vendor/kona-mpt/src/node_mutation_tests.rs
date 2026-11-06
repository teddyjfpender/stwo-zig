use super::*;
use crate::noop::{NoopTrieHinter, NoopTrieProvider};

#[test]
fn extension_split_short_path_preserves_original_tree_on_error() {
    let mut node = TrieNode::Extension {
        prefix: Nibbles::from_nibbles(&[1, 2, 3]),
        node: Box::new(TrieNode::Leaf {
            prefix: Nibbles::from_nibbles(&[4]),
            value: Bytes::from_static(b"old"),
        }),
    };
    let original = node.clone();
    assert!(
        node.insert(
            &Nibbles::from_nibbles(&[1, 2]),
            Bytes::from_static(b"new"),
            &NoopTrieProvider
        )
        .is_err()
    );
    assert_eq!(node, original);
}

#[test]
fn splitting_and_collapsing_nested_extensions_preserves_values_and_root() {
    let provider = NoopTrieProvider;
    let hinter = NoopTrieHinter;
    let keys = [[1, 2, 3, 4], [1, 2, 5, 6], [1, 7, 8, 9], [2, 3, 4, 5]];
    let values = [b"first".as_slice(), b"second", b"third", b"fourth"];
    let mut node = TrieNode::Empty;
    for (key, value) in keys.iter().zip(values) {
        node.insert(
            &Nibbles::from_nibbles(key),
            Bytes::copy_from_slice(value),
            &provider,
        )
        .unwrap();
    }
    for removed in (1..keys.len()).rev() {
        node.delete(&Nibbles::from_nibbles(&keys[removed]), &provider, &hinter)
            .unwrap();
        let mut rebuilt = TrieNode::Empty;
        for (key, value) in keys[..removed].iter().zip(values) {
            rebuilt
                .insert(
                    &Nibbles::from_nibbles(key),
                    Bytes::copy_from_slice(value),
                    &provider,
                )
                .unwrap();
            assert_eq!(
                node.open(&Nibbles::from_nibbles(key), &provider)
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                value
            );
        }
        assert_eq!(node.blind(), rebuilt.blind());
        assert_eq!(node, rebuilt);
    }
    node.delete(&Nibbles::from_nibbles(&keys[0]), &provider, &hinter)
        .unwrap();
    assert_eq!(node, TrieNode::Empty);
}
