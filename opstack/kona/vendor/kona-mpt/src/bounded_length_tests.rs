//! Independent byte-building reference, not a second capped-length formula.
use super::*;
use alloc::{vec, vec::Vec};
fn reference(node: &TrieNode) -> Vec<u8> {
    let mut out = Vec::new();
    match node {
        TrieNode::Empty => out.push(0x80),
        TrieNode::Blinded { commitment } => commitment.encode(&mut out),
        _ => {
            let mut payload = Vec::new();
            match node {
                TrieNode::Leaf { prefix, value } => {
                    alloy_trie::nodes::encode_path_leaf(prefix, true)
                        .as_slice()
                        .encode(&mut payload);
                    value.encode(&mut payload);
                }
                TrieNode::Extension { prefix, node } => {
                    alloy_trie::nodes::encode_path_leaf(prefix, false)
                        .as_slice()
                        .encode(&mut payload);
                    append_reference(node, &mut payload);
                }
                TrieNode::Branch { stack } => {
                    for child in stack {
                        append_reference(child, &mut payload);
                    }
                }
                _ => unreachable!(),
            }
            Header {
                list: true,
                payload_length: payload.len(),
            }
            .encode(&mut out);
            out.extend_from_slice(&payload);
        }
    }
    out
}
fn append_reference(node: &TrieNode, out: &mut Vec<u8>) {
    let bytes = reference(node);
    if bytes.len() >= 32 {
        // A blinded node is already the reference, rather than a raw node to hash.
        if let TrieNode::Blinded { commitment } = node {
            commitment.encode(out);
        } else {
            keccak256(bytes).encode(out);
        }
    } else {
        out.extend_from_slice(&bytes);
    }
}
fn check(node: &TrieNode) {
    let expected = reference(node);
    let mut encoded = Vec::new();
    node.encode(&mut encoded);
    assert_eq!(encoded, expected);
    assert_eq!(node.length(), expected.len());
    assert_eq!(
        node.blinded_length(),
        if expected.len() >= 32 {
            33
        } else {
            expected.len()
        }
    );
    let root = match node {
        TrieNode::Blinded { commitment } => *commitment,
        _ => keccak256(&expected),
    };
    assert_eq!(node.blind(), root);
}
#[test]
fn exact_inline_thresholds_and_path_prefix_lengths() {
    for path in 0..=64 {
        for size in 0..=65 {
            let leaf = TrieNode::Leaf {
                prefix: Nibbles::from_nibbles(vec![1; path]),
                value: vec![0x80; size].into(),
            };
            check(&leaf);
            check(&TrieNode::Extension {
                prefix: Nibbles::from_nibbles(vec![2; path]),
                node: Box::new(leaf),
            });
        }
    }
}
fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn tree(state: &mut u64, depth: usize) -> TrieNode {
    let value = random(state);
    if depth == 0 || value % 3 == 0 {
        TrieNode::Leaf {
            prefix: Nibbles::from_nibbles(vec![(value % 16) as u8; (value % 9) as usize]),
            value: vec![(value >> 8) as u8; (value % 60) as usize].into(),
        }
    } else if value % 3 == 1 {
        TrieNode::Extension {
            prefix: Nibbles::from_nibbles(vec![3; (value % 9 + 1) as usize]),
            node: Box::new(tree(state, depth - 1)),
        }
    } else {
        let mut stack = vec![TrieNode::Empty; 17];
        for child in stack.iter_mut().take((value % 4 + 1) as usize) {
            *child = tree(state, depth - 1);
        }
        stack[15] = TrieNode::new_blinded(B256::from([value as u8; 32]));
        TrieNode::Branch { stack }
    }
}
#[test]
fn deep_open_trees_match_reference_without_mutable_caches() {
    let mut state = 0x9e3779b97f4a7c15;
    for _ in 0..512 {
        check(&tree(&mut state, 7));
    }
}

#[test]
fn bounded_scratch_and_general_fallback_preserve_arbitrary_values_and_branch_lengths() {
    for count in 0..=20 {
        for size in [0, 1, 30, 31, 32, 55, 56, 255, 256, 1024] {
            let leaf = TrieNode::Leaf {
                prefix: Nibbles::from_nibbles(vec![0; 64]),
                value: vec![1; size].into(),
            };
            check(&leaf);
            check(&TrieNode::Branch {
                stack: vec![leaf; count],
            });
        }
    }
}
