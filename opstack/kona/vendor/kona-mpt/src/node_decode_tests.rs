use super::*;
use alloc::vec;
use alloy_primitives::Bytes;
use alloy_rlp::Encodable;
use alloy_trie::Nibbles;

#[test]
fn bounded_decoder_preserves_canonical_values_and_sibling_boundary() {
    for length in [0, 1, 15, 31, 32, 127, 256] {
        for nibbles in [0, 1, 2, 31, 63, 64] {
            let leaf = TrieNode::Leaf {
                prefix: Nibbles::from_nibbles(&vec![5; nibbles]),
                value: Bytes::from(vec![0xa5; length]),
            };
            // Large children become blinded when encoded, exactly as upstream.
            let mut branch = vec![TrieNode::Empty; 17];
            branch[3] = leaf.clone();
            for node in [leaf, TrieNode::Branch { stack: branch }] {
                let bytes = alloy_rlp::encode(&node);
                let mut with_sibling = bytes.clone();
                with_sibling.extend_from_slice(&[0x80, 0x42]);
                let mut reader = with_sibling.as_slice();
                let decoded = TrieNode::decode(&mut reader).unwrap();
                assert_eq!(reader, &[0x80, 0x42]);
                assert_eq!(alloy_rlp::encode(&decoded), bytes);
                for end in 0..bytes.len() {
                    assert!(TrieNode::decode(&mut &bytes[..end]).is_err());
                }
            }
        }
    }
}

#[test]
fn bounded_decoder_rejects_empty_overlong_and_cross_list_paths_without_panics() {
    let bad = [
        vec![0xc2, 0x80, 0x80],       // empty compact path previously indexed path[0]
        vec![0xc1, 0x00, 0x80],       // second item outside declared list
        vec![0xc3, 0x00, 0xc1, 0x80], // malformed inline child
    ];
    for bytes in bad {
        assert!(TrieNode::decode(&mut bytes.as_slice()).is_err());
    }
    for size in [0, 1, 3, 16, 18] {
        let bytes = alloy_rlp::encode(&vec![TrieNode::Empty; size]);
        assert!(TrieNode::decode(&mut bytes.as_slice()).is_err());
    }
    let path = Bytes::from([&[0x31][..], &[0xa5; 32][..]].concat());
    let mut body = Vec::new();
    path.encode(&mut body);
    Bytes::new().encode(&mut body);
    let mut bytes = Vec::new();
    Header {
        list: true,
        payload_length: body.len(),
    }
    .encode(&mut bytes);
    bytes.extend_from_slice(&body);
    assert!(TrieNode::decode(&mut bytes.as_slice()).is_err());
}

#[test]
fn packed_path_construction_matches_byte_per_nibble_reference() {
    for len in 0..=32 {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 13) as u8).collect();
        for first in [None, Some(0), Some(15)] {
            if len == 32 && first.is_some() {
                continue;
            }
            let mut reference: Vec<u8> = first.into_iter().collect();
            for byte in &bytes {
                reference.extend_from_slice(&[byte >> 4, byte & 15]);
            }
            assert_eq!(
                crate::util::unpack_path_to_nibbles(first, &bytes).to_vec(),
                reference
            );
        }
    }
}
