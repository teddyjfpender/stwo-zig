//! Single bounded RLP list view, two-item classification and one branch
//! allocation. No full branch pre-scan or Vec growth/copy ladder is needed.
use super::{BRANCH_LIST_LENGTH, LEAF_OR_EXTENSION_LIST_LENGTH, TrieNode};
use alloc::vec::Vec;
use alloy_primitives::B256;
use alloy_rlp::{Buf, Decodable, Header};

impl Decodable for TrieNode {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = *buf;
        let header = Header::decode(&mut payload)?;
        if !header.list {
            return match header.payload_length {
                0 => {
                    buf.advance(header.length());
                    Ok(Self::Empty)
                }
                32 => Ok(Self::new_blinded(B256::decode(buf)?)),
                _ => Err(alloy_rlp::Error::UnexpectedLength),
            };
        }
        // Header::decode checks that the declared payload fits. Children must
        // never consume bytes belonging to the following sibling/root.
        let (mut body, tail) = payload.split_at(header.payload_length);
        let mut probe = body;
        for _ in 0..LEAF_OR_EXTENSION_LIST_LENGTH {
            if probe.is_empty() {
                return Err(alloy_rlp::Error::UnexpectedLength);
            }
            let item = Header::decode(&mut probe)?;
            probe.advance(item.payload_length);
        }
        let node = if probe.is_empty() {
            Self::try_decode_leaf_or_extension_payload(&mut body)
                .map_err(|_| alloy_rlp::Error::UnexpectedList)?
        } else {
            let mut stack = Vec::with_capacity(BRANCH_LIST_LENGTH);
            for _ in 0..BRANCH_LIST_LENGTH {
                stack.push(Self::decode(&mut body)?);
            }
            Self::Branch { stack }
        };
        if !body.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        *buf = tail;
        Ok(node)
    }
}

#[cfg(test)]
#[path = "node_decode_tests.rs"]
mod tests;
