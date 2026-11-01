// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
    source::NodeSource,
    children::Children,
    memoize::Memoization,
    node::Node,
};
use alloc::{vec, vec::Vec};
use alloy_primitives::{hex, keccak256, map::B256IndexMap, Bytes, B256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, EMPTY_STRING_CODE};
use alloy_trie::{nodes::encode_path_leaf, Nibbles, EMPTY_ROOT_HASH};
use core::fmt;

/// The length in bytes of an RLP-encoded digest, i.e. hash length + 1 byte for the RLP header.
const DIGEST_RLP_LENGTH: usize = 1 + B256::len_bytes();

impl<M: Memoization> Node<M> {
    /// Returns the hash of the node.
    #[inline]
    pub(super) fn hash(&self) -> B256 {
        NodeRef::from_node(self).hash()
    }

    /// Returns the RLP encoding of the node.
    pub(super) fn rlp_encoded(&self) -> Vec<u8> {
        match self {
            Node::Null => vec![EMPTY_STRING_CODE],
            Node::Leaf(prefix, value, _) => {
                let path = encode_path_leaf(prefix, true);
                let mut out = encode_list_header(path.length() + value.length());
                path.encode(&mut out);
                value.encode(&mut out);

                out
            }
            Node::Extension(prefix, child, _) => {
                let path = encode_path_leaf(prefix, false);
                let node_ref = NodeRef::from_node(child);
                let mut out = encode_list_header(path.length() + node_ref.length());
                path.encode(&mut out);
                node_ref.encode(&mut out);

                out
            }
            Node::Branch(children, _) => {
                let mut child_refs: [NodeRef<'_>; 16] = Default::default();
                let mut payload_length = 1; // start with 1 for the EMPTY_STRING_CODE at the end

                for (i, child) in children.iter().enumerate() {
                    match child {
                        Some(node) => {
                            let node_ref = NodeRef::from_node(node);
                            payload_length += node_ref.length();
                            child_refs[i] = node_ref;
                        }
                        None => payload_length += 1,
                    }
                }

                let mut out = encode_list_header(payload_length);
                child_refs.iter().for_each(|child| child.encode(&mut out));
                // add an EMPTY_STRING_CODE for the missing value
                out.push(EMPTY_STRING_CODE);

                out
            }
            Node::Digest(digest) => alloy_rlp::encode(digest),
        }
    }

    /// Memoize the hash of every sub-trie.
    pub(super) fn memoize(&mut self) {
        // early termination for already memoized nodes or Null/Digest
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache)
                if cache.get().is_some() =>
            {
                return;
            }
            Node::Null | Node::Digest(_) => return,
            _ => {} // proceed to memoization for other variants
        }
        match self {
            Node::Extension(_, child, _) => child.memoize(),
            Node::Branch(children, _) => children.memoize(),
            _ => {} // no children to memoize for Leaf, Null, or Digest
        }
        if let Node::Branch(children, cache) = self {
            if let Some(rlp_node) = Self::branch_rlp_node(children) {
                cache.set(rlp_node);
                return;
            }
        }
        let rlp = self.rlp_encoded();
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.set(RlpNode::from_rlp(rlp));
            }
            _ => unreachable!(),
        }
    }

    /// Returns the RLP-encoded nodes of the trie in preorder.
    pub(super) fn rlp_nodes(&self) -> Vec<Bytes> {
        fn rec<'a, M: Memoization>(node: &'a Node<M>, nodes: &mut Vec<Bytes>) -> NodeRef<'a> {
            let node_ref = match node {
                Node::Extension(prefix, child, _) => {
                    let (path, child) = (encode_path_leaf(prefix, false), rec(child, nodes));
                    let mut out = encode_list_header(path.length() + child.length());
                    path.encode(&mut out);
                    child.encode(&mut out);
                    NodeRef::Rlp(out)
                }
                Node::Branch(children, _) => {
                    let mut list = Vec::with_capacity(17);
                    for child in children.iter() {
                        let node_ref = child.as_ref().map_or(NodeRef::Empty, |c| rec(c, nodes));
                        list.push(node_ref);
                    }
                    list.push(NodeRef::Empty);
                    NodeRef::Rlp(encode_list(&list))
                }
                Node::Leaf(..) => NodeRef::Rlp(node.rlp_encoded()), // do not use the cached value
                Node::Digest(digest) => NodeRef::Digest(digest),
                Node::Null => NodeRef::Empty,
            };
            match &node_ref {
                NodeRef::Rlp(rlp) if rlp.len() >= 32 => nodes.push(rlp.clone().into()),
                NodeRef::Cached(..) => unreachable!(),
                _ => {}
            }
            node_ref
        }

        if matches!(self, Node::Null) {
            return vec![];
        }

        let mut vec = Vec::new();
        match rec(self, &mut vec) {
            NodeRef::Rlp(rlp) if rlp.len() >= 32 => {}
            NodeRef::Cached(..) => unreachable!(),
            node_ref => vec.push(alloy_rlp::encode(node_ref).into()),
        }
        vec.reverse();

        vec
    }

    /// Creates a new trie from the given RLP encoded nodes.
    pub(super) fn from_rlp<T: AsRef<[u8]>>(
        nodes: impl IntoIterator<Item = T>,
    ) -> alloy_rlp::Result<Self> {
        let mut iterator = nodes.into_iter();

        // the first node must be the root
        let mut root = match iterator.next() {
            None => return Ok(Self::default()),
            Some(rlp) => {
                let mut node: Node<M> = alloy_rlp::decode_exact(rlp.as_ref())?;
                node.cache_set(RlpNode::from_rlp(rlp));
                node
            }
        };

        // compute the references of all the remaining nodes
        let (lower, _) = iterator.size_hint();
        let mut rlp_by_digest = B256IndexMap::with_capacity_and_hasher(lower, Default::default());
        for rlp in iterator {
            rlp_by_digest.insert(keccak256(&rlp), rlp);
        }

        // return the resolved trie
        root.resolve_digests(&rlp_by_digest)?;
        Ok(root)
    }

    /// Resolves all applicable digest nodes with the node corresponding to the RLP encoding.
    pub(super) fn resolve_digests(
        &mut self,
        rlp_by_digest: &(impl NodeSource + ?Sized),
    ) -> alloy_rlp::Result<()> {
        match self {
            Node::Null | Node::Leaf(..) => {}
            Node::Extension(_, child, _) => {
                child.resolve_digests(rlp_by_digest)?;
                if !matches!(**child, Node::Branch(..) | Node::Digest(..)) {
                    return Err(alloy_rlp::Error::Custom("extension node with invalid child"));
                }
            }
            Node::Branch(children, _) => {
                // stwo: digest children (nearly all of them, and nearly all
                // absent from the witness) are probed inline instead of
                // through a recursive call each.
                for slot in children.slots_mut().iter_mut() {
                    let Some(child) = slot else { continue };
                    match &**child {
                        Node::Digest(digest) => {
                            let Some(bytes) = rlp_by_digest.node_rlp(digest) else { continue };
                            if bytes.len() == 33 && bytes[0] == 0xa0 {
                                continue;
                            }
                            let rlp_node = RlpNode::from_digest(digest);
                            child.decode_exact_into(bytes)?;
                            child.cache_set(rlp_node);
                            child.resolve_digests(rlp_by_digest)?;
                        }
                        _ => child.resolve_digests(rlp_by_digest)?,
                    }
                    // a branch never holds a Null child (as `Entry` enforces)
                    if matches!(**child, Node::Null) {
                        *slot = None;
                    }
                }
            }
            Node::Digest(digest) => {
                if let Some(bytes) = rlp_by_digest.node_rlp(digest) {
                    // do not try to replace a node by a digest (stwo: decided
                    // from the encoding so the node is decoded straight into
                    // place instead of through a temporary and a second move)
                    if !(bytes.len() == 33 && bytes[0] == 0xa0) {
                        let rlp_node = RlpNode::from_digest(digest);
                        self.decode_exact_into(bytes)?;
                        self.cache_set(rlp_node);
                        self.resolve_digests(rlp_by_digest)?;
                    }
                }
            }
        }

        Ok(())
    }

    #[inline]
    fn cache_set(&mut self, rlp_node: RlpNode) {
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.set(rlp_node)
            }
            _ => {}
        }
    }
}

impl<M: Memoization> Decodable for Node<M> {
    #[inline]
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut node = Node::Null;
        node.decode_into(buf)?;
        Ok(node)
    }
}

impl<M: Memoization> Node<M> {
    /// stwo: decodes a whole encoding straight into `self` (a boxed child
    /// being resolved), avoiding the moves of a 176-byte node through
    /// `Result` temporaries. Errors like `alloy_rlp::decode_exact`.
    fn decode_exact_into(&mut self, bytes: &[u8]) -> alloy_rlp::Result<()> {
        let mut buf = bytes;
        self.decode_into(&mut buf)?;
        if !buf.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(())
    }

    fn decode_into(&mut self, buf: &mut &[u8]) -> alloy_rlp::Result<()> {
        // stwo: walk the list payload into a fixed 17-slot array instead of
        // collecting a heap `Vec<&[u8]>` per node (`Header::decode_raw`).
        let header = Header::decode(buf)?;
        if buf.len() < header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let (payload, rest) = buf.split_at(header.payload_length);
        *buf = rest;
        if !header.list {
            // if the node is not a list, it must be empty or a digest
            *self = match payload.len() {
                0 => Node::Null,
                32 => Node::Digest(B256::from_slice(payload)),
                _ => return Err(alloy_rlp::Error::UnexpectedLength),
            };
            return Ok(());
        }
        let mut items: [&[u8]; 17] = [&[]; 17];
        let mut count = 0usize;
        let mut cursor = payload;
        while !cursor.is_empty() {
            if count == 17 {
                return Err(alloy_rlp::Error::Custom("unexpected list length"));
            }
            let mut probe = cursor;
            let item = Header::decode(&mut probe)?;
            let total = cursor.len() - probe.len() + item.payload_length;
            if total > cursor.len() {
                return Err(alloy_rlp::Error::InputTooShort);
            }
            items[count] = &cursor[..total];
            cursor = &cursor[total..];
            count += 1;
        }
        match count {
            // branch node: 17-item node [ v0 ... v15, value ]
            17 => {
                // Build the branch inside its final node so the 128-byte
                // children table is not moved into the enum after decoding.
                *self = Node::Branch(Children::default(), M::default());
                let Node::Branch(children, _) = self else { unreachable!() };
                for (i, child_rlp) in items.iter().enumerate() {
                    if child_rlp != &[EMPTY_STRING_CODE] {
                        if i == 16 {
                            return Err(alloy_rlp::Error::Custom("branch node with value"));
                        } else if child_rlp.len() == 33 && child_rlp[0] == 0xa0 {
                            // A bare 32-byte digest, which is almost every
                            // child in a witness: construct it inside its
                            // allocation instead of decoding recursively into
                            // a 176-byte temporary and moving it twice.
                            children.insert(i as u8, boxed_digest(&child_rlp[1..]));
                        } else {
                            children.insert(i as u8, Node::decode(&mut &child_rlp[..])?.into());
                        }
                    }
                }
                if children.len() < 2 {
                    return Err(alloy_rlp::Error::Custom("branch node without two children"));
                }

                Ok(())
            }
            // leaf or extension node: 2-item node [ encodedPath, v ]
            // they are distinguished by a flag in the first nibble of the encodedPath
            2 => {
                let (mut encode_path, mut v) = (items[0], items[1]);
                let (path, is_leaf) = decode_path(&mut encode_path)?;
                if is_leaf {
                    *self = Node::Leaf(path, Bytes::decode(&mut v)?, M::default());
                    Ok(())
                } else {
                    let node = Node::decode(&mut v)?;
                    if !matches!(node, Node::Branch(..) | Node::Digest(..)) {
                        return Err(alloy_rlp::Error::Custom(
                            "extension node with invalid child",
                        ));
                    }
                    *self = Node::Extension(path, node.into(), M::default());
                    Ok(())
                }
            }
            _ => Err(alloy_rlp::Error::Custom("unexpected list length")),
        }
    }
}

/// An RLP-encoded node reference: the 33-byte `0xa0 || keccak` form of a
/// node of 32 or more bytes, or the node's own encoding when shorter.
///
/// stwo: stored as an 8-aligned 32-byte array plus a length (33 marks a
/// digest) instead of an `ArrayVec<u8, 33>`, so a branch re-encoding can
/// move the digest as four aligned words (see `branch_rlp_node`).
#[derive(Clone)]
#[repr(C, align(8))]
pub(super) struct RlpNode {
    bytes: [u8; 32],
    len: u8,
}

impl RlpNode {
    #[inline]
    fn from_rlp(rlp: impl AsRef<[u8]>) -> Self {
        let rlp = rlp.as_ref();
        if rlp.len() >= B256::len_bytes() {
            Self::from_digest(&keccak256(rlp))
        } else {
            let mut bytes = [0u8; 32];
            bytes[..rlp.len()].copy_from_slice(rlp);
            Self { bytes, len: rlp.len() as u8 }
        }
    }

    #[inline]
    fn from_digest(digest: &B256) -> Self {
        Self { bytes: digest.0, len: DIGEST_RLP_LENGTH as u8 }
    }

    #[inline]
    fn is_digest(&self) -> bool {
        self.len as usize == DIGEST_RLP_LENGTH
    }

    #[inline]
    fn hash(&self) -> B256 {
        if self.is_digest() {
            B256::from(self.bytes)
        } else {
            keccak256(&self.bytes[..self.len as usize])
        }
    }
}

impl fmt::Debug for RlpNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_digest() {
            write!(f, "0xa0{}", hex::encode(self.bytes))
        } else {
            write!(f, "0x{}", hex::encode(&self.bytes[..self.len as usize]))
        }
    }
}

impl Encodable for RlpNode {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        if self.is_digest() {
            out.put_u8(0xa0);
            out.put_slice(&self.bytes)
        } else {
            out.put_slice(&self.bytes[..self.len as usize])
        }
    }

    #[inline]
    fn length(&self) -> usize {
        self.len as usize
    }
}

/// stwo: little-endian word buffer for one branch encoding (at most
/// 3 + 16 * 33 + 1 = 532 bytes); bytes are OR-ed into zeroed words.
struct WordBuf {
    w: [u64; 68],
}

impl WordBuf {
    #[inline(always)]
    fn put_byte(&mut self, n: usize, b: u8) {
        debug_assert!(n < 8 * 68);
        // SAFETY: n < 532 for a branch encoding
        unsafe { *self.w.get_unchecked_mut(n >> 3) |= (b as u64) << ((n & 7) * 8) };
    }

    /// Writes `0xa0 || d` (33 bytes) at byte position `n`; `d` is 8-aligned.
    #[inline(always)]
    fn put_digest(&mut self, n: usize, d: &[u8; 32]) {
        debug_assert!(n + 33 <= 8 * 67);
        let p = d.as_ptr().cast::<u64>();
        // SAFETY: `d` is 8-aligned (checked by the caller); n + 33 < 8 * 68
        unsafe {
            let x = |i: usize| u64::from_le(p.add(i).read());
            let (d0, d1, d2, d3) = (x(0), x(1), x(2), x(3));
            // the 33 bytes as four words plus one byte, shifted by the 0xa0
            let v = [
                0xa0 | (d0 << 8),
                (d0 >> 56) | (d1 << 8),
                (d1 >> 56) | (d2 << 8),
                (d2 >> 56) | (d3 << 8),
            ];
            let k = n >> 3;
            let sh = ((n & 7) * 8) as u32;
            let w = self.w.as_mut_ptr().add(k);
            *w |= v[0] << sh;
            let carry = |x: u64| (x >> 1) >> (63 - sh);
            *w.add(1) = carry(v[0]) | (v[1] << sh);
            *w.add(2) = carry(v[1]) | (v[2] << sh);
            *w.add(3) = carry(v[2]) | (v[3] << sh);
            // byte 32 lands in word k + 4 at the same offset as byte 0 in k
            *w.add(4) = carry(v[3]) | ((d3 >> 56) << sh);
        }
    }

    #[inline(always)]
    fn as_bytes(&self, n: usize) -> &[u8] {
        // SAFETY: the words are plain bytes; n <= 8 * 68
        unsafe { core::slice::from_raw_parts(self.w.as_ptr().cast::<u8>(), n) }
    }
}

impl<M: Memoization> Node<M> {
    /// stwo: the reference of a branch whose children are all absent,
    /// digests or memoized, built in an aligned word buffer and hashed from
    /// it: no `Vec`, no `dyn BufMut`, no per-child `memcpy` call. `None` if a
    /// child has no cached reference (the generic path handles it).
    fn branch_rlp_node(children: &Children<M>) -> Option<RlpNode> {
        let mut payload = 1usize;
        for child in children.iter() {
            payload += match child.as_deref() {
                None => 1,
                Some(Node::Digest(_)) => DIGEST_RLP_LENGTH,
                Some(Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache)) => {
                    cache.get()?.length()
                }
                Some(Node::Null) => return None,
            };
        }
        let mut buf = WordBuf { w: [0; 68] };
        let mut n = 0;
        if payload < 56 {
            buf.put_byte(0, 0xc0 + payload as u8);
            n = 1;
        } else if payload < 256 {
            buf.put_byte(0, 0xf8);
            buf.put_byte(1, payload as u8);
            n = 2;
        } else {
            buf.put_byte(0, 0xf9);
            buf.put_byte(1, (payload >> 8) as u8);
            buf.put_byte(2, payload as u8);
            n = 3;
        }
        let mut put_bytes = |buf: &mut WordBuf, n: &mut usize, bytes: &[u8]| {
            for &b in bytes {
                buf.put_byte(*n, b);
                *n += 1;
            }
        };
        for child in children.iter() {
            let digest = match child.as_deref() {
                None => {
                    buf.put_byte(n, EMPTY_STRING_CODE);
                    n += 1;
                    continue;
                }
                Some(Node::Digest(d)) => &d.0,
                Some(Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache)) => {
                    let r = cache.get()?;
                    if !r.is_digest() {
                        put_bytes(&mut buf, &mut n, &r.bytes[..r.len as usize]);
                        continue;
                    }
                    &r.bytes
                }
                Some(Node::Null) => return None,
            };
            if (digest.as_ptr() as usize) & 7 == 0 {
                buf.put_digest(n, digest);
                n += DIGEST_RLP_LENGTH;
            } else {
                buf.put_byte(n, 0xa0);
                n += 1;
                put_bytes(&mut buf, &mut n, digest);
            }
        }
        buf.put_byte(n, EMPTY_STRING_CODE);
        n += 1;
        Some(RlpNode::from_rlp(buf.as_bytes(n)))
    }
}

/// Represents the way in which a node is referenced from within another node.
#[derive(Default)]
enum NodeRef<'a> {
    #[default]
    Empty,
    Digest(&'a B256),
    Cached(&'a RlpNode),
    Rlp(Vec<u8>),
}

impl NodeRef<'_> {
    #[inline]
    fn from_node<M: Memoization>(node: &Node<M>) -> NodeRef<'_> {
        match node {
            Node::Null => NodeRef::Empty,
            Node::Digest(digest) => NodeRef::Digest(digest),
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.get().map_or_else(|| NodeRef::Rlp(node.rlp_encoded()), NodeRef::Cached)
            }
        }
    }

    #[inline]
    fn hash(&self) -> B256 {
        match self {
            NodeRef::Empty => EMPTY_ROOT_HASH,
            NodeRef::Digest(&digest) => digest,
            NodeRef::Cached(rlp_node) => rlp_node.hash(),
            NodeRef::Rlp(rlp) => keccak256(rlp),
        }
    }
}

impl Encodable for NodeRef<'_> {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            NodeRef::Empty => out.put_u8(EMPTY_STRING_CODE),
            NodeRef::Digest(digest) => digest.encode(out),
            NodeRef::Cached(rlp_node) => rlp_node.encode(out),
            NodeRef::Rlp(rlp) => {
                if rlp.len() >= B256::len_bytes() {
                    keccak256(rlp).encode(out);
                } else {
                    out.put_slice(rlp);
                }
            }
        }
    }

    #[inline]
    fn length(&self) -> usize {
        match self {
            NodeRef::Empty => 1,
            NodeRef::Digest(_) => DIGEST_RLP_LENGTH,
            NodeRef::Cached(rlp_node) => rlp_node.length(),
            NodeRef::Rlp(rlp) => {
                if rlp.len() >= B256::len_bytes() {
                    DIGEST_RLP_LENGTH
                } else {
                    rlp.len()
                }
            }
        }
    }
}

#[inline]
fn encode_list_header(payload_length: usize) -> Vec<u8> {
    debug_assert!(payload_length > 1);
    let header = Header { list: true, payload_length };
    let mut out = Vec::with_capacity(header.length() + payload_length);
    header.encode(&mut out);
    out
}

/// Digest child built in place in its box.
#[inline(always)]
fn boxed_digest<M: Memoization>(digest: &[u8]) -> alloc::boxed::Box<Node<M>> {
    let mut node = alloc::boxed::Box::<Node<M>>::new_uninit();
    // SAFETY: the allocation is exactly one Node and is fully initialized here.
    let mut node = unsafe {
        node.as_mut_ptr().write(Node::Digest(B256::ZERO));
        node.assume_init()
    };
    if let Node::Digest(d) = &mut *node {
        copy_digest(&mut d.0, digest);
    }
    node
}

/// stwo: copies a 32-byte digest from an RLP buffer at any alignment.
///
/// `B256::from_slice` from an unaligned source called `memmove` (~77
/// instructions on RV64IM, which traps on misaligned access). With an
/// 8-aligned destination this reads the five aligned words that overlap the
/// source bytes (never a word without a source byte, so never another page)
/// and funnel-shifts them: about 25 instructions.
#[inline(always)]
fn copy_digest(dst: &mut [u8; 32], src: &[u8]) {
    let src = &src[..32];
    let d = dst.as_mut_ptr();
    let s = src.as_ptr();
    if cfg!(target_arch = "riscv64") && (d as usize) & 7 == 0 {
        let off = (s as usize) & 7;
        // SAFETY: every word read contains at least one byte of `src`; volatile
        // keeps the compiler from reasoning about the bytes outside it.
        unsafe {
            let d = d.cast::<u64>();
            if off == 0 {
                let w = s.cast::<u64>();
                for i in 0..4 {
                    d.add(i).write(core::ptr::read_volatile(w.add(i)));
                }
            } else {
                let w = s.sub(off).cast::<u64>();
                let sh = (off * 8) as u32;
                let back = 64 - sh;
                let mut cur = core::ptr::read_volatile(w);
                for i in 0..4 {
                    let next = core::ptr::read_volatile(w.add(i + 1));
                    d.add(i).write((cur >> sh) | (next << back));
                    cur = next;
                }
            }
        }
    } else {
        dst.copy_from_slice(src);
    }
}

fn decode_path(buf: &mut &[u8]) -> alloy_rlp::Result<(Nibbles, bool)> {
    let compact = Header::decode_bytes(buf, false)?;
    if compact.is_empty() {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let (is_leaf, odd_len) = match compact[0] >> 4 {
        0b0000 => (false, false),
        0b0001 => (false, true),
        0b0010 => (true, false),
        0b0011 => (true, true),
        _ => return Err(alloy_rlp::Error::Custom("node is not an extension or leaf")),
    };
    // Strip the HP prefix: for odd length, the first nibble of the key is in the low nibble
    // of the first byte; for even length, skip the first byte entirely.
    let nibbles = if odd_len {
        let first = compact[0] & 0x0f;
        let mut n = Nibbles::from_nibbles_unchecked([first]);
        n.extend(&Nibbles::unpack(&compact[1..]));
        n
    } else {
        Nibbles::unpack(&compact[1..])
    };
    Ok((nibbles, is_leaf))
}

fn encode_list<B, T>(values: &[B]) -> Vec<u8>
where
    B: core::borrow::Borrow<T>,
    T: ?Sized + Encodable,
{
    let mut payload_length = 0;
    for value in values {
        payload_length += value.borrow().length();
    }
    let mut out = encode_list_header(payload_length);
    for value in values {
        value.borrow().encode(&mut out);
    }
    out
}
