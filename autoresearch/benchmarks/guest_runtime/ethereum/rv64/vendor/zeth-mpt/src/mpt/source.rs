//! stwo: lookup of witness nodes by digest.
//!
//! `resolve_digests` probes the witness once per digest child of every
//! decoded branch, and almost all of those probes miss (a branch has up to 16
//! children; the witness holds the one or two on the accessed paths).
//! `PrehashedNodes` is an open-addressing table keyed by the first four
//! digest bytes, with the full 32-bit tag stored next to the index, so a miss
//! costs one slot load and a compare instead of a hash, a group probe and a
//! `memcmp` call.

use alloc::vec::Vec;
use alloy_primitives::{map::B256IndexMap, Bytes, B256};

/// A source of RLP-encoded trie nodes keyed by their Keccak-256 digest.
pub trait NodeSource {
    /// Returns the RLP encoding whose Keccak-256 digest is `digest`, if present.
    fn node_rlp(&self, digest: &B256) -> Option<&[u8]>;
}

impl<T: AsRef<[u8]>> NodeSource for B256IndexMap<T> {
    #[inline]
    fn node_rlp(&self, digest: &B256) -> Option<&[u8]> {
        self.get(digest).map(AsRef::as_ref)
    }
}

/// RLP-encoded trie nodes keyed by digest. The caller guarantees that every
/// key is the Keccak-256 digest of its value (as for `B256IndexMap` inputs).
#[derive(Debug, Clone, Default)]
pub struct PrehashedNodes {
    /// `tag << 32 | (entry index + 1)`; 0 marks an empty slot.
    slots: Vec<u64>,
    mask: usize,
    entries: Vec<(B256, Bytes)>,
}

#[inline(always)]
fn tag(digest: &B256) -> u32 {
    let b = digest.as_slice();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

impl PrehashedNodes {
    /// Creates an empty table sized for `capacity` distinct nodes.
    pub fn with_capacity(capacity: usize) -> Self {
        let size = (capacity.max(4) * 4).next_power_of_two();
        Self { slots: alloc::vec![0; size], mask: size - 1, entries: Vec::with_capacity(capacity) }
    }

    /// Inserts a node under its digest; a repeated digest keeps the first value.
    pub fn insert(&mut self, digest: B256, rlp: Bytes) {
        if 2 * (self.entries.len() + 1) > self.slots.len() {
            self.grow();
        }
        let t = tag(&digest);
        let mut i = t as usize & self.mask;
        loop {
            let slot = self.slots[i];
            if slot == 0 {
                self.entries.push((digest, rlp));
                self.slots[i] = (u64::from(t) << 32) | self.entries.len() as u64;
                return;
            }
            if (slot >> 32) as u32 == t && self.entries[(slot as u32 - 1) as usize].0 == digest {
                return;
            }
            i = (i + 1) & self.mask;
        }
    }

    fn grow(&mut self) {
        let size = (self.slots.len() * 2).max(16);
        self.slots = alloc::vec![0; size];
        self.mask = size - 1;
        for (n, (digest, _)) in self.entries.iter().enumerate() {
            let t = tag(digest);
            let mut i = t as usize & self.mask;
            while self.slots[i] != 0 {
                i = (i + 1) & self.mask;
            }
            self.slots[i] = (u64::from(t) << 32) | (n as u64 + 1);
        }
    }

    /// Number of distinct nodes.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the RLP encoding stored under `digest`.
    #[inline]
    pub fn get(&self, digest: &B256) -> Option<&Bytes> {
        if self.slots.is_empty() {
            return None;
        }
        let t = tag(digest);
        let mut i = t as usize & self.mask;
        loop {
            // SAFETY: `i <= mask < slots.len()`; non-zero slots index `entries`.
            let slot = unsafe { *self.slots.get_unchecked(i) };
            if slot == 0 {
                return None;
            }
            if (slot >> 32) as u32 == t {
                let entry = unsafe { self.entries.get_unchecked((slot as u32 - 1) as usize) };
                if entry.0 == *digest {
                    return Some(&entry.1);
                }
            }
            i = (i + 1) & self.mask;
        }
    }
}

impl NodeSource for PrehashedNodes {
    #[inline]
    fn node_rlp(&self, digest: &B256) -> Option<&[u8]> {
        self.get(digest).map(|b| b.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn table_matches_index_map() {
        let mut table = PrehashedNodes::with_capacity(3);
        let mut map = B256IndexMap::<Bytes>::default();
        for i in 0..500u32 {
            let rlp = Bytes::from(alloc::vec![i as u8; 1 + (i as usize % 70)]);
            let d = keccak256(&rlp);
            table.insert(d, rlp.clone());
            map.insert(d, rlp);
        }
        // force tag collisions on the index bits
        let mut d = B256::ZERO;
        for i in 0..50u8 {
            d.0[31] = i;
            table.insert(d, Bytes::from(alloc::vec![i]));
            map.insert(d, Bytes::from(alloc::vec![i]));
        }
        assert_eq!(table.len(), map.len());
        for (k, v) in &map {
            assert_eq!(table.node_rlp(k), Some(v.as_ref()));
        }
        for i in 0..2000u32 {
            let k = keccak256(i.to_le_bytes());
            assert_eq!(table.node_rlp(&k), map.node_rlp(&k));
        }
    }
}
