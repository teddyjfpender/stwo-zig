//! Borrowed, canonical preimage table. Used bytes are authenticated before access.
use alloc::{vec, vec::Vec};
use alloy_primitives::{B256, keccak256};
use core::{
    cell::{Cell, RefCell},
    fmt,
};

pub const MAGIC: &[u8; 8] = b"STWOPX01";
pub const HEADER: usize = 24;
pub const DESCRIPTOR: usize = 40;
pub const MAX_INPUT: usize = 16 * 1024 * 1024 - 4;
pub const MAX_RECORDS: usize = 131_072;
pub const MAX_BLOCKS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Limit,
    Order,
    Offset,
    Missing(B256),
    Hash,
    Metadata,
    Rlp,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OP witness {self:?}")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    Eager,
    Lazy,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub lookups: u64,
    pub hashes: u64,
    pub hashed_bytes: u64,
}

#[derive(Debug)]
pub struct Witness<'a> {
    metadata: &'a [u8],
    descriptors: &'a [u8],
    payload: &'a [u8],
    verified: RefCell<Vec<u64>>,
    stats: Cell<Stats>,
}
fn u32_at(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}
impl<'a> Witness<'a> {
    pub fn parse(bytes: &'a [u8], validation: Validation) -> Result<Self, Error> {
        if bytes.len() < HEADER {
            return Err(Error::Length);
        }
        if bytes.len() > MAX_INPUT {
            return Err(Error::Limit);
        }
        if &bytes[..8] != MAGIC || u32_at(bytes, 20) != 0 {
            return Err(Error::Version);
        }
        if u32_at(bytes, 16) != bytes.len() {
            return Err(Error::Length);
        }
        let metadata_len = u32_at(bytes, 8);
        let count = u32_at(bytes, 12);
        if count > MAX_RECORDS {
            return Err(Error::Limit);
        }
        let table_start = HEADER.checked_add(metadata_len).ok_or(Error::Length)?;
        let table_end = table_start
            .checked_add(count * DESCRIPTOR)
            .ok_or(Error::Length)?;
        if table_end > bytes.len() {
            return Err(Error::Length);
        }
        let descriptors = &bytes[table_start..table_end];
        let payload = &bytes[table_end..];
        let mut end = 0usize;
        for i in 0..count {
            let d = &descriptors[i * DESCRIPTOR..(i + 1) * DESCRIPTOR];
            if i > 0 && descriptors[(i - 1) * DESCRIPTOR..(i - 1) * DESCRIPTOR + 32] >= d[..32] {
                return Err(Error::Order);
            }
            if u32_at(d, 32) != end {
                return Err(Error::Offset);
            }
            end = end.checked_add(u32_at(d, 36)).ok_or(Error::Length)?;
            if end > payload.len() {
                return Err(Error::Length);
            }
        }
        if end != payload.len() {
            return Err(Error::Offset);
        }
        let this = Self {
            metadata: &bytes[HEADER..table_start],
            descriptors,
            payload,
            verified: RefCell::new(vec![0; count.div_ceil(64)]),
            stats: Cell::new(Stats::default()),
        };
        if validation == Validation::Eager {
            for i in 0..count {
                this.authenticate(i)?;
            }
        }
        Ok(this)
    }
    pub fn metadata(&self) -> &'a [u8] {
        self.metadata
    }
    pub fn records(&self) -> usize {
        self.descriptors.len() / DESCRIPTOR
    }
    pub fn stats(&self) -> Stats {
        self.stats.get()
    }
    fn authenticate(&self, index: usize) -> Result<&'a [u8], Error> {
        let d = &self.descriptors[index * DESCRIPTOR..(index + 1) * DESCRIPTOR];
        let offset = u32_at(d, 32);
        let value = &self.payload[offset..offset + u32_at(d, 36)];
        let mask = 1u64 << (index % 64);
        if self.verified.borrow()[index / 64] & mask == 0 {
            if keccak256(value).as_slice() != &d[..32] {
                return Err(Error::Hash);
            }
            self.verified.borrow_mut()[index / 64] |= mask;
            let mut stats = self.stats.get();
            stats.hashes += 1;
            stats.hashed_bytes += value.len() as u64;
            self.stats.set(stats);
        }
        Ok(value)
    }
    pub fn get(&self, hash: B256) -> Result<&'a [u8], Error> {
        let mut stats = self.stats.get();
        stats.lookups += 1;
        self.stats.set(stats);
        let mut low = 0;
        let mut high = self.records();
        while low < high {
            let mid = low + (high - low) / 2;
            let key = &self.descriptors[mid * DESCRIPTOR..mid * DESCRIPTOR + 32];
            match key.cmp(hash.as_slice()) {
                core::cmp::Ordering::Less => low = mid + 1,
                core::cmp::Ordering::Greater => high = mid,
                core::cmp::Ordering::Equal => return self.authenticate(mid),
            }
        }
        Err(Error::Missing(hash))
    }
}

/// Canonical producer encoder. Authentication remains the consumer's responsibility.
pub fn encode(metadata: &[u8], records: &[(B256, Vec<u8>)]) -> Result<Vec<u8>, Error> {
    if records.len() > MAX_RECORDS {
        return Err(Error::Limit);
    }
    let total = records.iter().try_fold(
        HEADER + metadata.len() + records.len() * DESCRIPTOR,
        |n, (_, v)| n.checked_add(v.len()).ok_or(Error::Limit),
    )?;
    if total > MAX_INPUT {
        return Err(Error::Limit);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(metadata);
    let mut offset = 0u32;
    for (i, (key, value)) in records.iter().enumerate() {
        if i > 0 && records[i - 1].0 >= *key {
            return Err(Error::Order);
        }
        out.extend_from_slice(key.as_slice());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        offset += value.len() as u32;
    }
    for (_, value) in records {
        out.extend_from_slice(value);
    }
    Ok(out)
}
