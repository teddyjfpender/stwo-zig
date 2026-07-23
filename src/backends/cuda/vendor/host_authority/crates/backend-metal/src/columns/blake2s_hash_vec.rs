use std::sync::OnceLock;

use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo_backend_metal_sys::metal::U32Buffer;

#[derive(Debug)]
pub struct Blake2sHashVec {
    pub(crate) buffer: U32Buffer,
    size: usize,
    host_cache: OnceLock<Vec<Blake2sHash>>,
}

unsafe impl Send for Blake2sHashVec {}
unsafe impl Sync for Blake2sHashVec {}

impl Blake2sHashVec {
    pub(crate) fn from_buffer(buffer: U32Buffer) -> Self {
        assert!(
            buffer.len().is_multiple_of(8),
            "Metal Blake2s hash buffers require eight u32 words per hash"
        );
        let size = buffer.len() / 8;
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn from_vec(host_array: Vec<Blake2sHash>) -> Self {
        let mut raw = Vec::with_capacity(host_array.len() * 8);
        for hash in &host_array {
            for chunk in hash.0.chunks_exact(4) {
                raw.push(u32::from_le_bytes(
                    chunk.try_into().expect("Blake2s hash words are 4 bytes"),
                ));
            }
        }
        let buffer =
            U32Buffer::from_slice(&raw).expect("Metal Blake2sHashVec upload should initialize");
        let host_cache = OnceLock::new();
        let _ = host_cache.set(host_array);
        Self {
            buffer,
            size: raw.len() / 8,
            host_cache,
        }
    }

    pub fn new_uninitialized(size: usize) -> Self {
        Self {
            buffer: U32Buffer::uninitialized(size * 8)
                .expect("Metal Blake2sHashVec allocation should initialize"),
            size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn new_zeroes(size: usize) -> Self {
        Self {
            buffer: U32Buffer::zeroed(size * 8)
                .expect("Metal Blake2sHashVec zero allocation should initialize"),
            size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn copy_from(&mut self, other: &Self) {
        let _ = self.host_cache.take();
        self.buffer
            .copy_from(&other.buffer)
            .expect("Metal Blake2sHashVec copy should succeed");
    }

    pub fn to_vec(&self) -> Vec<Blake2sHash> {
        if let Some(values) = self.host_cache.get() {
            return values.clone();
        }

        // Same contract as `BaseFieldVec::host_slice`: fence before a host read in
        // case the layer is still being written by an in-flight GPU submission.
        stwo_backend_metal_sys::metal::queue_drain()
            .expect("Metal queue drain before host read should succeed");
        let words =
            unsafe { std::slice::from_raw_parts(self.buffer.host_ptr(), self.buffer.len()) };
        let decoded = words
            .chunks_exact(8)
            .map(|chunk| {
                let mut bytes = [0u8; 32];
                for (word_index, word) in chunk.iter().enumerate() {
                    bytes[word_index * 4..(word_index + 1) * 4]
                        .copy_from_slice(&word.to_le_bytes());
                }
                Blake2sHash(bytes)
            })
            .collect::<Vec<_>>();
        let _ = self.host_cache.set(decoded.clone());
        decoded
    }

    pub fn get_data(&self, index: usize) -> Blake2sHash {
        assert!(
            index < self.size,
            "Blake2s hash index {index} out of bounds for len {}",
            self.size
        );
        if let Some(values) = self.host_cache.get() {
            return values[index];
        }

        let words = self
            .buffer
            .read_indices(&(0..8).map(|offset| index * 8 + offset).collect::<Vec<_>>())
            .expect("Metal Blake2sHashVec indexed readback should succeed");
        decode_blake2s_hash_from_words(&words)
    }

    pub fn set_data(&mut self, index: usize, value: Blake2sHash) {
        assert!(
            index < self.size,
            "Blake2s hash index {index} out of bounds for len {}",
            self.size
        );
        let _ = self.host_cache.take();
        for (word_index, chunk) in value.0.chunks_exact(4).enumerate() {
            self.buffer.set(
                index * 8 + word_index,
                u32::from_le_bytes(chunk.try_into().expect("Blake2s hash words are 4 bytes")),
            );
        }
    }

    pub fn batch_get(&self, indices: &[usize]) -> Vec<Blake2sHash> {
        if indices.is_empty() {
            return Vec::new();
        }
        if let Some(values) = self.host_cache.get() {
            return indices.iter().map(|&index| values[index]).collect();
        }

        let mut word_indices = Vec::with_capacity(indices.len() * 8);
        for &index in indices {
            assert!(
                index < self.size,
                "Blake2s hash index {index} out of bounds for len {}",
                self.size
            );
            word_indices.extend((0..8).map(|offset| index * 8 + offset));
        }
        let words = self
            .buffer
            .read_indices(&word_indices)
            .expect("Metal Blake2sHashVec batched readback should succeed");
        words
            .chunks_exact(8)
            .map(decode_blake2s_hash_from_words)
            .collect()
    }
}

fn decode_blake2s_hash_from_words(words: &[u32]) -> Blake2sHash {
    let mut bytes = [0u8; 32];
    for (word_index, word) in words.iter().enumerate() {
        bytes[word_index * 4..(word_index + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    Blake2sHash(bytes)
}

impl Clone for Blake2sHashVec {
    fn clone(&self) -> Self {
        let cloned = Self {
            buffer: self.buffer.clone(),
            size: self.size,
            host_cache: OnceLock::new(),
        };
        if let Some(values) = self.host_cache.get() {
            let _ = cloned.host_cache.set(values.clone());
        }
        cloned
    }
}

impl PartialEq<Vec<Blake2sHash>> for Blake2sHashVec {
    fn eq(&self, other: &Vec<Blake2sHash>) -> bool {
        self.to_vec() == *other
    }
}

impl PartialEq<Blake2sHashVec> for Vec<Blake2sHash> {
    fn eq(&self, other: &Blake2sHashVec) -> bool {
        *self == other.to_vec()
    }
}
