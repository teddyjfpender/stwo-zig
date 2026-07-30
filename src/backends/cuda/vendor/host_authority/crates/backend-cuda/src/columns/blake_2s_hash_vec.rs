use std::ffi::c_void;
use std::fmt::Debug;

use stwo::core::vcs::blake2_hash::Blake2sHash;

use crate::columns::bindings;

#[derive(Debug)]
pub struct Blake2sHashVec {
    pub(crate) device_ptr: *const Blake2sHash,
    pub(crate) size: usize,
}

unsafe impl Send for Blake2sHashVec {}
unsafe impl Sync for Blake2sHashVec {}

impl Blake2sHashVec {
    pub fn new(device_ptr: *const Blake2sHash, size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self { device_ptr, size }
    }

    pub fn from_vec(host_array: Vec<Blake2sHash>) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let size = host_array.len();
        let device_ptr = unsafe {
            bindings::copy_blake_2s_hash_vec_from_host_to_device(host_array.as_ptr(), size)
        };
        Self::new(device_ptr, size)
    }

    pub fn new_uninitialized(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self::new(unsafe { bindings::cuda_malloc_blake_2s_hash(size) }, size)
    }

    pub fn new_zeroes(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self::new(
            unsafe { bindings::cuda_alloc_zeroes_blake_2s_hash(size) },
            size,
        )
    }

    pub fn copy_from(&mut self, other: &Self) {
        assert!(self.size >= other.size);
        unsafe {
            bindings::copy_blake_2s_hash_vec_from_device_to_device(
                other.device_ptr,
                self.device_ptr,
                other.size,
            );
        }
    }

    pub fn to_vec(&self) -> Vec<Blake2sHash> {
        // Zero-init before the device copy: `set_len` on uninitialized memory is UB-adjacent.
        let mut host_data: Vec<Blake2sHash> = vec![Default::default(); self.size];
        unsafe {
            bindings::copy_blake_2s_hash_vec_from_device_to_host(
                self.device_ptr,
                host_data.as_mut_ptr(),
                self.size,
            );
        }
        host_data
    }

    pub fn get_data(&self, index: usize) -> Blake2sHash {
        let mut host_value = Blake2sHash([0u8; 32]);
        unsafe {
            bindings::cuda_get_blake_2s_hash(
                self.device_ptr,
                &mut host_value as *mut Blake2sHash,
                index,
            )
        };
        host_value
    }

    pub fn set_data(&mut self, index: usize, value: Blake2sHash) {
        unsafe {
            bindings::cuda_set_blake_2s_hash(
                self.device_ptr as *mut Blake2sHash,
                index,
                &value as *const Blake2sHash,
            );
        }
    }

    /// Batch get multiple Blake2s hashes by indices
    ///
    /// # Arguments
    /// * `indices` - List of indices to fetch
    ///
    /// # Returns
    /// Vector of hashes in the same order as indices
    pub fn batch_get(&self, indices: &[usize]) -> Vec<Blake2sHash> {
        if indices.is_empty() {
            return Vec::new();
        }

        // Prepare output buffer
        let mut result: Vec<Blake2sHash> = Vec::with_capacity(indices.len());

        // Convert usize to u32 (CUDA uses u32)
        let indices_u32: Vec<u32> = indices.iter().map(|&i| i as u32).collect();

        unsafe {
            result.set_len(indices.len());
            bindings::cuda_batch_get_blake_2s_hash(
                self.device_ptr,
                result.as_mut_ptr(),
                indices_u32.as_ptr(),
                indices.len() as u32,
            );
        }

        result
    }
}

impl Clone for Blake2sHashVec {
    fn clone(&self) -> Self {
        let mut cloned = Self::new_uninitialized(self.size);
        cloned.copy_from(self);
        cloned
    }
}

impl Drop for Blake2sHashVec {
    fn drop(&mut self) {
        unsafe { bindings::cuda_free_memory(self.device_ptr as *const c_void) };
    }
}

#[cfg(all(test, stwo_cuda_link))]
mod tests {
    use stwo::core::vcs::blake2_hash::Blake2sHash;
    use stwo::prover::backend::Column;

    use super::Blake2sHashVec;

    #[test]
    fn test_get_data_and_column_at_round_trip() {
        let hashes = vec![
            Blake2sHash([0x11; 32]),
            Blake2sHash([0x22; 32]),
            Blake2sHash([0x33; 32]),
        ];

        let column = Blake2sHashVec::from_vec(hashes.clone());

        assert_eq!(column.get_data(0), hashes[0]);
        assert_eq!(column.get_data(1), hashes[1]);
        assert_eq!(column.at(2), hashes[2]);
    }

    #[test]
    fn test_batch_get_round_trip() {
        let hashes = vec![
            Blake2sHash([0x10; 32]),
            Blake2sHash([0x20; 32]),
            Blake2sHash([0x30; 32]),
            Blake2sHash([0x40; 32]),
        ];

        let column = Blake2sHashVec::from_vec(hashes.clone());

        assert_eq!(
            column.batch_get(&[3, 1, 1, 0]),
            vec![hashes[3], hashes[1], hashes[1], hashes[0]]
        );
    }
}
