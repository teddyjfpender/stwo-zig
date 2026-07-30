use std::ffi::c_void;

use stwo::core::fields::qm31::SecureField;

use super::bindings;

#[derive(Debug)]
pub struct SecureFieldVec {
    pub device_ptr: *const u32,
    pub(crate) size: usize,
}

unsafe impl Send for SecureFieldVec {}
unsafe impl Sync for SecureFieldVec {}

impl SecureFieldVec {
    pub fn new(device_ptr: *const u32, size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self { device_ptr, size }
    }
    pub fn from_vec(host_array: Vec<SecureField>) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        // let start_time = Instant::now();
        let device_ptr = unsafe {
            bindings::copy_uint32_t_vec_from_host_to_device(
                host_array.as_ptr() as *const u32,
                4 * host_array.len() as u32,
            )
        };
        // let elapsed_time = Instant::now().duration_since(start_time);

        // let transfer_speed_gbps = (data_size_bytes as f64 / 1_000_000_000.0) /
        // elapsed_time.as_secs_f64();

        let size = host_array.len();
        Self::new(device_ptr, size)
    }

    pub fn new_uninitialized(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let device_ptr = unsafe { bindings::cuda_malloc_uint32_t((4 * size) as u32) };
        Self::new(device_ptr, size)
    }

    pub fn new_zeroes(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let device_ptr = unsafe { bindings::cuda_alloc_zeroes_uint32_t((4 * size) as u32) };
        Self::new(device_ptr, size)
    }

    pub fn copy_from(&mut self, other: &Self) {
        assert!(self.size >= other.size);
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_device(
                other.device_ptr,
                self.device_ptr,
                4 * other.size as u32,
            );
        }
    }

    pub fn to_vec(&self) -> Vec<SecureField> {
        // Zero-init before the device copy: `set_len` on uninitialized memory is UB-adjacent.
        let mut host_data: Vec<SecureField> = vec![Default::default(); self.size];
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_host(
                self.device_ptr,
                host_data.as_mut_ptr() as *const u32,
                4 * self.size as u32,
            );
        }
        host_data
    }

    pub fn get_data(&self, index: usize) -> SecureField {
        let cuda_val =
            unsafe { bindings::cuda_get_secure_field(self.device_ptr as *const c_void, index) };
        SecureField::from(cuda_val)
    }

    pub fn set_data(&mut self, index: usize, value: SecureField) {
        let limbs = value.to_m31_array();

        for (offset, limb) in limbs.into_iter().enumerate() {
            unsafe {
                bindings::cuda_set_uint32_t(
                    self.device_ptr as *const c_void,
                    index * 4 + offset,
                    limb.0,
                );
            }
        }
    }
}

impl Clone for SecureFieldVec {
    fn clone(&self) -> Self {
        let mut cloned = Self::new_uninitialized(self.size);
        cloned.copy_from(self);
        cloned
    }
}

impl Drop for SecureFieldVec {
    fn drop(&mut self) {
        unsafe {
            bindings::cuda_free_memory(self.device_ptr as *const c_void);
        }
    }
}

#[cfg(all(test, stwo_cuda_link))]
mod tests {
    use stwo::core::fields::qm31::SecureField;

    use super::*;

    #[test]
    fn test_constructor() {
        let size = 1 << 5;
        let from_raw = (1..(size + 1) as u32).collect::<Vec<u32>>();
        let host_data = from_raw
            .chunks(4)
            .map(|a| SecureField::from_u32_unchecked(a[0], a[1], a[2], a[3]))
            .collect::<Vec<_>>();
        let secure_field_vec = SecureFieldVec::from_vec(host_data.clone());

        assert_eq!(secure_field_vec.to_vec(), host_data);
        assert_eq!(secure_field_vec.size, host_data.len());
    }
}
