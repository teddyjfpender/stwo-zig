#![allow(dead_code)] // ported intact from the stwo-cuda prototype
use std::ffi::c_void;

use stwo::core::fields::m31::BaseField;

use super::bindings;
use crate::backend::exec_context::{check_cuda, CudaRuntimeError};

#[derive(Debug)]
pub struct BaseFieldVec {
    pub device_ptr: *const u32,
    pub size: usize,
    pub owns_memory: bool,
}
unsafe impl Send for BaseFieldVec {}
unsafe impl Sync for BaseFieldVec {}

impl BaseFieldVec {
    pub fn new(device_ptr: *const u32, size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self {
            device_ptr,
            size,
            owns_memory: true,
        }
    }

    /// Create a BaseFieldVec that references existing device memory without owning it.
    /// The caller is responsible for ensuring the memory outlives this BaseFieldVec.
    /// Drop will NOT free the memory. Clone will produce an owned copy.
    pub fn from_borrowed_ptr(device_ptr: *const u32, size: usize) -> Self {
        Self {
            device_ptr,
            size,
            owns_memory: false,
        }
    }

    pub fn from_vec(host_array: Vec<BaseField>) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let device_ptr = unsafe {
            bindings::copy_uint32_t_vec_from_host_to_device(
                host_array.as_ptr().cast::<u32>(),
                host_array.len() as u32,
            )
        };
        let size = host_array.len();
        Self::new(device_ptr, size)
    }

    pub fn new_uninitialized(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let device_ptr = unsafe { bindings::cuda_malloc_uint32_t(size as u32) };
        Self::new(device_ptr, size)
    }

    pub fn new_zeroes(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let device_ptr = unsafe { bindings::cuda_alloc_zeroes_uint32_t(size as u32) };
        Self::new(device_ptr, size)
    }

    pub fn get_data(&self, index: usize) -> BaseField {
        let value = unsafe { bindings::cuda_get_uint32_t(self.device_ptr as *const c_void, index) };
        BaseField::from_u32_unchecked(value)
    }

    pub fn set_data(&mut self, index: usize, value: BaseField) {
        unsafe {
            bindings::cuda_set_uint32_t(self.device_ptr as *const c_void, index, value.0);
        }
    }

    pub fn copy_from(&mut self, other: &Self) {
        assert!(self.size >= other.size);
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_device(
                other.device_ptr,
                self.device_ptr,
                other.size as u32,
            );
        }
    }

    pub fn copy_from_offset(&mut self, other: &Self, offset: usize) {
        assert!(self.size >= other.size);
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_device_offset(
                other.device_ptr,
                self.device_ptr,
                other.size as u32,
                offset as u32,
            );
        }
    }

    pub fn to_vec(&self) -> Vec<BaseField> {
        // Zero-init before the device copy: `set_len` on uninitialized memory is UB-adjacent.
        let mut host_data: Vec<BaseField> = vec![Default::default(); self.size];
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_host(
                self.device_ptr,
                host_data.as_mut_ptr() as *const u32,
                self.size as u32,
            );
        }
        host_data
    }
    pub fn extend(&mut self, other: &Self) {
        let new_size = self.size + other.size;
        let mut new_vec = Self::new_uninitialized(new_size);
        new_vec.copy_from(self);
        new_vec.copy_from_offset(other, self.size);
        *self = new_vec;
    }

    /// Pads the vector to the target size by filling with zeros.
    /// If the current size is already >= target_size, does nothing.
    pub fn pad_to_size(&mut self, target_size: usize) {
        if self.size >= target_size {
            return;
        }
        // Create new zeroed buffer of target size
        let mut new_vec = Self::new_zeroes(target_size);
        // Copy existing data
        new_vec.copy_from(self);
        // The remaining elements are already zero (from new_zeroes)
        *self = new_vec;
    }

    /// Release an owned allocation through the exact-status default-pool API.
    ///
    /// This is the formal staging counterpart to the legacy void-returning [`Drop`]
    /// path. It consumes the vector and disarms that fallback before issuing the
    /// checked free. A failed free is therefore returned to the caller and may leave
    /// the allocation live, but it is never followed by an unobservable second free.
    /// Borrowed vectors require no release and return success without calling CUDA.
    pub fn release_checked(self) -> Result<(), CudaRuntimeError> {
        self.release_checked_with(|device| unsafe {
            stwo_backend_cuda_kernels::raw::cuda_default_pool_free_checked(device)
        })
    }

    fn release_checked_with(
        mut self,
        release: impl FnOnce(*mut c_void) -> i32,
    ) -> Result<(), CudaRuntimeError> {
        if !self.owns_memory {
            return Ok(());
        }
        // Fail closed: after an exact-status release attempt, Drop must never route
        // this allocation through the legacy void compatibility API.
        self.owns_memory = false;
        check_cuda(
            "base_field_vec_free",
            release(self.device_ptr.cast_mut().cast()),
        )
    }
}

impl Clone for BaseFieldVec {
    fn clone(&self) -> Self {
        let mut cloned = Self::new_uninitialized(self.size);
        cloned.copy_from(self);
        cloned
    }
}

impl Drop for BaseFieldVec {
    fn drop(&mut self) {
        // Legacy compatibility only. Formal default-pool staging must consume the
        // vector through `release_checked` so the CUDA status remains observable.
        if self.owns_memory {
            unsafe {
                bindings::cuda_free_memory(self.device_ptr as *const c_void);
            }
        }
    }
}

#[cfg(test)]
mod ownership_tests {
    use core::ptr::NonNull;

    use super::*;

    fn owned_dangling() -> BaseFieldVec {
        BaseFieldVec {
            device_ptr: NonNull::<u32>::dangling().as_ptr(),
            size: 1,
            owns_memory: true,
        }
    }

    #[test]
    fn checked_release_returns_exact_failure_without_legacy_fallback() {
        let error = owned_dangling().release_checked_with(|_| 719).unwrap_err();
        assert_eq!(
            error,
            CudaRuntimeError::Cuda {
                operation: "base_field_vec_free",
                code: 719,
            }
        );
    }

    #[test]
    fn checked_release_skips_borrowed_memory() {
        BaseFieldVec::from_borrowed_ptr(NonNull::<u32>::dangling().as_ptr(), 1)
            .release_checked_with(|_| panic!("borrowed memory reached checked free"))
            .unwrap();
    }

    #[cfg(not(stwo_cuda_link))]
    #[test]
    fn checked_release_stub_reports_exact_not_supported_status() {
        assert_eq!(
            owned_dangling().release_checked(),
            Err(CudaRuntimeError::Cuda {
                operation: "base_field_vec_free",
                code: 801,
            })
        );
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Uint32Vec {
    pub device_ptr: *const u32,
    pub size: usize,
}
unsafe impl Send for Uint32Vec {}
unsafe impl Sync for Uint32Vec {}

#[allow(unused_variables)]
impl Uint32Vec {
    pub fn new(device_ptr: *const u32, size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self { device_ptr, size }
    }

    pub fn from_vec(host_array: Vec<u32>) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let device_ptr = unsafe {
            bindings::copy_uint32_t_vec_from_host_to_device(
                host_array.as_ptr(),
                host_array.len() as u32,
            )
        };
        let size = host_array.len();
        Self::new(device_ptr, size)
    }

    pub fn new_uninitialized(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self::new(unsafe { bindings::cuda_malloc_uint32_t(size as u32) }, size)
    }

    pub fn new_zeroes(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self::new(
            unsafe { bindings::cuda_alloc_zeroes_uint32_t(size as u32) },
            size,
        )
    }

    pub fn get_data(&self, index: usize) -> u32 {
        unsafe { bindings::cuda_get_uint32_t(self.device_ptr as *const c_void, index) }
    }

    pub fn set_data(&mut self, index: usize, value: u32) {
        unsafe {
            bindings::cuda_set_uint32_t(self.device_ptr as *const c_void, index, value);
        }
    }

    pub fn increase_at(&self, address: u32) {
        unsafe { bindings::cuda_increase_at(self.device_ptr as *const c_void, address) }
    }

    pub fn copy_from(&mut self, other: &Self) {
        assert!(self.size >= other.size);
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_device(
                other.device_ptr,
                self.device_ptr,
                other.size as u32,
            );
        }
    }

    pub fn copy_from_offset(&mut self, other: &Self, offset: usize) {
        assert!(self.size >= other.size);
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_device_offset(
                other.device_ptr,
                self.device_ptr,
                other.size as u32,
                offset as u32,
            );
        }
    }

    pub fn to_vec(&self) -> Vec<u32> {
        // Zero-init before the device copy: `set_len` on uninitialized memory is UB-adjacent.
        let mut host_data: Vec<u32> = vec![Default::default(); self.size];
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_host(
                self.device_ptr,
                host_data.as_mut_ptr() as *const u32,
                self.size as u32,
            );
        }
        host_data
    }

    pub fn extend(&mut self, other: &Self) {
        let new_size = self.size + other.size;
        let mut new_vec = Self::new_uninitialized(new_size);
        new_vec.copy_from(self);
        new_vec.copy_from_offset(other, self.size);
        *self = new_vec;
    }
}

impl Clone for Uint32Vec {
    fn clone(&self) -> Self {
        let mut cloned = Self::new_uninitialized(self.size);
        cloned.copy_from(self);
        cloned
    }
}

impl Drop for Uint32Vec {
    fn drop(&mut self) {
        unsafe { bindings::cuda_free_memory(self.device_ptr as *const c_void) };
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Uint128Vec {
    pub device_ptr: *const u32,
    pub size: usize,
}
unsafe impl Send for Uint128Vec {}
unsafe impl Sync for Uint128Vec {}

#[allow(unused_variables)]
impl Uint128Vec {
    pub fn new(device_ptr: *const u32, size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self { device_ptr, size }
    }

    pub fn from_vec(host_array: Vec<u128>) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        let device_ptr = unsafe {
            bindings::copy_uint32_t_vec_from_host_to_device(
                host_array.as_ptr().cast::<u32>(),
                (host_array.len() * 4) as u32,
            )
        };
        let size = host_array.len();
        Self::new(device_ptr, size)
    }

    pub fn new_uninitialized(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self::new(
            unsafe { bindings::cuda_malloc_uint32_t(4 * size as u32) },
            size,
        )
    }

    pub fn new_zeroes(size: usize) -> Self {
        crate::columns::bindings::ensure_mem_pool_init();
        Self::new(
            unsafe { bindings::cuda_alloc_zeroes_uint32_t(4 * size as u32) },
            size,
        )
    }

    // pub fn get_data(&self, index: usize) -> u32 {
    //     let value = unsafe {
    //         bindings::cuda_get_uint32_t(self.device_ptr as *const c_void, index)
    //     };
    //     value
    // }

    // pub fn set_data(&mut self, index: usize, value: u32) {
    //     unsafe {
    //         bindings::cuda_set_uint32_t(self.device_ptr as *const c_void, index, value);
    //     }
    // }

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

    pub fn to_vec(&self) -> Vec<u128> {
        // Zero-init before the device copy: `set_len` on uninitialized memory is UB-adjacent.
        let mut host_data: Vec<u128> = vec![Default::default(); self.size];
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_host(
                self.device_ptr,
                host_data.as_mut_ptr() as *const u32,
                4 * self.size as u32,
            );
        }
        host_data
    }
}

impl Clone for Uint128Vec {
    fn clone(&self) -> Self {
        let mut cloned = Self::new_uninitialized(self.size);
        cloned.copy_from(self);
        cloned
    }
}

impl Drop for Uint128Vec {
    fn drop(&mut self) {
        unsafe { bindings::cuda_free_memory(self.device_ptr as *const c_void) };
    }
}

#[cfg(all(test, stwo_cuda_link))]
mod tests {

    use super::*;

    #[test]
    fn test_constructor() {
        let size = 1 << 25;
        let host_data = (0..size).map(BaseField::from).collect::<Vec<_>>();
        let base_field_vec = BaseFieldVec::from_vec(host_data.clone());
        assert_eq!(base_field_vec.to_vec(), host_data);
        assert_eq!(base_field_vec.size, host_data.len());
    }

    #[test]
    fn test_zeroes() {
        let size = 64;
        BaseFieldVec::new_zeroes(size);
        BaseFieldVec::new_zeroes(size);
        BaseFieldVec::new_zeroes(size);
        BaseFieldVec::new_zeroes(size);
        BaseFieldVec::new_zeroes(size);
        BaseFieldVec::new_zeroes(size);
        BaseFieldVec::new_zeroes(size);
        let new_zeroes = BaseFieldVec::new_zeroes(size);
        for a in new_zeroes.to_vec().iter() {
            assert_eq!(a, &BaseField::from(0));
        }
    }
}

impl stwo::prover::poly::twiddles::TwiddleBuffer<stwo::prover::poly::BitReversedOrder>
    for BaseFieldVec
{
    fn empty() -> Self {
        BaseFieldVec::from_vec(Vec::new())
    }

    /// Device-side extraction: the reference implementation (`Vec<T>`'s impl in
    /// `stwo::prover::poly::twiddles`) takes one CONTIGUOUS prefix slice per FFT layer
    /// plus a single padding element, so the same selection is performed here as one
    /// device-to-device copy per layer — no host roundtrip of the (potentially
    /// hundreds of MB) full twiddle buffer. The layer offset arithmetic below mirrors
    /// the reference line for line; keep them in sync.
    fn extract_subdomain_twiddles(&self, domain_log_size: u32, subdomain_log_size: u32) -> Self {
        let domain_half_log_size = domain_log_size - 1;
        let subdomain_half_log_size = subdomain_log_size - 1;
        let buf_half_log_size = self.size.ilog2();
        assert!(
            subdomain_half_log_size <= domain_half_log_size
                && domain_half_log_size <= buf_half_log_size,
            "Invalid sizes: subdomain_half={subdomain_half_log_size}, \
             domain_half={domain_half_log_size}, buf_half={buf_half_log_size}"
        );

        let skip_layers = buf_half_log_size - domain_half_log_size;
        let buf_size = 1usize << buf_half_log_size;
        let out_size = 1usize << subdomain_half_log_size;
        let result = BaseFieldVec::new_uninitialized(out_size);

        let mut out_offset = 0usize;
        for layer in 0..subdomain_half_log_size as usize {
            let root_layer = skip_layers as usize + layer;
            let layer_start = buf_size - (buf_size >> root_layer);
            let subdomain_layer_size = 1usize << (subdomain_half_log_size as usize - 1 - layer);
            unsafe {
                bindings::copy_uint32_t_vec_from_device_to_device(
                    self.device_ptr.add(layer_start),
                    result.device_ptr.add(out_offset),
                    subdomain_layer_size as u32,
                );
            }
            out_offset += subdomain_layer_size;
        }
        // Padding to round the output buffer to a power of two.
        unsafe {
            bindings::copy_uint32_t_vec_from_device_to_device(
                self.device_ptr.add(self.size - 1),
                result.device_ptr.add(out_offset),
                1,
            );
        }
        debug_assert_eq!(out_offset + 1, out_size);
        result
    }
}
