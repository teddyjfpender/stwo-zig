#![allow(dead_code)] // ported intact from the stwo-cuda prototype
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::size_of;

use crate::columns::bindings;

#[must_use = "uploaded device pointer vectors must live until the native call finishes"]
pub(crate) struct UploadedDevicePointerVec {
    device_ptrs: *const *const u32,
}

impl UploadedDevicePointerVec {
    pub(crate) fn upload(host_ptrs: &[*const u32]) -> Self {
        let device_ptrs = unsafe {
            bindings::copy_device_pointer_vec_from_host_to_device(
                host_ptrs.as_ptr(),
                host_ptrs.len(),
            )
        };
        Self { device_ptrs }
    }

    pub(crate) fn as_ptr(&self) -> *const *const u32 {
        self.device_ptrs
    }
}

impl Drop for UploadedDevicePointerVec {
    fn drop(&mut self) {
        if self.device_ptrs.is_null() {
            return;
        }

        // The current proving-facing callers only drop this wrapper after native CUDA entrypoints
        // that synchronize before returning to Rust.
        unsafe {
            bindings::cuda_release_uploaded_pointer_vec(self.device_ptrs);
        }
    }
}

#[must_use = "uploaded device u32 vectors must live until the native call finishes"]
pub(crate) struct UploadedUint32Vec {
    device_ptr: *const u32,
}

impl UploadedUint32Vec {
    pub(crate) fn upload(host_values: &[u32]) -> Self {
        let device_ptr = unsafe {
            bindings::copy_uint32_t_vec_from_host_to_device(
                host_values.as_ptr(),
                host_values.len() as u32,
            )
        };
        Self { device_ptr }
    }

    pub(crate) fn as_ptr(&self) -> *const u32 {
        self.device_ptr
    }
}

impl Drop for UploadedUint32Vec {
    fn drop(&mut self) {
        if self.device_ptr.is_null() {
            return;
        }

        unsafe {
            bindings::cuda_free_memory(self.device_ptr.cast::<c_void>());
        }
    }
}

#[must_use = "uploaded device pod vectors must live until the native call finishes"]
pub(crate) struct UploadedPodVec<T> {
    device_ptr: *const T,
    _marker: PhantomData<T>,
}

impl<T> UploadedPodVec<T> {
    pub(crate) fn upload(host_values: &[T]) -> Self {
        assert_eq!(
            size_of::<T>() % size_of::<u32>(),
            0,
            "UploadedPodVec requires u32-aligned POD element sizes",
        );
        let word_count = host_values.len() * (size_of::<T>() / size_of::<u32>());
        let device_ptr = unsafe {
            bindings::copy_uint32_t_vec_from_host_to_device(
                host_values.as_ptr().cast::<u32>(),
                word_count as u32,
            )
        };
        Self {
            device_ptr: device_ptr.cast(),
            _marker: PhantomData,
        }
    }

    pub(crate) fn as_ptr(&self) -> *const T {
        self.device_ptr
    }
}

impl<T> Drop for UploadedPodVec<T> {
    fn drop(&mut self) {
        if self.device_ptr.is_null() {
            return;
        }

        unsafe {
            bindings::cuda_free_memory(self.device_ptr.cast::<c_void>());
        }
    }
}
