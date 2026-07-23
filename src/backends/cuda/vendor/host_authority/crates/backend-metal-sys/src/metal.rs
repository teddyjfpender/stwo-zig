// FFI surface ported from the stwo-metal prototype. The wrappers mirror the C
// entry points in runtime.m one-to-one, so clippy's API-shape lints (argument
// counts, per-function safety-doc boilerplate, complex callback types) are
// allowed wholesale instead of reshaping the vendored surface. `const_is_empty`
// fires on `STWO_METAL_KERNEL_LIBRARY{,_SOURCES}`, which are build-config
// dependent (AOT metallib vs runtime-compiled source) — empty in one
// configuration and non-empty in the other.
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::const_is_empty)]

use core::ffi::c_void;
use std::ffi::CStr;
use std::ptr::NonNull;
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/metal_autogen.rs"));

const ERROR_BUFFER_LEN: usize = 512;

/// FFI-compatible descriptor for one size-group in a multi-group batch point
/// evaluation.  Must match `StwoMetalBatchEvalGroup` in `runtime.m`.
#[repr(C)]
pub struct BatchEvalGroupDescriptor {
    pub flat_coeffs_ptr: *mut c_void,
    pub factors_ptr: *mut c_void,
    pub dst_ptr: *mut c_void,
    pub coeffs_log_len: u32,
    pub n_polys: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MetalRuntimeSupport {
    Available,
    DisabledByConfiguration,
    UnsupportedTarget,
    InitializationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetalError {
    message: String,
}

impl MetalError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for MetalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MetalError {}

#[derive(Debug)]
struct RuntimeHandle {
    raw: NonNull<c_void>,
}

unsafe impl Send for RuntimeHandle {}
unsafe impl Sync for RuntimeHandle {}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        unsafe { ffi::runtime_destroy(self.raw.as_ptr()) };
    }
}

#[derive(Debug)]
pub struct U32Buffer {
    raw: NonNull<c_void>,
    len: usize,
    /// Process-unique id, never reused. Raw pointers (FFI or MTLBuffer addresses) can
    /// alias across alloc/free cycles, which poisoned pointer-keyed caches; key caches
    /// by this instead.
    unique_id: u64,
}

fn next_buffer_unique_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

unsafe impl Send for U32Buffer {}
unsafe impl Sync for U32Buffer {}

impl U32Buffer {
    /// Returns an opaque process-local identifier suitable for internal caching.
    ///
    /// This does not promise pointer stability across processes or serialization.
    /// A process-unique, never-reused identity for this buffer object. Unlike a raw
    /// pointer, it cannot alias a freed buffer, so it is safe as a cache key.
    pub fn identity(&self) -> usize {
        self.unique_id as usize
    }

    /// Returns the raw FFI pointer for this buffer, for use in batch GPU operations.
    pub fn opaque_ptr(&self) -> *mut c_void {
        self.raw.as_ptr()
    }

    pub fn from_slice(values: &[u32]) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let raw = unsafe {
            ffi::buffer_from_host(
                runtime.raw.as_ptr(),
                values.as_ptr(),
                values.len(),
                error_buffer_mut_ptr,
            )
        }?;
        Ok(Self {
            raw,
            len: values.len(),
            unique_id: next_buffer_unique_id(),
        })
    }

    pub fn zeroed(len: usize) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let raw =
            unsafe { ffi::buffer_alloc_zeroed(runtime.raw.as_ptr(), len, error_buffer_mut_ptr) }?;
        Ok(Self {
            raw,
            len,
            unique_id: next_buffer_unique_id(),
        })
    }

    pub fn uninitialized(len: usize) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let raw = unsafe {
            ffi::buffer_alloc_uninitialized(runtime.raw.as_ptr(), len, error_buffer_mut_ptr)
        }?;
        Ok(Self {
            raw,
            len,
            unique_id: next_buffer_unique_id(),
        })
    }

    /// Allocates a private (GPU-only) buffer with the given contents uploaded
    /// from host memory via a staging blit. Private buffers receive driver
    /// optimizations unavailable to shared buffers, but their contents cannot
    /// be read directly by the CPU; readback requires a GPU blit.
    pub fn from_slice_private(values: &[u32]) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let raw = unsafe {
            ffi::buffer_from_host_private(
                runtime.raw.as_ptr(),
                values.as_ptr(),
                values.len(),
                error_buffer_mut_ptr,
            )
        }?;
        Ok(Self {
            raw,
            len: values.len(),
            unique_id: next_buffer_unique_id(),
        })
    }

    /// Allocates an uninitialized private (GPU-only) buffer.
    pub fn uninitialized_private(len: usize) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let raw = unsafe {
            ffi::buffer_alloc_uninitialized_private(runtime.raw.as_ptr(), len, error_buffer_mut_ptr)
        }?;
        Ok(Self {
            raw,
            len,
            unique_id: next_buffer_unique_id(),
        })
    }

    /// Returns true if this buffer uses `MTLResourceStorageModePrivate`.
    pub fn is_private(&self) -> bool {
        unsafe { ffi::buffer_is_private(self.raw.as_ptr()) }
    }

    /// Promotes a shared buffer to private storage in-place by blitting
    /// its contents to a new private buffer and replacing the underlying
    /// Metal buffer object. No-op if already private.
    pub fn promote_to_private(&mut self) -> Result<(), MetalError> {
        if self.is_private() {
            return Ok(());
        }
        let runtime = shared_runtime()?;
        unsafe {
            ffi::buffer_promote_to_private(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> u32 {
        assert!(
            index < self.len,
            "buffer index {index} out of bounds for len {}",
            self.len
        );
        unsafe { ffi::buffer_get(self.raw.as_ptr(), index) }
    }

    pub fn set(&mut self, index: usize, value: u32) {
        assert!(
            index < self.len,
            "buffer index {index} out of bounds for len {}",
            self.len
        );
        unsafe { ffi::buffer_set(self.raw.as_ptr(), index, value) };
    }

    pub fn copy_from(&mut self, other: &Self) -> Result<(), MetalError> {
        assert!(
            self.len >= other.len,
            "destination buffer len {} is smaller than source len {}",
            self.len,
            other.len
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::buffer_copy(
                runtime.raw.as_ptr(),
                other.raw.as_ptr(),
                self.raw.as_ptr(),
                other.len,
                0,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn copy_from_offset(&mut self, other: &Self, offset: usize) -> Result<(), MetalError> {
        assert!(
            offset + other.len <= self.len,
            "destination buffer len {} cannot fit source len {} at offset {}",
            self.len,
            other.len,
            offset
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::buffer_copy(
                runtime.raw.as_ptr(),
                other.raw.as_ptr(),
                self.raw.as_ptr(),
                other.len,
                offset,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn copy_range_from(
        &mut self,
        other: &Self,
        src_offset: usize,
        len: usize,
        dst_offset: usize,
    ) -> Result<(), MetalError> {
        assert!(
            src_offset + len <= other.len,
            "source buffer len {} cannot provide range {}..{}",
            other.len,
            src_offset,
            src_offset + len
        );
        assert!(
            dst_offset + len <= self.len,
            "destination buffer len {} cannot fit range len {} at offset {}",
            self.len,
            len,
            dst_offset
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::buffer_copy_range(
                runtime.raw.as_ptr(),
                other.raw.as_ptr(),
                self.raw.as_ptr(),
                src_offset,
                len,
                dst_offset,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn clone_range(&self, start: usize, len: usize) -> Result<Self, MetalError> {
        let mut cloned = Self::uninitialized(len)?;
        cloned.copy_range_from(self, start, len, 0)?;
        Ok(cloned)
    }

    pub fn to_vec(&self) -> Result<Vec<u32>, MetalError> {
        let runtime = shared_runtime()?;
        let mut values = vec![0u32; self.len];
        unsafe {
            ffi::buffer_read(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                values.as_mut_ptr(),
                self.len,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(values)
    }

    pub unsafe fn host_ptr(&self) -> *const u32 {
        ffi::buffer_host_ptr(self.raw.as_ptr())
    }

    pub fn read_indices(&self, indices: &[usize]) -> Result<Vec<u32>, MetalError> {
        let runtime = shared_runtime()?;
        assert!(
            self.len <= u32::MAX as usize,
            "indexed Metal buffer reads require len to fit in u32"
        );
        let index_values = indices
            .iter()
            .map(|&index| {
                assert!(
                    index < self.len,
                    "buffer index {index} out of bounds for len {}",
                    self.len
                );
                index as u32
            })
            .collect::<Vec<_>>();
        let mut values = vec![0u32; indices.len()];
        unsafe {
            ffi::buffer_read_indices(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                index_values.as_ptr(),
                index_values.len(),
                values.as_mut_ptr(),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(values)
    }

    pub fn bit_reverse(&mut self) -> Result<(), MetalError> {
        assert!(
            self.len.is_power_of_two(),
            "bit reverse requires a power-of-two buffer"
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::bit_reverse_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                self.len.ilog2(),
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn bit_reverse_u32x4(&mut self, element_len: usize) -> Result<(), MetalError> {
        assert!(
            element_len.is_power_of_two(),
            "bit reverse requires a power-of-two element length"
        );
        assert_eq!(
            self.len,
            element_len * 4,
            "u32x4 bit reverse requires exactly four limbs per element"
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::bit_reverse_u32x4(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                element_len.ilog2(),
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn invert_m31_in_place(&mut self) -> Result<(), MetalError> {
        let runtime = shared_runtime()?;
        unsafe {
            ffi::invert_m31_values_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                self.len,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn write_twiddle_level(
        &mut self,
        offset: usize,
        initial_xy: [u32; 2],
        step_xy: [u32; 2],
        level_log_size: u32,
    ) -> Result<(), MetalError> {
        assert!(
            level_log_size > 0,
            "twiddle precompute requires a non-zero level_log_size"
        );
        let level_len = 1usize << (level_log_size - 1);
        assert!(
            offset + level_len <= self.len,
            "twiddle level offset {} with level length {} exceeds buffer len {}",
            offset,
            level_len,
            self.len
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::precompute_twiddle_level_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                offset,
                initial_xy,
                step_xy,
                level_log_size,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn rfft_evaluate_in_place(&mut self, twiddles: &Self) -> Result<(), MetalError> {
        assert!(
            self.len.is_power_of_two(),
            "RFFT evaluate requires a power-of-two value buffer"
        );
        assert_eq!(
            twiddles.len,
            self.len / 2,
            "RFFT evaluate requires a twiddle slice with one half-coset tree tail"
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::rfft_evaluate_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                twiddles.raw.as_ptr(),
                self.len.ilog2(),
                error_buffer_mut_ptr,
            )
        }
    }

    /// Submit RFFT without blocking. Returns a handle to wait on later.
    /// The GPU work is committed and in-flight; call `handle.wait()` before
    /// reading the buffer contents.
    pub fn rfft_evaluate_in_place_async(
        &mut self,
        twiddles: &Self,
    ) -> Result<CommandBufferHandle, MetalError> {
        assert!(
            self.len.is_power_of_two(),
            "RFFT async requires a power-of-two value buffer"
        );
        assert_eq!(
            twiddles.len,
            self.len / 2,
            "RFFT async requires a twiddle slice with one half-coset tree tail"
        );
        let runtime = shared_runtime()?;
        let handle = unsafe {
            ffi::rfft_evaluate_async_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                twiddles.raw.as_ptr(),
                self.len.ilog2(),
                error_buffer_mut_ptr,
            )?
        };
        Ok(CommandBufferHandle {
            raw: NonNull::new(handle).expect("async RFFT returned null handle despite success"),
        })
    }

    pub fn rfft_evaluate_subbuffer_in_place(
        &mut self,
        value_offset: usize,
        values_len: usize,
        twiddles: &Self,
    ) -> Result<(), MetalError> {
        assert!(
            values_len.is_power_of_two(),
            "RFFT subbuffer evaluate requires a power-of-two value buffer"
        );
        assert!(
            value_offset + values_len <= self.len,
            "RFFT subbuffer evaluate range must stay within the backing buffer"
        );
        assert_eq!(
            twiddles.len,
            values_len / 2,
            "RFFT subbuffer evaluate requires a twiddle slice with one half-coset tree tail"
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::rfft_evaluate_subbuffer_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                value_offset,
                values_len.ilog2(),
                twiddles.raw.as_ptr(),
                error_buffer_mut_ptr,
            )
        }
    }

    /// Submit subbuffer RFFT without blocking. Returns a handle to wait on later.
    pub fn rfft_evaluate_subbuffer_in_place_async(
        &mut self,
        value_offset: usize,
        values_len: usize,
        twiddles: &Self,
    ) -> Result<CommandBufferHandle, MetalError> {
        assert!(
            values_len.is_power_of_two(),
            "RFFT async subbuffer requires a power-of-two value buffer"
        );
        assert!(
            value_offset + values_len <= self.len,
            "RFFT async subbuffer range must stay within the backing buffer"
        );
        assert_eq!(
            twiddles.len,
            values_len / 2,
            "RFFT async subbuffer requires a twiddle slice with one half-coset tree tail"
        );
        let runtime = shared_runtime()?;
        let handle = unsafe {
            ffi::rfft_evaluate_subbuffer_async_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                value_offset,
                values_len.ilog2(),
                twiddles.raw.as_ptr(),
                error_buffer_mut_ptr,
            )?
        };
        Ok(CommandBufferHandle {
            raw: NonNull::new(handle)
                .expect("async subbuffer RFFT returned null handle despite success"),
        })
    }

    /// Batch RFFT evaluate: process multiple same-size buffers in a single
    /// GPU command submission, eliminating per-buffer waitUntilCompleted overhead.
    ///
    /// All raw pointers must be valid U32Buffer opaque pointers obtained via
    /// [`opaque_ptr`], each backing a buffer of length `1 << values_log_len`.
    /// `twiddles` must have length `(1 << values_log_len) / 2`.
    pub unsafe fn rfft_evaluate_batch_raw(
        buffer_raw_ptrs: &[*mut c_void],
        values_log_len: u32,
        twiddles: &Self,
    ) -> Result<(), MetalError> {
        if buffer_raw_ptrs.is_empty() {
            return Ok(());
        }
        assert_eq!(
            twiddles.len,
            (1usize << values_log_len) / 2,
            "Batch RFFT requires a twiddle slice with one half-coset tree tail"
        );
        let runtime = shared_runtime()?;
        ffi::rfft_evaluate_multi_u32(
            runtime.raw.as_ptr(),
            buffer_raw_ptrs.as_ptr(),
            buffer_raw_ptrs.len() as u32,
            twiddles.raw.as_ptr(),
            values_log_len,
            error_buffer_mut_ptr,
        )
    }

    pub fn ifft_interpolate_in_place(
        &mut self,
        inverse_twiddles: &Self,
        scale_factor: u32,
    ) -> Result<(), MetalError> {
        assert!(
            self.len.is_power_of_two(),
            "IFFT interpolate requires a power-of-two value buffer"
        );
        assert_eq!(
            inverse_twiddles.len,
            self.len / 2,
            "IFFT interpolate requires an inverse-twiddle slice with one half-coset tree tail"
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::ifft_interpolate_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                inverse_twiddles.raw.as_ptr(),
                self.len.ilog2(),
                scale_factor,
                error_buffer_mut_ptr,
            )
        }
    }

    /// Batched IFFT: encode all columns' IFFT dispatches into ONE command buffer.
    /// Each column is IFFT'd independently. One wait at the end ensures all complete.
    pub fn ifft_interpolate_batch_in_place(
        buffers: &mut [Self],
        inverse_twiddles: &[&Self],
        scale_factors: &[u32],
    ) -> Result<(), MetalError> {
        assert_eq!(buffers.len(), inverse_twiddles.len());
        assert_eq!(buffers.len(), scale_factors.len());
        if buffers.is_empty() {
            return Ok(());
        }
        let runtime = shared_runtime()?;
        let values_ptrs: Vec<*mut std::ffi::c_void> =
            buffers.iter().map(|b| b.raw.as_ptr()).collect();
        let twiddle_ptrs: Vec<*mut std::ffi::c_void> =
            inverse_twiddles.iter().map(|t| t.raw.as_ptr()).collect();
        let log_lens: Vec<u32> = buffers.iter().map(|b| b.len.ilog2()).collect();
        unsafe {
            ffi::ifft_interpolate_batch_u32(
                runtime.raw.as_ptr(),
                &values_ptrs,
                &twiddle_ptrs,
                &log_lens,
                scale_factors,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn ifft_line_interpolate_in_place(
        &mut self,
        inverse_line_twiddles: &Self,
        scale_factor: u32,
    ) -> Result<(), MetalError> {
        assert!(
            self.len.is_power_of_two(),
            "Line IFFT interpolate requires a power-of-two value buffer"
        );
        assert_eq!(
            inverse_line_twiddles.len,
            self.len.saturating_sub(1),
            "Line IFFT interpolate requires stage twiddles of total length len(values)-1"
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::ifft_line_interpolate_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                inverse_line_twiddles.raw.as_ptr(),
                self.len.ilog2(),
                scale_factor,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn batch_eval_at_point_base_field(
        &self,
        factors: &Self,
        coeffs_log_len: u32,
        n_polys: usize,
    ) -> Result<Self, MetalError> {
        let coeffs_size = 1usize << coeffs_log_len;
        assert_eq!(
            self.len,
            coeffs_size * n_polys,
            "batched point evaluation requires a flattened coefficient buffer with coeffs_size * n_polys base-field elements"
        );
        assert_eq!(
            factors.len,
            (coeffs_log_len as usize) * 4,
            "batched point evaluation requires one qm31 folding factor per coefficient level"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(n_polys * 4)?;
        unsafe {
            ffi::batch_eval_at_point_base_field_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                factors.raw.as_ptr(),
                dst.raw.as_ptr(),
                coeffs_log_len,
                n_polys
                    .try_into()
                    .expect("batched point evaluation polynomial count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn batch_eval_first_pass_base_field(
        &self,
        factors: &Self,
        coeffs_log_len: u32,
        n_polys: usize,
    ) -> Result<Self, MetalError> {
        let coeffs_size = 1usize << coeffs_log_len;
        let blocks_per_poly = if coeffs_log_len > 9 {
            coeffs_size >> 9
        } else {
            1
        };
        assert_eq!(
            self.len,
            coeffs_size * n_polys,
            "batched point-evaluation first pass requires a flattened coefficient buffer with coeffs_size * n_polys base-field elements"
        );
        assert_eq!(
            factors.len,
            (coeffs_log_len as usize) * 4,
            "batched point-evaluation first pass requires one qm31 folding factor per coefficient level"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(blocks_per_poly * n_polys * 4)?;
        unsafe {
            ffi::batch_eval_first_pass_base_field_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                factors.raw.as_ptr(),
                dst.raw.as_ptr(),
                coeffs_log_len,
                n_polys.try_into().expect(
                    "batched point-evaluation first-pass polynomial count should fit in u32",
                ),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Evaluate multiple groups of same-size polynomials in a single Metal
    /// command buffer, avoiding per-group GPU round-trip overhead.
    ///
    /// Each entry in `groups` is `(flat_coeffs, factors, coeffs_log_len, n_polys)`.
    /// Returns one `U32Buffer` per group containing `n_polys * 4` u32 results
    /// (packed qm31 values).
    pub fn batch_eval_at_point_multi_group(
        groups: &[(&Self, &Self, u32, usize)],
    ) -> Result<Vec<Self>, MetalError> {
        if groups.is_empty() {
            return Ok(Vec::new());
        }

        let runtime = shared_runtime()?;

        // Allocate destination buffers up front.
        let dst_buffers: Vec<Self> = groups
            .iter()
            .map(|(_, _, _, n_polys)| Self::uninitialized(*n_polys * 4))
            .collect::<Result<Vec<_>, _>>()?;

        // Build FFI descriptors.
        let descriptors: Vec<BatchEvalGroupDescriptor> = groups
            .iter()
            .zip(dst_buffers.iter())
            .map(
                |((coeffs, factors, coeffs_log_len, n_polys), dst)| BatchEvalGroupDescriptor {
                    flat_coeffs_ptr: coeffs.raw.as_ptr(),
                    factors_ptr: factors.raw.as_ptr(),
                    dst_ptr: dst.raw.as_ptr(),
                    coeffs_log_len: *coeffs_log_len,
                    n_polys: (*n_polys)
                        .try_into()
                        .expect("multi-group batch eval polynomial count should fit in u32"),
                },
            )
            .collect();

        unsafe {
            ffi::batch_eval_at_point_multi_group_u32(
                runtime.raw.as_ptr(),
                descriptors.as_ptr(),
                descriptors
                    .len()
                    .try_into()
                    .expect("multi-group batch eval group count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }

        Ok(dst_buffers)
    }

    /// Evaluate multiple same-size polynomials at a point using the transposed
    /// dot-product algorithm: precomputed QM31 basis evaluations are dotted
    /// against M31 coefficients on the GPU with 256 threads per polynomial.
    ///
    /// `flat_coeffs`: flattened coefficient buffer (n_polys * n_coeffs M31 values)
    /// `basis_evals`: precomputed QM31 basis values (n_coeffs * 4 u32 values)
    /// `n_polys`: number of polynomials
    /// `n_coeffs`: number of coefficients per polynomial
    ///
    /// Returns a buffer of n_polys * 4 u32 values (packed QM31 results).
    pub fn batch_eval_at_point_transposed(
        flat_coeffs: &Self,
        basis_evals: &Self,
        n_polys: usize,
        n_coeffs: usize,
    ) -> Result<Self, MetalError> {
        assert_eq!(
            flat_coeffs.len,
            n_polys * n_coeffs,
            "transposed eval requires flat_coeffs with n_polys * n_coeffs elements"
        );
        assert_eq!(
            basis_evals.len,
            n_coeffs * 4,
            "transposed eval requires basis_evals with n_coeffs * 4 elements (packed QM31)"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(n_polys * 4)?;
        unsafe {
            ffi::batch_eval_at_point_transposed_u32(
                runtime.raw.as_ptr(),
                flat_coeffs.raw.as_ptr(),
                basis_evals.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_polys
                    .try_into()
                    .expect("transposed eval polynomial count should fit in u32"),
                n_coeffs
                    .try_into()
                    .expect("transposed eval coefficient count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Computes the barycentric evaluation: sum(eval_values[i] * weights[i])
    /// where eval_values is M31 and weights is QM31, returning a single QM31.
    pub fn barycentric_eval_at_point(
        eval_values: &Self,
        weights: &Self,
    ) -> Result<[u32; 4], MetalError> {
        let n_elements: u32 = eval_values
            .len
            .try_into()
            .expect("barycentric eval element count should fit in u32");
        assert_eq!(
            weights.len,
            eval_values.len * 4,
            "barycentric eval expects weights buffer with 4 * n_elements u32 values (QM31)"
        );

        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(4)?;
        unsafe {
            ffi::barycentric_eval_at_point_u32(
                runtime.raw.as_ptr(),
                eval_values.raw.as_ptr(),
                weights.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_elements,
                error_buffer_mut_ptr,
            )?;
        }
        let result = dst.to_vec()?;
        Ok([result[0], result[1], result[2], result[3]])
    }

    pub fn fix_first_variable_base_field(
        &self,
        assignment_limbs: [u32; 4],
    ) -> Result<Self, MetalError> {
        assert!(
            self.len.is_power_of_two() && self.len >= 2,
            "base-field MLE fix-first-variable requires a power-of-two buffer with at least two evaluations"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized((self.len / 2) * 4)?;
        unsafe {
            ffi::fix_first_variable_base_field_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                dst.raw.as_ptr(),
                self.len.ilog2(),
                assignment_limbs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn fix_first_variable_secure_field(
        &self,
        assignment_limbs: [u32; 4],
    ) -> Result<Self, MetalError> {
        assert!(
            self.len.is_multiple_of(4),
            "secure-field MLE fix-first-variable requires four limbs per evaluation"
        );
        let element_len = self.len / 4;
        assert!(
            element_len.is_power_of_two() && element_len >= 2,
            "secure-field MLE fix-first-variable requires a power-of-two element count with at least two evaluations"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized((element_len / 2) * 4)?;
        unsafe {
            ffi::fix_first_variable_secure_field_u32x4(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                dst.raw.as_ptr(),
                element_len.ilog2(),
                assignment_limbs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn gkr_gen_eq_evals_from_factors(
        factors: &Self,
        y_size: usize,
        v_limbs: [u32; 4],
    ) -> Result<Self, MetalError> {
        let eval_count = 1usize
            .checked_shl(y_size as u32)
            .expect("GKR eq-eval size should fit in usize");
        assert_eq!(
            factors.len,
            y_size * 2 * 4,
            "GKR eq-eval generation requires two qm31 factors per input coordinate"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(eval_count * 4)?;
        unsafe {
            ffi::gkr_gen_eq_evals_u32x4(
                runtime.raw.as_ptr(),
                factors.raw.as_ptr(),
                dst.raw.as_ptr(),
                y_size
                    .try_into()
                    .expect("GKR eq-eval y-size should fit in u32"),
                v_limbs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn gkr_next_grand_product_layer(&self) -> Result<Self, MetalError> {
        assert!(
            self.len.is_multiple_of(8),
            "GKR next grand-product layer requires an even number of secure-field evaluations"
        );
        let input_len = self.len / 4;
        assert!(
            input_len.is_power_of_two() && input_len >= 2,
            "GKR next grand-product layer requires a power-of-two logical input length with at least two evaluations"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized((input_len / 2) * 4)?;
        unsafe {
            ffi::gkr_next_grand_product_layer_u32x4(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                dst.raw.as_ptr(),
                input_len.ilog2(),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn gkr_next_logup_generic_layer(
        numerators: &Self,
        denominators: &Self,
    ) -> Result<(Self, Self), MetalError> {
        assert_eq!(
            numerators.len, denominators.len,
            "GKR next generic layer requires matching numerator and denominator lengths"
        );
        assert!(
            numerators.len.is_multiple_of(8),
            "GKR next generic layer requires an even number of secure-field evaluations"
        );
        let input_len = numerators.len / 4;
        assert!(
            input_len.is_power_of_two() && input_len >= 2,
            "GKR next generic layer requires a power-of-two logical input length with at least two evaluations"
        );
        let runtime = shared_runtime()?;
        let next_numerators = Self::uninitialized((input_len / 2) * 4)?;
        let next_denominators = Self::uninitialized((input_len / 2) * 4)?;
        unsafe {
            ffi::gkr_next_logup_generic_layer_u32x4(
                runtime.raw.as_ptr(),
                numerators.raw.as_ptr(),
                denominators.raw.as_ptr(),
                next_numerators.raw.as_ptr(),
                next_denominators.raw.as_ptr(),
                input_len.ilog2(),
                error_buffer_mut_ptr,
            )?;
        }
        Ok((next_numerators, next_denominators))
    }

    pub fn gkr_next_logup_multiplicities_layer(
        numerators: &Self,
        denominators: &Self,
    ) -> Result<(Self, Self), MetalError> {
        assert!(
            numerators.len * 4 == denominators.len,
            "GKR next multiplicities layer requires one base-field numerator per secure-field denominator element"
        );
        assert!(
            numerators.len.is_power_of_two() && numerators.len >= 2,
            "GKR next multiplicities layer requires a power-of-two logical input length with at least two evaluations"
        );
        let runtime = shared_runtime()?;
        let next_numerators = Self::uninitialized((numerators.len / 2) * 4)?;
        let next_denominators = Self::uninitialized((numerators.len / 2) * 4)?;
        unsafe {
            ffi::gkr_next_logup_multiplicities_layer_u32(
                runtime.raw.as_ptr(),
                numerators.raw.as_ptr(),
                denominators.raw.as_ptr(),
                next_numerators.raw.as_ptr(),
                next_denominators.raw.as_ptr(),
                numerators.len.ilog2(),
                error_buffer_mut_ptr,
            )?;
        }
        Ok((next_numerators, next_denominators))
    }

    pub fn gkr_next_logup_singles_layer(denominators: &Self) -> Result<(Self, Self), MetalError> {
        assert!(
            denominators.len.is_multiple_of(8),
            "GKR next singles layer requires an even number of secure-field evaluations"
        );
        let input_len = denominators.len / 4;
        assert!(
            input_len.is_power_of_two() && input_len >= 2,
            "GKR next singles layer requires a power-of-two logical input length with at least two evaluations"
        );
        let runtime = shared_runtime()?;
        let next_numerators = Self::uninitialized((input_len / 2) * 4)?;
        let next_denominators = Self::uninitialized((input_len / 2) * 4)?;
        unsafe {
            ffi::gkr_next_logup_singles_layer_u32x4(
                runtime.raw.as_ptr(),
                denominators.raw.as_ptr(),
                next_numerators.raw.as_ptr(),
                next_denominators.raw.as_ptr(),
                input_len.ilog2(),
                error_buffer_mut_ptr,
            )?;
        }
        Ok((next_numerators, next_denominators))
    }

    pub fn gkr_sum_grand_product(
        eq_evals: &Self,
        input_layer: &Self,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        assert_eq!(
            input_layer.len,
            eq_evals.len * 4,
            "GKR grand-product sum requires four secure-field evaluations per eq-eval term"
        );
        let n_terms = eq_evals.len / 4;
        let runtime = shared_runtime()?;
        unsafe {
            ffi::gkr_sum_grand_product_u32x4(
                runtime.raw.as_ptr(),
                eq_evals.raw.as_ptr(),
                input_layer.raw.as_ptr(),
                n_terms
                    .try_into()
                    .expect("GKR grand-product term count should fit in u32"),
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn gkr_sum_logup_generic(
        eq_evals: &Self,
        numerators: &Self,
        denominators: &Self,
        lambda_limbs: [u32; 4],
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        assert_eq!(
            numerators.len, denominators.len,
            "GKR generic sum requires matching numerator and denominator lengths"
        );
        assert_eq!(
            numerators.len,
            eq_evals.len * 4,
            "GKR generic sum requires four secure-field numerator evaluations per eq-eval term"
        );
        let n_terms = eq_evals.len / 4;
        let runtime = shared_runtime()?;
        unsafe {
            ffi::gkr_sum_logup_generic_u32x4(
                runtime.raw.as_ptr(),
                eq_evals.raw.as_ptr(),
                numerators.raw.as_ptr(),
                denominators.raw.as_ptr(),
                n_terms
                    .try_into()
                    .expect("GKR generic term count should fit in u32"),
                lambda_limbs,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn gkr_sum_logup_multiplicities(
        eq_evals: &Self,
        numerators: &Self,
        denominators: &Self,
        lambda_limbs: [u32; 4],
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        assert_eq!(
            denominators.len,
            eq_evals.len * 4,
            "GKR multiplicities sum requires four denominator evaluations per eq-eval term"
        );
        assert_eq!(
            numerators.len, eq_evals.len,
            "GKR multiplicities sum requires four base-field numerators per eq-eval term"
        );
        let n_terms = eq_evals.len / 4;
        let runtime = shared_runtime()?;
        unsafe {
            ffi::gkr_sum_logup_multiplicities_u32(
                runtime.raw.as_ptr(),
                eq_evals.raw.as_ptr(),
                numerators.raw.as_ptr(),
                denominators.raw.as_ptr(),
                n_terms
                    .try_into()
                    .expect("GKR multiplicities term count should fit in u32"),
                lambda_limbs,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn gkr_sum_logup_singles(
        eq_evals: &Self,
        denominators: &Self,
        lambda_limbs: [u32; 4],
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        assert_eq!(
            denominators.len,
            eq_evals.len * 4,
            "GKR singles sum requires four denominator evaluations per eq-eval term"
        );
        let n_terms = eq_evals.len / 4;
        let runtime = shared_runtime()?;
        unsafe {
            ffi::gkr_sum_logup_singles_u32x4(
                runtime.raw.as_ptr(),
                eq_evals.raw.as_ptr(),
                denominators.raw.as_ptr(),
                n_terms
                    .try_into()
                    .expect("GKR singles term count should fit in u32"),
                lambda_limbs,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn inclusive_prefix_sum_bit_rev_circle_domain_in_place(
        &mut self,
    ) -> Result<(), MetalError> {
        assert!(
            self.len.is_power_of_two(),
            "prefix sum requires a power-of-two base-field buffer"
        );
        let runtime = shared_runtime()?;
        unsafe {
            ffi::inclusive_prefix_sum_bit_rev_circle_domain_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                self.len.ilog2(),
                error_buffer_mut_ptr,
            )
        }
    }

    /// Compute M31 sum of 4 coordinate columns via batched GPU parallel reduction.
    /// All 4 reductions in a single command buffer. Returns [sum0, sum1, sum2, sum3].
    pub fn reduce_sum_m31_4col(cols: [&Self; 4]) -> Result<[u32; 4], MetalError> {
        let n_elements: u32 = cols[0]
            .len
            .try_into()
            .expect("reduce_sum_m31_4col element count should fit in u32");
        let runtime = shared_runtime()?;
        let output = Self::uninitialized(4)?;
        unsafe {
            ffi::reduce_sum_m31_4col(
                runtime.raw.as_ptr(),
                [
                    cols[0].raw.as_ptr(),
                    cols[1].raw.as_ptr(),
                    cols[2].raw.as_ptr(),
                    cols[3].raw.as_ptr(),
                ],
                output.raw.as_ptr(),
                n_elements,
                error_buffer_mut_ptr,
            )?;
        }
        let raw = output.to_vec()?;
        Ok([raw[0], raw[1], raw[2], raw[3]])
    }

    /// In-place prefix sum with constant subtraction for 4 coordinate columns.
    /// All 4 prefix sums in a single command buffer.
    pub fn prefix_sum_subtract_m31_4col(
        cols: [&mut Self; 4],
        cumsum_shifts: [u32; 4],
    ) -> Result<(), MetalError> {
        let n_elements: u32 = cols[0]
            .len
            .try_into()
            .expect("prefix_sum_subtract_m31_4col element count should fit in u32");
        let runtime = shared_runtime()?;
        unsafe {
            ffi::prefix_sum_subtract_m31_4col(
                runtime.raw.as_ptr(),
                [
                    cols[0].raw.as_ptr(),
                    cols[1].raw.as_ptr(),
                    cols[2].raw.as_ptr(),
                    cols[3].raw.as_ptr(),
                ],
                &cumsum_shifts,
                n_elements,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn permute_coset_to_circle_domain_bit_reversed(&self) -> Result<Self, MetalError> {
        assert!(
            self.len.is_power_of_two(),
            "coset permutation requires a power-of-two buffer"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(self.len)?;
        unsafe {
            ffi::permute_coset_to_circle_domain_bit_reversed_u32(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                dst.raw.as_ptr(),
                self.len.ilog2(),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn pack_secure_column_coords(coord_columns: [&Self; 4]) -> Result<Self, MetalError> {
        let [coord_0, coord_1, coord_2, coord_3] = coord_columns;
        let len = coord_0.len;
        assert_eq!(
            coord_1.len, len,
            "secure-column packing requires equal coordinate lengths"
        );
        assert_eq!(
            coord_2.len, len,
            "secure-column packing requires equal coordinate lengths"
        );
        assert_eq!(
            coord_3.len, len,
            "secure-column packing requires equal coordinate lengths"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(len * 4)?;
        unsafe {
            ffi::pack_secure_column_coords_u32x4(
                runtime.raw.as_ptr(),
                coord_0.raw.as_ptr(),
                coord_1.raw.as_ptr(),
                coord_2.raw.as_ptr(),
                coord_3.raw.as_ptr(),
                dst.raw.as_ptr(),
                len.try_into()
                    .expect("secure-column packing logical length should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn unpack_secure_column_coords(&self) -> Result<[Self; 4], MetalError> {
        assert!(
            self.len.is_multiple_of(4),
            "secure-column unpacking requires four limbs per element"
        );
        let len = self.len / 4;
        let runtime = shared_runtime()?;
        let coord_0 = Self::uninitialized(len)?;
        let coord_1 = Self::uninitialized(len)?;
        let coord_2 = Self::uninitialized(len)?;
        let coord_3 = Self::uninitialized(len)?;
        unsafe {
            ffi::unpack_secure_column_coords_u32x4(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                coord_0.raw.as_ptr(),
                coord_1.raw.as_ptr(),
                coord_2.raw.as_ptr(),
                coord_3.raw.as_ptr(),
                len.try_into()
                    .expect("secure-column unpacking logical length should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok([coord_0, coord_1, coord_2, coord_3])
    }

    pub fn accumulate_secure_columns_coords(
        lhs_columns: [&Self; 4],
        rhs_columns: [&Self; 4],
    ) -> Result<[Self; 4], MetalError> {
        let [lhs_0, lhs_1, lhs_2, lhs_3] = lhs_columns;
        let [rhs_0, rhs_1, rhs_2, rhs_3] = rhs_columns;
        let element_len = lhs_0.len;
        assert_eq!(lhs_1.len, element_len);
        assert_eq!(lhs_2.len, element_len);
        assert_eq!(lhs_3.len, element_len);
        assert_eq!(rhs_0.len, element_len);
        assert_eq!(rhs_1.len, element_len);
        assert_eq!(rhs_2.len, element_len);
        assert_eq!(rhs_3.len, element_len);

        let runtime = shared_runtime()?;
        let dst_0 = Self::uninitialized(element_len)?;
        let dst_1 = Self::uninitialized(element_len)?;
        let dst_2 = Self::uninitialized(element_len)?;
        let dst_3 = Self::uninitialized(element_len)?;
        unsafe {
            ffi::accumulate_secure_columns_coords_u32x4(
                runtime.raw.as_ptr(),
                lhs_0.raw.as_ptr(),
                lhs_1.raw.as_ptr(),
                lhs_2.raw.as_ptr(),
                lhs_3.raw.as_ptr(),
                rhs_0.raw.as_ptr(),
                rhs_1.raw.as_ptr(),
                rhs_2.raw.as_ptr(),
                rhs_3.raw.as_ptr(),
                dst_0.raw.as_ptr(),
                dst_1.raw.as_ptr(),
                dst_2.raw.as_ptr(),
                dst_3.raw.as_ptr(),
                element_len
                    .try_into()
                    .expect("secure-column accumulation length should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok([dst_0, dst_1, dst_2, dst_3])
    }

    pub fn lift_accumulate_secure_columns_coords(
        lifted_columns: [&Self; 4],
        current_columns: [&Self; 4],
    ) -> Result<[Self; 4], MetalError> {
        let [lifted_0, lifted_1, lifted_2, lifted_3] = lifted_columns;
        let [current_0, current_1, current_2, current_3] = current_columns;
        let current_len = current_0.len;
        assert_eq!(current_1.len, current_len);
        assert_eq!(current_2.len, current_len);
        assert_eq!(current_3.len, current_len);
        assert!(current_len.is_power_of_two() && current_len >= 2);
        let lifted_len = lifted_0.len;
        assert_eq!(lifted_1.len, lifted_len);
        assert_eq!(lifted_2.len, lifted_len);
        assert_eq!(lifted_3.len, lifted_len);
        assert!(lifted_len.is_power_of_two() && lifted_len >= 2);
        assert!(
            current_len >= lifted_len,
            "lift-and-accumulate requires current length >= lifted length"
        );
        let log_ratio = current_len.ilog2() - lifted_len.ilog2();

        let runtime = shared_runtime()?;
        let dst_0 = Self::uninitialized(current_len)?;
        let dst_1 = Self::uninitialized(current_len)?;
        let dst_2 = Self::uninitialized(current_len)?;
        let dst_3 = Self::uninitialized(current_len)?;
        unsafe {
            ffi::lift_accumulate_secure_columns_coords_u32x4(
                runtime.raw.as_ptr(),
                lifted_0.raw.as_ptr(),
                lifted_1.raw.as_ptr(),
                lifted_2.raw.as_ptr(),
                lifted_3.raw.as_ptr(),
                current_0.raw.as_ptr(),
                current_1.raw.as_ptr(),
                current_2.raw.as_ptr(),
                current_3.raw.as_ptr(),
                dst_0.raw.as_ptr(),
                dst_1.raw.as_ptr(),
                dst_2.raw.as_ptr(),
                dst_3.raw.as_ptr(),
                current_len.ilog2(),
                log_ratio,
                error_buffer_mut_ptr,
            )?;
        }
        Ok([dst_0, dst_1, dst_2, dst_3])
    }

    pub fn fri_fold_circle_into_line_first_layer_u32x4(
        &self,
        inverse_y_factors: &Self,
        alpha_limbs: [u32; 4],
    ) -> Result<Self, MetalError> {
        assert!(
            self.len.is_multiple_of(8),
            "fri first-layer fold requires an even number of secure-field elements"
        );
        let element_len = self.len / 4;
        let output_len = element_len / 2;
        assert_eq!(
            inverse_y_factors.len, output_len,
            "fri first-layer fold requires one inverse-y factor per output element"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len * 4)?;
        unsafe {
            ffi::fri_fold_circle_into_line_first_layer_u32x4(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                dst.raw.as_ptr(),
                inverse_y_factors.raw.as_ptr(),
                element_len.ilog2(),
                alpha_limbs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn fri_fold_circle_into_line_accumulate_from_coords_u32x4(
        src_columns: [&Self; 4],
        dst_columns: [&mut Self; 4],
        inverse_y_factors: &Self,
        alpha_limbs: [u32; 4],
        alpha_sq_limbs: [u32; 4],
    ) -> Result<(), MetalError> {
        let [src_0, src_1, src_2, src_3] = src_columns;
        let element_len = src_0.len;
        assert_eq!(src_1.len, element_len);
        assert_eq!(src_2.len, element_len);
        assert_eq!(src_3.len, element_len);
        assert!(
            element_len.is_multiple_of(2),
            "fri first-layer accumulation requires an even number of secure-field elements"
        );
        let output_len = element_len / 2;
        assert_eq!(
            inverse_y_factors.len, output_len,
            "fri first-layer accumulation requires one inverse-y factor per output element"
        );
        let [dst_0, dst_1, dst_2, dst_3] = dst_columns;
        assert_eq!(
            dst_0.len, output_len,
            "fri first-layer accumulation requires destination coordinate buffers sized to the output length"
        );
        assert_eq!(dst_1.len, output_len);
        assert_eq!(dst_2.len, output_len);
        assert_eq!(dst_3.len, output_len);
        let runtime = shared_runtime()?;
        unsafe {
            ffi::fri_fold_circle_into_line_accumulate_coords_u32x4(
                runtime.raw.as_ptr(),
                src_0.raw.as_ptr(),
                src_1.raw.as_ptr(),
                src_2.raw.as_ptr(),
                src_3.raw.as_ptr(),
                dst_0.raw.as_ptr(),
                dst_1.raw.as_ptr(),
                dst_2.raw.as_ptr(),
                dst_3.raw.as_ptr(),
                inverse_y_factors.raw.as_ptr(),
                element_len.ilog2(),
                alpha_limbs,
                alpha_sq_limbs,
                error_buffer_mut_ptr,
            )
        }
    }

    pub fn fri_fold_circle_into_line_first_layer_from_coords_u32x4(
        src_columns: [&Self; 4],
        inverse_y_factors: &Self,
        alpha_limbs: [u32; 4],
    ) -> Result<[Self; 4], MetalError> {
        let [src_0, src_1, src_2, src_3] = src_columns;
        let element_len = src_0.len;
        assert_eq!(src_1.len, element_len);
        assert_eq!(src_2.len, element_len);
        assert_eq!(src_3.len, element_len);
        assert!(
            element_len.is_multiple_of(2),
            "fri first-layer coordinate fold requires an even number of secure-field elements"
        );
        let output_len = element_len / 2;
        assert_eq!(
            inverse_y_factors.len, output_len,
            "fri first-layer coordinate fold requires one inverse-y factor per output element"
        );
        let runtime = shared_runtime()?;
        let dst_0 = Self::uninitialized(output_len)?;
        let dst_1 = Self::uninitialized(output_len)?;
        let dst_2 = Self::uninitialized(output_len)?;
        let dst_3 = Self::uninitialized(output_len)?;
        unsafe {
            ffi::fri_fold_circle_into_line_first_layer_coords_u32x4(
                runtime.raw.as_ptr(),
                src_0.raw.as_ptr(),
                src_1.raw.as_ptr(),
                src_2.raw.as_ptr(),
                src_3.raw.as_ptr(),
                dst_0.raw.as_ptr(),
                dst_1.raw.as_ptr(),
                dst_2.raw.as_ptr(),
                dst_3.raw.as_ptr(),
                inverse_y_factors.raw.as_ptr(),
                element_len.ilog2(),
                alpha_limbs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok([dst_0, dst_1, dst_2, dst_3])
    }

    pub fn fri_fold_line_step_from_coords_u32x4(
        src_columns: [&Self; 4],
        inverse_x_factors: &Self,
        alpha_limbs: [u32; 4],
    ) -> Result<[Self; 4], MetalError> {
        let [src_0, src_1, src_2, src_3] = src_columns;
        let element_len = src_0.len;
        assert_eq!(src_1.len, element_len);
        assert_eq!(src_2.len, element_len);
        assert_eq!(src_3.len, element_len);
        assert!(
            element_len.is_multiple_of(2),
            "fri line-fold step requires an even number of secure-field elements"
        );
        let output_len = element_len / 2;
        assert_eq!(
            inverse_x_factors.len, output_len,
            "fri line-fold step requires one inverse-x factor per output element"
        );
        let runtime = shared_runtime()?;
        let dst_0 = Self::uninitialized(output_len)?;
        let dst_1 = Self::uninitialized(output_len)?;
        let dst_2 = Self::uninitialized(output_len)?;
        let dst_3 = Self::uninitialized(output_len)?;
        unsafe {
            ffi::fri_fold_line_step_coords_u32x4(
                runtime.raw.as_ptr(),
                src_0.raw.as_ptr(),
                src_1.raw.as_ptr(),
                src_2.raw.as_ptr(),
                src_3.raw.as_ptr(),
                dst_0.raw.as_ptr(),
                dst_1.raw.as_ptr(),
                dst_2.raw.as_ptr(),
                dst_3.raw.as_ptr(),
                inverse_x_factors.raw.as_ptr(),
                element_len.ilog2(),
                alpha_limbs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok([dst_0, dst_1, dst_2, dst_3])
    }

    /// Async variant: submits the fold step without blocking.
    /// Returns (destination buffers, command buffer handle).
    pub fn fri_fold_line_step_from_coords_u32x4_async(
        src_columns: [&Self; 4],
        inverse_x_factors: &Self,
        alpha_limbs: [u32; 4],
    ) -> Result<([Self; 4], CommandBufferHandle), MetalError> {
        let [src_0, src_1, src_2, src_3] = src_columns;
        let element_len = src_0.len;
        assert_eq!(src_1.len, element_len);
        assert_eq!(src_2.len, element_len);
        assert_eq!(src_3.len, element_len);
        assert!(
            element_len.is_multiple_of(2),
            "fri line-fold step requires an even number of secure-field elements"
        );
        let output_len = element_len / 2;
        assert_eq!(
            inverse_x_factors.len, output_len,
            "fri line-fold step requires one inverse-x factor per output element"
        );
        let runtime = shared_runtime()?;
        let dst_0 = Self::uninitialized(output_len)?;
        let dst_1 = Self::uninitialized(output_len)?;
        let dst_2 = Self::uninitialized(output_len)?;
        let dst_3 = Self::uninitialized(output_len)?;
        let handle_ptr = unsafe {
            ffi::fri_fold_line_step_coords_u32x4_async(
                runtime.raw.as_ptr(),
                src_0.raw.as_ptr(),
                src_1.raw.as_ptr(),
                src_2.raw.as_ptr(),
                src_3.raw.as_ptr(),
                dst_0.raw.as_ptr(),
                dst_1.raw.as_ptr(),
                dst_2.raw.as_ptr(),
                dst_3.raw.as_ptr(),
                inverse_x_factors.raw.as_ptr(),
                element_len.ilog2(),
                alpha_limbs,
                error_buffer_mut_ptr,
            )
        }?;
        let handle = CommandBufferHandle {
            raw: NonNull::new(handle_ptr).expect("async fri fold returned null despite success"),
        };
        Ok(([dst_0, dst_1, dst_2, dst_3], handle))
    }

    pub fn fri_fold_line_step_u32x4(
        &self,
        inverse_x_factors: &Self,
        alpha_limbs: [u32; 4],
    ) -> Result<Self, MetalError> {
        assert!(
            self.len.is_multiple_of(8),
            "fri line-fold step requires an even number of secure-field elements"
        );
        let element_len = self.len / 4;
        let output_len = element_len / 2;
        assert_eq!(
            inverse_x_factors.len, output_len,
            "fri line-fold step requires one inverse-x factor per output element"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len * 4)?;
        unsafe {
            ffi::fri_fold_line_step_u32x4(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                dst.raw.as_ptr(),
                inverse_x_factors.raw.as_ptr(),
                element_len.ilog2(),
                alpha_limbs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn generate_wide_fibonacci_trace(
        input_a: &Self,
        input_b: &Self,
        n_columns: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            input_a.len.is_power_of_two(),
            "wide-fibonacci trace generation requires a power-of-two input length"
        );
        assert_eq!(
            input_a.len, input_b.len,
            "wide-fibonacci trace generation requires equal input lengths"
        );
        assert!(
            n_columns >= 2,
            "wide-fibonacci trace generation requires at least two columns"
        );
        let output_len = input_a
            .len
            .checked_mul(n_columns as usize)
            .expect("wide-fibonacci trace output length should fit in usize");
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::generate_wide_fibonacci_trace_u32(
                runtime.raw.as_ptr(),
                input_a.raw.as_ptr(),
                input_b.raw.as_ptr(),
                dst.raw.as_ptr(),
                input_a.len.ilog2(),
                n_columns,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the "big" trace for the memory_id_to_big witness component.
    ///
    /// # Arguments
    ///
    /// * `big_values` - Flat buffer of `[u32; 8]` per row (row-major, length = n_values * 8).
    /// * `mults` - Multiplicity buffer (length = n_values).
    /// * `n_values` - Number of real rows.
    /// * `column_length` - Power-of-two padded column length (>= n_values).
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 29 columns * `column_length` entries
    /// (28 value-limb columns + 1 multiplicity column).
    pub fn witness_memory_id_to_big_trace(
        big_values: &Self,
        mults: &Self,
        n_values: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_values as usize <= column_length as usize,
            "n_values must be <= column_length"
        );
        assert_eq!(
            big_values.len,
            n_values as usize * 8,
            "big_values length must be n_values * 8"
        );
        assert_eq!(
            mults.len, n_values as usize,
            "mults length must be n_values"
        );
        let n_trace_columns: usize = 29;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_memory_id_to_big_trace(
                runtime.raw.as_ptr(),
                big_values.raw.as_ptr(),
                mults.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_values,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the "small" trace for the memory_id_to_big witness component.
    ///
    /// # Arguments
    ///
    /// * `small_values` - Flat buffer of `[u32; 4]` per row (u128 as 4 limbs, row-major, length =
    ///   n_values * 4).
    /// * `mults` - Multiplicity buffer (length = n_values).
    /// * `n_values` - Number of real rows.
    /// * `column_length` - Power-of-two padded column length (>= n_values).
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 9 columns * `column_length` entries
    /// (8 value-limb columns + 1 multiplicity column).
    pub fn witness_memory_id_to_big_small_trace(
        small_values: &Self,
        mults: &Self,
        n_values: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_values as usize <= column_length as usize,
            "n_values must be <= column_length"
        );
        assert_eq!(
            small_values.len,
            n_values as usize * 4,
            "small_values length must be n_values * 4"
        );
        assert_eq!(
            mults.len, n_values as usize,
            "mults length must be n_values"
        );
        let n_trace_columns: usize = 9;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_memory_id_to_big_small_trace(
                runtime.raw.as_ptr(),
                small_values.raw.as_ptr(),
                mults.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_values,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn witness_memory_addr_to_id_trace(
        ids: &Self,
        mults: &Self,
        n_ids: u32,
        column_length: u32,
        split: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert_eq!(ids.len, n_ids as usize, "ids length must be n_ids");
        assert_eq!(mults.len, n_ids as usize, "mults length must be n_ids");
        let n_trace_columns = split as usize * 2;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_memory_addr_to_id_trace(
                runtime.raw.as_ptr(),
                ids.raw.as_ptr(),
                mults.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_ids,
                column_length,
                split,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the trace for the add_opcode_small witness component on GPU.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Flat buffer of (pc, ap, fp) tuples, row-major [n_rows * 3].
    /// * `address_to_id` - The address-to-raw-ID lookup table.
    /// * `big_values` - Row-major [n_big][8] u32 F252 values.
    /// * `small_values` - Row-major [n_small][4] u32 small values.
    /// * `n_rows` - Number of real input rows.
    /// * `column_length` - Power-of-two padded column length.
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 39 columns * `column_length` entries.
    pub fn witness_add_opcode_small_trace(
        inputs: &Self,
        address_to_id: &Self,
        big_values: &Self,
        small_values: &Self,
        n_rows: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_rows as usize <= column_length as usize,
            "n_rows must be <= column_length"
        );
        assert!(
            inputs.len >= n_rows as usize * 3,
            "inputs length must be >= n_rows * 3"
        );
        let n_trace_columns: usize = 39;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_add_opcode_small_trace(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                address_to_id.raw.as_ptr(),
                big_values.raw.as_ptr(),
                small_values.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the trace for the assert_eq_opcode_double_deref witness
    /// component on GPU.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Flat buffer of (pc, ap, fp) tuples, row-major [n_rows * 3].
    /// * `address_to_id` - The address-to-raw-ID lookup table.
    /// * `big_values` - Row-major [n_big][8] u32 F252 values.
    /// * `small_values` - Row-major [n_small][4] u32 small values.
    /// * `n_rows` - Number of real input rows.
    /// * `column_length` - Power-of-two padded column length.
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 19 columns * `column_length` entries.
    pub fn witness_assert_eq_double_deref_trace(
        inputs: &Self,
        address_to_id: &Self,
        big_values: &Self,
        small_values: &Self,
        n_rows: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_rows as usize <= column_length as usize,
            "n_rows must be <= column_length"
        );
        assert!(
            inputs.len >= n_rows as usize * 3,
            "inputs length must be >= n_rows * 3"
        );
        let n_trace_columns: usize = 19;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_assert_eq_double_deref_trace(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                address_to_id.raw.as_ptr(),
                big_values.raw.as_ptr(),
                small_values.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the trace for the jnz_opcode_taken witness component on GPU.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Flat buffer of (pc, ap, fp) tuples, row-major [n_rows * 3].
    /// * `address_to_id` - The address-to-raw-ID lookup table.
    /// * `big_values` - Row-major [n_big][8] u32 F252 values.
    /// * `small_values` - Row-major [n_small][4] u32 small values.
    /// * `n_rows` - Number of real input rows.
    /// * `column_length` - Power-of-two padded column length.
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 47 columns * `column_length` entries.
    pub fn witness_jnz_opcode_taken_trace(
        inputs: &Self,
        address_to_id: &Self,
        big_values: &Self,
        small_values: &Self,
        n_rows: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_rows as usize <= column_length as usize,
            "n_rows must be <= column_length"
        );
        assert!(
            inputs.len >= n_rows as usize * 3,
            "inputs length must be >= n_rows * 3"
        );
        let n_trace_columns: usize = 47;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_jnz_opcode_taken_trace(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                address_to_id.raw.as_ptr(),
                big_values.raw.as_ptr(),
                small_values.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the trace for the jump_opcode_rel_imm witness component on GPU.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Flat buffer of (pc, ap, fp) tuples, row-major [n_rows * 3].
    /// * `address_to_id` - The address-to-raw-ID lookup table.
    /// * `big_values` - Row-major [n_big][8] u32 F252 values.
    /// * `small_values` - Row-major [n_small][4] u32 small values.
    /// * `n_rows` - Number of real input rows.
    /// * `column_length` - Power-of-two padded column length.
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 13 columns * `column_length` entries.
    pub fn witness_jump_opcode_rel_imm_trace(
        inputs: &Self,
        address_to_id: &Self,
        big_values: &Self,
        small_values: &Self,
        n_rows: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_rows as usize <= column_length as usize,
            "n_rows must be <= column_length"
        );
        assert!(
            inputs.len >= n_rows as usize * 3,
            "inputs length must be >= n_rows * 3"
        );
        let n_trace_columns: usize = 13;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_jump_opcode_rel_imm_trace(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                address_to_id.raw.as_ptr(),
                big_values.raw.as_ptr(),
                small_values.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the trace for the call_opcode_rel_imm witness component on GPU.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Flat buffer of (pc, ap, fp) tuples, row-major [n_rows * 3].
    /// * `address_to_id` - The address-to-raw-ID lookup table.
    /// * `big_values` - Row-major [n_big][8] u32 F252 values.
    /// * `small_values` - Row-major [n_small][4] u32 small values.
    /// * `n_rows` - Number of real input rows.
    /// * `column_length` - Power-of-two padded column length.
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 24 columns * `column_length` entries.
    pub fn witness_call_opcode_rel_imm_trace(
        inputs: &Self,
        address_to_id: &Self,
        big_values: &Self,
        small_values: &Self,
        n_rows: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_rows as usize <= column_length as usize,
            "n_rows must be <= column_length"
        );
        assert!(
            inputs.len >= n_rows as usize * 3,
            "inputs length must be >= n_rows * 3"
        );
        let n_trace_columns: usize = 24;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_call_opcode_rel_imm_trace(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                address_to_id.raw.as_ptr(),
                big_values.raw.as_ptr(),
                small_values.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the trace for the ret_opcode witness component on GPU.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Flat buffer of (pc, ap, fp) tuples, row-major [n_rows * 3].
    /// * `address_to_id` - The address-to-raw-ID lookup table.
    /// * `big_values` - Row-major [n_big][8] u32 F252 values.
    /// * `small_values` - Row-major [n_small][4] u32 small values.
    /// * `n_rows` - Number of real input rows.
    /// * `column_length` - Power-of-two padded column length.
    ///
    /// # Returns
    ///
    /// Column-major output buffer with 16 columns * `column_length` entries.
    pub fn witness_ret_opcode_trace(
        inputs: &Self,
        address_to_id: &Self,
        big_values: &Self,
        small_values: &Self,
        n_rows: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert!(
            n_rows as usize <= column_length as usize,
            "n_rows must be <= column_length"
        );
        assert!(
            inputs.len >= n_rows as usize * 3,
            "inputs length must be >= n_rows * 3"
        );
        let n_trace_columns: usize = 16;
        let output_len = n_trace_columns * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_ret_opcode_trace(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                address_to_id.raw.as_ptr(),
                big_values.raw.as_ptr(),
                small_values.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Dispatch an opcode interaction-values kernel.
    ///
    /// Reads GPU trace columns and produces flat LookupData values that
    /// feed the generic interaction trace kernel.
    ///
    /// # Arguments
    /// * `trace_cols` - Column-major [n_trace_cols][col_len] u32 trace data.
    /// * `n_output_fields` - Number of flat output values per row.
    /// * `n_rows` - Actual row count (for enabler).
    /// * `col_len` - Padded power-of-two column length.
    /// * `dispatch_fn` - The FFI function to call.
    fn dispatch_interaction_values(
        trace_cols: &Self,
        n_output_fields: usize,
        n_rows: u32,
        col_len: u32,
        dispatch_fn: unsafe fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            u32,
            u32,
            fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
        ) -> Result<(), MetalError>,
    ) -> Result<Self, MetalError> {
        let output_len = n_output_fields * col_len as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            dispatch_fn(
                runtime.raw.as_ptr(),
                trace_cols.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                col_len,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Produce LookupData values for ret_opcode from GPU trace columns.
    /// 16 trace cols -> 82 flat output fields per row.
    pub fn interaction_values_ret_opcode(
        trace_cols: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_interaction_values(
            trace_cols,
            82,
            n_rows,
            col_len,
            ffi::interaction_values_ret_opcode,
        )
    }

    /// Produce LookupData values for jnz_opcode_taken from GPU trace columns.
    /// 47 trace cols -> 82 flat output fields per row.
    pub fn interaction_values_jnz_opcode_taken(
        trace_cols: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_interaction_values(
            trace_cols,
            82,
            n_rows,
            col_len,
            ffi::interaction_values_jnz_opcode_taken,
        )
    }

    /// Produce LookupData values for assert_eq_opcode_double_deref from GPU trace columns.
    /// 19 trace cols -> 55 flat output fields per row.
    pub fn interaction_values_assert_eq_double_deref(
        trace_cols: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_interaction_values(
            trace_cols,
            55,
            n_rows,
            col_len,
            ffi::interaction_values_assert_eq_double_deref,
        )
    }

    /// Produce LookupData values for jump_opcode_rel_imm from GPU trace columns.
    /// 13 trace cols -> 49 flat output fields per row.
    pub fn interaction_values_jump_opcode_rel_imm(
        trace_cols: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_interaction_values(
            trace_cols,
            49,
            n_rows,
            col_len,
            ffi::interaction_values_jump_opcode_rel_imm,
        )
    }

    /// Produce LookupData values for call_opcode_rel_imm from GPU trace columns.
    /// 24 trace cols -> 115 flat output fields per row.
    pub fn interaction_values_call_opcode_rel_imm(
        trace_cols: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_interaction_values(
            trace_cols,
            115,
            n_rows,
            col_len,
            ffi::interaction_values_call_opcode_rel_imm,
        )
    }

    /// Dispatch a fused interaction trace kernel (single-pass: trace cols → logup fractions).
    ///
    /// # Arguments
    /// * `trace_cols`    - Column-major [n_trace_cols][col_len] u32 trace data
    /// * `alpha_powers`  - [max_combine_size * 4] u32 QM31 alpha powers
    /// * `z`             - [4] u32 QM31 z value
    /// * `n_logup_cols`  - Number of logup columns for this opcode
    /// * `n_rows`        - Actual row count (for enabler)
    /// * `col_len`       - Padded power-of-two column length
    /// * `dispatch_fn`   - The FFI function to call
    fn dispatch_fused_interaction(
        trace_cols: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_logup_cols: usize,
        n_rows: u32,
        col_len: u32,
        dispatch_fn: unsafe fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            u32,
            u32,
            fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
        ) -> Result<(), MetalError>,
    ) -> Result<Self, MetalError> {
        assert_eq!(z.len, 4, "z must have 4 u32");
        let output_len = n_logup_cols * 4 * col_len as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            dispatch_fn(
                runtime.raw.as_ptr(),
                trace_cols.raw.as_ptr(),
                alpha_powers.raw.as_ptr(),
                z.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                col_len,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Fused interaction trace for ret_opcode: 16 trace cols → 4 logup cols.
    pub fn fused_interaction_ret_opcode(
        trace_cols: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_fused_interaction(
            trace_cols,
            alpha_powers,
            z,
            4,
            n_rows,
            col_len,
            ffi::fused_interaction_ret_opcode,
        )
    }

    /// Fused interaction trace for jump_opcode_rel_imm: 13 trace cols → 3 logup cols.
    pub fn fused_interaction_jump_opcode_rel_imm(
        trace_cols: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_fused_interaction(
            trace_cols,
            alpha_powers,
            z,
            3,
            n_rows,
            col_len,
            ffi::fused_interaction_jump_opcode_rel_imm,
        )
    }

    /// Fused interaction trace for assert_eq_double_deref: 19 trace cols → 4 logup cols.
    pub fn fused_interaction_assert_eq_double_deref(
        trace_cols: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_fused_interaction(
            trace_cols,
            alpha_powers,
            z,
            4,
            n_rows,
            col_len,
            ffi::fused_interaction_assert_eq_double_deref,
        )
    }

    /// Fused interaction trace for jnz_opcode_taken: 47 trace cols → 4 logup cols.
    pub fn fused_interaction_jnz_opcode_taken(
        trace_cols: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_fused_interaction(
            trace_cols,
            alpha_powers,
            z,
            4,
            n_rows,
            col_len,
            ffi::fused_interaction_jnz_opcode_taken,
        )
    }

    /// Fused interaction trace for call_opcode_rel_imm: 24 trace cols → 5 logup cols.
    pub fn fused_interaction_call_opcode_rel_imm(
        trace_cols: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_fused_interaction(
            trace_cols,
            alpha_powers,
            z,
            5,
            n_rows,
            col_len,
            ffi::fused_interaction_call_opcode_rel_imm,
        )
    }

    /// Fused interaction trace for add_opcode_small: 39 trace cols → 5 logup cols.
    pub fn fused_interaction_add_opcode_small(
        trace_cols: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_rows: u32,
        col_len: u32,
    ) -> Result<Self, MetalError> {
        Self::dispatch_fused_interaction(
            trace_cols,
            alpha_powers,
            z,
            5,
            n_rows,
            col_len,
            ffi::fused_interaction_add_opcode_small,
        )
    }

    /// Generic range-check witness trace generation on GPU.
    ///
    /// Copies `n_columns` multiplicity buffers (packed contiguously in column-major
    /// layout) into the output trace columns. Works for all range-check components:
    /// range_check_9_9, range_check_7_2_5, range_check_4_3, range_check_4_4,
    /// range_check_6, range_check_8, range_check_11, range_check_12,
    /// range_check_18, range_check_20, range_check_3_6_6_3, range_check_3_3_3_3_3,
    /// range_check_4_4_4_4.
    ///
    /// # Arguments
    /// * `mults`          - column-major [n_columns][column_length] u32 multiplicities
    /// * `n_columns`      - number of multiplicity / trace columns (= N_TRACE_COLUMNS)
    /// * `column_length`  - number of rows per column
    ///
    /// # Returns
    /// Column-major [n_columns][column_length] u32 trace output.
    pub fn witness_range_check_trace(
        mults: &Self,
        n_columns: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        let expected_len = n_columns as usize * column_length as usize;
        assert_eq!(
            mults.len, expected_len,
            "mults length must be n_columns * column_length"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(expected_len)?;
        unsafe {
            ffi::witness_range_check_trace(
                runtime.raw.as_ptr(),
                mults.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_columns,
                column_length,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the verify_instruction witness trace on GPU.
    ///
    /// Decodes Cairo instructions into their constituent bit-fields (offsets,
    /// felt5_high, felt6, opcode extension) and performs the address-to-id
    /// memory lookup, producing a 17-column trace in column-major layout.
    ///
    /// # Arguments
    /// * `inputs`       - Row-major [n_rows * 7] u32: (pc, off0, off1, off2, felt5h, felt6, opext)
    /// * `mults`        - [n_rows] u32 multiplicities
    /// * `addr_to_id`   - [addr_to_id_len] u32 address-to-id lookup table
    /// * `n_rows`       - number of real instruction rows
    /// * `column_length` - padded column length (power-of-two >= n_rows)
    ///
    /// # Returns
    /// Column-major [17][column_length] u32 trace output.
    pub fn witness_verify_instruction_trace(
        inputs: &Self,
        mults: &Self,
        addr_to_id: &Self,
        n_rows: u32,
        column_length: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            column_length.is_power_of_two(),
            "column_length must be a power of two"
        );
        assert_eq!(
            inputs.len,
            n_rows as usize * 7,
            "inputs length must be n_rows * 7"
        );
        assert_eq!(mults.len, n_rows as usize, "mults length must be n_rows");
        let output_len = 17 * column_length as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::witness_verify_instruction_trace(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                mults.raw.as_ptr(),
                addr_to_id.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                column_length,
                addr_to_id.len as u32,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the interaction trace for memory_id_to_big (big values).
    ///
    /// Computes logup fractions on GPU: for each row, compute 7 range-check
    /// column fractions and 1 yield column fraction, accumulate running sums.
    /// The last column still needs prefix-sum finalization on CPU.
    ///
    /// # Arguments
    /// * `limbs`         - Column-major [28][n_rows] limb values
    /// * `mults`         - [n_rows] multiplicities
    /// * `alpha_powers`  - [30] QM31 values = [120] u32 (lookup element powers)
    /// * `z`             - QM31 = [4] u32 (lookup element z)
    /// * `relation_ids`  - [9] u32 (RC_9_9, _B, _C, _D, _E, _F, _G, _H, MEM_ID_TO_BIG)
    /// * `n_rows`        - number of rows
    /// * `id_offset`     - offset added to row index for the yield column id
    /// * `large_id_base` - OR'd into id value for large memory values
    ///
    /// # Returns
    /// Column-major [32][n_rows] u32 output (8 QM31 columns = 32 M31 columns).
    pub fn interaction_trace_id_to_big(
        limbs: &Self,
        mults: &Self,
        alpha_powers: &Self,
        z: &Self,
        relation_ids: &Self,
        n_rows: u32,
        id_offset: u32,
        large_id_base: u32,
    ) -> Result<Self, MetalError> {
        assert_eq!(limbs.len, 28 * n_rows as usize, "limbs length mismatch");
        assert_eq!(mults.len, n_rows as usize, "mults length mismatch");
        assert_eq!(
            alpha_powers.len, 120,
            "alpha_powers must have 30 QM31 = 120 u32"
        );
        assert_eq!(z.len, 4, "z must have 4 u32");
        assert_eq!(relation_ids.len, 9, "relation_ids must have 9 u32");

        let output_len = 32 * n_rows as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::interaction_trace_id_to_big(
                runtime.raw.as_ptr(),
                limbs.raw.as_ptr(),
                mults.raw.as_ptr(),
                alpha_powers.raw.as_ptr(),
                z.raw.as_ptr(),
                relation_ids.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                id_offset,
                large_id_base,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the interaction trace for memory_id_to_big (small values).
    ///
    /// Same as the big variant but with 8 limbs, 2 range-check columns + 1 yield column
    /// = 3 QM31 columns = 12 M31 columns.
    pub fn interaction_trace_id_to_big_small(
        limbs: &Self,
        mults: &Self,
        alpha_powers: &Self,
        z: &Self,
        relation_ids: &Self,
        n_rows: u32,
    ) -> Result<Self, MetalError> {
        assert_eq!(limbs.len, 8 * n_rows as usize, "limbs length mismatch");
        assert_eq!(mults.len, n_rows as usize, "mults length mismatch");
        assert_eq!(z.len, 4, "z must have 4 u32");
        assert_eq!(relation_ids.len, 5, "relation_ids must have 5 u32");

        let output_len = 12 * n_rows as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::interaction_trace_id_to_big_small(
                runtime.raw.as_ptr(),
                limbs.raw.as_ptr(),
                mults.raw.as_ptr(),
                alpha_powers.raw.as_ptr(),
                z.raw.as_ptr(),
                relation_ids.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the interaction trace for memory_address_to_id on the GPU.
    ///
    /// # Arguments
    /// * `ids`            - Column-major [split][n_rows] id values
    /// * `mults`          - Column-major [split][n_rows] multiplicities
    /// * `alpha_powers`   - [3] QM31 values = [12] u32 (lookup element powers)
    /// * `z`              - QM31 = [4] u32 (lookup element z)
    /// * `relation_id`    - [1] u32 (MEMORY_ADDRESS_TO_ID_RELATION_ID)
    /// * `n_rows`         - number of rows per chunk
    /// * `split`          - MEMORY_ADDRESS_TO_ID_SPLIT (must be even)
    ///
    /// # Returns
    /// Column-major output: [split/2 * 4][n_rows] u32 (split/2 QM31 columns).
    pub fn interaction_trace_addr_to_id(
        ids: &Self,
        mults: &Self,
        alpha_powers: &Self,
        z: &Self,
        relation_id: &Self,
        n_rows: u32,
        split: u32,
    ) -> Result<Self, MetalError> {
        assert_eq!(
            ids.len,
            split as usize * n_rows as usize,
            "ids length mismatch"
        );
        assert_eq!(
            mults.len,
            split as usize * n_rows as usize,
            "mults length mismatch"
        );
        assert_eq!(z.len, 4, "z must have 4 u32");
        assert_eq!(relation_id.len, 1, "relation_id must have 1 u32");
        assert!(split.is_multiple_of(2), "split must be even");

        let n_logup_cols = (split / 2) as usize;
        let output_len = n_logup_cols * 4 * n_rows as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::interaction_trace_addr_to_id(
                runtime.raw.as_ptr(),
                ids.raw.as_ptr(),
                mults.raw.as_ptr(),
                alpha_powers.raw.as_ptr(),
                z.raw.as_ptr(),
                relation_id.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                split,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Generate the interaction trace using the generic data-driven kernel.
    ///
    /// # Arguments
    /// * `values`       - Flat column-major [n_value_columns][n_rows] u32 lookup data
    /// * `descriptors`  - Array of ColumnDescriptor (8 u32 each)
    /// * `alpha_powers` - [max_combine_size] QM31 = [max_combine_size*4] u32
    /// * `z`            - QM31 = [4] u32
    /// * `n_rows`       - number of rows (power of two)
    /// * `n_logup_cols` - number of logup columns
    /// * `n_rows_real`  - actual row count for enabler computation
    ///
    /// # Returns
    /// Column-major [n_logup_cols*4][n_rows] u32 output.
    pub fn interaction_trace_generic(
        values: &Self,
        descriptors: &Self,
        alpha_powers: &Self,
        z: &Self,
        n_rows: u32,
        n_logup_cols: u32,
        n_rows_real: u32,
    ) -> Result<Self, MetalError> {
        assert_eq!(z.len, 4, "z must have 4 u32");
        assert!(n_logup_cols > 0, "must have at least one logup column");

        let output_len = n_logup_cols as usize * 4 * n_rows as usize;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(output_len)?;
        unsafe {
            ffi::interaction_trace_generic(
                runtime.raw.as_ptr(),
                values.raw.as_ptr(),
                descriptors.raw.as_ptr(),
                alpha_powers.raw.as_ptr(),
                z.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_rows,
                n_logup_cols,
                n_rows_real,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn accumulate_wide_fibonacci_quotients(
        trace_evaluations: &Self,
        random_coeff_powers: &Self,
        denominator_inverses: &Self,
        domain_log_size: u32,
        eval_domain_log_size: u32,
        n_constraints: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            eval_domain_log_size >= domain_log_size,
            "wide-fibonacci quotient accumulation requires eval_domain_log_size >= domain_log_size"
        );
        assert!(
            n_constraints >= 1,
            "wide-fibonacci quotient accumulation requires at least one constraint"
        );
        let eval_domain_size = 1usize << eval_domain_log_size;
        let expected_trace_len = eval_domain_size
            .checked_mul(n_constraints as usize + 2)
            .expect("wide-fibonacci quotient trace length should fit in usize");
        assert_eq!(
            trace_evaluations.len, expected_trace_len,
            "wide-fibonacci quotient accumulation expects a contiguous column-major trace buffer"
        );
        assert_eq!(
            random_coeff_powers.len,
            n_constraints as usize * 4,
            "wide-fibonacci quotient accumulation expects one qm31 coefficient per constraint"
        );
        assert_eq!(
            denominator_inverses.len,
            1usize << (eval_domain_log_size - domain_log_size),
            "wide-fibonacci quotient accumulation expects one denominator inverse per evaluation-domain coset"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(eval_domain_size * 4)?;
        unsafe {
            ffi::accumulate_wide_fibonacci_quotients_u32x4(
                runtime.raw.as_ptr(),
                trace_evaluations.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                denominator_inverses.raw.as_ptr(),
                dst.raw.as_ptr(),
                domain_log_size,
                eval_domain_log_size,
                n_constraints,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn accumulate_partial_numerators(
        columns: &Self,
        column_indices: &Self,
        b_coeffs: &Self,
        c_coeffs: &Self,
        row_count: usize,
    ) -> Result<Self, MetalError> {
        assert!(
            row_count > 0,
            "partial numerator accumulation requires a non-zero row count"
        );
        assert_eq!(
            columns.len % row_count,
            0,
            "partial numerator accumulation expects flattened base columns with an integral number of rows"
        );
        assert_eq!(
            column_indices.len * 4,
            b_coeffs.len,
            "partial numerator accumulation expects one qm31 b coefficient per column index"
        );
        assert_eq!(
            column_indices.len * 4,
            c_coeffs.len,
            "partial numerator accumulation expects one qm31 c coefficient per column index"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::accumulate_partial_numerators_u32x4(
                runtime.raw.as_ptr(),
                columns.raw.as_ptr(),
                column_indices.raw.as_ptr(),
                b_coeffs.raw.as_ptr(),
                c_coeffs.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count
                    .try_into()
                    .expect("partial numerator accumulation row count should fit in u32"),
                column_indices
                    .len
                    .try_into()
                    .expect("partial numerator accumulation term count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn accumulate_partial_numerators_batched(
        columns: &Self,
        column_indices: &Self,
        b_coeffs: &Self,
        c_coeffs: &Self,
        term_offsets: &Self,
        term_counts: &Self,
        row_count: usize,
    ) -> Result<Self, MetalError> {
        assert!(
            row_count > 0,
            "batched partial numerator accumulation requires a non-zero row count"
        );
        assert_eq!(
            columns.len % row_count,
            0,
            "batched partial numerator accumulation expects flattened base columns with an integral number of rows"
        );
        assert_eq!(
            column_indices.len * 4,
            b_coeffs.len,
            "batched partial numerator accumulation expects one qm31 b coefficient per column index"
        );
        assert_eq!(
            column_indices.len * 4,
            c_coeffs.len,
            "batched partial numerator accumulation expects one qm31 c coefficient per column index"
        );
        assert_eq!(
            term_offsets.len, term_counts.len,
            "batched partial numerator accumulation expects one term offset per batch"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * term_counts.len * 4)?;
        unsafe {
            ffi::accumulate_partial_numerators_batched_u32x4(
                runtime.raw.as_ptr(),
                columns.raw.as_ptr(),
                column_indices.raw.as_ptr(),
                b_coeffs.raw.as_ptr(),
                c_coeffs.raw.as_ptr(),
                term_offsets.raw.as_ptr(),
                term_counts.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count
                    .try_into()
                    .expect("batched partial numerator accumulation row count should fit in u32"),
                term_counts
                    .len
                    .try_into()
                    .expect("batched partial numerator accumulation batch count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Fused accumulate + unpack: single command buffer encodes the batched
    /// partial-numerator accumulation kernel followed by N per-batch unpack
    /// kernels.  Eliminates N GPU round-trips and intermediate clone copies.
    ///
    /// Returns `n_batches` arrays of 4 coordinate buffers (one per QM31 limb).
    pub fn accumulate_and_unpack_partial_numerators_batched(
        columns: &Self,
        column_indices: &Self,
        b_coeffs: &Self,
        c_coeffs: &Self,
        term_offsets: &Self,
        term_counts: &Self,
        row_count: usize,
    ) -> Result<Vec<[Self; 4]>, MetalError> {
        let n_batches = term_counts.len;
        assert!(
            row_count > 0 && n_batches > 0,
            "fused accumulate+unpack requires non-zero row count and batch count"
        );
        let runtime = shared_runtime()?;
        // Pre-allocate output coordinate buffers.
        let mut coord_buffers: Vec<Self> = Vec::with_capacity(n_batches * 4);
        let mut coord_ptrs: Vec<*mut c_void> = Vec::with_capacity(n_batches * 4);
        for _ in 0..(n_batches * 4) {
            let buf = Self::uninitialized(row_count)?;
            coord_ptrs.push(buf.raw.as_ptr());
            coord_buffers.push(buf);
        }
        unsafe {
            ffi::accumulate_and_unpack_partial_numerators_batched_u32x4(
                runtime.raw.as_ptr(),
                columns.raw.as_ptr(),
                column_indices.raw.as_ptr(),
                b_coeffs.raw.as_ptr(),
                c_coeffs.raw.as_ptr(),
                term_offsets.raw.as_ptr(),
                term_counts.raw.as_ptr(),
                row_count
                    .try_into()
                    .expect("fused accumulate+unpack row count should fit in u32"),
                n_batches
                    .try_into()
                    .expect("fused accumulate+unpack batch count should fit in u32"),
                coord_ptrs.as_mut_ptr(),
                error_buffer_mut_ptr,
            )?;
        }
        // Reshape flat vec into per-batch [coord0, coord1, coord2, coord3].
        let mut result = Vec::with_capacity(n_batches);
        let mut drain = coord_buffers.into_iter();
        for _ in 0..n_batches {
            let c0 = drain.next().unwrap();
            let c1 = drain.next().unwrap();
            let c2 = drain.next().unwrap();
            let c3 = drain.next().unwrap();
            result.push([c0, c1, c2, c3]);
        }
        Ok(result)
    }

    /// Indirect variant of `accumulate_and_unpack_partial_numerators_batched`
    /// that reads column data through GPU virtual addresses, eliminating the
    /// CPU-side memmove staging copy of all unique columns into a flat buffer.
    pub fn accumulate_and_unpack_partial_numerators_indirect_batched(
        column_buffers: &[&Self],
        column_indices: &Self,
        b_coeffs: &Self,
        c_coeffs: &Self,
        term_offsets: &Self,
        term_counts: &Self,
        row_count: usize,
    ) -> Result<Vec<[Self; 4]>, MetalError> {
        let n_batches = term_counts.len;
        let n_unique_cols = column_buffers.len();
        assert!(
            row_count > 0 && n_batches > 0,
            "indirect accumulate+unpack requires non-zero row count and batch count"
        );
        let runtime = shared_runtime()?;

        // Collect raw pointers for each column buffer.
        let mut col_ptrs: Vec<*mut c_void> =
            column_buffers.iter().map(|buf| buf.raw.as_ptr()).collect();

        // Pre-allocate output coordinate buffers.
        let mut coord_buffers: Vec<Self> = Vec::with_capacity(n_batches * 4);
        let mut coord_ptrs: Vec<*mut c_void> = Vec::with_capacity(n_batches * 4);
        for _ in 0..(n_batches * 4) {
            let buf = Self::uninitialized(row_count)?;
            coord_ptrs.push(buf.raw.as_ptr());
            coord_buffers.push(buf);
        }
        unsafe {
            ffi::accumulate_and_unpack_partial_numerators_indirect_batched_u32x4(
                runtime.raw.as_ptr(),
                col_ptrs.as_mut_ptr(),
                n_unique_cols
                    .try_into()
                    .expect("indirect accumulate+unpack n_unique_cols should fit in u32"),
                column_indices.raw.as_ptr(),
                b_coeffs.raw.as_ptr(),
                c_coeffs.raw.as_ptr(),
                term_offsets.raw.as_ptr(),
                term_counts.raw.as_ptr(),
                row_count
                    .try_into()
                    .expect("indirect accumulate+unpack row count should fit in u32"),
                n_batches
                    .try_into()
                    .expect("indirect accumulate+unpack batch count should fit in u32"),
                coord_ptrs.as_mut_ptr(),
                error_buffer_mut_ptr,
            )?;
        }
        // Reshape flat vec into per-batch [coord0, coord1, coord2, coord3].
        let mut result = Vec::with_capacity(n_batches);
        let mut drain = coord_buffers.into_iter();
        for _ in 0..n_batches {
            let c0 = drain.next().unwrap();
            let c1 = drain.next().unwrap();
            let c2 = drain.next().unwrap();
            let c3 = drain.next().unwrap();
            result.push([c0, c1, c2, c3]);
        }
        Ok(result)
    }

    pub fn compute_quotients_and_combine(
        partial_coord_columns: [&Self; 4],
        sample_points: &Self,
        first_linear_terms: &Self,
        partial_log_sizes: &Self,
        partial_offsets: &Self,
        domain_x: &Self,
        domain_y: &Self,
        lifting_log_size: u32,
    ) -> Result<Self, MetalError> {
        let [partial_coord_0, partial_coord_1, partial_coord_2, partial_coord_3] =
            partial_coord_columns;
        let row_count = 1usize << lifting_log_size;
        assert_eq!(
            partial_coord_0.len, partial_coord_1.len,
            "quotient combination requires equal flattened partial numerator coordinate lengths"
        );
        assert_eq!(partial_coord_0.len, partial_coord_2.len);
        assert_eq!(partial_coord_0.len, partial_coord_3.len);
        assert_eq!(
            sample_points.len % 8,
            0,
            "quotient combination expects eight sample-point limbs per accumulation"
        );
        let n_accumulations = sample_points.len / 8;
        assert_eq!(
            first_linear_terms.len,
            n_accumulations * 4,
            "quotient combination expects one qm31 first-linear term per accumulation"
        );
        assert_eq!(
            partial_log_sizes.len, n_accumulations,
            "quotient combination expects one partial log-size per accumulation"
        );
        assert_eq!(
            partial_offsets.len, n_accumulations,
            "quotient combination expects one partial offset per accumulation"
        );
        assert_eq!(
            domain_x.len, row_count,
            "quotient combination expects one domain x-coordinate per lifting-domain row"
        );
        assert_eq!(
            domain_y.len, row_count,
            "quotient combination expects one domain y-coordinate per lifting-domain row"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::compute_quotients_and_combine_u32x4(
                runtime.raw.as_ptr(),
                partial_coord_0.raw.as_ptr(),
                partial_coord_1.raw.as_ptr(),
                partial_coord_2.raw.as_ptr(),
                partial_coord_3.raw.as_ptr(),
                sample_points.raw.as_ptr(),
                first_linear_terms.raw.as_ptr(),
                partial_log_sizes.raw.as_ptr(),
                partial_offsets.raw.as_ptr(),
                domain_x.raw.as_ptr(),
                domain_y.raw.as_ptr(),
                dst.raw.as_ptr(),
                lifting_log_size,
                n_accumulations
                    .try_into()
                    .expect("quotient combination accumulation count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn compute_quotients_and_combine_packed(
        partials: &Self,
        sample_points: &Self,
        first_linear_terms: &Self,
        partial_log_sizes: &Self,
        partial_offsets: &Self,
        domain_x: &Self,
        domain_y: &Self,
        lifting_log_size: u32,
    ) -> Result<Self, MetalError> {
        let row_count = 1usize << lifting_log_size;
        assert!(
            partials.len.is_multiple_of(4),
            "packed quotient combination expects qm31-packed partial numerators"
        );
        assert_eq!(
            sample_points.len % 8,
            0,
            "packed quotient combination expects eight sample-point limbs per accumulation"
        );
        let n_accumulations = sample_points.len / 8;
        assert_eq!(
            first_linear_terms.len,
            n_accumulations * 4,
            "packed quotient combination expects one qm31 first-linear term per accumulation"
        );
        assert_eq!(partial_log_sizes.len, n_accumulations);
        assert_eq!(partial_offsets.len, n_accumulations);
        assert_eq!(domain_x.len, row_count);
        assert_eq!(domain_y.len, row_count);
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::compute_quotients_and_combine_packed_u32x4(
                runtime.raw.as_ptr(),
                partials.raw.as_ptr(),
                sample_points.raw.as_ptr(),
                first_linear_terms.raw.as_ptr(),
                partial_log_sizes.raw.as_ptr(),
                partial_offsets.raw.as_ptr(),
                domain_x.raw.as_ptr(),
                domain_y.raw.as_ptr(),
                dst.raw.as_ptr(),
                lifting_log_size,
                n_accumulations
                    .try_into()
                    .expect("packed quotient combination accumulation count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Indirect-packed quotient combination: reads per-accumulation packed
    /// partial buffers via GPU virtual addresses, avoiding a contiguous staging
    /// copy.  `partial_buffers` supplies one buffer per accumulation;
    /// `partial_offsets` supplies the element offset within each buffer.
    pub fn compute_quotients_and_combine_indirect_packed(
        partial_buffers: &[&Self],
        sample_points: &Self,
        first_linear_terms: &Self,
        partial_log_sizes: &Self,
        partial_offsets: &Self,
        domain_x: &Self,
        domain_y: &Self,
        lifting_log_size: u32,
    ) -> Result<Self, MetalError> {
        let row_count = 1usize << lifting_log_size;
        let n_accumulations = partial_buffers.len();
        assert!(
            n_accumulations > 0,
            "indirect packed quotient combination requires at least one accumulation"
        );
        assert_eq!(
            sample_points.len,
            n_accumulations * 8,
            "indirect packed quotient combination expects eight sample-point limbs per accumulation"
        );
        assert_eq!(
            first_linear_terms.len,
            n_accumulations * 4,
            "indirect packed quotient combination expects one qm31 first-linear term per accumulation"
        );
        assert_eq!(partial_log_sizes.len, n_accumulations);
        assert_eq!(partial_offsets.len, n_accumulations);
        assert_eq!(domain_x.len, row_count);
        assert_eq!(domain_y.len, row_count);
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        let buffer_ptrs: Vec<*mut std::ffi::c_void> =
            partial_buffers.iter().map(|b| b.raw.as_ptr()).collect();
        unsafe {
            ffi::compute_quotients_and_combine_indirect_packed_u32x4(
                runtime.raw.as_ptr(),
                buffer_ptrs.as_ptr(),
                sample_points.raw.as_ptr(),
                first_linear_terms.raw.as_ptr(),
                partial_log_sizes.raw.as_ptr(),
                partial_offsets.raw.as_ptr(),
                domain_x.raw.as_ptr(),
                domain_y.raw.as_ptr(),
                dst.raw.as_ptr(),
                lifting_log_size,
                n_accumulations.try_into().expect(
                    "indirect packed quotient combination accumulation count should fit in u32",
                ),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn blake2s_build_leaves_lifted(
        flat_columns: &Self,
        column_offsets: &Self,
        column_log_sizes: &Self,
        lifting_log_size: u32,
    ) -> Result<Self, MetalError> {
        let row_count = 1usize << lifting_log_size;
        assert_eq!(
            column_offsets.len, column_log_sizes.len,
            "lifted Blake2s leaves require one offset per column log-size"
        );
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 8)?;
        unsafe {
            ffi::blake2s_build_leaves_lifted_u32(
                runtime.raw.as_ptr(),
                flat_columns.raw.as_ptr(),
                column_offsets.raw.as_ptr(),
                column_log_sizes.raw.as_ptr(),
                dst.raw.as_ptr(),
                column_offsets
                    .len
                    .try_into()
                    .expect("lifted Blake2s leaf column count should fit in u32"),
                lifting_log_size,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn blake2s_build_leaves_lifted_wide(
        columns: &[&Self],
        column_log_sizes: &[u32],
        lifting_log_size: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            !columns.is_empty(),
            "wide lifted Blake2s leaves require at least one source column"
        );
        assert_eq!(
            columns.len(),
            column_log_sizes.len(),
            "wide lifted Blake2s leaves require one log size per source column"
        );
        let row_count = 1usize << lifting_log_size;
        let runtime = shared_runtime()?;
        let state = Self::zeroed(row_count * 8)?;
        let dst = Self::uninitialized(row_count * 8)?;

        // Collect all column buffer pointers for the batched dispatch.
        let all_column_ptrs: Vec<*mut std::ffi::c_void> =
            columns.iter().map(|c| c.raw.as_ptr()).collect();

        unsafe {
            ffi::blake2s_build_leaves_lifted_wide_batched_u32(
                runtime.raw.as_ptr(),
                all_column_ptrs.as_ptr(),
                state.raw.as_ptr(),
                dst.raw.as_ptr(),
                column_log_sizes.as_ptr(),
                columns
                    .len()
                    .try_into()
                    .expect("wide lifted Blake2s column count should fit in u32"),
                lifting_log_size,
                error_buffer_mut_ptr,
            )?;
        }

        Ok(dst)
    }

    /// Single-pass leaf builder: processes all columns per GPU thread with
    /// Blake2s state in registers (zero copy, no intermediate state buffer).
    pub fn blake2s_build_leaves_lifted_fast(
        columns: &[&Self],
        column_log_sizes: &[u32],
        lifting_log_size: u32,
    ) -> Result<Self, MetalError> {
        assert!(
            !columns.is_empty(),
            "fast lifted Blake2s leaves require at least one source column"
        );
        assert_eq!(
            columns.len(),
            column_log_sizes.len(),
            "fast lifted Blake2s leaves require one log size per source column"
        );
        let row_count = 1usize << lifting_log_size;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 8)?;

        let column_ptrs: Vec<*mut std::ffi::c_void> =
            columns.iter().map(|c| c.raw.as_ptr()).collect();

        unsafe {
            ffi::blake2s_build_leaves_lifted_fast_u32(
                runtime.raw.as_ptr(),
                column_ptrs.as_ptr(),
                dst.raw.as_ptr(),
                column_log_sizes.as_ptr(),
                columns
                    .len()
                    .try_into()
                    .expect("fast lifted Blake2s column count should fit in u32"),
                lifting_log_size,
                error_buffer_mut_ptr,
            )?;
        }

        Ok(dst)
    }

    pub fn blake2s_build_next_layer(prev_layer: &Self) -> Result<Self, MetalError> {
        assert!(
            prev_layer.len.is_multiple_of(16),
            "packed Blake2s next-layer hashing expects pairs of eight-word child hashes"
        );
        let next_hash_count = prev_layer.len / 16;
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(next_hash_count * 8)?;
        unsafe {
            ffi::blake2s_build_next_layer_u32(
                runtime.raw.as_ptr(),
                prev_layer.raw.as_ptr(),
                dst.raw.as_ptr(),
                next_hash_count
                    .try_into()
                    .expect("Blake2s next-layer parent count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn blake2s_build_merkle_layers_from_leaves(
        leaf_layer: Self,
    ) -> Result<Vec<Self>, MetalError> {
        assert!(
            leaf_layer.len.is_multiple_of(8),
            "packed Blake2s leaves should contain eight words per hash"
        );
        let mut current_hash_count = leaf_layer.len / 8;
        assert!(
            current_hash_count.is_power_of_two(),
            "packed Blake2s leaves should contain a power-of-two hash count"
        );

        if current_hash_count == 0 {
            return Ok(vec![leaf_layer]);
        }

        let leaf_log_size = current_hash_count.ilog2();
        let runtime = shared_runtime()?;
        let mut upper_layers = Vec::with_capacity(leaf_log_size as usize);
        while current_hash_count > 1 {
            current_hash_count /= 2;
            upper_layers.push(Self::uninitialized(current_hash_count * 8)?);
        }

        let layer_ptrs = upper_layers
            .iter_mut()
            .map(|layer| layer.raw.as_ptr())
            .collect::<Vec<_>>();
        unsafe {
            ffi::blake2s_build_merkle_layers_u32(
                runtime.raw.as_ptr(),
                leaf_layer.raw.as_ptr(),
                layer_ptrs.as_ptr(),
                leaf_log_size,
                error_buffer_mut_ptr,
            )?;
        }

        let mut layers = Vec::with_capacity(upper_layers.len() + 1);
        layers.push(leaf_layer);
        layers.extend(upper_layers);
        Ok(layers)
    }

    /// Fused leaf-build + layer-build in a single Metal command buffer.
    /// Eliminates the CPU round-trip between the two GPU phases.
    pub fn blake2s_build_merkle_tree_fast(
        column_buffers: &[&Self],
        column_log_sizes: &[u32],
        lifting_log_size: u32,
    ) -> Result<Vec<Self>, MetalError> {
        assert_eq!(
            column_buffers.len(),
            column_log_sizes.len(),
            "column_buffers and column_log_sizes must have the same length"
        );
        let n_columns: u32 = column_buffers
            .len()
            .try_into()
            .expect("column count should fit in u32");
        let leaf_count: usize = 1 << lifting_log_size;

        let runtime = shared_runtime()?;
        let leaf_layer = Self::uninitialized(leaf_count * 8)?;

        let mut current_hash_count = leaf_count;
        let mut upper_layers = Vec::with_capacity(lifting_log_size as usize);
        while current_hash_count > 1 {
            current_hash_count /= 2;
            upper_layers.push(Self::uninitialized(current_hash_count * 8)?);
        }

        let col_ptrs: Vec<*mut std::ffi::c_void> =
            column_buffers.iter().map(|buf| buf.raw.as_ptr()).collect();
        let layer_ptrs: Vec<*mut std::ffi::c_void> = upper_layers
            .iter_mut()
            .map(|layer| layer.raw.as_ptr())
            .collect();

        unsafe {
            ffi::blake2s_build_merkle_tree_fast_u32(
                runtime.raw.as_ptr(),
                col_ptrs.as_ptr(),
                leaf_layer.raw.as_ptr(),
                layer_ptrs.as_ptr(),
                column_log_sizes.as_ptr(),
                n_columns,
                lifting_log_size,
                error_buffer_mut_ptr,
            )?;
        }

        let mut layers = Vec::with_capacity(upper_layers.len() + 1);
        layers.push(leaf_layer);
        layers.extend(upper_layers);
        Ok(layers)
    }

    /// Dispatch a GPU Blake2s PoW grind batch for a given `nonce_hi` value.
    ///
    /// Tries `batch_size` nonce candidates `(nonce_hi << 32) | 0 .. batch_size-1` and
    /// returns the smallest `nonce_lo` whose Blake2s hash has at least `pow_bits` trailing
    /// zeros. Returns `u32::MAX` if no match was found in this batch.
    pub fn blake2s_grind_batch(
        prefix_digest: &[u32; 8],
        pow_bits: u32,
        nonce_hi: u32,
        batch_size: u32,
    ) -> Result<u32, MetalError> {
        let runtime = shared_runtime()?;
        unsafe {
            ffi::blake2s_grind_batch(
                runtime.raw.as_ptr(),
                prefix_digest,
                pow_bits,
                nonce_hi,
                batch_size,
                error_buffer_mut_ptr,
            )
        }
    }

    /// Bulk gather hash nodes from multiple Merkle tree layers in a single
    /// GPU command buffer dispatch.
    pub fn merkle_decommit_gather(
        layers: &[&Self],
        per_layer_indices: &[&[u32]],
    ) -> Result<Vec<u32>, MetalError> {
        assert_eq!(
            layers.len(),
            per_layer_indices.len(),
            "merkle_decommit_gather: layers and per_layer_indices must have the same length"
        );
        let runtime = shared_runtime()?;
        let layer_ptrs: Vec<*mut std::ffi::c_void> =
            layers.iter().map(|l| l.raw.as_ptr()).collect();
        let per_layer_index_ptrs: Vec<*const u32> = per_layer_indices
            .iter()
            .map(|indices| indices.as_ptr())
            .collect();
        let per_layer_counts: Vec<u32> = per_layer_indices
            .iter()
            .map(|indices| indices.len() as u32)
            .collect();
        let total_gathers: u32 = per_layer_counts.iter().sum();
        if total_gathers == 0 {
            return Ok(Vec::new());
        }
        let mut out_hashes = vec![0u32; total_gathers as usize * 8];
        unsafe {
            ffi::merkle_decommit_gather(
                runtime.raw.as_ptr(),
                &layer_ptrs,
                &per_layer_index_ptrs,
                &per_layer_counts,
                out_hashes.as_mut_ptr(),
                total_gathers,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(out_hashes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_reference_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_reference_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_optimized_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_optimized_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                max_base_regs,
                max_ext_regs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Submit eval_program_v1 reference kernel without blocking.
    /// Returns `(dst_buffer, handle)` — call `handle.wait()` before reading
    /// the buffer contents.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_reference_async_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
    ) -> Result<(Self, CommandBufferHandle), MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        let handle = unsafe {
            ffi::eval_program_v1_reference_async_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                error_buffer_mut_ptr,
            )?
        };
        Ok((
            dst,
            CommandBufferHandle {
                raw: NonNull::new(handle)
                    .expect("async eval_program_v1 reference returned null handle despite success"),
            },
        ))
    }

    /// Submit eval_program_v1 optimized kernel without blocking.
    /// Returns `(dst_buffer, handle)` — call `handle.wait()` before reading
    /// the buffer contents.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_optimized_async_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
    ) -> Result<(Self, CommandBufferHandle), MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        let handle = unsafe {
            ffi::eval_program_v1_optimized_async_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                max_base_regs,
                max_ext_regs,
                error_buffer_mut_ptr,
            )?
        };
        Ok((
            dst,
            CommandBufferHandle {
                raw: NonNull::new(handle)
                    .expect("async eval_program_v1 optimized returned null handle despite success"),
            },
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_reference_u32x4_tg(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        threads_per_group: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_reference_u32x4_tg(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                threads_per_group,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_optimized_u32x4_tg(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
        threads_per_group: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_optimized_u32x4_tg(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                max_base_regs,
                max_ext_regs,
                threads_per_group,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_reference_b_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_reference_b_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_optimized_b_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_optimized_b_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                max_base_regs,
                max_ext_regs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_reference_c_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_reference_c_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_program_v1_optimized_c_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        base_insts: &Self,
        ext_insts: &Self,
        constraint_roots: &Self,
        row_count: usize,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_optimized_c_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                base_insts.raw.as_ptr(),
                ext_insts.raw.as_ptr(),
                constraint_roots.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_preprocessed_columns,
                n_base_params,
                n_ext_params,
                n_base_insts,
                n_ext_insts,
                n_constraints,
                max_base_regs,
                max_ext_regs,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_compiled_program_v1_u32x4(
        shader_source: &str,
        kernel_name: &str,
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        row_count: usize,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_compiled_program_v1_u32x4(
                runtime.raw.as_ptr(),
                shader_source.as_ptr(),
                shader_source.len(),
                kernel_name.as_ptr(),
                kernel_name.len(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Fused composition dispatch: evaluates the JIT constraint program,
    /// applies denom_inv multiplication, and writes directly to 4 coordinate
    /// buffers.  This eliminates the GPU->CPU->GPU round-trip.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_compiled_fused_composition_v1(
        shader_source: &str,
        kernel_name: &str,
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        denom_inv: &Self,
        row_count: usize,
        log_n_rows: u32,
    ) -> Result<[Self; 4], MetalError> {
        let runtime = shared_runtime()?;
        let coord_0 = Self::uninitialized(row_count)?;
        let coord_1 = Self::uninitialized(row_count)?;
        let coord_2 = Self::uninitialized(row_count)?;
        let coord_3 = Self::uninitialized(row_count)?;
        unsafe {
            ffi::eval_compiled_fused_composition_v1(
                runtime.raw.as_ptr(),
                shader_source.as_ptr(),
                shader_source.len(),
                kernel_name.as_ptr(),
                kernel_name.len(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                denom_inv.raw.as_ptr(),
                coord_0.raw.as_ptr(),
                coord_1.raw.as_ptr(),
                coord_2.raw.as_ptr(),
                coord_3.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                log_n_rows,
                error_buffer_mut_ptr,
            )?;
        }
        Ok([coord_0, coord_1, coord_2, coord_3])
    }

    pub fn eval_compiled_program_v1_u32x4_tg(
        shader_source: &str,
        kernel_name: &str,
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        row_count: usize,
        threads_per_group: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_compiled_program_v1_u32x4_tg(
                runtime.raw.as_ptr(),
                shader_source.as_ptr(),
                shader_source.len(),
                kernel_name.as_ptr(),
                kernel_name.len(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                threads_per_group,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Like [`Self::eval_compiled_program_v1_u32x4`] but non-blocking.
    ///
    /// Commits the GPU command buffer and returns immediately. The caller must
    /// call [`CommandBufferHandle::wait`] (or drop the handle) before reading
    /// the returned `U32Buffer` contents.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_compiled_program_v1_u32x4_async(
        shader_source: &str,
        kernel_name: &str,
        trace_values: &Self,
        interaction_offsets: &Self,
        preprocessed_values: &Self,
        base_params: &Self,
        ext_params: &Self,
        random_coeff_powers: &Self,
        row_count: usize,
    ) -> Result<(Self, CommandBufferHandle), MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        let handle = unsafe {
            ffi::eval_compiled_program_v1_u32x4_async(
                runtime.raw.as_ptr(),
                shader_source.as_ptr(),
                shader_source.len(),
                kernel_name.as_ptr(),
                kernel_name.len(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                error_buffer_mut_ptr,
            )?
        };
        Ok((
            dst,
            CommandBufferHandle {
                raw: NonNull::new(handle)
                    .expect("async eval_compiled_program_v1 returned null handle despite success"),
            },
        ))
    }

    /// Fused blit+compute dispatch: uses GPU blit encoder to concatenate
    /// individual column buffers into a flat trace buffer, then dispatches the
    /// JIT-compiled compute kernel — all in a single command buffer.
    ///
    /// This eliminates the CPU memmove bottleneck in the GPU pass-through path.
    /// The GPU's DMA engine performs the copies, and the compute kernel starts
    /// immediately after via implicit command buffer ordering.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_compiled_fused_blit_async(
        shader_source: &str,
        kernel_name: &str,
        column_buffers: &[&Self],
        column_lengths: &[usize],
        interaction_offsets: &Self,
        random_coeff_powers: &Self,
        row_count: usize,
    ) -> Result<(Self, CommandBufferHandle), MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;

        // Build array of raw buffer pointers for FFI.
        let raw_ptrs: Vec<*mut std::ffi::c_void> =
            column_buffers.iter().map(|b| b.raw.as_ptr()).collect();

        let handle = unsafe {
            ffi::eval_compiled_fused_blit_async(
                runtime.raw.as_ptr(),
                shader_source.as_ptr(),
                shader_source.len(),
                kernel_name.as_ptr(),
                kernel_name.len(),
                raw_ptrs.as_ptr(),
                column_lengths.as_ptr(),
                column_buffers.len(),
                interaction_offsets.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                error_buffer_mut_ptr,
            )?
        };
        Ok((
            dst,
            CommandBufferHandle {
                raw: NonNull::new(handle)
                    .expect("fused blit+compute returned null handle despite success"),
            },
        ))
    }

    pub fn eval_program_v1_wide_fibonacci_u32x4(
        trace_values: &Self,
        interaction_offsets: &Self,
        random_coeff_powers: &Self,
        row_count: usize,
        n_interactions: u32,
        n_constraints: u32,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let dst = Self::uninitialized(row_count * 4)?;
        unsafe {
            ffi::eval_program_v1_wide_fibonacci_u32x4(
                runtime.raw.as_ptr(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                n_interactions,
                n_constraints,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    pub fn sampled_values_v1_wide_fibonacci_u32x4(
        tree_descs: &Self,
        column_descs: &Self,
        values: &Self,
        n_trees: u32,
        point_x: &Self,
    ) -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        assert!(
            point_x.len == 4,
            "sampled-values V1 wide-fibonacci lane expects a single secure-field point coordinate"
        );
        let dst = Self::uninitialized(4)?;
        unsafe {
            ffi::sampled_values_v1_wide_fibonacci_u32x4(
                runtime.raw.as_ptr(),
                tree_descs.raw.as_ptr(),
                column_descs.raw.as_ptr(),
                values.raw.as_ptr(),
                point_x.raw.as_ptr(),
                dst.raw.as_ptr(),
                n_trees,
                error_buffer_mut_ptr,
            )?;
        }
        Ok(dst)
    }

    /// Dispatch a multiplicity accumulation kernel via a function pointer.
    ///
    /// The kernel atomically increments three multiplicity buffers based on
    /// the opcode's memory access pattern.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_mults_accumulate(
        inputs: &U32Buffer,
        address_to_id: &U32Buffer,
        big_values: &U32Buffer,
        small_values: &U32Buffer,
        addr_to_id_mults: &U32Buffer,
        id_to_big_mults: &U32Buffer,
        id_to_small_mults: &U32Buffer,
        n_rows: u32,
        kernel_fn: unsafe fn(
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
        ) -> Result<(), MetalError>,
    ) -> Result<(), MetalError> {
        let runtime = shared_runtime()?;
        unsafe {
            kernel_fn(
                runtime.raw.as_ptr(),
                inputs.raw.as_ptr(),
                address_to_id.raw.as_ptr(),
                big_values.raw.as_ptr(),
                small_values.raw.as_ptr(),
                addr_to_id_mults.raw.as_ptr(),
                id_to_big_mults.raw.as_ptr(),
                id_to_small_mults.raw.as_ptr(),
                n_rows,
                error_buffer_mut_ptr,
            )
        }
    }
}

impl Clone for U32Buffer {
    fn clone(&self) -> Self {
        let mut cloned =
            Self::uninitialized(self.len).expect("clone should allocate a Metal buffer");
        cloned
            .copy_from(self)
            .expect("clone should copy source Metal buffer");
        cloned
    }
}

/// Opaque handle to a committed Metal command buffer.
/// Allows deferred waiting: submit GPU work without blocking, wait later.
#[derive(Debug)]
pub struct CommandBufferHandle {
    raw: NonNull<c_void>,
}

// Safety: Metal command buffer objects are internally thread-safe.
unsafe impl Send for CommandBufferHandle {}

impl CommandBufferHandle {
    /// Block until the GPU command buffer completes, then check for errors.
    /// Consumes the handle (releases the retained ObjC reference).
    pub fn wait(self) -> Result<(), MetalError> {
        let ptr = self.raw.as_ptr();
        // Prevent Drop from releasing — wait already transfers ownership.
        std::mem::forget(self);
        unsafe { ffi::command_buffer_wait(ptr, error_buffer_mut_ptr) }
    }
}

impl Drop for CommandBufferHandle {
    fn drop(&mut self) {
        unsafe { ffi::command_buffer_release(self.raw.as_ptr()) };
    }
}

/// Handle to an uncommitted Metal command buffer used for batching multiple
/// compute dispatches.  Call [`Self::encode_compiled_program_v1`] to add
/// dispatches, then [`Self::commit`] to submit them all at once.
#[derive(Debug)]
pub struct BatchCommandBuffer {
    raw: NonNull<c_void>,
}

// Safety: Metal command buffer objects are internally thread-safe.
unsafe impl Send for BatchCommandBuffer {}

impl BatchCommandBuffer {
    /// Create a new uncommitted command buffer from the shared Metal runtime.
    pub fn create() -> Result<Self, MetalError> {
        let runtime = shared_runtime()?;
        let ptr =
            unsafe { ffi::command_buffer_create(runtime.raw.as_ptr(), error_buffer_mut_ptr) }?;
        Ok(Self {
            raw: NonNull::new(ptr).expect("command_buffer_create returned null despite success"),
        })
    }

    /// Encode a JIT-compiled V1 evaluation kernel dispatch into this command
    /// buffer.  The command buffer is NOT committed yet.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_compiled_program_v1(
        &self,
        shader_source: &str,
        kernel_name: &str,
        trace_values: &U32Buffer,
        interaction_offsets: &U32Buffer,
        preprocessed_values: &U32Buffer,
        base_params: &U32Buffer,
        ext_params: &U32Buffer,
        random_coeff_powers: &U32Buffer,
        dst: &U32Buffer,
        row_count: usize,
    ) -> Result<(), MetalError> {
        let runtime = shared_runtime()?;
        unsafe {
            ffi::encode_compiled_program_v1(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                shader_source.as_ptr(),
                shader_source.len(),
                kernel_name.as_ptr(),
                kernel_name.len(),
                trace_values.raw.as_ptr(),
                interaction_offsets.raw.as_ptr(),
                preprocessed_values.raw.as_ptr(),
                base_params.raw.as_ptr(),
                ext_params.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                error_buffer_mut_ptr,
            )
        }
    }

    /// Encode a fused blit+compute dispatch into this command buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_compiled_fused_blit_v1(
        &self,
        shader_source: &str,
        kernel_name: &str,
        column_buffers: &[&U32Buffer],
        column_lengths: &[usize],
        interaction_offsets: &U32Buffer,
        random_coeff_powers: &U32Buffer,
        dst: &U32Buffer,
        row_count: usize,
    ) -> Result<(), MetalError> {
        let runtime = shared_runtime()?;
        let raw_ptrs: Vec<*mut std::ffi::c_void> =
            column_buffers.iter().map(|b| b.raw.as_ptr()).collect();
        unsafe {
            ffi::encode_compiled_fused_blit_v1(
                runtime.raw.as_ptr(),
                self.raw.as_ptr(),
                shader_source.as_ptr(),
                shader_source.len(),
                kernel_name.as_ptr(),
                kernel_name.len(),
                raw_ptrs.as_ptr(),
                column_lengths.as_ptr(),
                column_buffers.len(),
                interaction_offsets.raw.as_ptr(),
                random_coeff_powers.raw.as_ptr(),
                dst.raw.as_ptr(),
                row_count.try_into().expect("row_count should fit in u32"),
                error_buffer_mut_ptr,
            )
        }
    }

    /// Commit the command buffer (non-blocking) and convert to a
    /// [`CommandBufferHandle`] for deferred waiting.
    pub fn commit(self) -> CommandBufferHandle {
        let ptr = self.raw.as_ptr();
        // Prevent Drop from releasing — we transfer ownership to CommandBufferHandle.
        std::mem::forget(self);
        unsafe { ffi::command_buffer_commit(ptr) };
        CommandBufferHandle {
            raw: NonNull::new(ptr).expect("commit should preserve non-null pointer"),
        }
    }
}

impl Drop for BatchCommandBuffer {
    fn drop(&mut self) {
        // If the batch is dropped without being committed, release the
        // command buffer to avoid leaking the ObjC object.
        unsafe { ffi::command_buffer_release(self.raw.as_ptr()) };
    }
}

impl Drop for U32Buffer {
    fn drop(&mut self) {
        unsafe { ffi::buffer_destroy(self.raw.as_ptr()) };
    }
}

pub fn metal_runtime_support() -> MetalRuntimeSupport {
    if env!("STWO_METAL_BUILD_MODE") == "no-metal" {
        return MetalRuntimeSupport::DisabledByConfiguration;
    }
    if !cfg!(target_os = "macos") {
        return MetalRuntimeSupport::UnsupportedTarget;
    }
    if shared_runtime().is_ok() {
        MetalRuntimeSupport::Available
    } else {
        MetalRuntimeSupport::InitializationFailed
    }
}

pub fn metal_runtime_error() -> Option<String> {
    shared_runtime().err().map(|error| error.message.clone())
}

fn shared_runtime() -> Result<&'static RuntimeHandle, MetalError> {
    static RUNTIME: OnceLock<Result<RuntimeHandle, MetalError>> = OnceLock::new();
    RUNTIME
        .get_or_init(RuntimeHandle::initialize)
        .as_ref()
        .map_err(Clone::clone)
}

/// Blocks until every command buffer committed to the shared queue so far has
/// completed (an empty command buffer is submitted and waited on; queues
/// execute in FIFO order, so it cannot complete before its predecessors).
///
/// Host-side code MUST call this before reading a buffer that a dropped-handle
/// async GPU submission (e.g. [`U32Buffer::rfft_evaluate_in_place_async`]) may
/// still be writing. GPU-side consumers do not need it: same-queue ordering
/// already serializes them after the producer.
pub fn queue_drain() -> Result<(), MetalError> {
    let runtime = shared_runtime()?;
    unsafe { ffi::queue_drain(runtime.raw.as_ptr(), error_buffer_mut_ptr) }
}

impl RuntimeHandle {
    fn initialize() -> Result<Self, MetalError> {
        if env!("STWO_METAL_BUILD_MODE") == "no-metal" {
            return Err(MetalError::new(
                "Metal runtime is disabled by STWO_METAL_MODE=no-metal.",
            ));
        }
        if !cfg!(target_os = "macos") {
            return Err(MetalError::new("Metal runtime requires a macOS host."));
        }
        if !STWO_METAL_KERNEL_LIBRARY.is_empty() {
            // AOT-compiled library embedded at build time.
            return unsafe {
                ffi::runtime_create(
                    STWO_METAL_KERNEL_LIBRARY.as_ptr(),
                    STWO_METAL_KERNEL_LIBRARY.len(),
                    error_buffer_mut_ptr,
                )
                .map(|raw| Self { raw })
            };
        }
        if !STWO_METAL_KERNEL_LIBRARY_SOURCES.is_empty() {
            // Shader sources embedded at build time; compiled once here by the Metal driver
            // (one library per translation unit).
            let sources: Vec<std::ffi::CString> = STWO_METAL_KERNEL_LIBRARY_SOURCES
                .iter()
                .map(|source| {
                    std::ffi::CString::new(*source)
                        .map_err(|_| MetalError::new("Embedded Metal source contains a NUL byte."))
                })
                .collect::<Result<_, _>>()?;
            let source_ptrs: Vec<*const core::ffi::c_char> =
                sources.iter().map(|source| source.as_ptr()).collect();
            return unsafe {
                ffi::runtime_create_from_sources(
                    source_ptrs.as_ptr(),
                    source_ptrs.len(),
                    error_buffer_mut_ptr,
                )
                .map(|raw| Self { raw })
            };
        }
        Err(MetalError::new(
            "Metal runtime was requested but no kernel library was embedded at build time.",
        ))
    }
}

fn error_buffer_mut_ptr(buffer: &mut [i8; ERROR_BUFFER_LEN]) -> *mut i8 {
    buffer.as_mut_ptr()
}

fn decode_error_buffer(buffer: &[i8; ERROR_BUFFER_LEN]) -> String {
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(stwo_metal_link)]
pub mod ffi {
    use super::{
        c_void, decode_error_buffer, BatchEvalGroupDescriptor, MetalError, NonNull,
        ERROR_BUFFER_LEN,
    };

    unsafe extern "C" {
        fn stwo_metal_runtime_create(
            metallib_bytes: *const u8,
            metallib_len: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_runtime_create_from_sources(
            library_sources: *const *const core::ffi::c_char,
            library_source_count: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_runtime_destroy(runtime: *mut c_void);
        fn stwo_metal_u32_buffer_from_host(
            runtime: *mut c_void,
            host_ptr: *const u32,
            len: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_u32_buffer_alloc_zeroed(
            runtime: *mut c_void,
            len: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_u32_buffer_alloc_uninitialized(
            runtime: *mut c_void,
            len: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_u32_buffer_alloc_uninitialized_private(
            runtime: *mut c_void,
            len: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_u32_buffer_from_host_private(
            runtime: *mut c_void,
            host_ptr: *const u32,
            len: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_u32_buffer_is_private(buffer: *mut c_void) -> bool;
        fn stwo_metal_u32_buffer_promote_to_private(
            runtime: *mut c_void,
            buffer: *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_u32_buffer_destroy(buffer: *mut c_void);
        fn stwo_metal_u32_buffer_read(
            runtime: *mut c_void,
            buffer: *mut c_void,
            host_ptr: *mut u32,
            len: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_u32_buffer_host_ptr(buffer: *mut c_void) -> *const u32;
        fn stwo_metal_u32_buffer_get(buffer: *mut c_void, index: usize) -> u32;
        fn stwo_metal_u32_buffer_set(buffer: *mut c_void, index: usize, value: u32);
        fn stwo_metal_u32_buffer_copy(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            len: usize,
            dst_offset: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_u32_buffer_copy_range(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            src_offset: usize,
            len: usize,
            dst_offset: usize,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_bit_reverse_u32(
            runtime: *mut c_void,
            buffer: *mut c_void,
            log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_bit_reverse_u32x4(
            runtime: *mut c_void,
            buffer: *mut c_void,
            log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_invert_m31_values_u32(
            runtime: *mut c_void,
            buffer: *mut c_void,
            len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_precompute_twiddle_level_u32(
            runtime: *mut c_void,
            dst: *mut c_void,
            offset: u32,
            initial_x: u32,
            initial_y: u32,
            step_x: u32,
            step_y: u32,
            level_log_size: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_rfft_evaluate_u32(
            runtime: *mut c_void,
            values: *mut c_void,
            twiddles: *mut c_void,
            values_log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_rfft_evaluate_subbuffer_u32(
            runtime: *mut c_void,
            values: *mut c_void,
            value_offset: usize,
            values_log_len: u32,
            twiddles: *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_rfft_evaluate_subbuffer_async_u32(
            runtime: *mut c_void,
            values: *mut c_void,
            value_offset: usize,
            values_log_len: u32,
            twiddles: *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_rfft_evaluate_multi_u32(
            runtime: *mut c_void,
            buffer_ptrs: *const *mut c_void,
            n_buffers: u32,
            twiddles: *mut c_void,
            values_log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_rfft_evaluate_async_u32(
            runtime: *mut c_void,
            values: *mut c_void,
            twiddles: *mut c_void,
            values_log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_command_buffer_wait(
            command_buffer: *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_command_buffer_release(command_buffer: *mut c_void);
        fn stwo_metal_queue_drain(
            runtime: *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_ifft_interpolate_u32(
            runtime: *mut c_void,
            values: *mut c_void,
            inverse_twiddles: *mut c_void,
            values_log_len: u32,
            scale_factor: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_ifft_interpolate_batch_u32(
            runtime: *mut c_void,
            values_ptrs: *const *mut c_void,
            inverse_twiddles_ptrs: *const *mut c_void,
            values_log_lens: *const u32,
            scale_factors: *const u32,
            n_columns: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_ifft_line_interpolate_u32(
            runtime: *mut c_void,
            values: *mut c_void,
            inverse_line_twiddles: *mut c_void,
            values_log_len: u32,
            scale_factor: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_batch_eval_at_point_base_field_u32(
            runtime: *mut c_void,
            flat_coeffs: *mut c_void,
            factors: *mut c_void,
            dst: *mut c_void,
            coeffs_log_len: u32,
            n_polys: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_batch_eval_at_point_multi_group_u32(
            runtime: *mut c_void,
            groups: *const BatchEvalGroupDescriptor,
            n_groups: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_batch_eval_at_point_transposed_u32(
            runtime: *mut c_void,
            flat_coeffs: *mut c_void,
            basis_evals: *mut c_void,
            dst: *mut c_void,
            n_polys: u32,
            n_coeffs: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_barycentric_eval_at_point_u32(
            runtime: *mut c_void,
            eval_values: *mut c_void,
            weights: *mut c_void,
            dst: *mut c_void,
            n_elements: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_batch_eval_first_pass_base_field_u32(
            runtime: *mut c_void,
            flat_coeffs: *mut c_void,
            factors: *mut c_void,
            dst: *mut c_void,
            coeffs_log_len: u32,
            n_polys: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fix_first_variable_base_field_u32(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            src_log_len: u32,
            assignment_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fix_first_variable_secure_field_u32x4(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            src_log_len: u32,
            assignment_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_gen_eq_evals_u32x4(
            runtime: *mut c_void,
            factors: *mut c_void,
            dst: *mut c_void,
            y_size: u32,
            v_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_next_grand_product_layer_u32x4(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            input_log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_next_logup_generic_layer_u32x4(
            runtime: *mut c_void,
            numerators: *mut c_void,
            denominators: *mut c_void,
            next_numerators: *mut c_void,
            next_denominators: *mut c_void,
            input_log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_next_logup_multiplicities_layer_u32(
            runtime: *mut c_void,
            numerators: *mut c_void,
            denominators: *mut c_void,
            next_numerators: *mut c_void,
            next_denominators: *mut c_void,
            input_log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_next_logup_singles_layer_u32x4(
            runtime: *mut c_void,
            denominators: *mut c_void,
            next_numerators: *mut c_void,
            next_denominators: *mut c_void,
            input_log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_sum_grand_product_u32x4(
            runtime: *mut c_void,
            eq_evals: *mut c_void,
            input_layer: *mut c_void,
            n_terms: u32,
            eval_at_0_limbs: *mut u32,
            eval_at_2_limbs: *mut u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_sum_logup_generic_u32x4(
            runtime: *mut c_void,
            eq_evals: *mut c_void,
            numerators: *mut c_void,
            denominators: *mut c_void,
            n_terms: u32,
            lambda_limbs: *const u32,
            eval_at_0_limbs: *mut u32,
            eval_at_2_limbs: *mut u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_sum_logup_multiplicities_u32(
            runtime: *mut c_void,
            eq_evals: *mut c_void,
            numerators: *mut c_void,
            denominators: *mut c_void,
            n_terms: u32,
            lambda_limbs: *const u32,
            eval_at_0_limbs: *mut u32,
            eval_at_2_limbs: *mut u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_gkr_sum_logup_singles_u32x4(
            runtime: *mut c_void,
            eq_evals: *mut c_void,
            denominators: *mut c_void,
            n_terms: u32,
            lambda_limbs: *const u32,
            eval_at_0_limbs: *mut u32,
            eval_at_2_limbs: *mut u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_inclusive_prefix_sum_bit_rev_circle_domain_u32(
            runtime: *mut c_void,
            buffer: *mut c_void,
            log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_reduce_sum_m31_4col(
            runtime: *mut c_void,
            col0: *mut c_void,
            col1: *mut c_void,
            col2: *mut c_void,
            col3: *mut c_void,
            output: *mut c_void,
            n_elements: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_prefix_sum_subtract_m31_4col(
            runtime: *mut c_void,
            col0: *mut c_void,
            col1: *mut c_void,
            col2: *mut c_void,
            col3: *mut c_void,
            cumsum_shifts: *const u32,
            n_elements: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_permute_coset_to_circle_domain_bit_reversed_u32(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            log_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_pack_secure_column_coords_u32x4(
            runtime: *mut c_void,
            coord_0: *mut c_void,
            coord_1: *mut c_void,
            coord_2: *mut c_void,
            coord_3: *mut c_void,
            dst: *mut c_void,
            element_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_unpack_secure_column_coords_u32x4(
            runtime: *mut c_void,
            src: *mut c_void,
            coord_0: *mut c_void,
            coord_1: *mut c_void,
            coord_2: *mut c_void,
            coord_3: *mut c_void,
            element_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_accumulate_secure_columns_coords_u32x4(
            runtime: *mut c_void,
            lhs_0: *mut c_void,
            lhs_1: *mut c_void,
            lhs_2: *mut c_void,
            lhs_3: *mut c_void,
            rhs_0: *mut c_void,
            rhs_1: *mut c_void,
            rhs_2: *mut c_void,
            rhs_3: *mut c_void,
            dst_0: *mut c_void,
            dst_1: *mut c_void,
            dst_2: *mut c_void,
            dst_3: *mut c_void,
            element_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_lift_accumulate_secure_columns_coords_u32x4(
            runtime: *mut c_void,
            lifted_0: *mut c_void,
            lifted_1: *mut c_void,
            lifted_2: *mut c_void,
            lifted_3: *mut c_void,
            current_0: *mut c_void,
            current_1: *mut c_void,
            current_2: *mut c_void,
            current_3: *mut c_void,
            dst_0: *mut c_void,
            dst_1: *mut c_void,
            dst_2: *mut c_void,
            dst_3: *mut c_void,
            current_log_size: u32,
            log_ratio: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fri_fold_circle_into_line_first_layer_u32x4(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            inverse_y_factors: *mut c_void,
            src_log_len: u32,
            alpha_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fri_fold_circle_into_line_accumulate_coords_u32x4(
            runtime: *mut c_void,
            src_0: *mut c_void,
            src_1: *mut c_void,
            src_2: *mut c_void,
            src_3: *mut c_void,
            dst_0: *mut c_void,
            dst_1: *mut c_void,
            dst_2: *mut c_void,
            dst_3: *mut c_void,
            inverse_y_factors: *mut c_void,
            src_log_len: u32,
            alpha_limbs: *const u32,
            alpha_sq_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fri_fold_circle_into_line_first_layer_coords_u32x4(
            runtime: *mut c_void,
            src_0: *mut c_void,
            src_1: *mut c_void,
            src_2: *mut c_void,
            src_3: *mut c_void,
            dst_0: *mut c_void,
            dst_1: *mut c_void,
            dst_2: *mut c_void,
            dst_3: *mut c_void,
            inverse_y_factors: *mut c_void,
            src_log_len: u32,
            alpha_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fri_fold_line_step_coords_u32x4(
            runtime: *mut c_void,
            src_0: *mut c_void,
            src_1: *mut c_void,
            src_2: *mut c_void,
            src_3: *mut c_void,
            dst_0: *mut c_void,
            dst_1: *mut c_void,
            dst_2: *mut c_void,
            dst_3: *mut c_void,
            inverse_x_factors: *mut c_void,
            src_log_len: u32,
            alpha_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fri_fold_line_step_coords_u32x4_async(
            runtime: *mut c_void,
            src_0: *mut c_void,
            src_1: *mut c_void,
            src_2: *mut c_void,
            src_3: *mut c_void,
            dst_0: *mut c_void,
            dst_1: *mut c_void,
            dst_2: *mut c_void,
            dst_3: *mut c_void,
            inverse_x_factors: *mut c_void,
            src_log_len: u32,
            alpha_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_fri_fold_line_step_u32x4(
            runtime: *mut c_void,
            src: *mut c_void,
            dst: *mut c_void,
            inverse_x_factors: *mut c_void,
            src_log_len: u32,
            alpha_limbs: *const u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_generate_wide_fibonacci_trace_u32(
            runtime: *mut c_void,
            input_a: *mut c_void,
            input_b: *mut c_void,
            trace: *mut c_void,
            input_log_len: u32,
            n_columns: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_memory_id_to_big_trace(
            runtime: *mut c_void,
            big_values: *mut c_void,
            mults: *mut c_void,
            trace: *mut c_void,
            n_values: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_memory_id_to_big_small_trace(
            runtime: *mut c_void,
            small_values: *mut c_void,
            mults: *mut c_void,
            trace: *mut c_void,
            n_values: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_memory_addr_to_id_trace(
            runtime: *mut c_void,
            ids: *mut c_void,
            mults: *mut c_void,
            trace: *mut c_void,
            n_ids: u32,
            column_length: u32,
            split: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_add_opcode_small_trace(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_assert_eq_double_deref_trace(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_jnz_opcode_taken_trace(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_jump_opcode_rel_imm_trace(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_call_opcode_rel_imm_trace(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_ret_opcode_trace(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_range_check_trace(
            runtime: *mut c_void,
            mults: *mut c_void,
            trace: *mut c_void,
            n_columns: u32,
            column_length: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_trace_id_to_big(
            runtime: *mut c_void,
            limbs: *mut c_void,
            mults: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            relation_ids: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            id_offset: u32,
            large_id_base: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_trace_id_to_big_small(
            runtime: *mut c_void,
            limbs: *mut c_void,
            mults: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            relation_ids: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_trace_addr_to_id(
            runtime: *mut c_void,
            ids: *mut c_void,
            mults: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            relation_id: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            split: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_trace_generic(
            runtime: *mut c_void,
            values: *mut c_void,
            descriptors: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            n_logup_cols: u32,
            n_rows_real: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_accumulate_wide_fibonacci_quotients_u32x4(
            runtime: *mut c_void,
            trace_evaluations: *mut c_void,
            random_coeff_powers: *mut c_void,
            denominator_inverses: *mut c_void,
            dst: *mut c_void,
            domain_log_size: u32,
            eval_domain_log_size: u32,
            n_constraints: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_accumulate_partial_numerators_u32x4(
            runtime: *mut c_void,
            columns: *mut c_void,
            column_indices: *mut c_void,
            b_coeffs: *mut c_void,
            c_coeffs: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_terms: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_accumulate_partial_numerators_batched_u32x4(
            runtime: *mut c_void,
            columns: *mut c_void,
            column_indices: *mut c_void,
            b_coeffs: *mut c_void,
            c_coeffs: *mut c_void,
            term_offsets: *mut c_void,
            term_counts: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_batches: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_accumulate_and_unpack_partial_numerators_batched_u32x4(
            runtime: *mut c_void,
            columns: *mut c_void,
            column_indices: *mut c_void,
            b_coeffs: *mut c_void,
            c_coeffs: *mut c_void,
            term_offsets: *mut c_void,
            term_counts: *mut c_void,
            row_count: u32,
            n_batches: u32,
            output_coord_buffers: *mut *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_accumulate_and_unpack_partial_numerators_indirect_batched_u32x4(
            runtime: *mut c_void,
            column_buffer_ptrs: *mut *mut c_void,
            n_unique_cols: u32,
            column_indices: *mut c_void,
            b_coeffs: *mut c_void,
            c_coeffs: *mut c_void,
            term_offsets: *mut c_void,
            term_counts: *mut c_void,
            row_count: u32,
            n_batches: u32,
            output_coord_buffers: *mut *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_compute_quotients_and_combine_u32x4(
            runtime: *mut c_void,
            partial_coord_0: *mut c_void,
            partial_coord_1: *mut c_void,
            partial_coord_2: *mut c_void,
            partial_coord_3: *mut c_void,
            sample_points: *mut c_void,
            first_linear_terms: *mut c_void,
            partial_log_sizes: *mut c_void,
            partial_offsets: *mut c_void,
            domain_x: *mut c_void,
            domain_y: *mut c_void,
            dst: *mut c_void,
            lifting_log_size: u32,
            n_accumulations: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_compute_quotients_and_combine_packed_u32x4(
            runtime: *mut c_void,
            partials: *mut c_void,
            sample_points: *mut c_void,
            first_linear_terms: *mut c_void,
            partial_log_sizes: *mut c_void,
            partial_offsets: *mut c_void,
            domain_x: *mut c_void,
            domain_y: *mut c_void,
            dst: *mut c_void,
            lifting_log_size: u32,
            n_accumulations: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_compute_quotients_and_combine_indirect_packed_u32x4(
            runtime: *mut c_void,
            partial_buffer_ptrs: *const *mut c_void,
            sample_points: *mut c_void,
            first_linear_terms: *mut c_void,
            partial_log_sizes: *mut c_void,
            partial_offsets: *mut c_void,
            domain_x: *mut c_void,
            domain_y: *mut c_void,
            dst: *mut c_void,
            lifting_log_size: u32,
            n_accumulations: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_build_leaves_lifted_u32(
            runtime: *mut c_void,
            flat_columns: *mut c_void,
            column_offsets: *mut c_void,
            column_log_sizes: *mut c_void,
            dst: *mut c_void,
            n_columns: u32,
            lifting_log_size: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_build_leaves_lifted_wide_chunk_u32(
            runtime: *mut c_void,
            column_buffers: *const *mut c_void,
            state: *mut c_void,
            dst: *mut c_void,
            column_log_sizes: *const u32,
            n_columns: u32,
            lifting_log_size: u32,
            processed_bytes_before: u32,
            is_first_chunk: u32,
            is_final_chunk: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_build_leaves_lifted_wide_batched_u32(
            runtime: *mut c_void,
            all_column_buffers: *const *mut c_void,
            state: *mut c_void,
            dst: *mut c_void,
            all_column_log_sizes: *const u32,
            total_columns: u32,
            lifting_log_size: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_build_leaves_lifted_fast_u32(
            runtime: *mut c_void,
            column_buffers: *const *mut c_void,
            dst: *mut c_void,
            column_log_sizes: *const u32,
            n_columns: u32,
            lifting_log_size: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_build_next_layer_u32(
            runtime: *mut c_void,
            prev_layer: *mut c_void,
            dst: *mut c_void,
            next_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_build_merkle_layers_u32(
            runtime: *mut c_void,
            leaf_layer: *mut c_void,
            layer_ptrs: *const *mut c_void,
            leaf_log_size: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_build_merkle_tree_fast_u32(
            runtime: *mut c_void,
            column_buffers: *const *mut c_void,
            leaf_layer: *mut c_void,
            layer_ptrs: *const *mut c_void,
            column_log_sizes: *const u32,
            n_columns: u32,
            lifting_log_size: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_reference_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_optimized_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            max_base_regs: u32,
            max_ext_regs: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_reference_async_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_eval_program_v1_optimized_async_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            max_base_regs: u32,
            max_ext_regs: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_eval_program_v1_reference_u32x4_tg(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            threads_per_group: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_optimized_u32x4_tg(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            max_base_regs: u32,
            max_ext_regs: u32,
            threads_per_group: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_reference_b_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_optimized_b_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            max_base_regs: u32,
            max_ext_regs: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_reference_c_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_optimized_c_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            base_insts: *mut c_void,
            ext_insts: *mut c_void,
            constraint_roots: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_preprocessed_columns: u32,
            n_base_params: u32,
            n_ext_params: u32,
            n_base_insts: u32,
            n_ext_insts: u32,
            n_constraints: u32,
            max_base_regs: u32,
            max_ext_regs: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_program_v1_wide_fibonacci_u32x4(
            runtime: *mut c_void,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            random_coeff_powers: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            n_interactions: u32,
            n_constraints: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_compiled_program_v1_u32x4(
            runtime: *mut c_void,
            shader_source: *const u8,
            shader_source_len: usize,
            kernel_name: *const u8,
            kernel_name_len: usize,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_compiled_fused_composition_v1(
            runtime: *mut c_void,
            shader_source: *const u8,
            shader_source_len: usize,
            kernel_name: *const u8,
            kernel_name_len: usize,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            denom_inv: *mut c_void,
            coord_0: *mut c_void,
            coord_1: *mut c_void,
            coord_2: *mut c_void,
            coord_3: *mut c_void,
            row_count: u32,
            log_n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_compiled_program_v1_u32x4_tg(
            runtime: *mut c_void,
            shader_source: *const u8,
            shader_source_len: usize,
            kernel_name: *const u8,
            kernel_name_len: usize,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            threads_per_group: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_compiled_program_v1_u32x4_async(
            runtime: *mut c_void,
            shader_source: *const u8,
            shader_source_len: usize,
            kernel_name: *const u8,
            kernel_name_len: usize,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            out_handle: *mut *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_eval_compiled_fused_blit_async(
            runtime: *mut c_void,
            shader_source: *const u8,
            shader_source_len: usize,
            kernel_name: *const u8,
            kernel_name_len: usize,
            column_buffer_ptrs: *const *mut c_void,
            column_lengths: *const usize,
            n_columns: usize,
            interaction_offsets: *mut c_void,
            random_coeff_powers: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            out_handle: *mut *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        // Batched command buffer lifecycle
        fn stwo_metal_command_buffer_create(
            runtime: *mut c_void,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> *mut c_void;
        fn stwo_metal_encode_compiled_program_v1(
            runtime: *mut c_void,
            command_buffer: *mut c_void,
            shader_source: *const u8,
            shader_source_len: usize,
            kernel_name: *const u8,
            kernel_name_len: usize,
            trace_values: *mut c_void,
            interaction_offsets: *mut c_void,
            preprocessed_values: *mut c_void,
            base_params: *mut c_void,
            ext_params: *mut c_void,
            random_coeff_powers: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_encode_compiled_fused_blit_v1(
            runtime: *mut c_void,
            command_buffer: *mut c_void,
            shader_source: *const u8,
            shader_source_len: usize,
            kernel_name: *const u8,
            kernel_name_len: usize,
            column_buffer_ptrs: *const *mut c_void,
            column_lengths: *const usize,
            n_columns: usize,
            interaction_offsets: *mut c_void,
            random_coeff_powers: *mut c_void,
            dst: *mut c_void,
            row_count: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_command_buffer_commit(command_buffer: *mut c_void);
        fn stwo_metal_sampled_values_v1_wide_fibonacci_u32x4(
            runtime: *mut c_void,
            tree_descs: *mut c_void,
            column_descs: *mut c_void,
            values: *mut c_void,
            point_x: *mut c_void,
            dst: *mut c_void,
            n_trees: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_u32_buffer_read_indices(
            runtime: *mut c_void,
            buffer: *mut c_void,
            indices: *const u32,
            indices_len: usize,
            host_ptr: *mut u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_blake2s_grind_batch(
            runtime: *mut c_void,
            prefix_digest: *const u32,
            pow_bits: u32,
            nonce_hi: u32,
            batch_size: u32,
            out_nonce_lo: *mut u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_witness_verify_instruction_trace(
            runtime: *mut c_void,
            inputs: *mut c_void,
            mults: *mut c_void,
            addr_to_id: *mut c_void,
            trace: *mut c_void,
            n_rows: u32,
            column_length: u32,
            addr_to_id_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_merkle_decommit_gather(
            runtime: *mut c_void,
            layer_ptrs: *const *mut c_void,
            n_layers: u32,
            per_layer_indices: *const *const u32,
            per_layer_counts: *const u32,
            out_hashes: *mut u32,
            total_gathers: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_mults_add_opcode_small(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            addr_to_id_mults: *mut c_void,
            id_to_big_mults: *mut c_void,
            id_to_small_mults: *mut c_void,
            n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_mults_assert_eq_double_deref(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            addr_to_id_mults: *mut c_void,
            id_to_big_mults: *mut c_void,
            id_to_small_mults: *mut c_void,
            n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_mults_jnz_opcode_taken(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            addr_to_id_mults: *mut c_void,
            id_to_big_mults: *mut c_void,
            id_to_small_mults: *mut c_void,
            n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_mults_jump_opcode_rel_imm(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            addr_to_id_mults: *mut c_void,
            id_to_big_mults: *mut c_void,
            id_to_small_mults: *mut c_void,
            n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_mults_call_opcode_rel_imm(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            addr_to_id_mults: *mut c_void,
            id_to_big_mults: *mut c_void,
            id_to_small_mults: *mut c_void,
            n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_mults_ret_opcode(
            runtime: *mut c_void,
            inputs: *mut c_void,
            address_to_id: *mut c_void,
            big_values: *mut c_void,
            small_values: *mut c_void,
            addr_to_id_mults: *mut c_void,
            id_to_big_mults: *mut c_void,
            id_to_small_mults: *mut c_void,
            n_rows: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_values_ret_opcode(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_values_jnz_opcode_taken(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_values_assert_eq_double_deref(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_values_jump_opcode_rel_imm(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_interaction_values_call_opcode_rel_imm(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fused_interaction_ret_opcode(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fused_interaction_jump_opcode_rel_imm(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fused_interaction_assert_eq_double_deref(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fused_interaction_jnz_opcode_taken(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fused_interaction_call_opcode_rel_imm(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
        fn stwo_metal_fused_interaction_add_opcode_small(
            runtime: *mut c_void,
            trace_cols: *mut c_void,
            alpha_powers: *mut c_void,
            z: *mut c_void,
            output: *mut c_void,
            n_rows: u32,
            col_len: u32,
            error_message: *mut i8,
            error_message_len: usize,
        ) -> bool;
    }

    pub unsafe fn runtime_create(
        metallib_bytes: *const u8,
        metallib_len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let raw = stwo_metal_runtime_create(
            metallib_bytes,
            metallib_len,
            error_ptr(&mut error),
            error.len(),
        );
        NonNull::new(raw).ok_or_else(|| MetalError::new(decode_error_buffer(&error)))
    }

    pub unsafe fn runtime_create_from_sources(
        library_sources: *const *const core::ffi::c_char,
        library_source_count: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let raw = stwo_metal_runtime_create_from_sources(
            library_sources,
            library_source_count,
            error_ptr(&mut error),
            error.len(),
        );
        NonNull::new(raw).ok_or_else(|| MetalError::new(decode_error_buffer(&error)))
    }

    pub unsafe fn runtime_destroy(runtime: *mut c_void) {
        stwo_metal_runtime_destroy(runtime);
    }

    pub unsafe fn buffer_from_host(
        runtime: *mut c_void,
        host_ptr: *const u32,
        len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let raw = stwo_metal_u32_buffer_from_host(
            runtime,
            host_ptr,
            len,
            error_ptr(&mut error),
            error.len(),
        );
        NonNull::new(raw).ok_or_else(|| MetalError::new(decode_error_buffer(&error)))
    }

    pub unsafe fn buffer_alloc_zeroed(
        runtime: *mut c_void,
        len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let raw =
            stwo_metal_u32_buffer_alloc_zeroed(runtime, len, error_ptr(&mut error), error.len());
        NonNull::new(raw).ok_or_else(|| MetalError::new(decode_error_buffer(&error)))
    }

    pub unsafe fn buffer_alloc_uninitialized(
        runtime: *mut c_void,
        len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let raw = stwo_metal_u32_buffer_alloc_uninitialized(
            runtime,
            len,
            error_ptr(&mut error),
            error.len(),
        );
        NonNull::new(raw).ok_or_else(|| MetalError::new(decode_error_buffer(&error)))
    }

    pub unsafe fn buffer_destroy(buffer: *mut c_void) {
        stwo_metal_u32_buffer_destroy(buffer);
    }

    pub unsafe fn buffer_read(
        runtime: *mut c_void,
        buffer: *mut c_void,
        host_ptr: *mut u32,
        len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_u32_buffer_read(
            runtime,
            buffer,
            host_ptr,
            len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn buffer_host_ptr(buffer: *mut c_void) -> *const u32 {
        stwo_metal_u32_buffer_host_ptr(buffer)
    }

    pub unsafe fn buffer_get(buffer: *mut c_void, index: usize) -> u32 {
        stwo_metal_u32_buffer_get(buffer, index)
    }

    pub unsafe fn buffer_set(buffer: *mut c_void, index: usize, value: u32) {
        stwo_metal_u32_buffer_set(buffer, index, value);
    }

    pub unsafe fn buffer_copy(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        len: usize,
        dst_offset: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_u32_buffer_copy(
            runtime,
            src,
            dst,
            len,
            dst_offset,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn buffer_copy_range(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        src_offset: usize,
        len: usize,
        dst_offset: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_u32_buffer_copy_range(
            runtime,
            src,
            dst,
            src_offset,
            len,
            dst_offset,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn buffer_from_host_private(
        runtime: *mut c_void,
        host_ptr: *const u32,
        len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let raw = stwo_metal_u32_buffer_from_host_private(
            runtime,
            host_ptr,
            len,
            error_ptr(&mut error),
            error.len(),
        );
        NonNull::new(raw).ok_or_else(|| MetalError::new(decode_error_buffer(&error)))
    }

    pub unsafe fn buffer_alloc_uninitialized_private(
        runtime: *mut c_void,
        len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let raw = stwo_metal_u32_buffer_alloc_uninitialized_private(
            runtime,
            len,
            error_ptr(&mut error),
            error.len(),
        );
        NonNull::new(raw).ok_or_else(|| MetalError::new(decode_error_buffer(&error)))
    }

    pub unsafe fn buffer_is_private(buffer: *mut c_void) -> bool {
        stwo_metal_u32_buffer_is_private(buffer)
    }

    pub unsafe fn buffer_promote_to_private(
        runtime: *mut c_void,
        buffer: *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_u32_buffer_promote_to_private(
            runtime,
            buffer,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn bit_reverse_u32(
        runtime: *mut c_void,
        buffer: *mut c_void,
        log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_bit_reverse_u32(runtime, buffer, log_len, error_ptr(&mut error), error.len())
        {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn bit_reverse_u32x4(
        runtime: *mut c_void,
        buffer: *mut c_void,
        log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_bit_reverse_u32x4(
            runtime,
            buffer,
            log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn invert_m31_values_u32(
        runtime: *mut c_void,
        buffer: *mut c_void,
        len: usize,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_invert_m31_values_u32(
            runtime,
            buffer,
            len.try_into()
                .expect("Metal inversion length should fit in u32"),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn precompute_twiddle_level_u32(
        runtime: *mut c_void,
        dst: *mut c_void,
        offset: usize,
        initial_xy: [u32; 2],
        step_xy: [u32; 2],
        level_log_size: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_precompute_twiddle_level_u32(
            runtime,
            dst,
            offset
                .try_into()
                .expect("Metal twiddle offset should fit in u32"),
            initial_xy[0],
            initial_xy[1],
            step_xy[0],
            step_xy[1],
            level_log_size,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn rfft_evaluate_u32(
        runtime: *mut c_void,
        values: *mut c_void,
        twiddles: *mut c_void,
        values_log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_rfft_evaluate_u32(
            runtime,
            values,
            twiddles,
            values_log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn rfft_evaluate_subbuffer_u32(
        runtime: *mut c_void,
        values: *mut c_void,
        value_offset: usize,
        values_log_len: u32,
        twiddles: *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_rfft_evaluate_subbuffer_u32(
            runtime,
            values,
            value_offset,
            values_log_len,
            twiddles,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn rfft_evaluate_subbuffer_async_u32(
        runtime: *mut c_void,
        values: *mut c_void,
        value_offset: usize,
        values_log_len: u32,
        twiddles: *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let handle = stwo_metal_rfft_evaluate_subbuffer_async_u32(
            runtime,
            values,
            value_offset,
            values_log_len,
            twiddles,
            error_ptr(&mut error),
            error.len(),
        );
        if !handle.is_null() {
            Ok(handle)
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn rfft_evaluate_multi_u32(
        runtime: *mut c_void,
        buffer_ptrs: *const *mut c_void,
        n_buffers: u32,
        twiddles: *mut c_void,
        values_log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_rfft_evaluate_multi_u32(
            runtime,
            buffer_ptrs,
            n_buffers,
            twiddles,
            values_log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn rfft_evaluate_async_u32(
        runtime: *mut c_void,
        values: *mut c_void,
        twiddles: *mut c_void,
        values_log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let handle = stwo_metal_rfft_evaluate_async_u32(
            runtime,
            values,
            twiddles,
            values_log_len,
            error_ptr(&mut error),
            error.len(),
        );
        if handle.is_null() {
            Err(MetalError::new(decode_error_buffer(&error)))
        } else {
            Ok(handle)
        }
    }

    pub unsafe fn command_buffer_wait(
        handle: *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_command_buffer_wait(handle, error_ptr(&mut error), error.len()) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn command_buffer_release(handle: *mut c_void) {
        stwo_metal_command_buffer_release(handle);
    }

    pub unsafe fn queue_drain(
        runtime: *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_queue_drain(runtime, error_ptr(&mut error), error.len()) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn ifft_interpolate_u32(
        runtime: *mut c_void,
        values: *mut c_void,
        inverse_twiddles: *mut c_void,
        values_log_len: u32,
        scale_factor: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_ifft_interpolate_u32(
            runtime,
            values,
            inverse_twiddles,
            values_log_len,
            scale_factor,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn ifft_interpolate_batch_u32(
        runtime: *mut c_void,
        values_ptrs: &[*mut c_void],
        inverse_twiddles_ptrs: &[*mut c_void],
        values_log_lens: &[u32],
        scale_factors: &[u32],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let n = values_ptrs.len() as u32;
        if stwo_metal_ifft_interpolate_batch_u32(
            runtime,
            values_ptrs.as_ptr(),
            inverse_twiddles_ptrs.as_ptr(),
            values_log_lens.as_ptr(),
            scale_factors.as_ptr(),
            n,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn ifft_line_interpolate_u32(
        runtime: *mut c_void,
        values: *mut c_void,
        inverse_line_twiddles: *mut c_void,
        values_log_len: u32,
        scale_factor: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_ifft_line_interpolate_u32(
            runtime,
            values,
            inverse_line_twiddles,
            values_log_len,
            scale_factor,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn batch_eval_at_point_base_field_u32(
        runtime: *mut c_void,
        flat_coeffs: *mut c_void,
        factors: *mut c_void,
        dst: *mut c_void,
        coeffs_log_len: u32,
        n_polys: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_batch_eval_at_point_base_field_u32(
            runtime,
            flat_coeffs,
            factors,
            dst,
            coeffs_log_len,
            n_polys,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn batch_eval_at_point_multi_group_u32(
        runtime: *mut c_void,
        groups: *const super::BatchEvalGroupDescriptor,
        n_groups: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_batch_eval_at_point_multi_group_u32(
            runtime,
            groups,
            n_groups,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn batch_eval_at_point_transposed_u32(
        runtime: *mut c_void,
        flat_coeffs: *mut c_void,
        basis_evals: *mut c_void,
        dst: *mut c_void,
        n_polys: u32,
        n_coeffs: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_batch_eval_at_point_transposed_u32(
            runtime,
            flat_coeffs,
            basis_evals,
            dst,
            n_polys,
            n_coeffs,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn barycentric_eval_at_point_u32(
        runtime: *mut c_void,
        eval_values: *mut c_void,
        weights: *mut c_void,
        dst: *mut c_void,
        n_elements: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_barycentric_eval_at_point_u32(
            runtime,
            eval_values,
            weights,
            dst,
            n_elements,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn batch_eval_first_pass_base_field_u32(
        runtime: *mut c_void,
        flat_coeffs: *mut c_void,
        factors: *mut c_void,
        dst: *mut c_void,
        coeffs_log_len: u32,
        n_polys: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_batch_eval_first_pass_base_field_u32(
            runtime,
            flat_coeffs,
            factors,
            dst,
            coeffs_log_len,
            n_polys,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn permute_coset_to_circle_domain_bit_reversed_u32(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_permute_coset_to_circle_domain_bit_reversed_u32(
            runtime,
            src,
            dst,
            log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn pack_secure_column_coords_u32x4(
        runtime: *mut c_void,
        coord_0: *mut c_void,
        coord_1: *mut c_void,
        coord_2: *mut c_void,
        coord_3: *mut c_void,
        dst: *mut c_void,
        element_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_pack_secure_column_coords_u32x4(
            runtime,
            coord_0,
            coord_1,
            coord_2,
            coord_3,
            dst,
            element_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn unpack_secure_column_coords_u32x4(
        runtime: *mut c_void,
        src: *mut c_void,
        coord_0: *mut c_void,
        coord_1: *mut c_void,
        coord_2: *mut c_void,
        coord_3: *mut c_void,
        element_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_unpack_secure_column_coords_u32x4(
            runtime,
            src,
            coord_0,
            coord_1,
            coord_2,
            coord_3,
            element_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn accumulate_secure_columns_coords_u32x4(
        runtime: *mut c_void,
        lhs_0: *mut c_void,
        lhs_1: *mut c_void,
        lhs_2: *mut c_void,
        lhs_3: *mut c_void,
        rhs_0: *mut c_void,
        rhs_1: *mut c_void,
        rhs_2: *mut c_void,
        rhs_3: *mut c_void,
        dst_0: *mut c_void,
        dst_1: *mut c_void,
        dst_2: *mut c_void,
        dst_3: *mut c_void,
        element_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_accumulate_secure_columns_coords_u32x4(
            runtime,
            lhs_0,
            lhs_1,
            lhs_2,
            lhs_3,
            rhs_0,
            rhs_1,
            rhs_2,
            rhs_3,
            dst_0,
            dst_1,
            dst_2,
            dst_3,
            element_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn lift_accumulate_secure_columns_coords_u32x4(
        runtime: *mut c_void,
        lifted_0: *mut c_void,
        lifted_1: *mut c_void,
        lifted_2: *mut c_void,
        lifted_3: *mut c_void,
        current_0: *mut c_void,
        current_1: *mut c_void,
        current_2: *mut c_void,
        current_3: *mut c_void,
        dst_0: *mut c_void,
        dst_1: *mut c_void,
        dst_2: *mut c_void,
        dst_3: *mut c_void,
        current_log_size: u32,
        log_ratio: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_lift_accumulate_secure_columns_coords_u32x4(
            runtime,
            lifted_0,
            lifted_1,
            lifted_2,
            lifted_3,
            current_0,
            current_1,
            current_2,
            current_3,
            dst_0,
            dst_1,
            dst_2,
            dst_3,
            current_log_size,
            log_ratio,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fix_first_variable_base_field_u32(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        src_log_len: u32,
        assignment_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fix_first_variable_base_field_u32(
            runtime,
            src,
            dst,
            src_log_len,
            assignment_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fix_first_variable_secure_field_u32x4(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        src_log_len: u32,
        assignment_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fix_first_variable_secure_field_u32x4(
            runtime,
            src,
            dst,
            src_log_len,
            assignment_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_gen_eq_evals_u32x4(
        runtime: *mut c_void,
        factors: *mut c_void,
        dst: *mut c_void,
        y_size: u32,
        v_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_gkr_gen_eq_evals_u32x4(
            runtime,
            factors,
            dst,
            y_size,
            v_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_next_grand_product_layer_u32x4(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        input_log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_gkr_next_grand_product_layer_u32x4(
            runtime,
            src,
            dst,
            input_log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_next_logup_generic_layer_u32x4(
        runtime: *mut c_void,
        numerators: *mut c_void,
        denominators: *mut c_void,
        next_numerators: *mut c_void,
        next_denominators: *mut c_void,
        input_log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_gkr_next_logup_generic_layer_u32x4(
            runtime,
            numerators,
            denominators,
            next_numerators,
            next_denominators,
            input_log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_next_logup_multiplicities_layer_u32(
        runtime: *mut c_void,
        numerators: *mut c_void,
        denominators: *mut c_void,
        next_numerators: *mut c_void,
        next_denominators: *mut c_void,
        input_log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_gkr_next_logup_multiplicities_layer_u32(
            runtime,
            numerators,
            denominators,
            next_numerators,
            next_denominators,
            input_log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_next_logup_singles_layer_u32x4(
        runtime: *mut c_void,
        denominators: *mut c_void,
        next_numerators: *mut c_void,
        next_denominators: *mut c_void,
        input_log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_gkr_next_logup_singles_layer_u32x4(
            runtime,
            denominators,
            next_numerators,
            next_denominators,
            input_log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_sum_grand_product_u32x4(
        runtime: *mut c_void,
        eq_evals: *mut c_void,
        input_layer: *mut c_void,
        n_terms: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let mut eval_at_0 = [0u32; 4];
        let mut eval_at_2 = [0u32; 4];
        if stwo_metal_gkr_sum_grand_product_u32x4(
            runtime,
            eq_evals,
            input_layer,
            n_terms,
            eval_at_0.as_mut_ptr(),
            eval_at_2.as_mut_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok((eval_at_0, eval_at_2))
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_sum_logup_generic_u32x4(
        runtime: *mut c_void,
        eq_evals: *mut c_void,
        numerators: *mut c_void,
        denominators: *mut c_void,
        n_terms: u32,
        lambda_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let mut eval_at_0 = [0u32; 4];
        let mut eval_at_2 = [0u32; 4];
        if stwo_metal_gkr_sum_logup_generic_u32x4(
            runtime,
            eq_evals,
            numerators,
            denominators,
            n_terms,
            lambda_limbs.as_ptr(),
            eval_at_0.as_mut_ptr(),
            eval_at_2.as_mut_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok((eval_at_0, eval_at_2))
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_sum_logup_multiplicities_u32(
        runtime: *mut c_void,
        eq_evals: *mut c_void,
        numerators: *mut c_void,
        denominators: *mut c_void,
        n_terms: u32,
        lambda_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let mut eval_at_0 = [0u32; 4];
        let mut eval_at_2 = [0u32; 4];
        if stwo_metal_gkr_sum_logup_multiplicities_u32(
            runtime,
            eq_evals,
            numerators,
            denominators,
            n_terms,
            lambda_limbs.as_ptr(),
            eval_at_0.as_mut_ptr(),
            eval_at_2.as_mut_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok((eval_at_0, eval_at_2))
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn gkr_sum_logup_singles_u32x4(
        runtime: *mut c_void,
        eq_evals: *mut c_void,
        denominators: *mut c_void,
        n_terms: u32,
        lambda_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let mut eval_at_0 = [0u32; 4];
        let mut eval_at_2 = [0u32; 4];
        if stwo_metal_gkr_sum_logup_singles_u32x4(
            runtime,
            eq_evals,
            denominators,
            n_terms,
            lambda_limbs.as_ptr(),
            eval_at_0.as_mut_ptr(),
            eval_at_2.as_mut_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok((eval_at_0, eval_at_2))
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn inclusive_prefix_sum_bit_rev_circle_domain_u32(
        runtime: *mut c_void,
        buffer: *mut c_void,
        log_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_inclusive_prefix_sum_bit_rev_circle_domain_u32(
            runtime,
            buffer,
            log_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn reduce_sum_m31_4col(
        runtime: *mut c_void,
        cols: [*mut c_void; 4],
        output: *mut c_void,
        n_elements: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_reduce_sum_m31_4col(
            runtime,
            cols[0],
            cols[1],
            cols[2],
            cols[3],
            output,
            n_elements,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn prefix_sum_subtract_m31_4col(
        runtime: *mut c_void,
        cols: [*mut c_void; 4],
        cumsum_shifts: &[u32; 4],
        n_elements: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_prefix_sum_subtract_m31_4col(
            runtime,
            cols[0],
            cols[1],
            cols[2],
            cols[3],
            cumsum_shifts.as_ptr(),
            n_elements,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fri_fold_circle_into_line_first_layer_u32x4(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        inverse_y_factors: *mut c_void,
        src_log_len: u32,
        alpha_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fri_fold_circle_into_line_first_layer_u32x4(
            runtime,
            src,
            dst,
            inverse_y_factors,
            src_log_len,
            alpha_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fri_fold_circle_into_line_accumulate_coords_u32x4(
        runtime: *mut c_void,
        src_0: *mut c_void,
        src_1: *mut c_void,
        src_2: *mut c_void,
        src_3: *mut c_void,
        dst_0: *mut c_void,
        dst_1: *mut c_void,
        dst_2: *mut c_void,
        dst_3: *mut c_void,
        inverse_y_factors: *mut c_void,
        src_log_len: u32,
        alpha_limbs: [u32; 4],
        alpha_sq_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fri_fold_circle_into_line_accumulate_coords_u32x4(
            runtime,
            src_0,
            src_1,
            src_2,
            src_3,
            dst_0,
            dst_1,
            dst_2,
            dst_3,
            inverse_y_factors,
            src_log_len,
            alpha_limbs.as_ptr(),
            alpha_sq_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fri_fold_circle_into_line_first_layer_coords_u32x4(
        runtime: *mut c_void,
        src_0: *mut c_void,
        src_1: *mut c_void,
        src_2: *mut c_void,
        src_3: *mut c_void,
        dst_0: *mut c_void,
        dst_1: *mut c_void,
        dst_2: *mut c_void,
        dst_3: *mut c_void,
        inverse_y_factors: *mut c_void,
        src_log_len: u32,
        alpha_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fri_fold_circle_into_line_first_layer_coords_u32x4(
            runtime,
            src_0,
            src_1,
            src_2,
            src_3,
            dst_0,
            dst_1,
            dst_2,
            dst_3,
            inverse_y_factors,
            src_log_len,
            alpha_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fri_fold_line_step_coords_u32x4(
        runtime: *mut c_void,
        src_0: *mut c_void,
        src_1: *mut c_void,
        src_2: *mut c_void,
        src_3: *mut c_void,
        dst_0: *mut c_void,
        dst_1: *mut c_void,
        dst_2: *mut c_void,
        dst_3: *mut c_void,
        inverse_x_factors: *mut c_void,
        src_log_len: u32,
        alpha_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fri_fold_line_step_coords_u32x4(
            runtime,
            src_0,
            src_1,
            src_2,
            src_3,
            dst_0,
            dst_1,
            dst_2,
            dst_3,
            inverse_x_factors,
            src_log_len,
            alpha_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fri_fold_line_step_coords_u32x4_async(
        runtime: *mut c_void,
        src_0: *mut c_void,
        src_1: *mut c_void,
        src_2: *mut c_void,
        src_3: *mut c_void,
        dst_0: *mut c_void,
        dst_1: *mut c_void,
        dst_2: *mut c_void,
        dst_3: *mut c_void,
        inverse_x_factors: *mut c_void,
        src_log_len: u32,
        alpha_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let ptr = stwo_metal_fri_fold_line_step_coords_u32x4_async(
            runtime,
            src_0,
            src_1,
            src_2,
            src_3,
            dst_0,
            dst_1,
            dst_2,
            dst_3,
            inverse_x_factors,
            src_log_len,
            alpha_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        );
        if !ptr.is_null() {
            Ok(ptr)
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fri_fold_line_step_u32x4(
        runtime: *mut c_void,
        src: *mut c_void,
        dst: *mut c_void,
        inverse_x_factors: *mut c_void,
        src_log_len: u32,
        alpha_limbs: [u32; 4],
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fri_fold_line_step_u32x4(
            runtime,
            src,
            dst,
            inverse_x_factors,
            src_log_len,
            alpha_limbs.as_ptr(),
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn generate_wide_fibonacci_trace_u32(
        runtime: *mut c_void,
        input_a: *mut c_void,
        input_b: *mut c_void,
        trace: *mut c_void,
        input_log_len: u32,
        n_columns: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_generate_wide_fibonacci_trace_u32(
            runtime,
            input_a,
            input_b,
            trace,
            input_log_len,
            n_columns,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_memory_id_to_big_trace(
        runtime: *mut c_void,
        big_values: *mut c_void,
        mults: *mut c_void,
        trace: *mut c_void,
        n_values: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_memory_id_to_big_trace(
            runtime,
            big_values,
            mults,
            trace,
            n_values,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_memory_id_to_big_small_trace(
        runtime: *mut c_void,
        small_values: *mut c_void,
        mults: *mut c_void,
        trace: *mut c_void,
        n_values: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_memory_id_to_big_small_trace(
            runtime,
            small_values,
            mults,
            trace,
            n_values,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_memory_addr_to_id_trace(
        runtime: *mut c_void,
        ids: *mut c_void,
        mults: *mut c_void,
        trace: *mut c_void,
        n_ids: u32,
        column_length: u32,
        split: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_memory_addr_to_id_trace(
            runtime,
            ids,
            mults,
            trace,
            n_ids,
            column_length,
            split,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_add_opcode_small_trace(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_add_opcode_small_trace(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            trace,
            n_rows,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_assert_eq_double_deref_trace(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_assert_eq_double_deref_trace(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            trace,
            n_rows,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_jnz_opcode_taken_trace(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_jnz_opcode_taken_trace(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            trace,
            n_rows,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_jump_opcode_rel_imm_trace(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_jump_opcode_rel_imm_trace(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            trace,
            n_rows,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_call_opcode_rel_imm_trace(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_call_opcode_rel_imm_trace(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            trace,
            n_rows,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_ret_opcode_trace(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_ret_opcode_trace(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            trace,
            n_rows,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_range_check_trace(
        runtime: *mut c_void,
        mults: *mut c_void,
        trace: *mut c_void,
        n_columns: u32,
        column_length: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_range_check_trace(
            runtime,
            mults,
            trace,
            n_columns,
            column_length,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn witness_verify_instruction_trace(
        runtime: *mut c_void,
        inputs: *mut c_void,
        mults: *mut c_void,
        addr_to_id: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        column_length: u32,
        addr_to_id_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_witness_verify_instruction_trace(
            runtime,
            inputs,
            mults,
            addr_to_id,
            trace,
            n_rows,
            column_length,
            addr_to_id_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_trace_id_to_big(
        runtime: *mut c_void,
        limbs: *mut c_void,
        mults: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        relation_ids: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        id_offset: u32,
        large_id_base: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_trace_id_to_big(
            runtime,
            limbs,
            mults,
            alpha_powers,
            z,
            relation_ids,
            trace,
            n_rows,
            id_offset,
            large_id_base,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_trace_id_to_big_small(
        runtime: *mut c_void,
        limbs: *mut c_void,
        mults: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        relation_ids: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_trace_id_to_big_small(
            runtime,
            limbs,
            mults,
            alpha_powers,
            z,
            relation_ids,
            trace,
            n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_trace_addr_to_id(
        runtime: *mut c_void,
        ids: *mut c_void,
        mults: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        relation_id: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        split: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_trace_addr_to_id(
            runtime,
            ids,
            mults,
            alpha_powers,
            z,
            relation_id,
            trace,
            n_rows,
            split,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_trace_generic(
        runtime: *mut c_void,
        values: *mut c_void,
        descriptors: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        trace: *mut c_void,
        n_rows: u32,
        n_logup_cols: u32,
        n_rows_real: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_trace_generic(
            runtime,
            values,
            descriptors,
            alpha_powers,
            z,
            trace,
            n_rows,
            n_logup_cols,
            n_rows_real,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn accumulate_wide_fibonacci_quotients_u32x4(
        runtime: *mut c_void,
        trace_evaluations: *mut c_void,
        random_coeff_powers: *mut c_void,
        denominator_inverses: *mut c_void,
        dst: *mut c_void,
        domain_log_size: u32,
        eval_domain_log_size: u32,
        n_constraints: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_accumulate_wide_fibonacci_quotients_u32x4(
            runtime,
            trace_evaluations,
            random_coeff_powers,
            denominator_inverses,
            dst,
            domain_log_size,
            eval_domain_log_size,
            n_constraints,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn accumulate_partial_numerators_u32x4(
        runtime: *mut c_void,
        columns: *mut c_void,
        column_indices: *mut c_void,
        b_coeffs: *mut c_void,
        c_coeffs: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_terms: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_accumulate_partial_numerators_u32x4(
            runtime,
            columns,
            column_indices,
            b_coeffs,
            c_coeffs,
            dst,
            row_count,
            n_terms,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn accumulate_partial_numerators_batched_u32x4(
        runtime: *mut c_void,
        columns: *mut c_void,
        column_indices: *mut c_void,
        b_coeffs: *mut c_void,
        c_coeffs: *mut c_void,
        term_offsets: *mut c_void,
        term_counts: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_batches: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_accumulate_partial_numerators_batched_u32x4(
            runtime,
            columns,
            column_indices,
            b_coeffs,
            c_coeffs,
            term_offsets,
            term_counts,
            dst,
            row_count,
            n_batches,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn accumulate_and_unpack_partial_numerators_batched_u32x4(
        runtime: *mut c_void,
        columns: *mut c_void,
        column_indices: *mut c_void,
        b_coeffs: *mut c_void,
        c_coeffs: *mut c_void,
        term_offsets: *mut c_void,
        term_counts: *mut c_void,
        row_count: u32,
        n_batches: u32,
        output_coord_buffers: *mut *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_accumulate_and_unpack_partial_numerators_batched_u32x4(
            runtime,
            columns,
            column_indices,
            b_coeffs,
            c_coeffs,
            term_offsets,
            term_counts,
            row_count,
            n_batches,
            output_coord_buffers,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn accumulate_and_unpack_partial_numerators_indirect_batched_u32x4(
        runtime: *mut c_void,
        column_buffer_ptrs: *mut *mut c_void,
        n_unique_cols: u32,
        column_indices: *mut c_void,
        b_coeffs: *mut c_void,
        c_coeffs: *mut c_void,
        term_offsets: *mut c_void,
        term_counts: *mut c_void,
        row_count: u32,
        n_batches: u32,
        output_coord_buffers: *mut *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_accumulate_and_unpack_partial_numerators_indirect_batched_u32x4(
            runtime,
            column_buffer_ptrs,
            n_unique_cols,
            column_indices,
            b_coeffs,
            c_coeffs,
            term_offsets,
            term_counts,
            row_count,
            n_batches,
            output_coord_buffers,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn compute_quotients_and_combine_u32x4(
        runtime: *mut c_void,
        partial_coord_0: *mut c_void,
        partial_coord_1: *mut c_void,
        partial_coord_2: *mut c_void,
        partial_coord_3: *mut c_void,
        sample_points: *mut c_void,
        first_linear_terms: *mut c_void,
        partial_log_sizes: *mut c_void,
        partial_offsets: *mut c_void,
        domain_x: *mut c_void,
        domain_y: *mut c_void,
        dst: *mut c_void,
        lifting_log_size: u32,
        n_accumulations: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_compute_quotients_and_combine_u32x4(
            runtime,
            partial_coord_0,
            partial_coord_1,
            partial_coord_2,
            partial_coord_3,
            sample_points,
            first_linear_terms,
            partial_log_sizes,
            partial_offsets,
            domain_x,
            domain_y,
            dst,
            lifting_log_size,
            n_accumulations,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn compute_quotients_and_combine_packed_u32x4(
        runtime: *mut c_void,
        partials: *mut c_void,
        sample_points: *mut c_void,
        first_linear_terms: *mut c_void,
        partial_log_sizes: *mut c_void,
        partial_offsets: *mut c_void,
        domain_x: *mut c_void,
        domain_y: *mut c_void,
        dst: *mut c_void,
        lifting_log_size: u32,
        n_accumulations: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_compute_quotients_and_combine_packed_u32x4(
            runtime,
            partials,
            sample_points,
            first_linear_terms,
            partial_log_sizes,
            partial_offsets,
            domain_x,
            domain_y,
            dst,
            lifting_log_size,
            n_accumulations,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn compute_quotients_and_combine_indirect_packed_u32x4(
        runtime: *mut c_void,
        partial_buffer_ptrs: *const *mut c_void,
        sample_points: *mut c_void,
        first_linear_terms: *mut c_void,
        partial_log_sizes: *mut c_void,
        partial_offsets: *mut c_void,
        domain_x: *mut c_void,
        domain_y: *mut c_void,
        dst: *mut c_void,
        lifting_log_size: u32,
        n_accumulations: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_compute_quotients_and_combine_indirect_packed_u32x4(
            runtime,
            partial_buffer_ptrs,
            sample_points,
            first_linear_terms,
            partial_log_sizes,
            partial_offsets,
            domain_x,
            domain_y,
            dst,
            lifting_log_size,
            n_accumulations,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn blake2s_build_leaves_lifted_u32(
        runtime: *mut c_void,
        flat_columns: *mut c_void,
        column_offsets: *mut c_void,
        column_log_sizes: *mut c_void,
        dst: *mut c_void,
        n_columns: u32,
        lifting_log_size: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_blake2s_build_leaves_lifted_u32(
            runtime,
            flat_columns,
            column_offsets,
            column_log_sizes,
            dst,
            n_columns,
            lifting_log_size,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn blake2s_build_leaves_lifted_wide_chunk_u32(
        runtime: *mut c_void,
        column_buffers: *const *mut c_void,
        state: *mut c_void,
        dst: *mut c_void,
        column_log_sizes: *const u32,
        n_columns: u32,
        lifting_log_size: u32,
        processed_bytes_before: u32,
        is_first_chunk: bool,
        is_final_chunk: bool,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_blake2s_build_leaves_lifted_wide_chunk_u32(
            runtime,
            column_buffers,
            state,
            dst,
            column_log_sizes,
            n_columns,
            lifting_log_size,
            processed_bytes_before,
            is_first_chunk as u32,
            is_final_chunk as u32,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn blake2s_build_leaves_lifted_wide_batched_u32(
        runtime: *mut c_void,
        all_column_buffers: *const *mut c_void,
        state: *mut c_void,
        dst: *mut c_void,
        all_column_log_sizes: *const u32,
        total_columns: u32,
        lifting_log_size: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_blake2s_build_leaves_lifted_wide_batched_u32(
            runtime,
            all_column_buffers,
            state,
            dst,
            all_column_log_sizes,
            total_columns,
            lifting_log_size,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn blake2s_build_leaves_lifted_fast_u32(
        runtime: *mut c_void,
        column_buffers: *const *mut c_void,
        dst: *mut c_void,
        column_log_sizes: *const u32,
        n_columns: u32,
        lifting_log_size: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_blake2s_build_leaves_lifted_fast_u32(
            runtime,
            column_buffers,
            dst,
            column_log_sizes,
            n_columns,
            lifting_log_size,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn blake2s_build_next_layer_u32(
        runtime: *mut c_void,
        prev_layer: *mut c_void,
        dst: *mut c_void,
        next_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_blake2s_build_next_layer_u32(
            runtime,
            prev_layer,
            dst,
            next_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn blake2s_build_merkle_layers_u32(
        runtime: *mut c_void,
        leaf_layer: *mut c_void,
        layer_ptrs: *const *mut c_void,
        leaf_log_size: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_blake2s_build_merkle_layers_u32(
            runtime,
            leaf_layer,
            layer_ptrs,
            leaf_log_size,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn blake2s_build_merkle_tree_fast_u32(
        runtime: *mut c_void,
        column_buffers: *const *mut c_void,
        leaf_layer: *mut c_void,
        layer_ptrs: *const *mut c_void,
        column_log_sizes: *const u32,
        n_columns: u32,
        lifting_log_size: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_blake2s_build_merkle_tree_fast_u32(
            runtime,
            column_buffers,
            leaf_layer,
            layer_ptrs,
            column_log_sizes,
            n_columns,
            lifting_log_size,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_reference_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_optimized_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            max_base_regs,
            max_ext_regs,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_async_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let handle = stwo_metal_eval_program_v1_reference_async_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            error_ptr(&mut error),
            error.len(),
        );
        if handle.is_null() {
            Err(MetalError::new(decode_error_buffer(&error)))
        } else {
            Ok(handle)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_async_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let handle = stwo_metal_eval_program_v1_optimized_async_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            max_base_regs,
            max_ext_regs,
            error_ptr(&mut error),
            error.len(),
        );
        if handle.is_null() {
            Err(MetalError::new(decode_error_buffer(&error)))
        } else {
            Ok(handle)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_u32x4_tg(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        threads_per_group: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_reference_u32x4_tg(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            threads_per_group,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_u32x4_tg(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
        threads_per_group: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_optimized_u32x4_tg(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            max_base_regs,
            max_ext_regs,
            threads_per_group,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_b_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_reference_b_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_b_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_optimized_b_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            max_base_regs,
            max_ext_regs,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_c_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_reference_c_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_c_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        base_insts: *mut c_void,
        ext_insts: *mut c_void,
        constraint_roots: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_preprocessed_columns: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_base_insts: u32,
        n_ext_insts: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_optimized_c_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            base_insts,
            ext_insts,
            constraint_roots,
            dst,
            row_count,
            n_interactions,
            n_preprocessed_columns,
            n_base_params,
            n_ext_params,
            n_base_insts,
            n_ext_insts,
            n_constraints,
            max_base_regs,
            max_ext_regs,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn eval_program_v1_wide_fibonacci_u32x4(
        runtime: *mut c_void,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        random_coeff_powers: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        n_interactions: u32,
        n_constraints: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_program_v1_wide_fibonacci_u32x4(
            runtime,
            trace_values,
            interaction_offsets,
            random_coeff_powers,
            dst,
            row_count,
            n_interactions,
            n_constraints,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_program_v1_u32x4(
        runtime: *mut c_void,
        shader_source: *const u8,
        shader_source_len: usize,
        kernel_name: *const u8,
        kernel_name_len: usize,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_compiled_program_v1_u32x4(
            runtime,
            shader_source,
            shader_source_len,
            kernel_name,
            kernel_name_len,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            dst,
            row_count,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_fused_composition_v1(
        runtime: *mut c_void,
        shader_source: *const u8,
        shader_source_len: usize,
        kernel_name: *const u8,
        kernel_name_len: usize,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        denom_inv: *mut c_void,
        coord_0: *mut c_void,
        coord_1: *mut c_void,
        coord_2: *mut c_void,
        coord_3: *mut c_void,
        row_count: u32,
        log_n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_compiled_fused_composition_v1(
            runtime,
            shader_source,
            shader_source_len,
            kernel_name,
            kernel_name_len,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            denom_inv,
            coord_0,
            coord_1,
            coord_2,
            coord_3,
            row_count,
            log_n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_program_v1_u32x4_tg(
        runtime: *mut c_void,
        shader_source: *const u8,
        shader_source_len: usize,
        kernel_name: *const u8,
        kernel_name_len: usize,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        threads_per_group: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_eval_compiled_program_v1_u32x4_tg(
            runtime,
            shader_source,
            shader_source_len,
            kernel_name,
            kernel_name_len,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            dst,
            row_count,
            threads_per_group,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_program_v1_u32x4_async(
        runtime: *mut c_void,
        shader_source: *const u8,
        shader_source_len: usize,
        kernel_name: *const u8,
        kernel_name_len: usize,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let mut out_handle: *mut c_void = std::ptr::null_mut();
        if stwo_metal_eval_compiled_program_v1_u32x4_async(
            runtime,
            shader_source,
            shader_source_len,
            kernel_name,
            kernel_name_len,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            dst,
            row_count,
            &mut out_handle,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(out_handle)
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_fused_blit_async(
        runtime: *mut c_void,
        shader_source: *const u8,
        shader_source_len: usize,
        kernel_name: *const u8,
        kernel_name_len: usize,
        column_buffer_ptrs: *const *mut c_void,
        column_lengths: *const usize,
        n_columns: usize,
        interaction_offsets: *mut c_void,
        random_coeff_powers: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let mut out_handle: *mut c_void = std::ptr::null_mut();
        if stwo_metal_eval_compiled_fused_blit_async(
            runtime,
            shader_source,
            shader_source_len,
            kernel_name,
            kernel_name_len,
            column_buffer_ptrs,
            column_lengths,
            n_columns,
            interaction_offsets,
            random_coeff_powers,
            dst,
            row_count,
            &mut out_handle,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(out_handle)
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    /// Create an uncommitted Metal command buffer for batching multiple dispatches.
    pub unsafe fn command_buffer_create(
        runtime: *mut c_void,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let ptr = stwo_metal_command_buffer_create(runtime, error_ptr(&mut error), error.len());
        if ptr.is_null() {
            Err(MetalError::new(decode_error_buffer(&error)))
        } else {
            Ok(ptr)
        }
    }

    /// Encode a JIT-compiled V1 evaluation kernel into an existing command buffer.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn encode_compiled_program_v1(
        runtime: *mut c_void,
        command_buffer: *mut c_void,
        shader_source: *const u8,
        shader_source_len: usize,
        kernel_name: *const u8,
        kernel_name_len: usize,
        trace_values: *mut c_void,
        interaction_offsets: *mut c_void,
        preprocessed_values: *mut c_void,
        base_params: *mut c_void,
        ext_params: *mut c_void,
        random_coeff_powers: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_encode_compiled_program_v1(
            runtime,
            command_buffer,
            shader_source,
            shader_source_len,
            kernel_name,
            kernel_name_len,
            trace_values,
            interaction_offsets,
            preprocessed_values,
            base_params,
            ext_params,
            random_coeff_powers,
            dst,
            row_count,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    /// Encode a fused blit+compute dispatch into an existing command buffer.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn encode_compiled_fused_blit_v1(
        runtime: *mut c_void,
        command_buffer: *mut c_void,
        shader_source: *const u8,
        shader_source_len: usize,
        kernel_name: *const u8,
        kernel_name_len: usize,
        column_buffer_ptrs: *const *mut c_void,
        column_lengths: *const usize,
        n_columns: usize,
        interaction_offsets: *mut c_void,
        random_coeff_powers: *mut c_void,
        dst: *mut c_void,
        row_count: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_encode_compiled_fused_blit_v1(
            runtime,
            command_buffer,
            shader_source,
            shader_source_len,
            kernel_name,
            kernel_name_len,
            column_buffer_ptrs,
            column_lengths,
            n_columns,
            interaction_offsets,
            random_coeff_powers,
            dst,
            row_count,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    /// Commit a batch command buffer (non-blocking).
    pub unsafe fn command_buffer_commit(handle: *mut c_void) {
        stwo_metal_command_buffer_commit(handle);
    }

    pub unsafe fn sampled_values_v1_wide_fibonacci_u32x4(
        runtime: *mut c_void,
        tree_descs: *mut c_void,
        column_descs: *mut c_void,
        values: *mut c_void,
        point_x: *mut c_void,
        dst: *mut c_void,
        n_trees: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_sampled_values_v1_wide_fibonacci_u32x4(
            runtime,
            tree_descs,
            column_descs,
            values,
            point_x,
            dst,
            n_trees,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn buffer_read_indices(
        runtime: *mut c_void,
        buffer: *mut c_void,
        indices: *const u32,
        indices_len: usize,
        host_ptr: *mut u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_u32_buffer_read_indices(
            runtime,
            buffer,
            indices,
            indices_len,
            host_ptr,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    /// Dispatch GPU Blake2s PoW grind for a single `nonce_hi` batch.
    ///
    /// Returns the smallest `nonce_lo` found (0..batch_size) or `u32::MAX` if none.
    pub unsafe fn blake2s_grind_batch(
        runtime: *mut c_void,
        prefix_digest: &[u32; 8],
        pow_bits: u32,
        nonce_hi: u32,
        batch_size: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<u32, MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        let mut out_nonce_lo: u32 = u32::MAX;
        if stwo_metal_blake2s_grind_batch(
            runtime,
            prefix_digest.as_ptr(),
            pow_bits,
            nonce_hi,
            batch_size,
            &mut out_nonce_lo,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(out_nonce_lo)
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    /// Bulk gather hash nodes from multiple Merkle tree layers.
    pub unsafe fn merkle_decommit_gather(
        runtime: *mut c_void,
        layer_ptrs: &[*mut c_void],
        per_layer_indices: &[*const u32],
        per_layer_counts: &[u32],
        out_hashes: *mut u32,
        total_gathers: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let n_layers = layer_ptrs.len() as u32;
        debug_assert_eq!(per_layer_indices.len(), n_layers as usize);
        debug_assert_eq!(per_layer_counts.len(), n_layers as usize);
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_merkle_decommit_gather(
            runtime,
            layer_ptrs.as_ptr(),
            n_layers,
            per_layer_indices.as_ptr(),
            per_layer_counts.as_ptr(),
            out_hashes,
            total_gathers,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_add_opcode_small(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        addr_to_id_mults: *mut c_void,
        id_to_big_mults: *mut c_void,
        id_to_small_mults: *mut c_void,
        n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_mults_add_opcode_small(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            addr_to_id_mults,
            id_to_big_mults,
            id_to_small_mults,
            n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_assert_eq_double_deref(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        addr_to_id_mults: *mut c_void,
        id_to_big_mults: *mut c_void,
        id_to_small_mults: *mut c_void,
        n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_mults_assert_eq_double_deref(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            addr_to_id_mults,
            id_to_big_mults,
            id_to_small_mults,
            n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_jnz_opcode_taken(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        addr_to_id_mults: *mut c_void,
        id_to_big_mults: *mut c_void,
        id_to_small_mults: *mut c_void,
        n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_mults_jnz_opcode_taken(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            addr_to_id_mults,
            id_to_big_mults,
            id_to_small_mults,
            n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_jump_opcode_rel_imm(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        addr_to_id_mults: *mut c_void,
        id_to_big_mults: *mut c_void,
        id_to_small_mults: *mut c_void,
        n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_mults_jump_opcode_rel_imm(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            addr_to_id_mults,
            id_to_big_mults,
            id_to_small_mults,
            n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_call_opcode_rel_imm(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        addr_to_id_mults: *mut c_void,
        id_to_big_mults: *mut c_void,
        id_to_small_mults: *mut c_void,
        n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_mults_call_opcode_rel_imm(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            addr_to_id_mults,
            id_to_big_mults,
            id_to_small_mults,
            n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_ret_opcode(
        runtime: *mut c_void,
        inputs: *mut c_void,
        address_to_id: *mut c_void,
        big_values: *mut c_void,
        small_values: *mut c_void,
        addr_to_id_mults: *mut c_void,
        id_to_big_mults: *mut c_void,
        id_to_small_mults: *mut c_void,
        n_rows: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_mults_ret_opcode(
            runtime,
            inputs,
            address_to_id,
            big_values,
            small_values,
            addr_to_id_mults,
            id_to_big_mults,
            id_to_small_mults,
            n_rows,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_values_ret_opcode(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_values_ret_opcode(
            runtime,
            trace_cols,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_values_jnz_opcode_taken(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_values_jnz_opcode_taken(
            runtime,
            trace_cols,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_values_assert_eq_double_deref(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_values_assert_eq_double_deref(
            runtime,
            trace_cols,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_values_jump_opcode_rel_imm(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_values_jump_opcode_rel_imm(
            runtime,
            trace_cols,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn interaction_values_call_opcode_rel_imm(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_interaction_values_call_opcode_rel_imm(
            runtime,
            trace_cols,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fused_interaction_ret_opcode(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fused_interaction_ret_opcode(
            runtime,
            trace_cols,
            alpha_powers,
            z,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fused_interaction_jump_opcode_rel_imm(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fused_interaction_jump_opcode_rel_imm(
            runtime,
            trace_cols,
            alpha_powers,
            z,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fused_interaction_assert_eq_double_deref(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fused_interaction_assert_eq_double_deref(
            runtime,
            trace_cols,
            alpha_powers,
            z,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fused_interaction_jnz_opcode_taken(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fused_interaction_jnz_opcode_taken(
            runtime,
            trace_cols,
            alpha_powers,
            z,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fused_interaction_call_opcode_rel_imm(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fused_interaction_call_opcode_rel_imm(
            runtime,
            trace_cols,
            alpha_powers,
            z,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }

    pub unsafe fn fused_interaction_add_opcode_small(
        runtime: *mut c_void,
        trace_cols: *mut c_void,
        alpha_powers: *mut c_void,
        z: *mut c_void,
        output: *mut c_void,
        n_rows: u32,
        col_len: u32,
        error_ptr: fn(&mut [i8; ERROR_BUFFER_LEN]) -> *mut i8,
    ) -> Result<(), MetalError> {
        let mut error = [0i8; ERROR_BUFFER_LEN];
        if stwo_metal_fused_interaction_add_opcode_small(
            runtime,
            trace_cols,
            alpha_powers,
            z,
            output,
            n_rows,
            col_len,
            error_ptr(&mut error),
            error.len(),
        ) {
            Ok(())
        } else {
            Err(MetalError::new(decode_error_buffer(&error)))
        }
    }
}

#[cfg(not(stwo_metal_link))]
pub mod ffi {
    use super::{c_void, BatchEvalGroupDescriptor, MetalError, NonNull};

    pub unsafe fn runtime_create(
        _metallib_bytes: *const u8,
        _metallib_len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn runtime_create_from_sources(
        _library_sources: *const *const core::ffi::c_char,
        _library_source_count: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-backend-metal-sys.",
        ))
    }

    pub unsafe fn runtime_destroy(_runtime: *mut c_void) {}

    pub unsafe fn buffer_from_host(
        _runtime: *mut c_void,
        _host_ptr: *const u32,
        _len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_alloc_zeroed(
        _runtime: *mut c_void,
        _len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_alloc_uninitialized(
        _runtime: *mut c_void,
        _len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_from_host_private(
        _runtime: *mut c_void,
        _host_ptr: *const u32,
        _len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_alloc_uninitialized_private(
        _runtime: *mut c_void,
        _len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<NonNull<c_void>, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_is_private(_buffer: *mut c_void) -> bool {
        false
    }

    pub unsafe fn buffer_promote_to_private(
        _runtime: *mut c_void,
        _buffer: *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_destroy(_buffer: *mut c_void) {}

    pub unsafe fn buffer_read(
        _runtime: *mut c_void,
        _buffer: *mut c_void,
        _host_ptr: *mut u32,
        _len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_host_ptr(_buffer: *mut c_void) -> *const u32 {
        core::ptr::null()
    }

    pub unsafe fn buffer_get(_buffer: *mut c_void, _index: usize) -> u32 {
        panic!("Metal buffer access was requested without linked Metal support")
    }

    pub unsafe fn buffer_set(_buffer: *mut c_void, _index: usize, _value: u32) {
        panic!("Metal buffer mutation was requested without linked Metal support")
    }

    pub unsafe fn buffer_copy(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _len: usize,
        _dst_offset: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_copy_range(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _src_offset: usize,
        _len: usize,
        _dst_offset: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn bit_reverse_u32(
        _runtime: *mut c_void,
        _buffer: *mut c_void,
        _log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn bit_reverse_u32x4(
        _runtime: *mut c_void,
        _buffer: *mut c_void,
        _log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn invert_m31_values_u32(
        _runtime: *mut c_void,
        _buffer: *mut c_void,
        _len: usize,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn precompute_twiddle_level_u32(
        _runtime: *mut c_void,
        _dst: *mut c_void,
        _offset: usize,
        _initial_xy: [u32; 2],
        _step_xy: [u32; 2],
        _level_log_size: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn rfft_evaluate_u32(
        _runtime: *mut c_void,
        _values: *mut c_void,
        _twiddles: *mut c_void,
        _values_log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn rfft_evaluate_multi_u32(
        _runtime: *mut c_void,
        _buffer_ptrs: *const *mut c_void,
        _n_buffers: u32,
        _twiddles: *mut c_void,
        _values_log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn rfft_evaluate_async_u32(
        _runtime: *mut c_void,
        _values: *mut c_void,
        _twiddles: *mut c_void,
        _values_log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn rfft_evaluate_subbuffer_u32(
        _runtime: *mut c_void,
        _values: *mut c_void,
        _value_offset: usize,
        _values_log_len: u32,
        _twiddles: *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn rfft_evaluate_subbuffer_async_u32(
        _runtime: *mut c_void,
        _values: *mut c_void,
        _value_offset: usize,
        _values_log_len: u32,
        _twiddles: *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn command_buffer_wait(
        _handle: *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn command_buffer_release(_handle: *mut c_void) {}

    pub unsafe fn queue_drain(
        _runtime: *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn command_buffer_create(
        _runtime: *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn encode_compiled_program_v1(
        _runtime: *mut c_void,
        _command_buffer: *mut c_void,
        _shader_source: *const u8,
        _shader_source_len: usize,
        _kernel_name: *const u8,
        _kernel_name_len: usize,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn encode_compiled_fused_blit_v1(
        _runtime: *mut c_void,
        _command_buffer: *mut c_void,
        _shader_source: *const u8,
        _shader_source_len: usize,
        _kernel_name: *const u8,
        _kernel_name_len: usize,
        _column_buffer_ptrs: *const *mut c_void,
        _column_lengths: *const usize,
        _n_columns: usize,
        _interaction_offsets: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn command_buffer_commit(_handle: *mut c_void) {}

    pub unsafe fn ifft_interpolate_u32(
        _runtime: *mut c_void,
        _values: *mut c_void,
        _inverse_twiddles: *mut c_void,
        _values_log_len: u32,
        _scale_factor: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn ifft_interpolate_batch_u32(
        _runtime: *mut c_void,
        _values_ptrs: &[*mut c_void],
        _inverse_twiddles_ptrs: &[*mut c_void],
        _values_log_lens: &[u32],
        _scale_factors: &[u32],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn ifft_line_interpolate_u32(
        _runtime: *mut c_void,
        _values: *mut c_void,
        _inverse_line_twiddles: *mut c_void,
        _values_log_len: u32,
        _scale_factor: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn batch_eval_at_point_base_field_u32(
        _runtime: *mut c_void,
        _flat_coeffs: *mut c_void,
        _factors: *mut c_void,
        _dst: *mut c_void,
        _coeffs_log_len: u32,
        _n_polys: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn batch_eval_at_point_multi_group_u32(
        _runtime: *mut c_void,
        _groups: *const super::BatchEvalGroupDescriptor,
        _n_groups: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn batch_eval_at_point_transposed_u32(
        _runtime: *mut c_void,
        _flat_coeffs: *mut c_void,
        _basis_evals: *mut c_void,
        _dst: *mut c_void,
        _n_polys: u32,
        _n_coeffs: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn barycentric_eval_at_point_u32(
        _runtime: *mut c_void,
        _eval_values: *mut c_void,
        _weights: *mut c_void,
        _dst: *mut c_void,
        _n_elements: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn batch_eval_first_pass_base_field_u32(
        _runtime: *mut c_void,
        _flat_coeffs: *mut c_void,
        _factors: *mut c_void,
        _dst: *mut c_void,
        _coeffs_log_len: u32,
        _n_polys: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn permute_coset_to_circle_domain_bit_reversed_u32(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn pack_secure_column_coords_u32x4(
        _runtime: *mut c_void,
        _coord_0: *mut c_void,
        _coord_1: *mut c_void,
        _coord_2: *mut c_void,
        _coord_3: *mut c_void,
        _dst: *mut c_void,
        _element_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn unpack_secure_column_coords_u32x4(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _coord_0: *mut c_void,
        _coord_1: *mut c_void,
        _coord_2: *mut c_void,
        _coord_3: *mut c_void,
        _element_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn accumulate_secure_columns_coords_u32x4(
        _runtime: *mut c_void,
        _lhs_0: *mut c_void,
        _lhs_1: *mut c_void,
        _lhs_2: *mut c_void,
        _lhs_3: *mut c_void,
        _rhs_0: *mut c_void,
        _rhs_1: *mut c_void,
        _rhs_2: *mut c_void,
        _rhs_3: *mut c_void,
        _dst_0: *mut c_void,
        _dst_1: *mut c_void,
        _dst_2: *mut c_void,
        _dst_3: *mut c_void,
        _element_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn lift_accumulate_secure_columns_coords_u32x4(
        _runtime: *mut c_void,
        _lifted_0: *mut c_void,
        _lifted_1: *mut c_void,
        _lifted_2: *mut c_void,
        _lifted_3: *mut c_void,
        _current_0: *mut c_void,
        _current_1: *mut c_void,
        _current_2: *mut c_void,
        _current_3: *mut c_void,
        _dst_0: *mut c_void,
        _dst_1: *mut c_void,
        _dst_2: *mut c_void,
        _dst_3: *mut c_void,
        _current_log_size: u32,
        _log_ratio: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fix_first_variable_base_field_u32(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _src_log_len: u32,
        _assignment_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fix_first_variable_secure_field_u32x4(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _src_log_len: u32,
        _assignment_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_gen_eq_evals_u32x4(
        _runtime: *mut c_void,
        _factors: *mut c_void,
        _dst: *mut c_void,
        _y_size: u32,
        _v_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_next_grand_product_layer_u32x4(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _input_log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_next_logup_generic_layer_u32x4(
        _runtime: *mut c_void,
        _numerators: *mut c_void,
        _denominators: *mut c_void,
        _next_numerators: *mut c_void,
        _next_denominators: *mut c_void,
        _input_log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_next_logup_multiplicities_layer_u32(
        _runtime: *mut c_void,
        _numerators: *mut c_void,
        _denominators: *mut c_void,
        _next_numerators: *mut c_void,
        _next_denominators: *mut c_void,
        _input_log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_next_logup_singles_layer_u32x4(
        _runtime: *mut c_void,
        _denominators: *mut c_void,
        _next_numerators: *mut c_void,
        _next_denominators: *mut c_void,
        _input_log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_sum_grand_product_u32x4(
        _runtime: *mut c_void,
        _eq_evals: *mut c_void,
        _input_layer: *mut c_void,
        _n_terms: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_sum_logup_generic_u32x4(
        _runtime: *mut c_void,
        _eq_evals: *mut c_void,
        _numerators: *mut c_void,
        _denominators: *mut c_void,
        _n_terms: u32,
        _lambda_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_sum_logup_multiplicities_u32(
        _runtime: *mut c_void,
        _eq_evals: *mut c_void,
        _numerators: *mut c_void,
        _denominators: *mut c_void,
        _n_terms: u32,
        _lambda_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn gkr_sum_logup_singles_u32x4(
        _runtime: *mut c_void,
        _eq_evals: *mut c_void,
        _denominators: *mut c_void,
        _n_terms: u32,
        _lambda_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<([u32; 4], [u32; 4]), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn inclusive_prefix_sum_bit_rev_circle_domain_u32(
        _runtime: *mut c_void,
        _buffer: *mut c_void,
        _log_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn reduce_sum_m31_4col(
        _runtime: *mut c_void,
        _cols: [*mut c_void; 4],
        _output: *mut c_void,
        _n_elements: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn prefix_sum_subtract_m31_4col(
        _runtime: *mut c_void,
        _cols: [*mut c_void; 4],
        _cumsum_shifts: &[u32; 4],
        _n_elements: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fri_fold_circle_into_line_first_layer_u32x4(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _inverse_y_factors: *mut c_void,
        _src_log_len: u32,
        _alpha_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fri_fold_circle_into_line_accumulate_coords_u32x4(
        _runtime: *mut c_void,
        _src_0: *mut c_void,
        _src_1: *mut c_void,
        _src_2: *mut c_void,
        _src_3: *mut c_void,
        _dst_0: *mut c_void,
        _dst_1: *mut c_void,
        _dst_2: *mut c_void,
        _dst_3: *mut c_void,
        _inverse_y_factors: *mut c_void,
        _src_log_len: u32,
        _alpha_limbs: [u32; 4],
        _alpha_sq_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fri_fold_circle_into_line_first_layer_coords_u32x4(
        _runtime: *mut c_void,
        _src_0: *mut c_void,
        _src_1: *mut c_void,
        _src_2: *mut c_void,
        _src_3: *mut c_void,
        _dst_0: *mut c_void,
        _dst_1: *mut c_void,
        _dst_2: *mut c_void,
        _dst_3: *mut c_void,
        _inverse_y_factors: *mut c_void,
        _src_log_len: u32,
        _alpha_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fri_fold_line_step_coords_u32x4(
        _runtime: *mut c_void,
        _src_0: *mut c_void,
        _src_1: *mut c_void,
        _src_2: *mut c_void,
        _src_3: *mut c_void,
        _dst_0: *mut c_void,
        _dst_1: *mut c_void,
        _dst_2: *mut c_void,
        _dst_3: *mut c_void,
        _inverse_x_factors: *mut c_void,
        _src_log_len: u32,
        _alpha_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fri_fold_line_step_coords_u32x4_async(
        _runtime: *mut c_void,
        _src_0: *mut c_void,
        _src_1: *mut c_void,
        _src_2: *mut c_void,
        _src_3: *mut c_void,
        _dst_0: *mut c_void,
        _dst_1: *mut c_void,
        _dst_2: *mut c_void,
        _dst_3: *mut c_void,
        _inverse_x_factors: *mut c_void,
        _src_log_len: u32,
        _alpha_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fri_fold_line_step_u32x4(
        _runtime: *mut c_void,
        _src: *mut c_void,
        _dst: *mut c_void,
        _inverse_x_factors: *mut c_void,
        _src_log_len: u32,
        _alpha_limbs: [u32; 4],
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn generate_wide_fibonacci_trace_u32(
        _runtime: *mut c_void,
        _input_a: *mut c_void,
        _input_b: *mut c_void,
        _trace: *mut c_void,
        _input_log_len: u32,
        _n_columns: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_memory_id_to_big_trace(
        _runtime: *mut c_void,
        _big_values: *mut c_void,
        _mults: *mut c_void,
        _trace: *mut c_void,
        _n_values: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_memory_id_to_big_small_trace(
        _runtime: *mut c_void,
        _small_values: *mut c_void,
        _mults: *mut c_void,
        _trace: *mut c_void,
        _n_values: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_memory_addr_to_id_trace(
        _runtime: *mut c_void,
        _ids: *mut c_void,
        _mults: *mut c_void,
        _trace: *mut c_void,
        _n_ids: u32,
        _column_length: u32,
        _split: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_add_opcode_small_trace(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_assert_eq_double_deref_trace(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_jnz_opcode_taken_trace(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_jump_opcode_rel_imm_trace(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_call_opcode_rel_imm_trace(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_ret_opcode_trace(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_range_check_trace(
        _runtime: *mut c_void,
        _mults: *mut c_void,
        _trace: *mut c_void,
        _n_columns: u32,
        _column_length: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn witness_verify_instruction_trace(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _mults: *mut c_void,
        _addr_to_id: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _column_length: u32,
        _addr_to_id_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_trace_id_to_big(
        _runtime: *mut c_void,
        _limbs: *mut c_void,
        _mults: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _relation_ids: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _id_offset: u32,
        _large_id_base: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_trace_id_to_big_small(
        _runtime: *mut c_void,
        _limbs: *mut c_void,
        _mults: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _relation_ids: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_trace_addr_to_id(
        _runtime: *mut c_void,
        _ids: *mut c_void,
        _mults: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _relation_id: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _split: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_trace_generic(
        _runtime: *mut c_void,
        _values: *mut c_void,
        _descriptors: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _trace: *mut c_void,
        _n_rows: u32,
        _n_logup_cols: u32,
        _n_rows_real: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn accumulate_wide_fibonacci_quotients_u32x4(
        _runtime: *mut c_void,
        _trace_evaluations: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _denominator_inverses: *mut c_void,
        _dst: *mut c_void,
        _domain_log_size: u32,
        _eval_domain_log_size: u32,
        _n_constraints: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn accumulate_partial_numerators_u32x4(
        _runtime: *mut c_void,
        _columns: *mut c_void,
        _column_indices: *mut c_void,
        _b_coeffs: *mut c_void,
        _c_coeffs: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_terms: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn accumulate_partial_numerators_batched_u32x4(
        _runtime: *mut c_void,
        _columns: *mut c_void,
        _column_indices: *mut c_void,
        _b_coeffs: *mut c_void,
        _c_coeffs: *mut c_void,
        _term_offsets: *mut c_void,
        _term_counts: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_batches: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn accumulate_and_unpack_partial_numerators_batched_u32x4(
        _runtime: *mut c_void,
        _columns: *mut c_void,
        _column_indices: *mut c_void,
        _b_coeffs: *mut c_void,
        _c_coeffs: *mut c_void,
        _term_offsets: *mut c_void,
        _term_counts: *mut c_void,
        _row_count: u32,
        _n_batches: u32,
        _output_coord_buffers: *mut *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn accumulate_and_unpack_partial_numerators_indirect_batched_u32x4(
        _runtime: *mut c_void,
        _column_buffer_ptrs: *mut *mut c_void,
        _n_unique_cols: u32,
        _column_indices: *mut c_void,
        _b_coeffs: *mut c_void,
        _c_coeffs: *mut c_void,
        _term_offsets: *mut c_void,
        _term_counts: *mut c_void,
        _row_count: u32,
        _n_batches: u32,
        _output_coord_buffers: *mut *mut c_void,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn compute_quotients_and_combine_u32x4(
        _runtime: *mut c_void,
        _partial_coord_0: *mut c_void,
        _partial_coord_1: *mut c_void,
        _partial_coord_2: *mut c_void,
        _partial_coord_3: *mut c_void,
        _sample_points: *mut c_void,
        _first_linear_terms: *mut c_void,
        _partial_log_sizes: *mut c_void,
        _partial_offsets: *mut c_void,
        _domain_x: *mut c_void,
        _domain_y: *mut c_void,
        _dst: *mut c_void,
        _lifting_log_size: u32,
        _n_accumulations: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn compute_quotients_and_combine_packed_u32x4(
        _runtime: *mut c_void,
        _partials: *mut c_void,
        _sample_points: *mut c_void,
        _first_linear_terms: *mut c_void,
        _partial_log_sizes: *mut c_void,
        _partial_offsets: *mut c_void,
        _domain_x: *mut c_void,
        _domain_y: *mut c_void,
        _dst: *mut c_void,
        _lifting_log_size: u32,
        _n_accumulations: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn compute_quotients_and_combine_indirect_packed_u32x4(
        _runtime: *mut c_void,
        _partial_buffer_ptrs: *const *mut c_void,
        _sample_points: *mut c_void,
        _first_linear_terms: *mut c_void,
        _partial_log_sizes: *mut c_void,
        _partial_offsets: *mut c_void,
        _domain_x: *mut c_void,
        _domain_y: *mut c_void,
        _dst: *mut c_void,
        _lifting_log_size: u32,
        _n_accumulations: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn blake2s_build_merkle_layers_u32(
        _runtime: *mut c_void,
        _leaf_layer: *mut c_void,
        _layer_ptrs: *const *mut c_void,
        _leaf_log_size: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn blake2s_build_merkle_tree_fast_u32(
        _runtime: *mut c_void,
        _column_buffers: *const *mut c_void,
        _leaf_layer: *mut c_void,
        _layer_ptrs: *const *mut c_void,
        _column_log_sizes: *const u32,
        _n_columns: u32,
        _lifting_log_size: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _max_base_regs: u32,
        _max_ext_regs: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_async_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_async_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _max_base_regs: u32,
        _max_ext_regs: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_u32x4_tg(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _threads_per_group: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_u32x4_tg(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _max_base_regs: u32,
        _max_ext_regs: u32,
        _threads_per_group: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_b_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_b_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _max_base_regs: u32,
        _max_ext_regs: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_reference_c_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_program_v1_optimized_c_u32x4(
        _runtime: *mut c_void,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _base_insts: *mut c_void,
        _ext_insts: *mut c_void,
        _constraint_roots: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _n_interactions: u32,
        _n_preprocessed_columns: u32,
        _n_base_params: u32,
        _n_ext_params: u32,
        _n_base_insts: u32,
        _n_ext_insts: u32,
        _n_constraints: u32,
        _max_base_regs: u32,
        _max_ext_regs: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_program_v1_u32x4(
        _runtime: *mut c_void,
        _shader_source: *const u8,
        _shader_source_len: usize,
        _kernel_name: *const u8,
        _kernel_name_len: usize,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_fused_composition_v1(
        _runtime: *mut c_void,
        _shader_source: *const u8,
        _shader_source_len: usize,
        _kernel_name: *const u8,
        _kernel_name_len: usize,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _denom_inv: *mut c_void,
        _coord_0: *mut c_void,
        _coord_1: *mut c_void,
        _coord_2: *mut c_void,
        _coord_3: *mut c_void,
        _row_count: u32,
        _log_n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_program_v1_u32x4_tg(
        _runtime: *mut c_void,
        _shader_source: *const u8,
        _shader_source_len: usize,
        _kernel_name: *const u8,
        _kernel_name_len: usize,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _threads_per_group: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_program_v1_u32x4_async(
        _runtime: *mut c_void,
        _shader_source: *const u8,
        _shader_source_len: usize,
        _kernel_name: *const u8,
        _kernel_name_len: usize,
        _trace_values: *mut c_void,
        _interaction_offsets: *mut c_void,
        _preprocessed_values: *mut c_void,
        _base_params: *mut c_void,
        _ext_params: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn eval_compiled_fused_blit_async(
        _runtime: *mut c_void,
        _shader_source: *const u8,
        _shader_source_len: usize,
        _kernel_name: *const u8,
        _kernel_name_len: usize,
        _column_buffer_ptrs: *const *mut c_void,
        _column_lengths: *const usize,
        _n_columns: usize,
        _interaction_offsets: *mut c_void,
        _random_coeff_powers: *mut c_void,
        _dst: *mut c_void,
        _row_count: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<*mut c_void, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn sampled_values_v1_wide_fibonacci_u32x4(
        _runtime: *mut c_void,
        _tree_descs: *mut c_void,
        _column_descs: *mut c_void,
        _values: *mut c_void,
        _point_x: *mut c_void,
        _dst: *mut c_void,
        _n_trees: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn buffer_read_indices(
        _runtime: *mut c_void,
        _buffer: *mut c_void,
        _indices: *const u32,
        _indices_len: usize,
        _host_ptr: *mut u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn blake2s_grind_batch(
        _runtime: *mut c_void,
        _prefix_digest: &[u32; 8],
        _pow_bits: u32,
        _nonce_hi: u32,
        _batch_size: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<u32, MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn merkle_decommit_gather(
        _runtime: *mut c_void,
        _layer_ptrs: &[*mut c_void],
        _per_layer_indices: &[*const u32],
        _per_layer_counts: &[u32],
        _out_hashes: *mut u32,
        _total_gathers: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_add_opcode_small(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _addr_to_id_mults: *mut c_void,
        _id_to_big_mults: *mut c_void,
        _id_to_small_mults: *mut c_void,
        _n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_assert_eq_double_deref(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _addr_to_id_mults: *mut c_void,
        _id_to_big_mults: *mut c_void,
        _id_to_small_mults: *mut c_void,
        _n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_jnz_opcode_taken(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _addr_to_id_mults: *mut c_void,
        _id_to_big_mults: *mut c_void,
        _id_to_small_mults: *mut c_void,
        _n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_jump_opcode_rel_imm(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _addr_to_id_mults: *mut c_void,
        _id_to_big_mults: *mut c_void,
        _id_to_small_mults: *mut c_void,
        _n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_call_opcode_rel_imm(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _addr_to_id_mults: *mut c_void,
        _id_to_big_mults: *mut c_void,
        _id_to_small_mults: *mut c_void,
        _n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn mults_ret_opcode(
        _runtime: *mut c_void,
        _inputs: *mut c_void,
        _address_to_id: *mut c_void,
        _big_values: *mut c_void,
        _small_values: *mut c_void,
        _addr_to_id_mults: *mut c_void,
        _id_to_big_mults: *mut c_void,
        _id_to_small_mults: *mut c_void,
        _n_rows: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_values_ret_opcode(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_values_jnz_opcode_taken(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_values_assert_eq_double_deref(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_values_jump_opcode_rel_imm(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn interaction_values_call_opcode_rel_imm(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fused_interaction_ret_opcode(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fused_interaction_jump_opcode_rel_imm(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fused_interaction_assert_eq_double_deref(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fused_interaction_jnz_opcode_taken(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fused_interaction_call_opcode_rel_imm(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }

    pub unsafe fn fused_interaction_add_opcode_small(
        _runtime: *mut c_void,
        _trace_cols: *mut c_void,
        _alpha_powers: *mut c_void,
        _z: *mut c_void,
        _output: *mut c_void,
        _n_rows: u32,
        _col_len: u32,
        _error_ptr: fn(&mut [i8; 512]) -> *mut i8,
    ) -> Result<(), MetalError> {
        Err(MetalError::new(
            "Metal support was not linked into stwo-metal-sys.",
        ))
    }
}
