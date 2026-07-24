use std::sync::OnceLock;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::prover::backend::simd::m31::{PackedM31, N_LANES};
use stwo_backend_metal_sys::metal::U32Buffer;

use super::SecureFieldVec;

#[derive(Debug)]
pub struct BaseFieldVec {
    pub(crate) buffer: U32Buffer,
    size: usize,
    host_cache: OnceLock<Vec<BaseField>>,
}

unsafe impl Send for BaseFieldVec {}
unsafe impl Sync for BaseFieldVec {}

impl BaseFieldVec {
    #[allow(dead_code)]
    pub(crate) fn buffer_identity(&self) -> usize {
        self.buffer.identity()
    }

    pub(crate) fn host_slice(&self) -> &[BaseField] {
        if let Some(values) = self.host_cache.get() {
            return values;
        }

        // The buffer may still be written by an in-flight async GPU submission whose
        // completion handle was dropped (`evaluate_polynomials` relies on queue order,
        // which covers GPU consumers only). Fence before any host view; this is the
        // single choke point that makes every host read of GPU data safe.
        stwo_backend_metal_sys::metal::queue_drain()
            .expect("Metal queue drain before host read should succeed");

        let raw = unsafe { self.buffer.host_ptr() };
        if !raw.is_null() {
            return unsafe { std::slice::from_raw_parts(raw.cast::<BaseField>(), self.size) };
        }

        self.host_cache.get_or_init(|| {
            self.buffer
                .to_vec()
                .expect("Metal BaseFieldVec readback should succeed")
                .into_iter()
                .map(BaseField::from_u32_unchecked)
                .collect()
        })
    }

    pub fn from_buffer(buffer: U32Buffer) -> Self {
        let size = buffer.len();
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn from_vec(host_array: Vec<BaseField>) -> Self {
        let raw: Vec<u32> = host_array.into_iter().map(|value| value.0).collect();
        let size = raw.len();
        let buffer =
            U32Buffer::from_slice(&raw).expect("Metal BaseFieldVec upload should initialize");
        let cached = raw
            .into_iter()
            .map(BaseField::from_u32_unchecked)
            .collect::<Vec<_>>();
        let host_cache = OnceLock::new();
        let _ = host_cache.set(cached);
        Self {
            buffer,
            size,
            host_cache,
        }
    }

    pub fn new_uninitialized(size: usize) -> Self {
        let buffer = U32Buffer::uninitialized(size)
            .expect("Metal BaseFieldVec allocation should initialize");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    /// Creates a `BaseFieldVec` backed by a private (GPU-only) Metal buffer
    /// whose contents are uploaded from host memory via a staging blit.
    ///
    /// Private buffers receive driver-level optimizations that shared buffers
    /// cannot. They should be used for trace columns that are only read by
    /// GPU compute/blit passes and never by the CPU after initial upload.
    pub fn from_vec_private(host_array: Vec<BaseField>) -> Self {
        let raw: Vec<u32> = host_array.into_iter().map(|value| value.0).collect();
        let size = raw.len();
        let buffer = U32Buffer::from_slice_private(&raw)
            .expect("Metal BaseFieldVec private upload should succeed");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    /// Creates a `BaseFieldVec` from a raw `&[u32]` slice by uploading
    /// directly to a private (GPU-only) Metal buffer. Skips BaseField
    /// conversion overhead — caller must ensure values are valid M31 elements.
    pub fn from_u32_slice_private(raw: &[u32]) -> Self {
        let size = raw.len();
        let buffer = U32Buffer::from_slice_private(raw)
            .expect("Metal BaseFieldVec private upload from u32 slice should succeed");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    /// Allocates a private (GPU-only) uninitialized buffer.
    pub fn new_uninitialized_private(size: usize) -> Self {
        let buffer = U32Buffer::uninitialized_private(size)
            .expect("Metal BaseFieldVec private allocation should succeed");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    /// Returns `true` if this buffer uses `MTLResourceStorageModePrivate`.
    pub fn is_private(&self) -> bool {
        self.buffer.is_private()
    }

    /// Promotes the underlying buffer to private (GPU-only) storage.
    /// Invalidates any cached host data. No-op if already private.
    pub fn promote_to_private(&mut self) {
        if self.buffer.is_private() {
            return;
        }
        let _ = self.host_cache.take();
        self.buffer
            .promote_to_private()
            .expect("Metal BaseFieldVec promote-to-private should succeed");
    }

    pub fn new_zeroes(size: usize) -> Self {
        let buffer =
            U32Buffer::zeroed(size).expect("Metal BaseFieldVec zero allocation should initialize");
        Self {
            buffer,
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

    /// Returns a reference to the underlying GPU buffer.
    /// Useful for GPU-side buffer concatenation without CPU round-trips.
    pub fn gpu_buffer(&self) -> &U32Buffer {
        &self.buffer
    }

    pub fn get_data(&self, index: usize) -> BaseField {
        if let Some(values) = self.host_cache.get() {
            return values[index];
        }
        BaseField::from_u32_unchecked(self.buffer.get(index))
    }

    pub fn set_data(&mut self, index: usize, value: BaseField) {
        let _ = self.host_cache.take();
        self.buffer.set(index, value.0);
    }

    pub fn copy_from(&mut self, other: &Self) {
        let _ = self.host_cache.take();
        self.buffer
            .copy_from(&other.buffer)
            .expect("Metal BaseFieldVec copy should succeed");
    }

    pub fn copy_from_offset(&mut self, other: &Self, offset: usize) {
        let _ = self.host_cache.take();
        self.buffer
            .copy_from_offset(&other.buffer, offset)
            .expect("Metal BaseFieldVec offset copy should succeed");
    }

    pub fn to_vec(&self) -> Vec<BaseField> {
        self.host_slice().to_vec()
    }

    pub fn batch_get(&self, indices: &[usize]) -> Vec<BaseField> {
        if let Some(values) = self.host_cache.get() {
            return indices.iter().map(|&index| values[index]).collect();
        }

        if indices.is_empty() {
            return Vec::new();
        }

        if indices.len().saturating_mul(8) <= self.size {
            return self
                .buffer
                .read_indices(indices)
                .expect("Metal BaseFieldVec indexed readback should succeed")
                .into_iter()
                .map(BaseField::from_u32_unchecked)
                .collect();
        }

        let host_values = self.host_slice();
        indices.iter().map(|&index| host_values[index]).collect()
    }

    pub fn bit_reverse(&mut self) {
        let _ = self.host_cache.take();
        self.buffer
            .bit_reverse()
            .expect("Metal BaseFieldVec bit reverse should succeed");
    }

    pub fn coset_to_circle_domain_bit_reversed(&self) -> Self {
        let buffer = self
            .buffer
            .permute_coset_to_circle_domain_bit_reversed()
            .expect("Metal BaseFieldVec permutation should succeed");
        Self {
            buffer,
            size: self.size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn fix_first_variable(&self, assignment: SecureField) -> SecureFieldVec {
        assert!(
            self.size >= 2,
            "Metal BaseFieldVec MLE fix-first-variable requires at least two evaluations"
        );
        let buffer = self
            .buffer
            .fix_first_variable_base_field(assignment.to_m31_array().map(|limb| limb.0))
            .expect("Metal BaseFieldVec MLE fix-first-variable should succeed");
        SecureFieldVec::from_buffer(buffer)
    }

    pub fn gkr_next_logup_multiplicities_layer(
        &self,
        denominators: &SecureFieldVec,
    ) -> (SecureFieldVec, SecureFieldVec) {
        let (next_numerators, next_denominators) =
            U32Buffer::gkr_next_logup_multiplicities_layer(&self.buffer, &denominators.buffer)
                .expect("Metal base-field multiplicities next-layer generation should succeed");
        (
            SecureFieldVec::from_buffer(next_numerators),
            SecureFieldVec::from_buffer(next_denominators),
        )
    }

    pub fn inclusive_prefix_sum_bit_rev_circle_domain(&mut self) {
        let _ = self.host_cache.take();
        self.buffer
            .inclusive_prefix_sum_bit_rev_circle_domain_in_place()
            .expect("Metal BaseFieldVec prefix sum should succeed");
    }

    pub fn gkr_sum_logup_multiplicities(
        &self,
        eq_evals: &SecureFieldVec,
        denominators: &SecureFieldVec,
        lambda: SecureField,
    ) -> (SecureField, SecureField) {
        let (eval_at_0, eval_at_2) = U32Buffer::gkr_sum_logup_multiplicities(
            &eq_evals.buffer,
            &self.buffer,
            &denominators.buffer,
            lambda.to_m31_array().map(|limb| limb.0),
        )
        .expect("Metal GKR multiplicities sum should succeed");
        (
            SecureField::from_u32_unchecked(eval_at_0[0], eval_at_0[1], eval_at_0[2], eval_at_0[3]),
            SecureField::from_u32_unchecked(eval_at_2[0], eval_at_2[1], eval_at_2[2], eval_at_2[3]),
        )
    }

    pub fn extend(&mut self, other: &Self) {
        let new_size = self.size + other.size;
        let mut new_vec = Self::new_uninitialized(new_size);
        new_vec.copy_from(self);
        new_vec.copy_from_offset(other, self.size);
        *self = new_vec;
    }

    pub fn pad_to_size(&mut self, target_size: usize) {
        if self.size >= target_size {
            return;
        }
        let mut new_vec = Self::new_zeroes(target_size);
        new_vec.copy_from(self);
        *self = new_vec;
    }

    pub fn split_at_mid(self) -> (Self, Self) {
        assert!(
            self.size.is_power_of_two() && self.size >= 2,
            "Metal BaseFieldVec split_at_mid requires a power-of-two length of at least two"
        );
        let mid = self.size / 2;
        let left_buffer = self
            .buffer
            .clone_range(0, mid)
            .expect("Metal BaseFieldVec split_at_mid left half GPU copy should succeed");
        let right_buffer = self
            .buffer
            .clone_range(mid, mid)
            .expect("Metal BaseFieldVec split_at_mid right half GPU copy should succeed");
        (
            Self::from_buffer(left_buffer),
            Self::from_buffer(right_buffer),
        )
    }

    /// Creates a `BaseFieldVec` from a `&[PackedM31]` slice by uploading the raw
    /// u32 data directly to a Metal buffer.
    ///
    /// This is significantly faster than the naive `from_vec(to_cpu())` path because
    /// it avoids element-by-element conversion: `PackedM31` is `#[repr(transparent)]`
    /// over `Simd<u32, 16>`, so the slice can be reinterpreted as `&[u32]` and
    /// uploaded in a single bulk copy.
    pub fn from_packed_m31_slice(packed: &[PackedM31]) -> Self {
        let size = packed.len() * N_LANES;
        // SAFETY: PackedM31 is #[repr(transparent)] over Simd<u32, 16> which has
        // the same layout as [u32; 16]. Reinterpreting &[PackedM31] as &[u32] is
        // safe because both are POD types with compatible layouts.
        let raw_u32_slice: &[u32] =
            unsafe { std::slice::from_raw_parts(packed.as_ptr() as *const u32, size) };
        let buffer = U32Buffer::from_slice(raw_u32_slice)
            .expect("Metal BaseFieldVec upload should initialize");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    /// Like `from_packed_m31_slice`, but uploads to a private (GPU-only) Metal buffer
    /// via a staging blit. Private buffers receive driver-level optimizations that shared
    /// buffers cannot, and should be used for trace columns that are only read by
    /// GPU compute/blit passes and never by the CPU after initial upload.
    pub fn from_packed_m31_slice_private(packed: &[PackedM31]) -> Self {
        let size = packed.len() * N_LANES;
        // SAFETY: PackedM31 is #[repr(transparent)] over Simd<u32, 16> which has
        // the same layout as [u32; 16]. Reinterpreting &[PackedM31] as &[u32] is
        // safe because both are POD types with compatible layouts.
        let raw_u32_slice: &[u32] =
            unsafe { std::slice::from_raw_parts(packed.as_ptr() as *const u32, size) };
        let buffer = U32Buffer::from_slice_private(raw_u32_slice)
            .expect("Metal BaseFieldVec private upload should succeed");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    /// Returns a zero-copy view of the GPU buffer as a `&[PackedM31]` slice.
    ///
    /// On Apple Silicon unified memory, the GPU buffer's host pointer points to
    /// the same physical memory used by the GPU. `PackedM31` is `#[repr(transparent)]`
    /// over `Simd<u32, 16>`, which has the same layout as `[u32; 16]`. Since both
    /// `M31` and `u32` are `#[repr(transparent)]`, the contiguous u32 values in
    /// the GPU buffer can be reinterpreted as `PackedM31` groups of 16 without
    /// any data transformation.
    ///
    /// # Panics
    /// Panics if the buffer length is not a multiple of `N_LANES` (16), or if
    /// the host pointer is null (discrete GPU without unified memory).
    pub fn as_packed_m31_slice(&self) -> &[PackedM31] {
        assert!(
            self.size.is_multiple_of(N_LANES),
            "as_packed_m31_slice requires buffer length {} to be a multiple of N_LANES ({})",
            self.size,
            N_LANES,
        );

        // Try direct host pointer first (zero-copy on unified memory).
        let raw = unsafe { self.buffer.host_ptr() };
        assert!(
            !raw.is_null(),
            "as_packed_m31_slice requires unified memory (host_ptr must be non-null)"
        );

        let packed_len = self.size / N_LANES;
        // SAFETY: PackedM31 is #[repr(transparent)] over Simd<u32, 16> which has
        // the same layout as [u32; 16]. M31 is #[repr(transparent)] over u32.
        // The pointer is valid for `self.size` u32 values = `packed_len` PackedM31 values.
        // The alignment of Simd<u32, 16> is at least that of u32, and Metal buffers
        // are page-aligned, so alignment is satisfied.
        unsafe { std::slice::from_raw_parts(raw as *const PackedM31, packed_len) }
    }

    /// Copies the GPU buffer contents into a new `Vec<PackedM31>`.
    ///
    /// This is significantly faster than the naive path of
    /// `to_cpu() -> iter -> collect::<BaseColumn>()` because it performs a single
    /// memcpy of the contiguous host-mapped memory rather than element-by-element
    /// conversion and re-packing.
    ///
    /// # Panics
    /// Panics if the buffer length is not a multiple of `N_LANES` (16).
    pub fn to_packed_m31_vec(&self) -> Vec<PackedM31> {
        self.as_packed_m31_slice().to_vec()
    }
}

impl Clone for BaseFieldVec {
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
