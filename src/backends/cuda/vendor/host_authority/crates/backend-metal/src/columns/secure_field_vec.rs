use std::sync::OnceLock;

use num_traits::One;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_metal_sys::metal::U32Buffer;

use super::BaseFieldVec;

#[derive(Debug)]
pub struct SecureFieldVec {
    pub(crate) buffer: U32Buffer,
    size: usize,
    /// Lazily materialized host copy. Populated on the first bulk read and reused by
    /// every subsequent read; MUST be invalidated (`take()`) by every `&mut self`
    /// mutation. Constructors start empty.
    host_cache: OnceLock<Vec<SecureField>>,
}

unsafe impl Send for SecureFieldVec {}
unsafe impl Sync for SecureFieldVec {}

impl SecureFieldVec {
    pub(crate) fn from_buffer(buffer: U32Buffer) -> Self {
        let size = buffer.len() / 4;
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn into_buffer(self) -> U32Buffer {
        self.buffer
    }

    pub fn gkr_generate_eq_evals(y: &[SecureField], v: SecureField) -> Self {
        if y.is_empty() {
            return Self::from_vec(vec![v]);
        }

        let factors = y
            .iter()
            .flat_map(|y_i| {
                let lhs = SecureField::one() - *y_i;
                [lhs, *y_i]
            })
            .flat_map(|value| value.to_m31_array().map(|limb| limb.0))
            .collect::<Vec<_>>();
        let factors = U32Buffer::from_slice(&factors)
            .expect("Metal GKR eq-eval factor upload should initialize");
        let buffer = U32Buffer::gkr_gen_eq_evals_from_factors(
            &factors,
            y.len(),
            v.to_m31_array().map(|limb| limb.0),
        )
        .expect("Metal GKR eq-eval generation should succeed");
        Self::from_buffer(buffer)
    }

    pub fn from_vec(host_array: Vec<SecureField>) -> Self {
        let raw: Vec<u32> = host_array
            .into_iter()
            .flat_map(|value| value.to_m31_array().map(|limb| limb.0))
            .collect();
        let size = raw.len() / 4;
        let buffer =
            U32Buffer::from_slice(&raw).expect("Metal SecureFieldVec upload should initialize");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn from_base_coords(columns: [&BaseFieldVec; 4]) -> Self {
        let size = columns[0].len();
        let buffer = U32Buffer::pack_secure_column_coords([
            &columns[0].buffer,
            &columns[1].buffer,
            &columns[2].buffer,
            &columns[3].buffer,
        ])
        .expect("Metal secure-field packing should succeed");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn new_uninitialized(size: usize) -> Self {
        let buffer = U32Buffer::uninitialized(size * 4)
            .expect("Metal SecureFieldVec allocation should initialize");
        Self {
            buffer,
            size,
            host_cache: OnceLock::new(),
        }
    }

    pub fn new_zeroes(size: usize) -> Self {
        let buffer = U32Buffer::zeroed(size * 4)
            .expect("Metal SecureFieldVec zero allocation should initialize");
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

    pub fn get_data(&self, index: usize) -> SecureField {
        assert!(
            index < self.size,
            "secure-field index {index} out of bounds for len {}",
            self.size
        );
        if let Some(values) = self.host_cache.get() {
            return values[index];
        }
        let base = index * 4;
        SecureField::from_u32_unchecked(
            self.buffer.get(base),
            self.buffer.get(base + 1),
            self.buffer.get(base + 2),
            self.buffer.get(base + 3),
        )
    }

    /// A host view of the whole column. One bulk readback on first use; cached after.
    pub fn host_values(&self) -> &[SecureField] {
        self.host_cache.get_or_init(|| {
            // Same contract as `BaseFieldVec::host_slice`: fence the queue before a
            // host read, in case an async producer's handle was dropped.
            stwo_backend_metal_sys::metal::queue_drain()
                .expect("Metal queue drain before host read should succeed");
            let raw = self
                .buffer
                .to_vec()
                .expect("Metal SecureFieldVec readback should succeed");
            raw.chunks_exact(4)
                .map(|limbs| {
                    SecureField::from_u32_unchecked(limbs[0], limbs[1], limbs[2], limbs[3])
                })
                .collect()
        })
    }

    pub fn set_data(&mut self, index: usize, value: SecureField) {
        let _ = self.host_cache.take();
        assert!(
            index < self.size,
            "secure-field index {index} out of bounds for len {}",
            self.size
        );
        let base = index * 4;
        for (offset, limb) in value.to_m31_array().into_iter().enumerate() {
            self.buffer.set(base + offset, limb.0);
        }
    }

    pub fn copy_from(&mut self, other: &Self) {
        let _ = self.host_cache.take();
        assert!(
            self.size >= other.size,
            "destination secure-field len {} is smaller than source len {}",
            self.size,
            other.size
        );
        self.buffer
            .copy_from(&other.buffer)
            .expect("Metal SecureFieldVec copy should succeed");
    }

    pub fn to_vec(&self) -> Vec<SecureField> {
        self.host_values().to_vec()
    }

    pub fn to_base_coords(&self) -> [BaseFieldVec; 4] {
        let [coord_0, coord_1, coord_2, coord_3] = self
            .buffer
            .unpack_secure_column_coords()
            .expect("Metal secure-field unpacking should succeed");
        [
            BaseFieldVec::from_buffer(coord_0),
            BaseFieldVec::from_buffer(coord_1),
            BaseFieldVec::from_buffer(coord_2),
            BaseFieldVec::from_buffer(coord_3),
        ]
    }

    pub fn bit_reverse(&mut self) {
        let _ = self.host_cache.take();
        self.buffer
            .bit_reverse_u32x4(self.size)
            .expect("Metal SecureFieldVec bit reverse should succeed");
    }

    pub fn fold_circle_into_line_first_layer(
        &self,
        inverse_y_factors: &[u32],
        alpha: SecureField,
    ) -> Self {
        let factors = U32Buffer::from_slice(inverse_y_factors)
            .expect("Metal inverse-y factor upload should initialize");
        let alpha_limbs = alpha.to_m31_array().map(|limb| limb.0);
        let buffer = self
            .buffer
            .fri_fold_circle_into_line_first_layer_u32x4(&factors, alpha_limbs)
            .expect("Metal FRI first-layer fold should succeed");
        Self {
            host_cache: OnceLock::new(),
            buffer,
            size: self.size / 2,
        }
    }

    pub fn fold_circle_into_line_first_layer_with_factor_buffer(
        &self,
        inverse_y_factors: &U32Buffer,
        alpha: SecureField,
    ) -> Self {
        let alpha_limbs = alpha.to_m31_array().map(|limb| limb.0);
        let buffer = self
            .buffer
            .fri_fold_circle_into_line_first_layer_u32x4(inverse_y_factors, alpha_limbs)
            .expect("Metal FRI first-layer fold should succeed");
        Self {
            host_cache: OnceLock::new(),
            buffer,
            size: self.size / 2,
        }
    }

    pub fn fold_circle_into_line_accumulate_into_base_coords(
        &self,
        dst_columns: &mut [BaseFieldVec; 4],
        inverse_y_factors: &[u32],
        alpha: SecureField,
    ) {
        let src_columns = self.to_base_coords();
        Self::fold_circle_into_line_accumulate_base_coords(
            [
                &src_columns[0],
                &src_columns[1],
                &src_columns[2],
                &src_columns[3],
            ],
            dst_columns,
            inverse_y_factors,
            alpha,
        );
    }

    pub fn fold_circle_into_line_accumulate_base_coords(
        src_columns: [&BaseFieldVec; 4],
        dst_columns: &mut [BaseFieldVec; 4],
        inverse_y_factors: &[u32],
        alpha: SecureField,
    ) {
        let factors = U32Buffer::from_slice(inverse_y_factors)
            .expect("Metal inverse-y factor upload should initialize");
        Self::fold_circle_into_line_accumulate_base_coords_with_factor_buffer(
            src_columns,
            dst_columns,
            &factors,
            alpha,
        );
    }

    pub fn fold_circle_into_line_accumulate_base_coords_with_factor_buffer(
        src_columns: [&BaseFieldVec; 4],
        dst_columns: &mut [BaseFieldVec; 4],
        inverse_y_factors: &U32Buffer,
        alpha: SecureField,
    ) {
        let alpha_limbs = alpha.to_m31_array().map(|limb| limb.0);
        let alpha_sq_limbs = (alpha * alpha).to_m31_array().map(|limb| limb.0);
        let [src_0, src_1, src_2, src_3] = src_columns;
        let [dst_0, dst_1, dst_2, dst_3] = dst_columns;
        U32Buffer::fri_fold_circle_into_line_accumulate_from_coords_u32x4(
            [&src_0.buffer, &src_1.buffer, &src_2.buffer, &src_3.buffer],
            [
                &mut dst_0.buffer,
                &mut dst_1.buffer,
                &mut dst_2.buffer,
                &mut dst_3.buffer,
            ],
            inverse_y_factors,
            alpha_limbs,
            alpha_sq_limbs,
        )
        .expect("Metal FRI first-layer accumulation should succeed");
    }

    pub fn fold_circle_into_line_first_layer_base_coords_with_factor_buffer(
        src_columns: [&BaseFieldVec; 4],
        inverse_y_factors: &U32Buffer,
        alpha: SecureField,
    ) -> [BaseFieldVec; 4] {
        let alpha_limbs = alpha.to_m31_array().map(|limb| limb.0);
        let [src_0, src_1, src_2, src_3] = src_columns;
        let [dst_0, dst_1, dst_2, dst_3] =
            U32Buffer::fri_fold_circle_into_line_first_layer_from_coords_u32x4(
                [&src_0.buffer, &src_1.buffer, &src_2.buffer, &src_3.buffer],
                inverse_y_factors,
                alpha_limbs,
            )
            .expect("Metal FRI first-layer coordinate fold should succeed");
        [
            BaseFieldVec::from_buffer(dst_0),
            BaseFieldVec::from_buffer(dst_1),
            BaseFieldVec::from_buffer(dst_2),
            BaseFieldVec::from_buffer(dst_3),
        ]
    }

    pub fn fold_line_step(&self, inverse_x_factors: &[u32], alpha: SecureField) -> Self {
        let factors = U32Buffer::from_slice(inverse_x_factors)
            .expect("Metal inverse-x factor upload should initialize");
        self.fold_line_step_with_factor_buffer(&factors, alpha)
    }

    /// Like [`fold_line_step`] but takes a pre-uploaded GPU-resident factor
    /// buffer, avoiding the O(n/2) CPU-to-GPU upload on every call.
    pub fn fold_line_step_with_factor_buffer(
        &self,
        inverse_x_factors: &U32Buffer,
        alpha: SecureField,
    ) -> Self {
        let alpha_limbs = alpha.to_m31_array().map(|limb| limb.0);
        let buffer = self
            .buffer
            .fri_fold_line_step_u32x4(inverse_x_factors, alpha_limbs)
            .expect("Metal FRI line-fold step should succeed");
        Self {
            host_cache: OnceLock::new(),
            buffer,
            size: self.size / 2,
        }
    }

    pub fn fold_line_step_base_coords(
        src_columns: [&BaseFieldVec; 4],
        inverse_x_factors: &[u32],
        alpha: SecureField,
    ) -> [BaseFieldVec; 4] {
        let factors = U32Buffer::from_slice(inverse_x_factors)
            .expect("Metal inverse-x factor upload should initialize");
        Self::fold_line_step_base_coords_with_factor_buffer(src_columns, &factors, alpha)
    }

    pub fn fold_line_step_base_coords_with_factor_buffer(
        src_columns: [&BaseFieldVec; 4],
        inverse_x_factors: &U32Buffer,
        alpha: SecureField,
    ) -> [BaseFieldVec; 4] {
        let alpha_limbs = alpha.to_m31_array().map(|limb| limb.0);
        let [src_0, src_1, src_2, src_3] = src_columns;
        let [dst_0, dst_1, dst_2, dst_3] = U32Buffer::fri_fold_line_step_from_coords_u32x4(
            [&src_0.buffer, &src_1.buffer, &src_2.buffer, &src_3.buffer],
            inverse_x_factors,
            alpha_limbs,
        )
        .expect("Metal FRI line-fold step should succeed");
        [
            BaseFieldVec::from_buffer(dst_0),
            BaseFieldVec::from_buffer(dst_1),
            BaseFieldVec::from_buffer(dst_2),
            BaseFieldVec::from_buffer(dst_3),
        ]
    }

    /// Async variant: submits fold step without blocking. Returns (columns, handle).
    pub fn fold_line_step_base_coords_with_factor_buffer_async(
        src_columns: [&BaseFieldVec; 4],
        inverse_x_factors: &U32Buffer,
        alpha: SecureField,
    ) -> (
        [BaseFieldVec; 4],
        stwo_backend_metal_sys::metal::CommandBufferHandle,
    ) {
        let alpha_limbs = alpha.to_m31_array().map(|limb| limb.0);
        let [src_0, src_1, src_2, src_3] = src_columns;
        let ([dst_0, dst_1, dst_2, dst_3], handle) =
            U32Buffer::fri_fold_line_step_from_coords_u32x4_async(
                [&src_0.buffer, &src_1.buffer, &src_2.buffer, &src_3.buffer],
                inverse_x_factors,
                alpha_limbs,
            )
            .expect("Metal FRI line-fold step async should succeed");
        (
            [
                BaseFieldVec::from_buffer(dst_0),
                BaseFieldVec::from_buffer(dst_1),
                BaseFieldVec::from_buffer(dst_2),
                BaseFieldVec::from_buffer(dst_3),
            ],
            handle,
        )
    }

    pub fn fix_first_variable(&self, assignment: SecureField) -> Self {
        assert!(
            self.size >= 2,
            "Metal SecureFieldVec MLE fix-first-variable requires at least two evaluations"
        );
        let buffer = self
            .buffer
            .fix_first_variable_secure_field(assignment.to_m31_array().map(|limb| limb.0))
            .expect("Metal SecureFieldVec MLE fix-first-variable should succeed");
        Self::from_buffer(buffer)
    }

    pub fn gkr_next_grand_product_layer(&self) -> Self {
        let buffer = self
            .buffer
            .gkr_next_grand_product_layer()
            .expect("Metal GKR next grand-product layer should succeed");
        Self::from_buffer(buffer)
    }

    pub fn gkr_next_logup_generic_layer(numerators: &Self, denominators: &Self) -> (Self, Self) {
        let (next_numerators, next_denominators) =
            U32Buffer::gkr_next_logup_generic_layer(&numerators.buffer, &denominators.buffer)
                .expect("Metal GKR next generic layer should succeed");
        (
            Self::from_buffer(next_numerators),
            Self::from_buffer(next_denominators),
        )
    }

    pub fn gkr_next_logup_singles_layer(denominators: &Self) -> (Self, Self) {
        let (next_numerators, next_denominators) =
            U32Buffer::gkr_next_logup_singles_layer(&denominators.buffer)
                .expect("Metal GKR next singles layer should succeed");
        (
            Self::from_buffer(next_numerators),
            Self::from_buffer(next_denominators),
        )
    }

    pub fn gkr_sum_grand_product(
        eq_evals: &Self,
        input_layer: &Self,
    ) -> (SecureField, SecureField) {
        let (eval_at_0, eval_at_2) =
            U32Buffer::gkr_sum_grand_product(&eq_evals.buffer, &input_layer.buffer)
                .expect("Metal GKR grand-product sum should succeed");
        (
            SecureField::from_u32_unchecked(eval_at_0[0], eval_at_0[1], eval_at_0[2], eval_at_0[3]),
            SecureField::from_u32_unchecked(eval_at_2[0], eval_at_2[1], eval_at_2[2], eval_at_2[3]),
        )
    }

    pub fn gkr_sum_logup_generic(
        eq_evals: &Self,
        numerators: &Self,
        denominators: &Self,
        lambda: SecureField,
    ) -> (SecureField, SecureField) {
        let (eval_at_0, eval_at_2) = U32Buffer::gkr_sum_logup_generic(
            &eq_evals.buffer,
            &numerators.buffer,
            &denominators.buffer,
            lambda.to_m31_array().map(|limb| limb.0),
        )
        .expect("Metal GKR generic sum should succeed");
        (
            SecureField::from_u32_unchecked(eval_at_0[0], eval_at_0[1], eval_at_0[2], eval_at_0[3]),
            SecureField::from_u32_unchecked(eval_at_2[0], eval_at_2[1], eval_at_2[2], eval_at_2[3]),
        )
    }

    pub fn gkr_sum_logup_singles(
        eq_evals: &Self,
        denominators: &Self,
        lambda: SecureField,
    ) -> (SecureField, SecureField) {
        let (eval_at_0, eval_at_2) = U32Buffer::gkr_sum_logup_singles(
            &eq_evals.buffer,
            &denominators.buffer,
            lambda.to_m31_array().map(|limb| limb.0),
        )
        .expect("Metal GKR singles sum should succeed");
        (
            SecureField::from_u32_unchecked(eval_at_0[0], eval_at_0[1], eval_at_0[2], eval_at_0[3]),
            SecureField::from_u32_unchecked(eval_at_2[0], eval_at_2[1], eval_at_2[2], eval_at_2[3]),
        )
    }

    pub fn split_at_mid(self) -> (Self, Self) {
        assert!(
            self.size >= 2 && self.size.is_power_of_two(),
            "Metal SecureFieldVec split_at_mid requires a power-of-two length of at least two"
        );
        let mid = self.size / 2;
        // Each SecureField element occupies 4 u32 slots in the buffer.
        let mid_u32 = mid * 4;
        let half_u32 = mid * 4;
        let left_buffer = self
            .buffer
            .clone_range(0, half_u32)
            .expect("Metal SecureFieldVec split_at_mid left half GPU copy should succeed");
        let right_buffer = self
            .buffer
            .clone_range(mid_u32, half_u32)
            .expect("Metal SecureFieldVec split_at_mid right half GPU copy should succeed");
        (
            Self {
                host_cache: OnceLock::new(),
                buffer: left_buffer,
                size: mid,
            },
            Self {
                host_cache: OnceLock::new(),
                buffer: right_buffer,
                size: mid,
            },
        )
    }
}

impl Clone for SecureFieldVec {
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            size: self.size,
            host_cache: OnceLock::new(),
        }
    }
}
