//! Zero-copy bridge between MetalBackend GPU buffers and SimdBackend PackedM31 format.
//!
//! On Apple Silicon unified memory, GPU Metal buffers share the same physical memory
//! as the CPU. This module provides efficient conversions between
//! `CircleEvaluation<MetalBackend>` and `CircleEvaluation<SimdBackend>` that exploit
//! this shared memory layout.
//!
//! # Memory Layout Compatibility
//!
//! - `M31` is `#[repr(transparent)]` over `u32`
//! - `PackedM31` is `#[repr(transparent)]` over `Simd<u32, 16>`
//! - `Simd<u32, 16>` has the same memory layout as `[u32; 16]`
//! - `BaseColumn` (SimdBackend) stores `data: Vec<PackedM31>` = contiguous `[u32; N]`
//! - `BaseFieldVec` (MetalBackend) stores a `U32Buffer` = contiguous `[u32; N]`
//!
//! Therefore, a GPU buffer of N u32 values can be reinterpreted as N/16 `PackedM31`
//! values with identical memory layout -- zero copy on unified memory.

use stwo::core::fields::m31::{BaseField, M31};
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::PackedM31;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, FromSimdColumns};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

use super::MetalBackend;
use crate::columns::base_field_vec::BaseFieldVec as MetalBaseFieldVec;

/// The witness-transfer seam: witness generators produce SIMD columns; this uploads them to
/// GPU-private buffers in bulk (single blit per column on unified memory).
impl FromSimdColumns for MetalBackend {
    fn from_simd_base_column(column: Col<SimdBackend, BaseField>) -> Col<Self, BaseField> {
        MetalBaseFieldVec::from_packed_m31_slice_private(&column.data)
    }

    fn from_simd_evals(
        evals: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) -> Vec<CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>> {
        evals.iter().map(simd_eval_to_metal_eval).collect()
    }
}

/// Convert a `CircleEvaluation<MetalBackend>` to `CircleEvaluation<SimdBackend>` using
/// zero-copy memory reinterpretation on unified memory.
///
/// Instead of the naive path (`to_cpu() -> iter -> collect::<BaseColumn>()`) which
/// iterates element-by-element, this function reinterprets the GPU buffer's host
/// pointer directly as `&[PackedM31]` and performs a single bulk `memcpy` into the
/// `Vec<PackedM31>` backing the `BaseColumn`.
///
/// # Performance
///
/// For a column of N u32 values, the naive path does:
/// 1. `to_cpu()` → allocate + copy N u32 values
/// 2. `iter()` → iterate N elements
/// 3. `collect::<BaseColumn>()` → chunk into N/16 PackedM31, pack each
///
/// This function does:
/// 1. Read host pointer (zero-cost)
/// 2. `to_vec()` on `&[PackedM31]` → single memcpy of N*4 bytes
///
/// For ~33M values (fib(524K)), this reduces per-column conversion from ~10ms to ~1ms.
#[allow(dead_code)]
pub fn metal_eval_to_simd_eval(
    eval: &CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>,
) -> CircleEvaluation<SimdBackend, M31, BitReversedOrder> {
    let domain = eval.domain;
    let packed_data = eval.values.to_packed_m31_vec();
    let length = eval.values.len();
    let column = BaseColumn {
        data: packed_data,
        length,
    };
    CircleEvaluation::new(domain, column)
}

/// Convert a batch of `CircleEvaluation<MetalBackend>` to `CircleEvaluation<SimdBackend>`
/// using the zero-copy bridge.
#[allow(dead_code)]
pub fn metal_evals_to_simd_evals(
    evals: &[CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>],
) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
    evals.iter().map(metal_eval_to_simd_eval).collect()
}

/// Convert a `CircleEvaluation<SimdBackend>` to `CircleEvaluation<MetalBackend>` by
/// uploading the `PackedM31` data directly to a private (GPU-only) Metal buffer.
///
/// This is the fast inverse of `metal_eval_to_simd_eval`. Instead of the naive path:
/// `eval.values.to_cpu() -> into_iter() -> collect::<MetalBaseFieldVec>()`
/// which iterates element-by-element through `FromIterator<BaseField>`, this function
/// reinterprets the `Vec<PackedM31>` backing the `BaseColumn` as `&[u32]` and uploads
/// it in a single bulk copy to a private GPU buffer via a staging blit.
///
/// Private buffers receive driver-level optimizations (faster GPU reads) compared to
/// shared buffers, and the CPU never needs to read back committed trace data.
///
/// # Performance
///
/// For a column of N values (N/16 PackedM31 groups):
/// - Naive path: to_cpu() allocates Vec<BaseField>, then from_iter collects back to shared buffer
/// - This function: single memcpy of the PackedM31 data directly to private GPU buffer
pub fn simd_eval_to_metal_eval(
    eval: &CircleEvaluation<SimdBackend, M31, BitReversedOrder>,
) -> CircleEvaluation<MetalBackend, BaseField, BitReversedOrder> {
    let domain = eval.domain;
    let metal_values = MetalBaseFieldVec::from_packed_m31_slice_private(&eval.values.data);
    CircleEvaluation::new(domain, metal_values)
}

/// Convert a batch of `CircleEvaluation<SimdBackend>` to `CircleEvaluation<MetalBackend>`
/// using the fast bulk-upload path.
#[allow(dead_code)]
pub fn simd_evals_to_metal_evals(
    evals: &[CircleEvaluation<SimdBackend, M31, BitReversedOrder>],
) -> Vec<CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>> {
    evals.iter().map(simd_eval_to_metal_eval).collect()
}

/// Extract `Vec<PackedM31>` directly from a `CircleEvaluation<MetalBackend>` via
/// zero-copy reinterpretation of unified memory.
///
/// This is the core primitive that interaction claim generators need: they require
/// owned `Vec<PackedM31>` data for lookup tables. Instead of going through the full
/// `to_cpu() -> BaseColumn -> .data.clone()` path, this reads the GPU buffer's host
/// pointer as `&[PackedM31]` and copies it in one shot.
#[allow(dead_code)]
pub fn metal_eval_to_packed_m31_vec(
    eval: &CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>,
) -> Vec<PackedM31> {
    eval.values.to_packed_m31_vec()
}

#[cfg(test)]
mod tests {
    use stwo::core::fields::m31::{BaseField, M31};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::backend::simd::m31::PackedM31;
    use stwo::prover::backend::Column;
    use stwo::prover::poly::circle::CircleEvaluation;
    use stwo::prover::poly::BitReversedOrder;

    use super::{metal_eval_to_packed_m31_vec, metal_eval_to_simd_eval};
    use crate::columns::base_field_vec::BaseFieldVec as MetalBaseFieldVec;

    #[test]
    fn zero_copy_round_trip_preserves_values() {
        // Create test data: 256 M31 values (16 PackedM31 groups).
        let n: u32 = 256;
        let values: Vec<BaseField> = (0..n).map(M31::from).collect();

        // Create MetalBackend evaluation.
        let metal_vec = MetalBaseFieldVec::from_vec(values.clone());
        let log_size = n.ilog2();
        let domain = CanonicCoset::new(log_size).circle_domain();
        let metal_eval: CircleEvaluation<
            crate::backend::MetalBackend,
            BaseField,
            BitReversedOrder,
        > = CircleEvaluation::new(domain, metal_vec);

        // Convert via zero-copy bridge.
        let simd_eval = metal_eval_to_simd_eval(&metal_eval);

        // Verify all values match.
        let result_values = simd_eval.values.to_cpu();
        assert_eq!(result_values, values);
    }

    #[test]
    fn simd_to_metal_round_trip_preserves_values() {
        let n: u32 = 256;
        let values: Vec<BaseField> = (0..n).map(M31::from).collect();

        // Create SimdBackend evaluation.
        let simd_column: BaseColumn = values.iter().copied().collect();
        let log_size = n.ilog2();
        let domain = CanonicCoset::new(log_size).circle_domain();
        let simd_eval = CircleEvaluation::<
            stwo::prover::backend::simd::SimdBackend,
            BaseField,
            BitReversedOrder,
        >::new(domain, simd_column);

        // Convert to MetalBackend via zero-copy bridge.
        let metal_eval = super::simd_eval_to_metal_eval(&simd_eval);

        // Verify all values match by reading back from Metal buffer.
        let readback: Vec<BaseField> = metal_eval.values.to_vec();
        assert_eq!(readback, values);
    }

    #[test]
    fn packed_m31_extraction_matches_simd_column_data() {
        let n: u32 = 256;
        let values: Vec<BaseField> = (0..n).map(|i| M31::from(i.wrapping_mul(7) % 100)).collect();

        // Create the reference SimdBackend column.
        let simd_column: BaseColumn = values.iter().copied().collect();
        let expected_packed: Vec<PackedM31> = simd_column.data.clone();

        // Create MetalBackend evaluation and extract PackedM31.
        let metal_vec = MetalBaseFieldVec::from_vec(values);
        let log_size = n.ilog2();
        let domain = CanonicCoset::new(log_size).circle_domain();
        let metal_eval: CircleEvaluation<
            crate::backend::MetalBackend,
            BaseField,
            BitReversedOrder,
        > = CircleEvaluation::new(domain, metal_vec);
        let actual_packed = metal_eval_to_packed_m31_vec(&metal_eval);

        // Verify the PackedM31 vectors are identical.
        assert_eq!(actual_packed.len(), expected_packed.len());
        for (a, e) in actual_packed.iter().zip(expected_packed.iter()) {
            assert_eq!(a.to_array(), e.to_array());
        }
    }
}
