use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::prover::backend::{Column, ColumnOps};

use crate::backend::CudaBackend;
use crate::columns as interface;
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::bindings;
use crate::columns::blake_2s_hash_vec::Blake2sHashVec;
use crate::columns::secure_field_vec::SecureFieldVec;

/// Split a device buffer of `2 * half_words` u32 words into two freshly allocated
/// device buffers of `half_words` each — two device-to-device copies, no host
/// roundtrip. Returns the halves' device pointers; the caller wraps them in the
/// appropriate column type (which owns and later frees them). The source buffer is
/// not freed here; it is released when the consumed column drops.
fn split_device_words(src: *const u32, half_words: usize) -> (*const u32, *const u32) {
    let left = unsafe { bindings::cuda_malloc_uint32_t(half_words as u32) };
    let right = unsafe { bindings::cuda_malloc_uint32_t(half_words as u32) };
    unsafe {
        bindings::copy_uint32_t_vec_from_device_to_device(src, left, half_words as u32);
        bindings::copy_uint32_t_vec_from_device_to_device(
            src.add(half_words),
            right,
            half_words as u32,
        );
    }
    (left, right)
}

impl ColumnOps<BaseField> for CudaBackend {
    type Column = BaseFieldVec;

    fn bit_reverse_column(column: &mut Self::Column) {
        let size = column.len();
        assert!(size.is_power_of_two() && size < u32::MAX as usize);

        unsafe {
            interface::bindings::bit_reverse_base_field(column.device_ptr, size);
        }
    }
}

impl ColumnOps<SecureField> for CudaBackend {
    type Column = SecureFieldVec;
    fn bit_reverse_column(column: &mut Self::Column) {
        let size = column.len();
        assert!(size.is_power_of_two() && size < u32::MAX as usize);

        unsafe {
            interface::bindings::bit_reverse_secure_field(column.device_ptr, size);
        }
    }
}

impl Column<BaseField> for interface::base_field_vec::BaseFieldVec {
    fn zeros(len: usize) -> Self {
        Self::new_zeroes(len)
    }

    fn to_cpu(&self) -> Vec<BaseField> {
        self.to_vec()
    }

    fn len(&self) -> usize {
        self.size
    }

    fn at(&self, index: usize) -> BaseField {
        Self::get_data(self, index)
    }

    /// Batched gather: one kernel + one D2H copy for all indices. The default
    /// (per-element `at`) is one 4-byte PCIe roundtrip per index — the decommit phase
    /// issues ~queries x columns of those, which measured as the dominant warm-prove
    /// cost. Device storage is raw u32 words, so the gathered values carry the exact
    /// stored representation (`at_unreduced` semantics, same as `at` here).
    fn gather_unreduced(&self, indices: &[usize]) -> Vec<BaseField> {
        let indices_u32: Vec<u32> = indices
            .iter()
            .map(|&index| {
                debug_assert!(index < self.size);
                index as u32
            })
            .collect();
        let mut out: Vec<BaseField> = vec![Default::default(); indices.len()];
        unsafe {
            bindings::cuda_gather_uint32_t(
                self.device_ptr,
                indices_u32.as_ptr(),
                indices_u32.len() as u32,
                out.as_mut_ptr().cast(),
            );
        }
        out
    }

    fn set(&mut self, _index: usize, _value: BaseField) {
        Self::set_data(self, _index, _value);
    }

    fn split_at_mid(self) -> (Self, Self) {
        assert!(
            self.size.is_multiple_of(2),
            "column split_at_mid requires an even-length column"
        );
        let mid = self.size / 2;
        let (left, right) = split_device_words(self.device_ptr, mid);
        (BaseFieldVec::new(left, mid), BaseFieldVec::new(right, mid))
    }

    unsafe fn uninitialized(len: usize) -> Self {
        Self {
            device_ptr: bindings::cuda_malloc_uint32_t(len as u32),
            size: len,
            owns_memory: true,
        }
    }
}

impl FromIterator<BaseField> for BaseFieldVec {
    fn from_iter<T: IntoIterator<Item = BaseField>>(iter: T) -> Self {
        let vec: Vec<BaseField> = iter.into_iter().collect();
        BaseFieldVec::from_vec(vec)
    }
}

impl IntoIterator for BaseFieldVec {
    type Item = BaseField;

    type IntoIter = std::vec::IntoIter<BaseField>;

    fn into_iter(self) -> Self::IntoIter {
        self.to_cpu().into_iter()
    }
}

impl Column<SecureField> for SecureFieldVec {
    fn zeros(_len: usize) -> Self {
        Self::new_zeroes(_len)
    }

    fn to_cpu(&self) -> Vec<SecureField> {
        self.to_vec()
    }

    fn len(&self) -> usize {
        self.size
    }

    fn at(&self, _index: usize) -> SecureField {
        Self::get_data(self, _index)
    }

    fn set(&mut self, _index: usize, _value: SecureField) {
        Self::set_data(self, _index, _value);
    }

    fn split_at_mid(self) -> (Self, Self) {
        assert!(
            self.size.is_multiple_of(2),
            "column split_at_mid requires an even-length column"
        );
        let mid = self.size / 2;
        // 4 u32 words per QM31 element.
        let (left, right) = split_device_words(self.device_ptr, 4 * mid);
        (
            SecureFieldVec::new(left, mid),
            SecureFieldVec::new(right, mid),
        )
    }

    unsafe fn uninitialized(len: usize) -> Self {
        Self {
            device_ptr: bindings::cuda_malloc_uint32_t(4 * len as u32),
            size: len,
        }
    }
}

impl FromIterator<SecureField> for SecureFieldVec {
    fn from_iter<T: IntoIterator<Item = SecureField>>(iter: T) -> Self {
        let data: Vec<SecureField> = iter.into_iter().collect();
        Self::from_vec(data)
    }
}

impl Column<Blake2sHash> for Blake2sHashVec {
    fn zeros(len: usize) -> Self {
        Self::new_zeroes(len)
    }

    fn to_cpu(&self) -> Vec<Blake2sHash> {
        self.to_vec()
    }

    fn len(&self) -> usize {
        self.size
    }

    fn at(&self, index: usize) -> Blake2sHash {
        Self::get_data(self, index)
    }

    fn set(&mut self, _index: usize, _value: Blake2sHash) {
        Self::set_data(self, _index, _value);
    }

    unsafe fn uninitialized(len: usize) -> Self {
        Self {
            device_ptr: bindings::cuda_malloc_blake_2s_hash(len),
            size: len,
        }
    }

    fn split_at_mid(self) -> (Self, Self) {
        assert!(
            self.size.is_multiple_of(2),
            "column split_at_mid requires an even-length column"
        );
        let mid = self.size / 2;
        // A Blake2sHash is 32 bytes = 8 u32 words.
        let (left, right) = split_device_words(self.device_ptr.cast(), 8 * mid);
        (
            Blake2sHashVec::new(left.cast(), mid),
            Blake2sHashVec::new(right.cast(), mid),
        )
    }
}

impl FromIterator<Blake2sHash> for Blake2sHashVec {
    fn from_iter<T: IntoIterator<Item = Blake2sHash>>(iter: T) -> Self {
        let data: Vec<Blake2sHash> = iter.into_iter().collect();
        Self::from_vec(data)
    }
}
#[cfg(all(test, stwo_cuda_link))]
mod tests {
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fields::qm31::SecureField;
    use stwo::prover::backend::{Column, ColumnOps, CpuBackend};

    use crate::backend::CudaBackend;
    use crate::columns::base_field_vec::BaseFieldVec;
    use crate::columns::secure_field_vec::SecureFieldVec;

    #[test]
    fn test_bit_reverse_base_field() {
        let size: usize = 1 << 10;
        let column_data = (0..size as u32).map(BaseField::from).collect::<Vec<_>>();
        let mut expected_result = column_data.clone();
        CpuBackend::bit_reverse_column(&mut expected_result);

        let mut column = BaseFieldVec::from_vec(column_data);
        <CudaBackend as ColumnOps<BaseField>>::bit_reverse_column(&mut column);

        assert_eq!(column.to_cpu(), expected_result);
    }

    #[test]
    fn test_bit_reverse_secure_field() {
        let size: usize = 1 << 16;

        let from_raw = (1..(size + 1) as u32).collect::<Vec<u32>>();
        let from_cpu = from_raw
            .chunks(4)
            .map(|a| SecureField::from_u32_unchecked(a[0], a[1], a[2], a[3]))
            .collect::<Vec<_>>();
        let mut array_expected = from_cpu.clone();

        CpuBackend::bit_reverse_column(&mut array_expected);

        let mut array = SecureFieldVec::from_vec(from_cpu.clone());
        <CudaBackend as ColumnOps<SecureField>>::bit_reverse_column(&mut array);

        assert_eq!(array.to_cpu(), array_expected);
    }
}
