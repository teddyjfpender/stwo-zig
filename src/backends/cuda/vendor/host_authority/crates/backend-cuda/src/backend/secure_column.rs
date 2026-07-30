use stwo::prover::secure_column::SecureColumnByCoords;

use crate::backend::CudaBackend;
use crate::columns::base_field_vec::BaseFieldVec;

#[allow(dead_code)]
pub struct CudaSecureColumn {
    columns: [*const u32; 4],
}

#[allow(dead_code)]
impl CudaSecureColumn {
    /// Four independent uninitialized coordinate columns. Callers overwrite every
    /// element before reading (FRI fold writes the full output), so no zero-fill is
    /// needed — and cloning one uninitialized buffer would only add three
    /// device-to-device copies of garbage.
    pub unsafe fn new_with_size(size: usize) -> SecureColumnByCoords<CudaBackend> {
        SecureColumnByCoords {
            columns: std::array::from_fn(|_| BaseFieldVec::new_uninitialized(size)),
        }
    }

    pub fn device_ptr(&self) -> *const *const u32 {
        self.columns.as_ptr()
    }
}

impl<'a> From<&'a SecureColumnByCoords<CudaBackend>> for CudaSecureColumn {
    fn from(secure_column: &'a SecureColumnByCoords<CudaBackend>) -> Self {
        let columns = &secure_column.columns;
        let columns_ptrs_as_vec = columns
            .iter()
            .map(|column| column.device_ptr)
            .collect::<Vec<*const u32>>();
        let columns_ptrs_as_array: [*const u32; 4] = columns_ptrs_as_vec.try_into().unwrap();

        Self {
            columns: columns_ptrs_as_array,
        }
    }
}

impl<'a> From<&'a mut SecureColumnByCoords<CudaBackend>> for CudaSecureColumn {
    fn from(secure_column: &'a mut SecureColumnByCoords<CudaBackend>) -> Self {
        let columns = &secure_column.columns;
        let columns_ptrs_as_vec = columns
            .iter()
            .map(|column| column.device_ptr)
            .collect::<Vec<*const u32>>();
        let columns_ptrs_as_array: [*const u32; 4] = columns_ptrs_as_vec.try_into().unwrap();

        Self {
            columns: columns_ptrs_as_array,
        }
    }
}
