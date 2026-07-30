use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::bit_reverse;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::prover::backend::{Column, ColumnOps};

use super::MetalBackend;
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::blake2s_hash_vec::Blake2sHashVec;
use crate::columns::secure_field_vec::SecureFieldVec;

fn split_host_backed_vec<T, V>(values: Vec<T>, from_vec: fn(Vec<T>) -> V) -> (V, V) {
    assert!(
        values.len().is_multiple_of(2),
        "column split_at_mid requires an even-length column"
    );
    let mid = values.len() / 2;
    let mut values = values;
    let right = values.split_off(mid);
    (from_vec(values), from_vec(right))
}

impl ColumnOps<BaseField> for MetalBackend {
    type Column = BaseFieldVec;

    fn bit_reverse_column(column: &mut Self::Column) {
        let size = column.len();
        assert!(size.is_power_of_two() && size < u32::MAX as usize);
        column.bit_reverse();
    }
}

impl ColumnOps<SecureField> for MetalBackend {
    type Column = SecureFieldVec;

    fn bit_reverse_column(column: &mut Self::Column) {
        let size = column.len();
        assert!(size.is_power_of_two() && size < u32::MAX as usize);
        column.bit_reverse();
    }
}

impl ColumnOps<Blake2sHash> for MetalBackend {
    type Column = Blake2sHashVec;

    fn bit_reverse_column(column: &mut Self::Column) {
        let mut hashes = column.to_vec();
        bit_reverse(&mut hashes);
        *column = Blake2sHashVec::from_vec(hashes);
    }
}

impl Column<BaseField> for BaseFieldVec {
    fn zeros(len: usize) -> Self {
        Self::new_zeroes(len)
    }

    fn to_cpu(&self) -> Vec<BaseField> {
        self.to_vec()
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn at(&self, index: usize) -> BaseField {
        self.get_data(index)
    }

    fn set(&mut self, index: usize, value: BaseField) {
        self.set_data(index, value);
    }

    fn split_at_mid(self) -> (Self, Self) {
        self.split_at_mid()
    }

    unsafe fn uninitialized(len: usize) -> Self {
        Self::new_uninitialized(len)
    }
}

impl FromIterator<BaseField> for BaseFieldVec {
    fn from_iter<T: IntoIterator<Item = BaseField>>(iter: T) -> Self {
        Self::from_vec(iter.into_iter().collect())
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
    fn zeros(len: usize) -> Self {
        Self::new_zeroes(len)
    }

    fn to_cpu(&self) -> Vec<SecureField> {
        self.to_vec()
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn at(&self, index: usize) -> SecureField {
        self.get_data(index)
    }

    fn set(&mut self, index: usize, value: SecureField) {
        self.set_data(index, value);
    }

    fn split_at_mid(self) -> (Self, Self) {
        self.split_at_mid()
    }

    unsafe fn uninitialized(len: usize) -> Self {
        Self::new_uninitialized(len)
    }
}

impl FromIterator<SecureField> for SecureFieldVec {
    fn from_iter<T: IntoIterator<Item = SecureField>>(iter: T) -> Self {
        Self::from_vec(iter.into_iter().collect())
    }
}

impl IntoIterator for SecureFieldVec {
    type Item = SecureField;
    type IntoIter = std::vec::IntoIter<SecureField>;

    fn into_iter(self) -> Self::IntoIter {
        self.to_cpu().into_iter()
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
        self.len()
    }

    fn at(&self, index: usize) -> Blake2sHash {
        self.get_data(index)
    }

    fn set(&mut self, index: usize, value: Blake2sHash) {
        self.set_data(index, value);
    }

    fn split_at_mid(self) -> (Self, Self) {
        split_host_backed_vec(self.to_vec(), Blake2sHashVec::from_vec)
    }

    unsafe fn uninitialized(len: usize) -> Self {
        Self::new_uninitialized(len)
    }
}

impl FromIterator<Blake2sHash> for Blake2sHashVec {
    fn from_iter<T: IntoIterator<Item = Blake2sHash>>(iter: T) -> Self {
        Self::from_vec(iter.into_iter().collect())
    }
}
