use num_traits::One;
use stwo::core::fields::qm31::SecureField;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo::prover::AccumulationOps;
use stwo_backend_metal_sys::metal::U32Buffer;

use super::MetalBackend;
use crate::columns::base_field_vec::BaseFieldVec;

fn metal_secure_column_from_coordinate_columns(
    columns: [BaseFieldVec; 4],
) -> SecureColumnByCoords<MetalBackend> {
    SecureColumnByCoords { columns }
}

pub(crate) fn metal_secure_column_from_values(
    values: Vec<SecureField>,
) -> SecureColumnByCoords<MetalBackend> {
    let len = values.len();
    let mut columns = std::array::from_fn(|_| BaseFieldVec::new_uninitialized(len));
    for (index, value) in values.into_iter().enumerate() {
        for (column, coord) in columns.iter_mut().zip(value.to_m31_array()) {
            column.set_data(index, coord);
        }
    }
    SecureColumnByCoords { columns }
}

impl AccumulationOps for MetalBackend {
    fn accumulate(column: &mut SecureColumnByCoords<Self>, other: &SecureColumnByCoords<Self>) {
        let updated = U32Buffer::accumulate_secure_columns_coords(
            [
                &column.columns[0].buffer,
                &column.columns[1].buffer,
                &column.columns[2].buffer,
                &column.columns[3].buffer,
            ],
            [
                &other.columns[0].buffer,
                &other.columns[1].buffer,
                &other.columns[2].buffer,
                &other.columns[3].buffer,
            ],
        )
        .expect("Metal secure-column accumulation should succeed");
        *column =
            metal_secure_column_from_coordinate_columns(updated.map(BaseFieldVec::from_buffer));
    }

    fn generate_secure_powers(felt: SecureField, n_powers: usize) -> Vec<SecureField> {
        (0..n_powers)
            .scan(SecureField::one(), |acc, _| {
                let res = *acc;
                *acc *= felt;
                Some(res)
            })
            .collect()
    }

    fn lift_and_accumulate(
        cols: Vec<SecureColumnByCoords<Self>>,
    ) -> Option<SecureColumnByCoords<Self>> {
        let mut cols_iter = cols.into_iter();
        let first = cols_iter.next()?;
        const INITIAL_SIZE: usize = 2;
        assert!(
            first.len() >= INITIAL_SIZE,
            "A column must be of length at least {INITIAL_SIZE}."
        );

        let mut curr: SecureColumnByCoords<MetalBackend> =
            SecureColumnByCoords::zeros(INITIAL_SIZE);
        for col in std::iter::once(first).chain(cols_iter) {
            let updated = U32Buffer::lift_accumulate_secure_columns_coords(
                [
                    &curr.columns[0].buffer,
                    &curr.columns[1].buffer,
                    &curr.columns[2].buffer,
                    &curr.columns[3].buffer,
                ],
                [
                    &col.columns[0].buffer,
                    &col.columns[1].buffer,
                    &col.columns[2].buffer,
                    &col.columns[3].buffer,
                ],
            )
            .expect("Metal lift-and-accumulate should succeed");

            curr =
                metal_secure_column_from_coordinate_columns(updated.map(BaseFieldVec::from_buffer));
        }
        Some(curr)
    }
}
