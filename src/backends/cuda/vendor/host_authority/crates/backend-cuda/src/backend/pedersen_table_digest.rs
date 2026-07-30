use super::{
    requested_padded_rows, PedersenTableContentDigest, PedersenTableRegistrationError,
    PEDERSEN_TABLE_N_COLUMNS,
};

const PEDERSEN_DIGEST_DOMAIN: &[u8] = b"stwo.borrowed-pedersen-table.v1";

pub(super) fn pedersen_content_hasher(source_rows: usize, padded_rows: usize) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PEDERSEN_DIGEST_DOMAIN);
    hasher.update(&(PEDERSEN_TABLE_N_COLUMNS as u64).to_le_bytes());
    hasher.update(&(source_rows as u64).to_le_bytes());
    hasher.update(&(padded_rows as u64).to_le_bytes());
    hasher
}

pub(super) fn hash_pedersen_column(hasher: &mut blake3::Hasher, column: usize, words: &[u32]) {
    hasher.update(&(column as u64).to_le_bytes());
    // The digest covers the exact bytes passed to CUDA, including zero padding.
    // `u8` has alignment 1 and the byte span is exactly the initialized slice.
    let bytes = unsafe {
        core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), core::mem::size_of_val(words))
    };
    hasher.update(bytes);
}

pub(super) fn finish_pedersen_digest(hasher: blake3::Hasher) -> PedersenTableContentDigest {
    PedersenTableContentDigest::new(*hasher.finalize().as_bytes())
}

/// Compute the content identity expected by checked registration without
/// touching CUDA. The fill closure is held to the same exact shape and padding
/// contract as the upload pass.
pub fn compute_borrowed_pedersen_table_digest(
    n_rows: usize,
    mut fill_column: impl FnMut(usize, &mut Vec<u32>),
) -> Result<PedersenTableContentDigest, PedersenTableRegistrationError> {
    let padded_rows = requested_padded_rows(n_rows)?;
    let mut hasher = pedersen_content_hasher(n_rows, padded_rows);
    let mut buf = Vec::new();
    buf.try_reserve_exact(padded_rows).map_err(|_| {
        PedersenTableRegistrationError::HostAllocationFailed {
            allocation: "padded pedersen digest buffer",
        }
    })?;
    for column in 0..PEDERSEN_TABLE_N_COLUMNS {
        buf.clear();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_column(column, &mut buf);
        }))
        .is_err()
        {
            return Err(PedersenTableRegistrationError::FillPanicked { column });
        }
        if buf.len() != n_rows {
            return Err(PedersenTableRegistrationError::ColumnLength {
                column,
                expected: n_rows,
                actual: buf.len(),
            });
        }
        buf.try_reserve_exact(padded_rows - buf.len())
            .map_err(|_| PedersenTableRegistrationError::HostAllocationFailed {
                allocation: "padded pedersen digest buffer",
            })?;
        buf.resize(padded_rows, 0);
        hash_pedersen_column(&mut hasher, column, &buf);
    }
    Ok(finish_pedersen_digest(hasher))
}
