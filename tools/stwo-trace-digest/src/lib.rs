//! Domain-separated per-column and chained per-component trace digests.
//!
//! The single source of the trace checkpoint record layout shared by the Cairo trace oracle
//! (`tools/stwo-cairo-trace-oracle`, Stwo `7b211ed`) and the circuit recursion oracle
//! (`tools/stwo-circuit-oracle-rs`, `proving@5a7c5ed`). The Zig comparator is
//! `src/frontends/cairo/conformance/checkpoint.zig`, parameterised by the same domains.
//!
//! ```text
//! column      := SHA-256(column_domain || component_ordinal u32 || u32:len(label) label
//!                        || column_ordinal u32 || row_count u64 || value u32 ...)
//! accumulator := SHA-256(accumulator_domain || previous[32] || component_ordinal u32
//!                        || u32:len(label) label || n_columns u32
//!                        || (column_ordinal u32 || row_count u64 || column[32])*)
//! ```
//!
//! All integers are little-endian; values are canonical M31 in the stored (bit-reversed) order.
//! Callers start the accumulator from 32 zero bytes and chain it across components in order.
//!
//! Each consumer includes this file with
//! `#[path = "../../stwo-trace-digest/src/lib.rs"] mod trace_digest;`, so `stwo` resolves to the
//! consumer's own pin. Only `BaseField`'s canonical `u32` representation is read, which both pins
//! share.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use stwo::core::fields::m31::BaseField;

/// A pair of column and accumulator domains (each NUL-terminated).
#[derive(Clone, Copy)]
pub struct Domains {
    pub column: &'static [u8],
    pub accumulator: &'static [u8],
}

/// Appends `u32:len(label) label`; checkpoints with their own accumulator record reuse it.
pub fn update_label(hasher: &mut Sha256, label: &str) -> Result<()> {
    let length = u32::try_from(label.len()).context("component label exceeds u32")?;
    hasher.update(length.to_le_bytes());
    hasher.update(label.as_bytes());
    Ok(())
}

/// The digest of one column of one component.
pub fn column_digest(
    domains: Domains,
    component_ordinal: u32,
    label: &str,
    column_ordinal: u32,
    values: &[BaseField],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(domains.column);
    hasher.update(component_ordinal.to_le_bytes());
    update_label(&mut hasher, label)?;
    hasher.update(column_ordinal.to_le_bytes());
    hasher.update(u64::try_from(values.len())?.to_le_bytes());
    for value in values {
        hasher.update(value.0.to_le_bytes());
    }
    Ok(hasher.finalize().into())
}

/// Chains one component's `(row_count, column digest)` list onto `previous`.
pub fn accumulator_digest(
    domains: Domains,
    previous: [u8; 32],
    component_ordinal: u32,
    label: &str,
    columns: &[(u64, [u8; 32])],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(domains.accumulator);
    hasher.update(previous);
    hasher.update(component_ordinal.to_le_bytes());
    update_label(&mut hasher, label)?;
    hasher.update(u32::try_from(columns.len())?.to_le_bytes());
    for (ordinal, (row_count, digest)) in columns.iter().enumerate() {
        hasher.update(u32::try_from(ordinal)?.to_le_bytes());
        hasher.update(row_count.to_le_bytes());
        hasher.update(digest);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Domains = Domains {
        column: b"STWO_TRACE_DIGEST_TEST_COLUMN_A\0",
        accumulator: b"STWO_TRACE_DIGEST_TEST_ACCUMULATOR_A\0",
    };
    const B: Domains = Domains {
        column: b"STWO_TRACE_DIGEST_TEST_COLUMN_B\0",
        accumulator: b"STWO_TRACE_DIGEST_TEST_ACCUMULATOR_B\0",
    };

    /// The column record is exactly the documented byte string.
    #[test]
    fn column_digest_matches_the_documented_record() {
        let values = [BaseField::from(1), BaseField::from(2)];
        let mut record = Vec::new();
        record.extend_from_slice(A.column);
        record.extend_from_slice(&3u32.to_le_bytes());
        record.extend_from_slice(&2u32.to_le_bytes());
        record.extend_from_slice(b"eq");
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&2u64.to_le_bytes());
        record.extend_from_slice(&1u32.to_le_bytes());
        record.extend_from_slice(&2u32.to_le_bytes());
        let expected: [u8; 32] = Sha256::digest(&record).into();
        assert_eq!(column_digest(A, 3, "eq", 0, &values).unwrap(), expected);
    }

    /// Digests are separated by domain and chained across components.
    #[test]
    fn digests_are_domain_separated_and_chained() {
        let values = [BaseField::from(1), BaseField::from(2)];
        let column = column_digest(A, 3, "eq", 0, &values).unwrap();
        let first = accumulator_digest(A, [0; 32], 3, "eq", &[(2, column)]).unwrap();
        let second = accumulator_digest(A, first, 4, "qm31_ops", &[]).unwrap();
        assert_ne!(column, first);
        assert_ne!(first, second);
        assert_ne!(column, column_digest(B, 3, "eq", 0, &values).unwrap());
        assert_ne!(
            first,
            accumulator_digest(B, [0; 32], 3, "eq", &[(2, column)]).unwrap()
        );
    }
}
