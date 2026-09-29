//! Per-column and chained per-component trace digests.
//!
//! The record layout is the one of `tools/stwo-cairo-trace-oracle/src/checkpoint.rs`
//! (`column_digest`, `accumulator_digest`), mirrored in Zig by
//! `src/frontends/cairo/conformance/checkpoint.zig`; only the domain strings differ, so a single
//! Zig comparator parameterised by domain serves both lanes. That crate pins a different upstream
//! (`stwo-cairo@82f2125`), so the two functions are restated here rather than shared.
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
//! The accumulator starts from 32 zero bytes and is chained across components in order.

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::fields::m31::BaseField;

/// A pair of column and accumulator domains.
#[derive(Clone, Copy)]
pub struct Domains {
    pub column: &'static [u8],
    pub accumulator: &'static [u8],
}

pub const PREPROCESSED: Domains = Domains {
    column: b"STWO_CIRCUIT_PREPROCESSED_COLUMN_V1\0",
    accumulator: b"STWO_CIRCUIT_PREPROCESSED_ACCUMULATOR_V1\0",
};
pub const BASE: Domains = Domains {
    column: b"STWO_CIRCUIT_BASE_COLUMN_V1\0",
    accumulator: b"STWO_CIRCUIT_BASE_ACCUMULATOR_V1\0",
};
pub const INTERACTION: Domains = Domains {
    column: b"STWO_CIRCUIT_INTERACTION_COLUMN_V1\0",
    accumulator: b"STWO_CIRCUIT_INTERACTION_ACCUMULATOR_V1\0",
};

fn update_label(hasher: &mut Sha256, label: &str) -> Result<()> {
    let length = u32::try_from(label.len()).context("component label exceeds u32")?;
    hasher.update(length.to_le_bytes());
    hasher.update(label.as_bytes());
    Ok(())
}

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

#[derive(Serialize)]
pub struct ColumnRecord {
    pub ordinal: u32,
    /// The preprocessed column id, for preprocessed columns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub log_size: u32,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct ComponentColumns {
    pub ordinal: u32,
    pub label: String,
    pub columns: Vec<ColumnRecord>,
    pub accumulator_sha256: String,
}

/// Digests the columns of consecutive components and chains their accumulator.
pub struct ColumnDigester {
    domains: Domains,
    accumulator: [u8; 32],
    components: Vec<ComponentColumns>,
}

impl ColumnDigester {
    pub fn new(domains: Domains) -> Self {
        Self {
            domains,
            accumulator: [0; 32],
            components: Vec::new(),
        }
    }

    /// Adds one component; `columns` yields `(id, values)` in tree order, one at a time, so a
    /// lazy iterator keeps a single column resident.
    pub fn component<V: AsRef<[BaseField]>>(
        &mut self,
        label: &str,
        columns: impl IntoIterator<Item = (Option<String>, V)>,
    ) -> Result<()> {
        let ordinal = u32::try_from(self.components.len())?;
        let mut records = Vec::new();
        let mut inputs = Vec::new();
        for (index, (id, values)) in columns.into_iter().enumerate() {
            let values = values.as_ref();
            let column_ordinal = u32::try_from(index)?;
            let digest = column_digest(self.domains, ordinal, label, column_ordinal, values)?;
            let row_count = u64::try_from(values.len())?;
            inputs.push((row_count, digest));
            records.push(ColumnRecord {
                ordinal: column_ordinal,
                id,
                log_size: values.len().ilog2(),
                sha256: hex::encode(digest),
            });
        }
        self.accumulator =
            accumulator_digest(self.domains, self.accumulator, ordinal, label, &inputs)?;
        self.components.push(ComponentColumns {
            ordinal,
            label: label.to_owned(),
            columns: records,
            accumulator_sha256: hex::encode(self.accumulator),
        });
        Ok(())
    }

    /// The per-component records and the final accumulator.
    pub fn finish(self) -> (Vec<ComponentColumns>, String) {
        (self.components, hex::encode(self.accumulator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Digests are separated by domain and chained across components.
    #[test]
    fn digest_contract_is_domain_separated_and_chained() {
        let values = [BaseField::from(1), BaseField::from(2)];
        let column = column_digest(BASE, 3, "eq", 0, &values).unwrap();
        let first = accumulator_digest(BASE, [0; 32], 3, "eq", &[(2, column)]).unwrap();
        let second = accumulator_digest(BASE, first, 4, "qm31_ops", &[]).unwrap();
        assert_ne!(column, first);
        assert_ne!(first, second);
        assert_ne!(
            column,
            column_digest(INTERACTION, 3, "eq", 0, &values).unwrap()
        );
    }
}
