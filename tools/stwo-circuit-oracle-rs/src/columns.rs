//! Per-column and chained per-component trace digests for the circuit lane.
//!
//! The record layout and the digest functions are the shared `tools/stwo-trace-digest` source
//! (compiled in as `crate::trace_digest`), also used by `tools/stwo-cairo-trace-oracle` and
//! mirrored in Zig by `src/frontends/cairo/conformance/checkpoint.zig`; only the domain strings
//! differ, so a single Zig comparator parameterised by domain serves both lanes. This module
//! defines the circuit domains and a digester that chains components from 32 zero bytes.

use anyhow::Result;
use serde::Serialize;
use stwo::core::fields::m31::BaseField;

pub use crate::trace_digest::Domains;
use crate::trace_digest::{accumulator_digest, column_digest};

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

    /// The digester chains the shared digests from 32 zero bytes, one component at a time.
    #[test]
    fn digester_chains_the_shared_digests() {
        let values = vec![BaseField::from(1), BaseField::from(2)];
        let mut digester = ColumnDigester::new(BASE);
        digester.component("eq", [(None, values.clone())]).unwrap();
        digester
            .component("qm31_ops", Vec::<(Option<String>, Vec<BaseField>)>::new())
            .unwrap();
        let (components, last) = digester.finish();

        let column = column_digest(BASE, 0, "eq", 0, &values).unwrap();
        let first = accumulator_digest(BASE, [0; 32], 0, "eq", &[(2, column)]).unwrap();
        let second = accumulator_digest(BASE, first, 1, "qm31_ops", &[]).unwrap();
        assert_eq!(components[0].columns[0].sha256, hex::encode(column));
        assert_eq!(components[0].accumulator_sha256, hex::encode(first));
        assert_eq!(last, hex::encode(second));
    }

    /// The three circuit domain pairs are pairwise distinct.
    #[test]
    fn circuit_domains_are_distinct() {
        let all = [PREPROCESSED, BASE, INTERACTION];
        for (i, a) in all.iter().enumerate() {
            assert_ne!(a.column, a.accumulator);
            for b in &all[i + 1..] {
                assert_ne!(a.column, b.column);
                assert_ne!(a.accumulator, b.accumulator);
            }
        }
    }
}
