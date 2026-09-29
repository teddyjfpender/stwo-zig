//! Out-of-domain sampling constants of `crates/stark_verifier/src/oods.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! The in-circuit OODS gadgets (`EvalDomainSamples`, `compute_fri_input`,
//! `collect_oods_responses`) emit gates through the builder and land with
//! it; they must follow `oods.rs`'s own grouping by `(x.idx, y.idx)`, not
//! the core PCS quotient batching.

const core = @import("stwo_core");

/// `COMPOSITION_SPLIT`: the composition polynomial is split into
/// `2^COMPOSITION_LOG_SPLIT` parts.
pub const COMPOSITION_SPLIT: usize = @as(usize, 1) << core.verifier_types.COMPOSITION_LOG_SPLIT;
/// `N_COMPOSITION_COLUMNS`: one M31 column per QM31 coordinate of each part.
pub const N_COMPOSITION_COLUMNS: usize = COMPOSITION_SPLIT * core.fields.qm31.SECURE_EXTENSION_DEGREE;

comptime {
    if (N_COMPOSITION_COLUMNS != 8) @compileError("oods.rs fixes 8 composition columns");
}
