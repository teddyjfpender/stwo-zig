//! Diagnostic phase clocks only; never serialized as proof authority.
pub const Stats = struct {
    witness_ns: u64 = 0,
    layout_ns: u64 = 0,
    fixed_columns_ns: u64 = 0,
    fixed_commitment_ns: u64 = 0,
    main_columns_ns: u64 = 0,
    main_commitment_ns: u64 = 0,
    finalize_ns: u64 = 0,
    whole_ns: u64 = 0,
};
