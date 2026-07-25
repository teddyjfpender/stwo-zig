//! Data contracts shared by mixed-height trace commitment responsibilities.

pub const Cohort = struct {
    first_column: u32,
    column_count: u32,
    trace_log_rows: u32,
    evaluation_log_rows: u32,
    coefficient_offset_words: usize,
    coefficient_words: usize,
    evaluation_offset_words: usize,
    evaluation_words: usize,
};

pub const WriterSpan = struct {
    schedule_ordinal: u32,
    component_index: u32,
    first_column: u32,
    column_count: u32,
    trace_log_rows: u32,
    coefficient_offset_words: usize,
    coefficient_words: usize,
};

pub const InputForm = enum(u8) {
    evaluations,
    coefficients,
};

pub const Slots = struct {
    coefficients: u32,
    evaluations: u32,
    column_logs: u32,
    column_offsets: u32,
    merkle_hashes: u32,
    merkle_layers: u32,
    progressive_states: ?u32,
    root: u32,
    twiddles_forward: u32,
    twiddles_inverse: u32,
};
