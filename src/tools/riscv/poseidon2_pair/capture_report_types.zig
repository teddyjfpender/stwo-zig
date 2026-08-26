//! Leaf value types for the strict C-013 child report.

pub const AttemptMetrics = struct {
    execution_steps: usize,
    execution_ns: u64,
    proving_ns: u64,
    proof_encoding_ns: u64,
    verification_ns: u64,
    verified_request_ns: u64,
    proof_wire_bytes: usize,
    preprocessed_cells: u64,
    main_cells: u64,
    interaction_cells: u64,
};

pub const Pcs = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    queries: usize,
    fold_step: u32,
};

pub const Resources = struct {
    scope: []const u8,
    source: []const u8,
    lifetime_peak_physical_footprint_bytes: ?u64,
    process_cpu_ns: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    cycles: ?u64,
    unavailable_reason: ?[]const u8,
};
