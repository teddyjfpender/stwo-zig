//! Scalar CPU convenience surface for the backend-generic Cairo trace prover.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const pcs_core = @import("stwo_core").pcs;
const generic = @import("stwo_cairo_frontend").prove_trace;

pub const Hasher = generic.Hasher;
pub const MerkleChannel = generic.MerkleChannel;
pub const Channel = generic.Channel;
pub const Proof = generic.Proof;
pub const ExtendedProof = generic.ExtendedProof;
pub const RawTraceEntry = generic.RawTraceEntry;
pub const Error = generic.Error;
pub const CairoTraceStatement = generic.CairoTraceStatement;
pub const ProveOutput = generic.ProveOutput;
pub const genTraceColumns = generic.genTraceColumns;
pub const verifyCairoTrace = generic.verifyCairoTrace;

/// Proves through the default scalar backend while preserving the original
/// concrete convenience signature outside the backend-neutral frontend.
pub fn proveCairoTrace(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    trace_entries: []const RawTraceEntry,
    log_size: u32,
) anyerror!ProveOutput {
    return generic.proveCairoTrace(
        CpuBackend,
        allocator,
        pcs_config,
        trace_entries,
        log_size,
    );
}

pub fn proveCairoTraceFromFile(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    trace_path: []const u8,
) anyerror!ProveOutput {
    return generic.proveCairoTraceFromFile(
        CpuBackend,
        allocator,
        pcs_config,
        trace_path,
    );
}
