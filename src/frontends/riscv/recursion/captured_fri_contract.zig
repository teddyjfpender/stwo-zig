//! Internal captured fri authority shard; use captured_fri.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const circle = stwo_core.circle;
pub const canonic = stwo_core.poly.circle.canonic;
pub const circuit_mod = @import("air/fri_verifier_circuit.zig");
pub const pcs_circuit_mod = @import("air/pcs_deep_circuit.zig");
pub const fri_merkle = @import("air/fri_merkle_leaf_witness.zig");
pub const merkle_root = @import("air/merkle_root_witness.zig");
pub const trace_merkle = @import("air/trace_merkle_witness.zig");
pub const protocol = @import("protocol.zig");
pub const sample_point_layout = @import("sample_point_layout.zig");
pub const transcript_claims = @import("../air/transcript/claims.zig");

pub const STAGE_TELEMETRY_ENV = "STWO_RECURSION_OUTER_STAGE_TELEMETRY";

pub const Error = std.mem.Allocator.Error || circuit_mod.Error || pcs_circuit_mod.Error ||
    merkle_root.Error || trace_merkle.Error || sample_point_layout.Error || error{
    ArithmeticOverflow,
    CaptureShapeMismatch,
    PositionNotCanonical,
};

pub const ProfileConfig = struct {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    claimed_sum_count: u32,

    pub fn fromPcs(config: anytype) ProfileConfig {
        return .{
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .interaction_pow_bits = protocol.INTERACTION_POW_BITS,
            .pcs_pow_bits = config.pow_bits,
            .claimed_sum_count = transcript_claims.COMPONENT_COUNT,
        };
    }
};

pub fn captureStageFailure(comptime stage: []const u8, err: anyerror) void {
    if (!std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) return;
    std.debug.print(
        "  captured-fri stage={s} failed={s}\n",
        .{ stage, @errorName(err) },
    );
}

pub fn validateDigest(value: protocol.Digest) Error!void {
    for (value) |word| if (word >= m31.Modulus)
        return error.CaptureShapeMismatch;
}

pub fn validateM31(value: M31) Error!void {
    if (value.toU32() >= m31.Modulus) return error.CaptureShapeMismatch;
}

pub fn validateQm31(value: QM31) Error!void {
    for (value.toM31Array()) |word| try validateM31(word);
}

pub fn canonicalPosition(value: anytype) Error!M31 {
    const canonical = std.math.cast(u32, value) orelse
        return error.PositionNotCanonical;
    if (canonical >= m31.Modulus) return error.PositionNotCanonical;
    return M31.fromCanonical(canonical);
}

pub fn mapTreeQueryPosition(position: usize, max_log_size: u32, tree_log_size: u32) usize {
    if (tree_log_size == 0) return 0;
    if (max_log_size < tree_log_size) {
        return (position >> 1 << @intCast(tree_log_size - max_log_size + 1)) +
            (position & 1);
    }
    return (position >> @intCast(max_log_size - tree_log_size + 1) << 1) +
        (position & 1);
}

pub fn add(lhs: usize, rhs: usize) Error!usize {
    return std.math.add(usize, lhs, rhs) catch error.ArithmeticOverflow;
}

pub fn multiply(lhs: usize, rhs: anytype) Error!usize {
    const canonical = std.math.cast(usize, rhs) orelse
        return error.ArithmeticOverflow;
    return std.math.mul(usize, lhs, canonical) catch error.ArithmeticOverflow;
}

pub fn take(
    comptime T: type,
    storage: []T,
    cursor: *usize,
    count: usize,
) []const T {
    const start = cursor.*;
    cursor.* += count;
    std.debug.assert(cursor.* <= storage.len);
    return storage[start..cursor.*];
}
