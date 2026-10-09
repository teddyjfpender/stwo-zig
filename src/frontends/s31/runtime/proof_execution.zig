//! Execution-only helpers for the full gate prover. The topology, commitment
//! and public statement are trusted caller inputs, never decoded from a proof.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const native = @import("native_verifier.zig");

/// Verify serialized bytes against the commitment of the independently built
/// topology. Recomputing that commitment here repeats fixed-table FFT/hash work.
pub fn verifyCommitted(
    allocator: std.mem.Allocator,
    pp: *const circuit.common.preprocessed.PreprocessedCircuit,
    bundle: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    root: [32]u8,
    public_words: [8]u32,
    encoded: []const u8,
    hybrid: ?native.HybridSpec,
) !void {
    const layout = pp.layout();
    const logs = try circuit.common.component_list.circuitComponentLogSizes(&layout);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(logs, pcs.fri_config.log_blowup_factor, root);
    if (hybrid) |spec|
        try native.verifyHybrid(allocator, &layout, bundle, pcs, root, hash, public_words, encoded, spec)
    else
        try native.verify(allocator, &layout, bundle, pcs, root, hash, public_words, encoded);
}

/// At most one interval per fixed transcript step. Normal proving does not
/// sample clocks here. Opt-in timings expose no witness values or digests.
pub const PhaseObserver = struct {
    timer: ?std.time.Timer,
    intervals: [@typeInfo(cpu.prove.Step).@"enum".fields.len]u64 = @splat(0),

    pub fn init() !PhaseObserver {
        return .{ .timer = if (std.process.hasEnvVarConstant("STWO_CIRCUIT_STAGE_PROFILE"))
            try std.time.Timer.start()
        else
            null };
    }

    pub fn onStep(self: *PhaseObserver, which: cpu.prove.Step, _: [32]u8) void {
        if (self.timer) |*timer| self.intervals[@intFromEnum(which)] = timer.lap();
    }

    pub fn print(self: *const PhaseObserver) void {
        if (self.timer == null) return;
        inline for (@typeInfo(cpu.prove.Step).@"enum".fields) |field| {
            std.debug.print("S31_PHASE {s} {d:.6}s\n", .{
                field.name,
                @as(f64, @floatFromInt(self.intervals[field.value])) / std.time.ns_per_s,
            });
        }
    }
};
