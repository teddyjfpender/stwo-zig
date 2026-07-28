const std = @import("std");
const CpuBackend = @import("../../backends/cpu_scalar/mod.zig").CpuBackend;
const pcs_core = @import("stwo_core").pcs;
const core_fri = @import("stwo_core").fri;
const verification = @import("stwo_core").verifier_types.VerificationError;
const generic = @import("stwo_cairo_frontend").prove_trace;
const scalar = @import("../../integrations/cairo_cpu/prove_trace.zig");

fn config() !pcs_core.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try core_fri.FriConfig.init(0, 1, 3),
    };
}

fn syntheticTrace() [16]generic.RawTraceEntry {
    var entries: [16]generic.RawTraceEntry = undefined;
    for (&entries, 0..) |*entry, index| entry.* = .{
        .pc = @intCast(index + 1),
        .ap = @intCast(100 + index),
        .fp = 200,
    };
    return entries;
}

test "cairo prove trace: generic CPU proof verifies" {
    const allocator = std.testing.allocator;
    const entries = syntheticTrace();
    const output = try generic.proveCairoTrace(
        CpuBackend,
        allocator,
        try config(),
        &entries,
        4,
    );
    try generic.verifyCairoTrace(
        allocator,
        try config(),
        output.statement,
        output.proof,
    );
}

test "cairo prove trace: scalar compatibility wrapper rejects statement mismatch" {
    const allocator = std.testing.allocator;
    const entries = syntheticTrace();
    const output = try scalar.proveCairoTrace(allocator, try config(), &entries, 4);
    var bad_statement = output.statement;
    bad_statement.n_trace_columns = 99;

    if (scalar.verifyCairoTrace(
        allocator,
        try config(),
        bad_statement,
        output.proof,
    )) |_| {
        try std.testing.expect(false);
    } else |err| {
        try std.testing.expect(
            err == verification.OodsNotMatching or
                err == verification.InvalidStructure or
                err == verification.ShapeMismatch,
        );
    }
}

test "cairo prove trace: scalar compatibility wrapper proves trace file" {
    const allocator = std.testing.allocator;
    const output = scalar.proveCairoTraceFromFile(
        allocator,
        try config(),
        "vectors/cairo_traces/fib.trace",
    ) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    try scalar.verifyCairoTrace(
        allocator,
        try config(),
        output.statement,
        output.proof,
    );
}
