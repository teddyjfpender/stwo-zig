const std = @import("std");
const Workloads = @import("ethereum_workloads_v1.zig");
const Runner = @import("../runner/mod.zig");
test "Ethereum profiling workloads execute exact cycles outputs and family counts" {
    const a = std.testing.allocator;
    inline for (std.meta.tags(Workloads.Kind)) |kind| {
        const w = try Workloads.make(kind, 4);
        var session = try Runner.EthereumShaExecutionSession.init(a, &w.elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true });
        defer session.deinit();
        var run = try session.startSegment(@intCast(w.cycles));
        defer run.deinit();
        try std.testing.expectEqual(w.cycles, run.base.cycle_count);
        try std.testing.expectEqual(.halt_flag, run.base.completion_reason);
        try std.testing.expectEqualSlices(u8, &w.output, run.base.output.?);
        try std.testing.expectEqual(w.keccak_calls, run.extension.keccakf_calls.records().len);
        try std.testing.expectEqual(w.recovery_calls, run.extension.signer_recovery_calls.records().len);
        if (w.keccak_calls > 1) {
            const calls = run.extension.keccakf_calls.records();
            try std.testing.expectEqualSlices(u32, &calls[0].output, &calls[1].input);
            try std.testing.expect(!std.mem.eql(u32, &calls[0].input, &calls[1].input));
        }
    }
    try std.testing.expectError(error.WorkloadIterationLimit, Workloads.make(.memory_heavy, 0));
    try std.testing.expectError(error.WorkloadIterationLimit, Workloads.make(.keccak_heavy, 1025));
}
