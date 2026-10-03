//! Independent checkpoint stages in one process. The canonical circuit,
//! evaluator table, worker pool, and CUDA runtime (when supplied) stay live.
const std = @import("std");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const stage = @import("stage.zig");
const stage_session = @import("stage_session.zig");

const Job = struct {
    manifest: []const u8,
    checkpoint: []const u8,
};

pub fn run(
    allocator: std.mem.Allocator,
    registry: wire.registry.CircuitRegistry,
    provers: *const circuit_cpu.prove.Provers,
    source: ?circuit_cpu.recursion.proof_source.Source,
    jobs_path: []const u8,
) !void {
    var wall = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = try std.fs.cwd().readFileAlloc(a, jobs_path, 64 << 20);
    const parsed = try std.json.parseFromSlice([]Job, a, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    if (parsed.value.len == 0 or parsed.value.len > 256) return error.InvalidCampaignSize;
    var session: stage_session.Session = undefined;
    try session.initInPlace(allocator, registry, provers, source);
    defer session.deinit();
    std.debug.print("circuit-stage-campaign setup_ns={} jobs={}\n", .{ wall.lap(), parsed.value.len });
    for (parsed.value, 0..) |job, index| {
        var job_arena = std.heap.ArenaAllocator.init(allocator);
        defer job_arena.deinit();
        const inputs = try stage.loadInputs(job_arena.allocator(), job.manifest);
        var files = try session.run(inputs, false);
        defer files.deinit();
        try std.fs.cwd().writeFile(.{ .sub_path = job.checkpoint, .data = files.checkpoint.written() });
        std.debug.print("circuit-stage-campaign job={} entries={} reductions={} wall_ns={}\n", .{
            index, inputs.len, files.stats.n_pair_reductions, wall.lap(),
        });
    }
}
