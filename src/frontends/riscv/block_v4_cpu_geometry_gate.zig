//! Read-only first-round geometry scan from a separately hash-pinned candidate
//! key manifest. It creates no STARK, recursive proof, or authority marker.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const gate = @import("prover/block_v4_cpu_geometry_gate_v1.zig");
const manifest_mod = @import("prover/block_v4_cpu_trusted_manifest_v1.zig");
const runner = @import("prover/block_v4_cpu_runner_source.zig");
const parent = @import("recursion/blake3_execution_parent_protocol.zig");

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 9 and args.len != 10) return error.ExpectedElfInputOracleMaxCyclesScheduleManifestSha256OutputDirOptionalHostLimitGiB;
    const max_cycles = try std.fmt.parseInt(u32, args[4], 10);
    if (max_cycles == 0 or max_cycles > 1 << 22) return error.InvalidSegmentBudget;
    const manifest_hash = try manifest_mod.parseSha256Hex(args[7]);
    const limit_gib = if (args.len == 10) try std.fmt.parseInt(usize, args[9], 10) else 40;
    if (limit_gib < 1 or limit_gib > 56) return error.InvalidGeometryHostLimitGiB;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, limit_gib * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(oracle);
    const schedule = try std.fs.cwd().readFileAlloc(a, args[5], 1024 * 1024);
    defer a.free(schedule);
    var admitted = try manifest_mod.read(a, std.fs.cwd(), args[6], manifest_hash);
    defer admitted.deinit();
    try admitted.admitInputs(elf, input, oracle, schedule);
    const config = parent.Profile.csp_q70_pow26.config();
    var source = try runner.Source.initWithSchedule(a, elf, input, oracle, max_cycles, config, admitted.sourcePins(), schedule);
    defer source.deinit();
    try std.fs.cwd().makePath(args[8]);
    var dir = try std.fs.cwd().openDir(args[8], .{});
    defer dir.close();
    const report = try gate.run(a, dir, budget, &source, admitted.trusted(), manifest_hash, config, .{});
    const statement_hash = std.fmt.bytesToHex(report.statement_sha256, .lower);
    std.debug.print("BLOCK_V4_GEOMETRY scope={s} segments={d} memory_events={d} memory_instances={d} memory_shards={d} opcode_shards={d} external_shards={d} elapsed_ns={d} tracked_work_peak_bytes={d} statement_sha256={s}\n", .{
        report.scope,                   report.segments,            report.memory_events,         report.memory_instances,
        report.memory_range_shards,     report.opcode_range_shards, report.external_range_shards, report.elapsed_ns,
        report.tracked_work_peak_bytes, &statement_hash,
    });
}
