//! Preserve source geometry and completed profiling scopes on a rejected batch.
//! This is a diagnostic artifact, never an accepted proof or chain checkpoint.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Recorder = @import("stwo_prover_api").stage_profile.Recorder;
pub fn write(a: std.mem.Allocator, directory: std.fs.Dir, index: u32, first_step: u64, public: A.Public, cells: Receipt.SourceCells, recorder: *Recorder, failure: anyerror) !void {
    var profile = try recorder.snapshot(a);
    defer profile.deinit(a);
    const value = .{
        .schema = "rv64-ethereum-rejected-batch-v1",
        .accepted = false,
        .failure = @errorName(failure),
        .index = index,
        .first_step = first_step,
        .instructions = public.cpu.statement.steps,
        .cpu_log = public.cpu.statement.logSize(),
        .division_requests = public.cpu.division_requests,
        .division_log = public.cpu.division_log,
        .multiplication_requests = public.cpu.multiplication_requests,
        .multiplication_log = public.cpu.multiplication_log,
        .keccak_calls = public.cpu.keccak_calls,
        .keccak_log = public.cpu.keccak_log,
        .keccak_bridge_log = public.cpu.bridge_log,
        .secp = public.cpu.secp,
        .ram = public.ram,
        .before = public.before,
        .after = public.after,
        .initial_pc = public.cpu.statement.initial_pc,
        .final_pc = public.cpu.statement.final_pc,
        .source_cells = cells,
        .stages = profile,
    };
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    const name = try std.fmt.allocPrint(a, "batch-{d:0>6}.rejected-{d}.json", .{ index, std.time.milliTimestamp() });
    defer a.free(name);
    try Receipt.writeExclusive(directory, name, json);
}
