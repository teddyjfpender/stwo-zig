//! Fast strict replay gate for terminal-aware execution schedules. No proofs.
const std = @import("std");
const runner = @import("runner/mod.zig");
const statement = @import("prover/blake3_segment_statement.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 5) return error.ExpectedElfInputOracleLimit;
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(oracle);
    const limit = try std.fmt.parseInt(u32, args[4], 10);
    switch (try runner.elf_loader.requestedExecutionProfile(elf)) {
        .rv32im_zkvm_ethereum_v1 => try check(.rv32im_zkvm_ethereum_v1, a, elf, input, oracle, limit),
        .rv32im_zkvm_ethereum_sha_v1 => try check(.rv32im_zkvm_ethereum_sha_v1, a, elf, input, oracle, limit),
        else => return error.UnsupportedEthereumBlockProfile,
    }
}
fn check(comptime profile: @import("isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32) !void {
    const Session = if (profile == .rv32im_zkvm_ethereum_sha_v1) runner.EthereumShaExecutionSession else runner.EthereumExecutionSession;
    const planned = try @import("prover/blake3_execution_preflight.zig").runEthereumForProfile(profile, a, elf, input, oracle, limit);
    var session = try Session.init(a, elf, .{ .input = input, .strict_completion = true, .stop_on_halt_flag = true, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var current = try session.startSegment(try planned.schedule.budget(0));
    var live = true;
    defer if (live) current.deinit();
    if (!std.meta.eql(planned.first, try endpoint(profile, a, &current.base, .entry))) return error.FirstEndpointMismatch;
    for (1..planned.schedule.segments) |i| {
        const continuation = current.base.continuation orelse return error.MissingContinuation;
        current.deinit();
        live = false;
        current = try session.resumeSegment(continuation, try planned.schedule.budget(@intCast(i)));
        live = true;
        if (current.base.global_first_cycle != try planned.schedule.firstCycle(@intCast(i))) return error.ReplayScheduleMismatch;
    }
    if (!current.base.isComplete() or !std.mem.eql(u8, current.base.output orelse return error.MissingOutput, oracle)) return error.OutputMismatch;
    if (!std.meta.eql(planned.last, try endpoint(profile, a, &current.base, .exit))) return error.LastEndpointMismatch;
    std.debug.print("PREFLIGHT_REPLAY verified=true proof=false cycles={d} segments={d} maximum_leaf_cycles={d} required_terminal_cycles={d} terminal_leaf_cycles={d}\n", .{ planned.last.cycle, planned.schedule.segments, limit, planned.required_terminal_cycles, try planned.schedule.budget(planned.schedule.segments - 1) });
}
fn endpoint(comptime profile: @import("isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, segment: *const @import("runner/result.zig").SegmentResult, side: @import("recursion/air/blake3_memory_snapshot.zig").Side) !statement.Endpoint {
    var io = try @import("prover/blake3_segment_public.zig").Owned.init(a, segment);
    defer io.deinit();
    var program = try @import("air/program/blake3_commitment.zig").buildDeclared(a, @import("air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = profile }, .{}, segment.rw_memory.program_words, null);
    defer program.deinit();
    io.data.program_root = program.root;
    const snapshot = @import("recursion/air/blake3_memory_snapshot.zig");
    var initial = try snapshot.fromSnapshot(a, &segment.rw_memory, .entry, .ordinary_boundary);
    defer initial.deinit();
    var final = try snapshot.fromSnapshot(a, &segment.rw_memory, .exit, .ordinary_boundary);
    defer final.deinit();
    io.data.initial_rw_root = initial.root;
    io.data.final_rw_root = final.root;
    return statement.captureEndpoint(a, segment, &io.data, side);
}
