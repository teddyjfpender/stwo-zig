//! Public one-shot and resumable entry points for the combined Ethereum profile.

const std = @import("std");
const result_mod = @import("result.zig");
const segment_session = @import("segment_session.zig");

pub const RunResult = result_mod.EthereumRunResult;
pub const SegmentResult = result_mod.EthereumSegmentResult;
pub const ExecutionSession = segment_session.ExecutionSession(.rv32im_zkvm_ethereum_v1);

pub fn run(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
) !RunResult {
    return runConfigured(allocator, elf_bytes, &.{}, max_steps, false, false);
}

pub fn runWithInput(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    max_steps: usize,
) !RunResult {
    return runConfigured(allocator, elf_bytes, input, max_steps, true, true);
}

fn runConfigured(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    max_steps: usize,
    stop_on_halt_flag: bool,
    strict_completion: bool,
) !RunResult {
    var session = try ExecutionSession.initLegacy(allocator, elf_bytes, .{
        .input = input,
        .stop_on_halt_flag = stop_on_halt_flag,
        .strict_completion = strict_completion,
    });
    defer session.deinit();
    return session.runLegacy(max_steps);
}
