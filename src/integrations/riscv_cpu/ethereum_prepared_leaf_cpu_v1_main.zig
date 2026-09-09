//! Narrow entrypoint for the shared prepared CPU leaf command.
const std = @import("std");
const replay = @import("stwo_riscv_cpu_integration").ethereum_incremental_full_leaf_replay_command_v4;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const options = if (arguments.len > 1 and std.mem.eql(u8, arguments[1], replay.prepared_cpu_command_name)) arguments[2..] else arguments[1..];
    try replay.runPreparedCpu(allocator, options);
}
