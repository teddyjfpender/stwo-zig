//! Actual same-PC Keccak calls in distinct native windows. The second call
//! consumes the first call's output, so swapping their RAM payload is invalid
//! even though local control and pointer arguments coincide.
const std = @import("std");
pub const code = [_]u32{
    0x001002b7, // lui x5, 0x100
    0x10028293, // addi x5, x5, 256
    0x00200393, // addi x7, x0, 2
    @import("../../isa/custom0.zig").encodeKeccakf(5),
    0xfff38393, // addi x7, x7, -1
    0xfe039ce3, // bne x7, x0, -8
    0x00100137,
    0x00100193,
    0x02b00213,
    0x00412223,
    0x02312423,
    0x00312023,
    0x0000006f,
};
pub const cycles: u64 = 15;
pub const cuts = [_]u32{ 3, 3, 3, 6 };
pub const output: [43]u8 = blk: {
    var bytes: [43]u8 = @splat(0);
    bytes[32] = 1;
    break :blk bytes;
};
pub fn elf() @TypeOf(@import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1)) {
    var bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, value|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    return bytes;
}
test "Keccak two actual windows share control but have distinct chained RAM inputs" {
    const a = std.testing.allocator;
    const image = elf();
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &image, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true });
    defer session.deinit();
    var prefix = try session.startSegment(cuts[0]);
    defer prefix.deinit();
    var first = try session.resumeSegment(prefix.base.continuation.?, cuts[1]);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, cuts[2]);
    defer second.deinit();
    var suffix = try session.resumeSegment(second.base.continuation.?, cuts[3]);
    defer suffix.deinit();
    const x = first.extension.keccakf_calls.records()[0];
    const y = second.extension.keccakf_calls.records()[0];
    try std.testing.expectEqual(@as(usize, 1), first.extension.keccakf_calls.records().len);
    try std.testing.expectEqual(@as(usize, 1), second.extension.keccakf_calls.records().len);
    try std.testing.expectEqual(x.execution_clock, y.execution_clock);
    try std.testing.expectEqual(x.pc, y.pc);
    try std.testing.expectEqual(x.pointer_register, y.pointer_register);
    try std.testing.expectEqual(x.pointer_previous_clock, y.pointer_previous_clock);
    try std.testing.expectEqual(x.state_ptr, y.state_ptr);
    try std.testing.expectEqualSlices(u32, &x.output, &y.input);
    try std.testing.expect(!std.mem.eql(u32, &x.input, &y.input));
    try std.testing.expectEqual(.halt_flag, suffix.base.completion_reason);
    try std.testing.expectEqualSlices(u8, &output, suffix.base.output.?);
    try std.testing.expectEqual(cycles, prefix.base.cycle_count + first.base.cycle_count + second.base.cycle_count + suffix.base.cycle_count);
}
