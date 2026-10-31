const std = @import("std");
const core = @import("stwo_core");
const stream = @import("provider_interaction.zig");
const values = @import("values.zig");
const legacy = @import("../../../air/memory_commitment/poseidon2_air.zig");
const Relations = @import("../../../air/relation_challenges.zig").Relations;
fn failure(a: std.mem.Allocator, records: []const values.PermutationIO, relations: *const Relations) !void {
    var interaction = try stream.generate(a, records, 10, relations);
    defer interaction.deinit();
}
test "RV64 RAM provider streaming: exact old prefix bytes full capacity outputs and bounded allocation failures" {
    const a = std.testing.allocator;
    var recorder = values.Recorder{ .allocator = a };
    defer recorder.deinit();
    const words: [64]u64 = @splat(0xfedcba9876543210);
    _ = try values.hashValues(.chunk512, &words, &recorder);
    // Cross two complete inversion batches and a one-record tail. Repeated
    // valid IO tuples need no extra permutation execution.
    const original = recorder.calls.items[0..38].*;
    try recorder.calls.ensureTotalCapacity(a, 513);
    for (38..513) |i| recorder.calls.appendAssumeCapacity(original[i % 38]);
    const calls = try a.alloc(legacy.Call, recorder.calls.items.len);
    defer a.free(calls);
    const outputs = try a.alloc([16]u32, calls.len);
    defer a.free(outputs);
    for (calls, outputs, recorder.calls.items) |*call, *output, record| {
        call.* = .{ .input = undefined, .io = true };
        for (&call.input, output, record.input, record.output) |*in, *out, x, y| {
            in.* = x.toU32();
            out.* = y.toU32();
        }
    }
    var channel = @import("../protocol.zig").Channel{};
    channel.mixU32s(&.{0x12345678});
    const relations = try Relations.draw(a, &channel);
    var reference = try legacy.generateIoInteractionFromOutputs(a, calls, outputs, 10, &relations);
    defer reference.deinit(a);
    var actual = try stream.generate(a, recorder.calls.items, 10, &relations);
    defer actual.deinit();
    try std.testing.expectEqualDeep(reference.claims.sums, actual.claims);
    for (reference.columns, 0..) |column, i| try std.testing.expectEqualSlices(core.fields.m31.M31, column, actual.columns[i * 1024 ..][0..1024]);
    const saved = recorder.calls.items[0].output[15];
    recorder.calls.items[0].output[15] = saved.add(core.fields.m31.M31.one());
    var changed = try stream.generate(a, recorder.calls.items, 10, &relations);
    defer changed.deinit();
    try std.testing.expect(!changed.claims[1].eql(actual.claims[1]));
    recorder.calls.items[0].output[15] = saved;
    try std.testing.checkAllAllocationFailures(a, failure, .{ recorder.calls.items, &relations });
    var zero = relations;
    zero.poseidon2_io = @TypeOf(zero.poseidon2_io).init(core.fields.qm31.QM31.fromBase(recorder.calls.items[0].input[0]), core.fields.qm31.QM31.zero());
    try std.testing.expectError(error.ZeroDenominator, stream.generate(a, recorder.calls.items, 10, &zero));
}
