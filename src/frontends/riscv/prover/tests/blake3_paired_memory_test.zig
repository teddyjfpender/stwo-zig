//! Paired root preservation and workload-independent untouched-memory cost.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const shared = @import("../blake3_shared_path_emit.zig");
const Discard = struct {
    pub fn append(_: *@This(), comptime Air: type, _: []const Air.Row) !void {}
};
test "paired memory rejects changes outside the admitted address union" {
    const a = std.testing.allocator;
    const before = [_]tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 } };
    const after = [_]tree.Leaf{ .{ .index = 0, .value = 3 }, .{ .index = 1, .value = 4 } };
    const hasher = tree.TreeHasher.init(.memory);
    const roots = [2]tree.Digest{ try hasher.root(&before), try hasher.root(&after) };
    const inputs = [_]shared.Input{.{ .address = 0, .caller = .{ .circuit = 1, .wire = 0 } }};
    var sink = Discard{};
    try std.testing.expectError(error.UnchangedMemorySubtreeMismatch, shared.emitPair(a, .{ &inputs, &inputs }, 100, roots, .{ &before, &after }, &sink));
    try std.testing.expectError(error.UnchangedMemoryRootMismatch, shared.emitPair(a, .{ &.{}, &.{} }, 100, roots, .{ &before, &after }, &sink));
    _ = try shared.emitPair(a, .{ &.{}, &.{} }, 100, .{ roots[0], roots[0] }, .{ &before, &before }, &sink);
}

test "paired memory resumed proof cost does not scale with untouched input" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00100137, 0x10012203, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    var previous_counts: ?@import("../blake3_commitment_columns.zig").Counts = null;
    for ([_]usize{ 16, 4096 }) |bytes| {
        var elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 16, .rv32im_zkvm_v1);
        declareInput(&elf, @intCast(bytes));
        const input = try a.alloc(u8, bytes);
        defer a.free(input);
        @memset(input, 0xa5);
        var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .input = input, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
        defer session.deinit();
        var first = try session.startSegment(1);
        defer first.deinit();
        var last = try session.resumeSegment(first.continuation.?, 100);
        defer last.deinit();
        var owner = try @import("../blake3_segment_execution.zig").Owner.initCompact(a, &last);
        defer owner.deinit();
        // The second segment has no public input claim; all original input
        // bytes are now ordinary memory, mostly hidden in unchanged subtrees.
        try std.testing.expectEqual(@as(usize, 0), owner.input.len);
        try std.testing.expect(last.rw_memory.words.len >= bytes / 4);
        try std.testing.expect(owner.plan.memories.len < 10);
        if (previous_counts) |counts| try std.testing.expectEqualDeep(counts, owner.hashes.counts);
        previous_counts = owner.hashes.counts;
        const Api = @import("../blake3_execution_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
        const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
        const pin = try owner.admission();
        const prepared = try Api.PreparedVerifier.initCompact(a, &owner.native.statement, pin, config, owner.native.compact_ranges.?.plan);
        defer prepared.deinit();
        const proved = try Api.proveCompact(a, owner.native, owner.hashes, pin, config);
        var verified = try Api.verifyPreparedCaptureOwned(a, proved.proof, prepared, prepared.id);
        defer verified.deinit();
        var arithmetic = try @import("../../recursion/air/blake3_execution_composition.zig").prepare(a, prepared, &verified, prepared.id);
        defer arithmetic.deinit();
        try arithmetic.validate(a, prepared, &verified, prepared.id);
    }
}
fn declareInput(elf: []u8, bytes: u32) void {
    const names = "\x00__text_start\x00__text_len\x00__input_start\x00__input_end\x00";
    @memcpy(elf[480..][0..names.len], names);
    std.mem.writeInt(u32, elf[308..312], names.len, .little);
    std.mem.writeInt(u32, elf[268..272], 5 * 16, .little);
    std.mem.writeInt(u32, elf[608..612], @intCast(std.mem.indexOf(u8, names, "__input_start").?), .little);
    std.mem.writeInt(u32, elf[612..616], 0x00100100, .little);
    std.mem.writeInt(u32, elf[624..628], @intCast(std.mem.indexOf(u8, names, "__input_end").?), .little);
    std.mem.writeInt(u32, elf[628..632], 0x00100100 + bytes, .little);
}
