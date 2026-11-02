const std = @import("std");
const core = @import("stwo_core");
const base = @import("../setup.zig");
const service = @import("../service.zig");
const compact = @import("../compact.zig");
const profile = @import("../../../execution_profile.zig");
const isa = @import("../../../decode.zig");
const L = @import("../../layout.zig");
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
fn make(allocator: std.mem.Allocator) !void {
    const words = [_]u32{ 0x00000013, 0x00000073, 0x00100073 };
    const program = base.Program{ .base = 0x100001000, .words = &words };
    var ordinary = try base.Setup.init(allocator, program);
    defer ordinary.deinit();
    var admitted = try service.init(allocator, program);
    defer admitted.deinit();
    try std.testing.expect(!std.mem.eql(u8, &ordinary.identity, &admitted.identity));
    const H = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
    var identity_hash = H.init(.{});
    identity_hash.update(service.DOMAIN);
    identity_hash.update(&ordinary.identity);
    var expected_identity: [32]u8 = undefined;
    identity_hash.final(&expected_identity);
    try std.testing.expectEqualSlices(u8, &expected_identity, &admitted.identity);
    for (words, admitted.rows, admitted.decoded, 0..) |raw, actual, entry, i| {
        try std.testing.expectEqualDeep(service.deriveRow(program.pc(i), raw), actual);
        try std.testing.expectEqual(raw, entry.raw);
        if (!actual[base.field.valid].isZero()) {
            try std.testing.expectEqualDeep(try profile.decode(.keccak_service_v1, raw), entry.instruction);
            for (entry.enabled, 0..) |enabled, slot| try std.testing.expectEqual(!actual[base.field.slots + slot].isZero(), enabled);
        }
    }
    try std.testing.expectError(error.InvalidRv64RomExecution, ordinary.lookup(program.pc(1)));
    try std.testing.expectEqual(@as(usize, 1), try admitted.lookup(program.pc(1)));
    try std.testing.expectError(error.InvalidRv64RomExecution, admitted.lookup(program.pc(2)));
    try std.testing.expectEqualDeep(ordinary.rows[0], admitted.rows[0]);
    const row = admitted.rows[1];
    const tuple = compact.fromRow(&row);
    var selectors: [65]Q = @splat(Q.zero());
    selectors[@intFromEnum(isa.Opcode.ECALL)] = Q.one();
    const fixed = compact.inflateFixed(&tuple, &selectors);
    try std.testing.expectEqual(@as(u32, profile.POINTER_REGISTER), row[base.field.rs1].v);
    try std.testing.expectEqual(@as(u32, profile.TAG_REGISTER), row[base.field.rs2].v);
    try std.testing.expect(fixed[L.fixed.slot_start].eql(Q.one()));
    try std.testing.expect(fixed[L.fixed.slot_start + 1].eql(Q.one()));
    try std.testing.expect(fixed[L.fixed.slot_start + 2].isZero());
    try std.testing.expect(fixed[L.fixed.slot_start + 3].isZero());
    try std.testing.expect(fixed[L.fixed.word_start + @intFromEnum(L.Word.a)].eql(Q.one()));
    try std.testing.expect(fixed[L.fixed.word_start + @intFromEnum(L.Word.b)].eql(Q.one()));
    try std.testing.expect(fixed[L.fixed.word_start + @intFromEnum(L.Word.result)].isZero());
    const decoded = try profile.decode(.keccak_service_v1, words[1]);
    try std.testing.expectEqual(profile.POINTER_REGISTER, decoded.rs1);
    try std.testing.expectEqual(profile.TAG_REGISTER, decoded.rs2);
    try std.testing.expect(profile.effects(.keccak_service_v1, .ECALL).reads_rs1);
    try std.testing.expect(!profile.effects(.rv64im, .ECALL).reads_rs1);
}
test "Service ROM: immutable ABI identity, full-width PC, explicit register reads and no implicit RAM slot" {
    try make(a);
    try std.testing.checkAllAllocationFailures(a, make, .{});
}
