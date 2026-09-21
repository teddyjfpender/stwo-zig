//! Native and verifier preimage compatibility checks.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("air/statement_geometry.zig");
const channel = @import("recursion/poseidon2_channel.zig");
const owner = @import("air/statement_v2_authority_preimage.zig");
const Input = owner.Input;
const write = owner.write;
const hash = owner.hash;
const DOMAIN = owner.DOMAIN;

test "native authority preimage preserves legacy split encoding and hash" {
    const components = [_]statement.FamilyComponentDesc{.{ .family = @enumFromInt(0), .log_size = 19, .n_rows = 0x1234_abcd, .n_columns = 10 }};
    const infra = [_]statement.InfraComponentDesc{.{ .kind = .memory, .log_size = 20, .n_rows = 0x8000_ffff, .n_columns = 8 }};
    const input = Input{ .initial_pc = 0x8000_1234, .final_pc = 0xfedc_5678, .cycle_count = 0xffff_0001, .wire_id = .{ 1, 2, 3, 4, 5, 6, 7, core.fields.m31.Modulus - 1 }, .component_descs = &components, .infra_descs = &infra };
    var words: [38]u32 = undefined;
    try write(input, &words);
    const expected = [_]u32{ 2, 0, 1, 0, 1, 0, 1, 0, 0x1234, 0x8000, 0x5678, 0xfedc, 1, 0xffff, 1, 2, 3, 4, 5, 6, 7, core.fields.m31.Modulus - 1, 0, 0, 19, 0, 0xabcd, 0x1234, 10, 0, @intFromEnum(statement.InfraKind.memory), 0, 20, 0, 0xffff, 0x8000, 8, 0 };
    try std.testing.expectEqualSlices(u32, &expected, &words);
    try std.testing.expectEqual(channel.hashCanonicalU32s(&expected, DOMAIN), try hash(input));
    try std.testing.expectError(error.InvalidNativeAuthorityPreimageLength, write(input, words[0..37]));
}

test "native authority preimage matches native adjacent statement authorities" {
    const support = @import("air/public_data_v2_test_support.zig");
    const native = @import("air/statement_v2.zig");
    const public_data = @import("air/public_data_v2.zig");
    const fixture = try support.Fixture.init();
    const components = [_]statement.FamilyComponentDesc{.{ .family = @enumFromInt(0), .log_size = 4, .n_rows = 2, .n_columns = 10 }};
    const infra = [_]statement.InfraComponentDesc{.{ .kind = .memory, .log_size = 4, .n_rows = 4, .n_columns = 8 }};
    const sources = .{ fixture.leftSource(), fixture.rightSource() };
    inline for (sources) |source| {
        const words = try support.encode(std.testing.allocator, &source);
        defer std.testing.allocator.free(words);
        const data = try public_data.PublicDataV2.authenticate(words);
        const core_public = try native.canonicalCorePublicData(&data);
        const input = Input{ .initial_pc = core_public.initial_pc, .final_pc = core_public.final_pc, .cycle_count = core_public.clock, .wire_id = data.wireId(), .component_descs = &components, .infra_descs = &infra };
        // Independent copy of the old encoding, including its unsplit digest.
        var expected: [38]u32 = undefined;
        for ([_]u32{ 2, 1, 1, 1, core_public.initial_pc, core_public.final_pc, core_public.clock }, 0..) |value, index| {
            expected[2 * index] = value & 65535;
            expected[2 * index + 1] = value >> 16;
        }
        @memcpy(expected[14..22], &data.wireId());
        for ([_]u32{ 0, 4, 2, 10, @intFromEnum(statement.InfraKind.memory), 4, 4, 8 }, 0..) |value, index| {
            expected[22 + 2 * index] = value & 65535;
            expected[23 + 2 * index] = value >> 16;
        }
        const digest = channel.hashCanonicalU32s(&expected, DOMAIN);
        try std.testing.expectEqual(digest, try hash(input));
        try std.testing.expectEqual(digest, try native.authorityIdentityFromGeometry(&data, &components, &infra));
    }
}
