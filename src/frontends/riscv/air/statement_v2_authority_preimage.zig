//! Exact native statement-authority preimage, shared with recursive hashing.
//! Emission authenticates neither the public scalars nor admitted geometry.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("statement.zig");
const channel = @import("../recursion/poseidon2_channel.zig");
const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const DOMAIN: u32 = 0x5253_5632;
pub const HEADER_WORD_COUNT: usize = 22;
pub const DESCRIPTOR_WORD_COUNT: usize = 8;
pub const ValidationError = error{ InvalidComponentGeometry, NonCanonicalDigest };
pub const Error = ValidationError || error{InvalidNativeAuthorityPreimageLength};
pub const SpanScalar = enum { initial_pc, final_pc, cycle_count };
pub const GeometryField = enum { component_count, infra_count, kind, log_size, n_rows, n_columns };
pub const GeometryKind = enum { counts, component, infra };
pub const Source = union(enum) {
    protocol: u32,
    admitted_geometry: struct { kind: GeometryKind, index: u16, field: GeometryField, limb: u1, expected: u16 },
    /// PCs map to the corresponding SpanStatement u32 limb pair. Cycle count
    /// maps to executed_cycle_count's low pair with its upper pair zero.
    span_scalar: struct { field: SpanScalar, limb: u1 },
    wire_hash_digest: u3,
};
pub const Input = struct {
    initial_pc: u32,
    final_pc: u32,
    cycle_count: u32,
    wire_id: channel.Digest,
    component_descs: []const statement.FamilyComponentDesc,
    infra_descs: []const statement.InfraComponentDesc,

    pub fn validate(self: Input) ValidationError!void {
        if (self.component_descs.len > statement.MAX_COMPONENTS or self.infra_descs.len > statement.MAX_INFRA_COMPONENTS)
            return error.InvalidComponentGeometry;
        for (self.wire_id) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
    }
};

pub fn wordCount(component_count: usize, infra_count: usize) ValidationError!usize {
    if (component_count > statement.MAX_COMPONENTS or infra_count > statement.MAX_INFRA_COMPONENTS)
        return error.InvalidComponentGeometry;
    return HEADER_WORD_COUNT + DESCRIPTOR_WORD_COUNT * (component_count + infra_count);
}

/// Sink implements word(Source,u32) void. Unrestricted u32 scalars always
/// split into two u16 words; the wire digest remains eight canonical M31s.
pub fn emit(sink: anytype, input: Input) void {
    for ([_]u32{ FORMAT_VERSION, SCHEMA_VERSION }) |value| {
        sink.word(.{ .protocol = value }, value);
        sink.word(.{ .protocol = 0 }, 0);
    }
    geometry(sink, .counts, 0, .component_count, @intCast(input.component_descs.len));
    geometry(sink, .counts, 0, .infra_count, @intCast(input.infra_descs.len));
    for (std.enums.values(SpanScalar), [_]u32{ input.initial_pc, input.final_pc, input.cycle_count }) |field, value| {
        for (0..2) |limb| sink.word(.{ .span_scalar = .{ .field = field, .limb = @intCast(limb) } }, @as(u16, @truncate(value >> @as(u5, @intCast(16 * limb)))));
    }
    for (input.wire_id, 0..) |word, index| sink.word(.{ .wire_hash_digest = @intCast(index) }, word);
    for (input.component_descs, 0..) |desc, index| {
        geometry(sink, .component, @intCast(index), .kind, @intFromEnum(desc.family));
        descriptor(sink, .component, @intCast(index), desc);
    }
    for (input.infra_descs, 0..) |desc, index| {
        geometry(sink, .infra, @intCast(index), .kind, @intFromEnum(desc.kind));
        descriptor(sink, .infra, @intCast(index), desc);
    }
}

fn descriptor(sink: anytype, kind: GeometryKind, index: u16, desc: anytype) void {
    geometry(sink, kind, index, .log_size, desc.log_size);
    geometry(sink, kind, index, .n_rows, desc.n_rows);
    geometry(sink, kind, index, .n_columns, desc.n_columns);
}
fn geometry(sink: anytype, kind: GeometryKind, index: u16, field: GeometryField, value: u32) void {
    for (0..2) |limb| {
        const word: u16 = @truncate(value >> @as(u5, @intCast(16 * limb)));
        sink.word(.{ .admitted_geometry = .{ .kind = kind, .index = index, .field = field, .limb = @intCast(limb), .expected = word } }, word);
    }
}

pub fn write(input: Input, destination: []u32) Error!void {
    try input.validate();
    if (destination.len != try wordCount(input.component_descs.len, input.infra_descs.len)) return error.InvalidNativeAuthorityPreimageLength;
    var sink = WordSink{ .words = destination };
    emit(&sink, input);
    std.debug.assert(sink.at == destination.len);
}

pub fn hash(input: Input) ValidationError!channel.Digest {
    try input.validate();
    var sink = HashSink{ .hasher = channel.CanonicalWordHasher.init(DOMAIN) };
    emit(&sink, input);
    return sink.hasher.finalize();
}
const WordSink = struct {
    words: []u32,
    at: usize = 0,
    pub fn word(self: *WordSink, _: Source, value: u32) void {
        self.words[self.at] = value;
        self.at += 1;
    }
};
const HashSink = struct {
    hasher: channel.CanonicalWordHasher,
    pub fn word(self: *HashSink, _: Source, value: u32) void {
        self.hasher.update(&.{M31.fromCanonical(value)});
    }
};

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
    const support = @import("public_data_v2_test_support.zig");
    const native = @import("statement_v2.zig");
    const public_data = @import("public_data_v2.zig");
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
