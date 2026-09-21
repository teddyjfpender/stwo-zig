//! Exact native statement-authority preimage, shared with recursive hashing.
//! Emission authenticates neither the public scalars nor admitted geometry.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("statement_geometry.zig");
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
