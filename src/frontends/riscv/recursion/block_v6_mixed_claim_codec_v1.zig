//! Bounded claim-only metadata. Decode grants no proof or global authority;
//! reconstruct original Values from independent admissions before root verify.
const std = @import("std");
const Types = @import("block_v6_mixed_claim_types_v1.zig");
const Scalars = @import("block_v6_mixed_claim_scalars_v1.zig");
const Wire = @import("../prover/guest_precompile/proof_artifact_wire.zig");
const Writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer;
pub const Record = Types.Record;
pub const Claim = Types.Claim;
pub const Family = Types.Family;
pub const Limits = Types.Limits;
pub const VERSION: u32 = 1;
pub const MAGIC = "B6MCLAIM";
pub const HEADER_BYTES = MAGIC.len + 4 + 32 + 32 + 4;
pub fn schemaId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/mixed-original-claims/v1;");
    inline for (std.meta.fields(Family)) |field| {
        hash.update(field.name ++ std.fmt.comptimePrint("={d};", .{field.value}));
        Scalars.schema(Types.Payload(@enumFromInt(field.value)), &hash);
    }
    return hash.finalResult();
}
pub const Decoded = struct {
    allocator: std.mem.Allocator,
    records: []Record,
    pub fn deinit(self: *Decoded) void {
        for (self.records) |record| switch (record.claim) {
            inline else => |value| Scalars.free(self.allocator, value),
        };
        self.allocator.free(self.records);
        self.* = undefined;
    }
};
fn requireLimits(limits: Limits) !void {
    if (limits.max_bytes < HEADER_BYTES or limits.max_owned_bytes == 0 or limits.max_slice_elements == 0 or limits.max_slice_elements > std.math.maxInt(u32)) return error.InvalidMixedClaimLimits;
}
pub fn encode(a: std.mem.Allocator, records: []const Record, expected: []const Types.Bus.Expected, limits: Limits) ![]u8 {
    var writer = Writer.init(a, limits.max_bytes);
    defer writer.deinit();
    try writeTo(&writer, records, expected, limits);
    return writer.toOwnedSlice();
}
fn writeTo(writer: anytype, records: []const Record, expected: []const Types.Bus.Expected, limits: Limits) !void {
    try requireLimits(limits);
    if (records.len != expected.len) return error.UntrustedMixedClaimRoster;
    const roster = try Types.Bus.rosterDigest(expected);
    try writer.writeAll(MAGIC);
    try Wire.writeInt(writer, u32, VERSION);
    try writer.writeAll(&schemaId());
    try writer.writeAll(&roster);
    try Wire.writeInt(writer, u32, @intCast(records.len));
    for (records, expected) |record, pin| {
        try Types.require(record, pin);
        try Wire.writeInt(writer, u32, @intFromEnum(std.meta.activeTag(record.claim)));
        try Wire.writeInt(writer, u32, record.index);
        switch (record.claim) {
            inline else => |value| try Scalars.write(writer, value, limits),
        }
    }
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, expected: []const Types.Bus.Expected, limits: Limits) !Decoded {
    try requireLimits(limits);
    if (bytes.len > limits.max_bytes) return error.MixedClaimResourceLimit;
    const roster = try Types.Bus.rosterDigest(expected);
    var reader = Scalars.Reader{ .a = a, .cursor = Wire.Cursor.init(bytes), .limits = limits };
    if (!std.mem.eql(u8, try reader.cursor.take(MAGIC.len), MAGIC) or try reader.cursor.readInt(u32) != VERSION or
        !std.mem.eql(u8, try reader.cursor.take(32), &schemaId()) or !std.mem.eql(u8, try reader.cursor.take(32), &roster)) return error.UntrustedMixedClaimHeader;
    const count = try reader.cursor.readInt(u32);
    if (count != expected.len or count > Types.Bus.MAX_CHILDREN) return error.UntrustedMixedClaimRoster;
    reader.owned = try std.math.mul(usize, count, @sizeOf(Record));
    if (reader.owned > limits.max_owned_bytes or try std.math.mul(usize, count, 8) > bytes.len - reader.cursor.position) return error.MixedClaimResourceLimit;
    const records = try a.alloc(Record, count);
    var initialized: usize = 0;
    errdefer {
        for (records[0..initialized]) |record| switch (record.claim) {
            inline else => |value| Scalars.free(a, value),
        };
        a.free(records);
    }
    for (records, expected) |*record, pin| {
        const tag = try reader.cursor.readKnownEnum(Family);
        const index = try reader.cursor.readInt(u32);
        const label = Types.label(pin);
        if (label.family != tag or label.index != index) return error.UntrustedMixedClaimRoster;
        record.* = .{ .index = index, .claim = switch (tag) {
            inline else => |family| @unionInit(Claim, @tagName(family), try reader.read(Types.Payload(family))),
        } };
        initialized += 1;
    }
    if (reader.cursor.position != bytes.len) return error.TrailingMixedClaimBytes;
    // A canonical, fixed-width re-encoding is an inexpensive exact format gate.
    var canonical = CompareWriter{ .bytes = bytes };
    try writeTo(&canonical, records, expected, limits);
    if (canonical.position != bytes.len) return error.NoncanonicalMixedClaimBytes;
    return .{ .allocator = a, .records = records };
}

/// Exact re-encoding comparison streams over existing bytes, avoiding another
/// metadata-sized allocation during hostile input admission.
const CompareWriter = struct {
    bytes: []const u8,
    position: usize = 0,
    pub fn writeAll(self: *@This(), value: []const u8) !void {
        if (value.len > self.bytes.len - self.position or !std.mem.eql(u8, value, self.bytes[self.position..][0..value.len])) return error.NoncanonicalMixedClaimBytes;
        self.position += value.len;
    }
    pub fn writeClaim(self: *@This(), value: @import("stwo_core").fields.qm31.QM31) !void {
        var raw: [16]u8 = undefined;
        for (value.toM31Array(), 0..) |limb, i| {
            if (limb.v >= @import("stwo_core").fields.m31.Modulus) return error.NonCanonicalM31;
            std.mem.writeInt(u32, raw[i * 4 ..][0..4], limb.v, .little);
        }
        try self.writeAll(&raw);
    }
};
