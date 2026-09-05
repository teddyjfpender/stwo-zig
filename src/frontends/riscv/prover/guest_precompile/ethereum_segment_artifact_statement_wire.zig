//! Canonical codec for the native SegmentV2 statement inside Ethereum v3.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const public_data_v2 = @import("../../air/public_data_v2.zig");
const statement = @import("../../air/statement.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const segment_v2 = @import("../../recursion/segment_statement_v2.zig");
const base_wire = @import("proof_artifact_wire.zig");

pub const schema_version: u16 = 1;

pub const Owned = struct {
    value: statement_v2.RiscVStatementV2,
    canonical_words: []M31,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.canonical_words);
        self.* = undefined;
    }
};

/// Independent cold-boundary owner whose canonical words are reachable only
/// through the immutable PublicDataV2 lease.  Unlike `Owned`, this type does
/// not expose a mutable slice and therefore permits allocation-free cached
/// authentication during all later verifier transcript passes.
pub const RetainedOwned = struct {
    value: statement_v2.RiscVStatementV2,
    lease: public_data_v2.PublicDataV2.OwnedValidatedLeaseV2,

    pub fn deinit(self: *RetainedOwned) void {
        self.lease.deinit();
        self.* = undefined;
    }
};

pub fn encode(
    writer: anytype,
    value: *const statement_v2.RiscVStatementV2,
    max_section_bytes: usize,
) !void {
    try value.validate();
    const core = &value.core;
    if (core.n_components > statement.MAX_COMPONENTS or
        core.n_infra > statement.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidComponentCount;
    }
    const words = value.public_data.words();
    try validateWordCount(words.len, max_section_bytes);
    try base_wire.writeInt(writer, u16, schema_version);
    try encodeCoreGeometry(writer, core);
    try base_wire.writeInt(writer, u32, @intCast(words.len));
    for (words) |word|
        try base_wire.writeInt(writer, u32, word.toU32());
    for (value.authority_id) |word|
        try base_wire.writeInt(writer, u32, word);
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_section_bytes: usize,
) !Owned {
    var raw = try decodeRaw(allocator, bytes, max_section_bytes);
    errdefer allocator.free(raw.words);
    const public_data = try public_data_v2.PublicDataV2.authenticate(raw.words);
    raw.core.public_data = try statement_v2.canonicalCorePublicData(&public_data);
    const value = try statement_v2.RiscVStatementV2.init(raw.core, public_data);
    if (!std.meta.eql(value.authority_id, raw.authority_id))
        return error.StatementAuthorityMismatch;
    try value.validate();
    return .{ .value = value, .canonical_words = raw.words };
}

/// Decode at an independent cold trust boundary using snapshot authorities
/// already authenticated by STWESG31.  The returned process-local lease owns
/// the words and is consumed by the fresh verifier; no digest can mint it.
pub fn decodeWithRetainedLease(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_section_bytes: usize,
    retained: public_data_v2.PublicDataV2.RetainedSnapshots,
    counters: ?*public_data_v2.PublicDataV2.ValidationCountersV2,
) !RetainedOwned {
    var raw = try decodeRaw(allocator, bytes, max_section_bytes);
    var words_owned = true;
    errdefer if (words_owned) allocator.free(raw.words);
    var lease = try public_data_v2.PublicDataV2.OwnedValidatedLeaseV2
        .adoptRetained(allocator, raw.words, retained, counters);
    words_owned = false;
    errdefer lease.deinit();
    raw.core.public_data = try statement_v2.canonicalCorePublicData(lease.data());
    const value = try statement_v2.RiscVStatementV2.init(
        raw.core,
        lease.data().*,
    );
    if (!std.meta.eql(value.authority_id, raw.authority_id))
        return error.StatementAuthorityMismatch;
    try value.validate();
    return .{ .value = value, .lease = lease };
}

const RawDecoded = struct {
    core: statement.RiscVStatement,
    words: []M31,
    authority_id: segment_v2.Digest,
};

fn decodeRaw(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_section_bytes: usize,
) !RawDecoded {
    if (bytes.len > max_section_bytes) return error.StatementResourceLimitExceeded;
    var cursor = base_wire.Cursor.init(bytes);
    if (try cursor.readInt(u16) != schema_version)
        return error.UnsupportedStatementVersion;
    const core = try decodeCoreGeometry(&cursor);
    const word_count = try cursor.readCount();
    try validateWordCount(word_count, max_section_bytes);
    const words = try allocator.alloc(M31, word_count);
    errdefer allocator.free(words);
    for (words) |*word| {
        const raw = try cursor.readInt(u32);
        if (raw >= m31.Modulus) return error.NonCanonicalM31;
        word.* = M31.fromCanonical(raw);
    }
    var authority_id: segment_v2.Digest = undefined;
    for (&authority_id) |*word| {
        word.* = try cursor.readInt(u32);
        if (word.* >= m31.Modulus) return error.NonCanonicalDigest;
    }
    try cursor.requireDone();
    return .{ .core = core, .words = words, .authority_id = authority_id };
}

fn encodeCoreGeometry(writer: anytype, core: *const statement.RiscVStatement) !void {
    try base_wire.writeInt(writer, u32, core.n_components);
    for (core.component_descs[0..core.n_components]) |descriptor| {
        try writeEnum(writer, descriptor.family);
        try base_wire.writeInt(writer, u32, descriptor.log_size);
        try base_wire.writeInt(writer, u32, descriptor.n_rows);
        try base_wire.writeInt(writer, u32, descriptor.n_columns);
    }
    try base_wire.writeInt(writer, u32, core.initial_pc);
    try base_wire.writeInt(writer, u32, core.final_pc);
    try base_wire.writeInt(writer, u32, core.total_steps);
    try base_wire.writeInt(writer, u32, core.n_infra);
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        try writeEnum(writer, descriptor.kind);
        try base_wire.writeInt(writer, u32, descriptor.log_size);
        try base_wire.writeInt(writer, u32, descriptor.n_rows);
        try base_wire.writeInt(writer, u32, descriptor.n_columns);
    }
}

fn decodeCoreGeometry(cursor: *base_wire.Cursor) !statement.RiscVStatement {
    var core: statement.RiscVStatement = undefined;
    core.initializeDescriptorStorage();
    core.n_components = try cursor.readInt(u32);
    if (core.n_components > statement.MAX_COMPONENTS)
        return error.InvalidComponentCount;
    for (core.component_descs[0..core.n_components]) |*descriptor| {
        descriptor.* = .{
            .family = try cursor.readKnownEnum(@TypeOf(descriptor.family)),
            .log_size = try cursor.readInt(u32),
            .n_rows = try cursor.readInt(u32),
            .n_columns = try cursor.readInt(u32),
        };
    }
    core.initial_pc = try cursor.readInt(u32);
    core.final_pc = try cursor.readInt(u32);
    core.total_steps = try cursor.readInt(u32);
    core.n_infra = try cursor.readInt(u32);
    if (core.n_infra > statement.MAX_INFRA_COMPONENTS)
        return error.InvalidInfrastructureCount;
    for (core.infra_descs[0..core.n_infra]) |*descriptor| {
        descriptor.* = .{
            .kind = try cursor.readKnownEnum(statement.InfraKind),
            .log_size = try cursor.readInt(u32),
            .n_rows = try cursor.readInt(u32),
            .n_columns = try cursor.readInt(u32),
        };
    }
    return core;
}

fn validateWordCount(count: usize, max_section_bytes: usize) !void {
    if (count < segment_v2.MIN_CANONICAL_WORDS)
        return error.InvalidCanonicalWordCount;
    const bytes = std.math.mul(usize, count, @sizeOf(u32)) catch
        return error.StatementResourceLimitExceeded;
    if (bytes > max_section_bytes) return error.StatementResourceLimitExceeded;
}

fn writeEnum(writer: anytype, value: anytype) !void {
    const T = @TypeOf(value);
    const Tag = @typeInfo(T).@"enum".tag_type;
    try base_wire.writeInt(writer, Tag, @intFromEnum(value));
}

test "segment V2 statement geometry cold decode owns canonical inactive descriptors" {
    const allocator = std.testing.allocator;
    var core: statement.RiscVStatement = undefined;
    core.initializeDescriptorStorage();
    core.n_components = 1;
    core.component_descs[0] = .{
        .family = .branch_eq,
        .log_size = 4,
        .n_rows = 3,
        .n_columns = 8,
    };
    core.initial_pc = 0x1000;
    core.final_pc = 0x1004;
    core.total_steps = 3;
    core.n_infra = 1;
    core.infra_descs[0] = .{
        .kind = .memory,
        .log_size = 4,
        .n_rows = 2,
        .n_columns = 8,
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encodeCoreGeometry(encoded.writer(allocator), &core);
    var cursor = base_wire.Cursor.init(encoded.items);
    const decoded = try decodeCoreGeometry(&cursor);
    try cursor.requireDone();

    try std.testing.expectEqualDeep(core.component_descs, decoded.component_descs);
    try std.testing.expectEqualDeep(core.infra_descs, decoded.infra_descs);
    try std.testing.expectEqual(core.initial_pc, decoded.initial_pc);
    try std.testing.expectEqual(core.final_pc, decoded.final_pc);
    try std.testing.expectEqual(core.total_steps, decoded.total_steps);
}
