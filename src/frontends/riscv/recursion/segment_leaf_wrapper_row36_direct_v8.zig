//! Dormant physical row-36 writer for the V8 Statement AIR.
//!
//! Its fixed ordinal schedule is verifier-owned and independent of the leaf's
//! wire count. The dynamic row values and fan-out come from the admitted
//! native Statement source and the existing V6 consumer schedule. A verifier
//! derives the public wire count from authenticated SegmentV2 data. This file
//! does not activate a wrapper proof; the enclosing circuit must use that same
//! verifier-owned parameter when evaluating every row.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const air = @import("air/segment_leaf_statement_source_direct_v8.zig");
const v6 = @import("air/segment_leaf_statement_source_direct_v6.zig");
const framework = @import("air/framework_interaction.zig");
const universal = @import("air/universal_challenges.zig");
const relation_interaction = @import("air/relation_interaction.zig");
const boundary = @import("segment_leaf_statement_contract_v2.zig");
const PublicDataV2 = @import("../air/public_data_v2.zig").PublicDataV2;
const link_mod = @import("ethereum_leaf_link_program_v3.zig");
const child_mod = @import("ethereum_leaf_child_field_program_v1.zig");
const native = @import("segment_leaf_outer_air_v2.zig").Statement;

pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const FixedKey = struct {
    semantic_digest: [32]u8,
    log_size: u32,
    column_digest: [32]u8,

    pub fn compile(allocator: std.mem.Allocator) !FixedKey {
        var definition = try air.build(allocator);
        defer definition.deinit();
        _ = try air.authenticate(&definition);
        return .{
            .semantic_digest = air.SEMANTIC_DIGEST,
            .log_size = air.LOG_SIZE,
            .column_digest = ordinalDigest(),
        };
    }

    pub fn validate(self: *const FixedKey) !void {
        if (!std.meta.eql(self.semantic_digest, air.SEMANTIC_DIGEST) or
            self.log_size != air.LOG_SIZE or
            !std.meta.eql(self.column_digest, ordinalDigest()))
            return error.InvalidV8StatementFixedKey;
    }
};

pub const Claim = struct {
    total: QM31,
    audit: relation_interaction.DomainAudit,
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    key: FixedKey,
    /// This is the public AIR parameter supplied by the verifier boundary.
    wire_count: u32,
    rows: []air.Row,
    rows_digest: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        key: *const FixedKey,
        expected: *const PublicDataV2,
        admitted_manifest: *const boundary.ManifestV2,
        link: *const link_mod.ProgramV3,
        child: *const child_mod.ProgramV1,
        native_rows: []const native.Row,
        fanout: *const v6.Schedule,
    ) !Writer {
        const verifier_count = try air.VerifierWireCount.derive(expected, admitted_manifest);
        const view = try expected.authenticatedView();
        if (native_rows.len < view.words.len) return error.InvalidV8StatementSourceShape;
        for (native_rows[0..view.words.len], view.words) |source_row, word|
            if (!source_row[0].eql(word)) return error.V8StatementWireSourceMismatch;
        return initForKnownCount(allocator, key, verifier_count.parameters()[0].toU32(), link, child, native_rows, fanout);
    }

    /// Unit-test row math only. Production callers cannot supply a raw count.
    fn initForKnownCount(
        allocator: std.mem.Allocator,
        key: *const FixedKey,
        wire_count: u32,
        link: *const link_mod.ProgramV3,
        child: *const child_mod.ProgramV1,
        native_rows: []const native.Row,
        fanout: *const v6.Schedule,
    ) !Writer {
        try key.validate();
        if (wire_count < air.MIN_WIRE_WORDS or wire_count > air.MAX_WIRE_WORDS or
            native_rows.len != @as(usize, wire_count) + boundary.CONTEXT_WORD_COUNT)
            return error.InvalidV8StatementSourceShape;
        try fanout.validateAgainst(link, child, native_rows);
        if (fanout.rows.len != native_rows.len) return error.InvalidV8StatementSourceShape;

        const rows = try allocator.alloc(air.Row, air.CAPACITY);
        errdefer allocator.free(rows);
        for (rows, 0..) |*out, ordinal| {
            var value = M31.zero();
            var extra: u32 = 0;
            if (ordinal < native_rows.len) {
                const source_row = native_rows[ordinal];
                const scheduled = fanout.rows[ordinal];
                const wire = ordinal < wire_count;
                const scope = if (wire) boundary.WIRE_SCOPE else boundary.CONTEXT_SCOPE;
                const index: u32 = @intCast(if (wire) ordinal else ordinal - wire_count);
                if (source_row[1].toU32() != 1 or
                    source_row[2].toU32() != scope or
                    source_row[3].toU32() != index or
                    !source_row[0].eql(scheduled[0]) or
                    scheduled[1].toU32() != 1 or
                    scheduled[3].toU32() != scope or
                    scheduled[4].toU32() != index)
                    return error.InvalidV8StatementSourceOrder;
                value = source_row[0];
                extra = scheduled[2].toU32();
            }
            out.* = try air.logicalRow(ordinal, wire_count, value, extra);
            if (out[air.PHYSICAL_MAIN_COLUMN_COUNT + air.PREPROCESSED_COLUMN_COUNT].toU32() != wire_count)
                return error.NonuniformV8StatementParameter;
        }
        return .{ .allocator = allocator, .key = key.*, .wire_count = wire_count, .rows = rows, .rows_digest = digestRows(rows) };
    }

    pub fn deinit(self: *Writer) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn fillPreprocessed(self: *const Writer, columns: [][]M31) !void {
        try self.key.validate();
        try checkColumns(columns, air.PREPROCESSED_COLUMN_COUNT);
        try air.writePreprocessed(columns[0]);
        if (!std.meta.eql(self.key.column_digest, digestColumn(columns[0])))
            return error.InvalidV8StatementFixedColumn;
    }

    pub fn fillMain(self: *const Writer, columns: [][]M31) !void {
        try self.key.validate();
        try self.validateRows();
        try checkColumns(columns, air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (self.rows, 0..) |row, logical| {
            const committed = framework.committedRow(logical, air.LOG_SIZE);
            for (columns, 0..) |column, i| column[committed] = row[i];
        }
    }

    pub fn fillInteraction(self: *const Writer, relations: *const universal.UniversalRelations, columns: [][]M31) !Claim {
        try self.key.validate();
        try self.validateRows();
        try relations.validate();
        try checkColumns(columns, air.INTERACTION_COLUMN_COUNT);
        var definition = try air.build(self.allocator);
        defer definition.deinit();
        const authenticated = try air.authenticate(&definition);
        var generated = try authenticated.generateInteraction(
            self.allocator,
            &definition.arena,
            air.SEMANTIC_DIGEST,
            .{definition.event},
            self.rows,
            air.LOG_SIZE,
            relations,
        );
        defer generated.deinit(self.allocator);
        if (generated.columns.len != columns.len) return error.InvalidV8StatementColumns;
        const total = generated.claims.total();
        const audit = try authenticated.auditPreparedDomainSums(self.allocator, self.rows, relations, total);
        for (generated.columns, columns) |from, to| {
            if (from.len != to.len) return error.InvalidV8StatementColumns;
            @memcpy(to, from);
        }
        return .{ .total = total, .audit = audit };
    }

    fn validateRows(self: *const Writer) !void {
        if (self.rows.len != air.CAPACITY or !std.meta.eql(self.rows_digest, digestRows(self.rows)))
            return error.InvalidV8StatementRows;
        for (self.rows, 0..) |row, ordinal| {
            const expected = try air.logicalRow(ordinal, self.wire_count, row[0], row[3].toU32());
            if (!std.meta.eql(row, expected)) return error.InvalidV8StatementRows;
        }
    }
};

fn checkColumns(columns: [][]M31, expected: usize) !void {
    if (columns.len != expected) return error.InvalidV8StatementColumns;
    for (columns) |column| {
        if (column.len != air.CAPACITY) return error.InvalidV8StatementColumns;
        for (column) |value| if (!value.isZero()) return error.V8StatementDestinationNotFresh;
    }
}

fn ordinalDigest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv-v8-statement-fixed-ordinal\x00");
    hash.update(&air.SEMANTIC_DIGEST);
    var size: [4]u8 = undefined;
    std.mem.writeInt(u32, &size, air.LOG_SIZE, .little);
    hash.update(&size);
    for (0..air.CAPACITY) |committed| {
        const ordinal = framework.committedRow(committed, air.LOG_SIZE);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(ordinal), .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}

fn digestColumn(column: []const M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv-v8-statement-fixed-ordinal\x00");
    hash.update(&air.SEMANTIC_DIGEST);
    var size: [4]u8 = undefined;
    std.mem.writeInt(u32, &size, air.LOG_SIZE, .little);
    hash.update(&size);
    for (column) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word.toU32(), .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}

fn digestRows(rows: []const air.Row) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv-v8-statement-physical-rows\x00");
    hash.update(&air.SEMANTIC_DIGEST);
    for (rows) |row| for (row) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word.toU32(), .little);
        hash.update(&bytes);
    };
    return hash.finalResult();
}

test "V8 row36 physical writer has one fixed key across distinct wire counts" {
    const allocator = std.testing.allocator;
    const fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    var link = try link_mod.ProgramV3.init(allocator);
    defer link.deinit();
    var child = try child_mod.ProgramV1.initWithNativeProgramBridge(allocator, &fixture.components, &fixture.infra);
    defer child.deinit();
    const key = try FixedKey.compile(allocator);
    try key.validate();
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);

    var prior_fixed: ?[32]u8 = null;
    for ([_]u32{ 664, 668 }) |wire_count| {
        const source = try allocator.alloc(native.Row, wire_count + boundary.CONTEXT_WORD_COUNT);
        defer allocator.free(source);
        for (source, 0..) |*row, index| {
            const wire = index < wire_count;
            row.* = native.logicalRow(
                M31.fromCanonical(@intCast(17 + index % 101)),
                M31.one(),
                M31.fromCanonical(if (wire) boundary.WIRE_SCOPE else boundary.CONTEXT_SCOPE),
                M31.fromCanonical(@intCast(if (wire) index else index - wire_count)),
            );
        }
        var fanout = try v6.Schedule.init(allocator, &link, &child, source);
        defer fanout.deinit();
        // The synthetic fixture has no authenticated child; the private
        // constructor exercises physical row math only.
        var writer = try Writer.initForKnownCount(allocator, &key, wire_count, &link, &child, source, &fanout);
        defer writer.deinit();
        try std.testing.expectEqual(@as(usize, air.CAPACITY), writer.rows.len);
        const fixed = try allocColumns(allocator, air.PREPROCESSED_COLUMN_COUNT);
        defer freeColumns(allocator, fixed);
        const main = try allocColumns(allocator, air.PHYSICAL_MAIN_COLUMN_COUNT);
        defer freeColumns(allocator, main);
        const interaction = try allocColumns(allocator, air.INTERACTION_COLUMN_COUNT);
        defer freeColumns(allocator, interaction);
        try writer.fillPreprocessed(fixed);
        try writer.fillMain(main);
        const claims = try writer.fillInteraction(&universal.UniversalRelations.dummy(), interaction);
        try std.testing.expect(claims.total.eql(claims.audit.total));
        try std.testing.expect(!claims.total.isZero());
        // The new bit-decomposed AIR must preserve the prior typed source's
        // relation claim and every committed LogUp cell for the same words.
        var prior_definition = try v6.build(allocator);
        defer prior_definition.deinit();
        const prior_plan = try v6.authenticate(&prior_definition);
        var prior_interaction = try prior_plan.generateInteraction(
            allocator,
            &prior_definition.arena,
            v6.SEMANTIC_DIGEST,
            .{prior_definition.event},
            fanout.rows,
            air.LOG_SIZE,
            &universal.UniversalRelations.dummy(),
        );
        defer prior_interaction.deinit(allocator);
        try std.testing.expect(claims.total.eql(prior_interaction.claims.total()));
        for (interaction, prior_interaction.columns) |actual, expected|
            try std.testing.expectEqualSlices(M31, expected, actual);
        try std.testing.expectEqualDeep(key.column_digest, digestColumn(fixed[0]));
        try std.testing.expectEqual(try air.fixedOrdinalRow(664), fixed[0][framework.committedRow(664, air.LOG_SIZE)]);
        try std.testing.expectEqual(wire_count, writer.rows[air.CAPACITY - 1][air.PHYSICAL_MAIN_COLUMN_COUNT + air.PREPROCESSED_COLUMN_COUNT].toU32());
        if (prior_fixed) |digest| try std.testing.expectEqualDeep(digest, digestColumn(fixed[0]));
        prior_fixed = digestColumn(fixed[0]);
        try std.testing.expectError(error.V8StatementDestinationNotFresh, writer.fillPreprocessed(fixed));
        try std.testing.expectError(error.V8StatementDestinationNotFresh, writer.fillMain(main));

        source[wire_count][2] = M31.fromCanonical(boundary.WIRE_SCOPE);
        try std.testing.expectError(error.InvalidDirectStatementV6Schedule, Writer.initForKnownCount(allocator, &key, wire_count, &link, &child, source, &fanout));
        source[wire_count][2] = M31.fromCanonical(boundary.CONTEXT_SCOPE);
        try std.testing.expectError(error.InvalidV8StatementSourceShape, Writer.initForKnownCount(allocator, &key, wire_count + 1, &link, &child, source, &fanout));

        const original_value = writer.rows[0][0];
        writer.rows[0][0] = original_value.add(M31.one());
        const fresh_main = try allocColumns(allocator, air.PHYSICAL_MAIN_COLUMN_COUNT);
        defer freeColumns(allocator, fresh_main);
        try std.testing.expectError(error.InvalidV8StatementRows, writer.fillMain(fresh_main));
        writer.rows[0][0] = original_value;
        const original_extra = writer.rows[0][3];
        writer.rows[0][3] = original_extra.add(M31.one());
        try std.testing.expectError(error.InvalidV8StatementRows, writer.fillMain(fresh_main));
        writer.rows[0][3] = original_extra;
        writer.rows[0][air.PHYSICAL_MAIN_COLUMN_COUNT + air.PREPROCESSED_COLUMN_COUNT] = M31.fromCanonical(wire_count + 1);
        try std.testing.expectError(error.InvalidV8StatementRows, writer.fillInteraction(&universal.UniversalRelations.dummy(), interaction));
    }
    var bad_key = key;
    bad_key.column_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidV8StatementFixedKey, bad_key.validate());
}

test "V8 row36 public initializer binds wire values and admitted manifest" {
    const allocator = std.testing.allocator;
    const fixture_mod = @import("../air/public_data_v2_test_support.zig");
    const fixture = try fixture_mod.Fixture.init();
    const words = try fixture_mod.encode(allocator, &fixture.leftSource());
    defer allocator.free(words);
    const expected = try PublicDataV2.authenticate(words);
    const manifest = try boundary.ManifestV2.init(words.len);
    const source = try allocator.alloc(native.Row, words.len + boundary.CONTEXT_WORD_COUNT);
    defer allocator.free(source);
    for (source, 0..) |*row, index| {
        const wire = index < words.len;
        row.* = native.logicalRow(
            if (wire) words[index] else M31.fromCanonical(17),
            M31.one(),
            M31.fromCanonical(if (wire) boundary.WIRE_SCOPE else boundary.CONTEXT_SCOPE),
            M31.fromCanonical(@intCast(if (wire) index else index - words.len)),
        );
    }
    const fixture_child = @import("tests/ethereum_leaf_child_field_test.zig");
    var link = try link_mod.ProgramV3.init(allocator);
    defer link.deinit();
    var child = try child_mod.ProgramV1.initWithNativeProgramBridge(allocator, &fixture_child.components, &fixture_child.infra);
    defer child.deinit();
    var fanout = try v6.Schedule.init(allocator, &link, &child, source);
    defer fanout.deinit();
    const key = try FixedKey.compile(allocator);
    var writer = try Writer.init(allocator, &key, &expected, &manifest, &link, &child, source, &fanout);
    defer writer.deinit();
    try std.testing.expectEqual(@as(u32, @intCast(words.len)), writer.wire_count);

    const saved = source[0][0];
    source[0][0] = saved.add(M31.one());
    try std.testing.expectError(error.V8StatementWireSourceMismatch, Writer.init(allocator, &key, &expected, &manifest, &link, &child, source, &fanout));
    source[0][0] = saved;
    const wrong = try boundary.ManifestV2.init(words.len + 4);
    try std.testing.expectError(error.DirectStatementV8ManifestMismatch, Writer.init(allocator, &key, &expected, &wrong, &link, &child, source, &fanout));
}

fn allocColumns(allocator: std.mem.Allocator, count: usize) ![][]M31 {
    const columns = try allocator.alloc([]M31, count);
    errdefer allocator.free(columns);
    var made: usize = 0;
    errdefer for (columns[0..made]) |column| allocator.free(column);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, air.CAPACITY);
        @memset(column.*, M31.zero());
        made += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
