//! Versioned direct-leaf statement source with exact local-identity fan-out.
//!
//! The native SegmentV2 Statement AIR emits each S2WR/S2CX word once. The
//! V5 child-field router consumes 56 more words. This AIR replaces that source
//! in a future proof roster: one committed main value has weight two only at
//! the 56 verifier-key-pinned coordinates, and weight one everywhere else.
//! The legacy V2 AIR and key remain unchanged.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");
const interaction = @import("relation_interaction.zig");
const old = @import("../segment_leaf_outer_air_v2.zig").Statement;
const child_program = @import("../ethereum_leaf_child_field_program_v1.zig");
const local = @import("../segment_leaf_wrapper_local_identity_v5.zig");

pub const FORMAT_VERSION: u16 = 5;
pub const STABLE_NAME = "recursion.segment_leaf_v5.statement_source.direct";
pub const SCHEDULE_DOMAIN = "stwo-zig/riscv-leaf-v5-statement-fanout\x00";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize = 5;
pub const DIRECT_CONSTRAINT_COUNT: usize = 6;
pub const RELATION_EVENT_COUNT: usize = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const SEMANTIC_DIGEST_HEX = "dfaae5ac9be8e0ef67e92b019800ad7391b3ffe2fcfd376937bc11ba570f014d";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var value: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&value, SEMANTIC_DIGEST_HEX) catch @compileError("invalid V5 Statement AIR digest");
    break :blk value;
};

pub const MAIN_COLUMN_NAMES = [_][]const u8{"recursion.segment_leaf_v5.statement_source.value"};
pub const PREPROCESSED_COLUMN_NAMES = [_][]const u8{
    "recursion_segment_leaf_v5_statement_source_active",
    "recursion_segment_leaf_v5_statement_source_extra_use",
    "recursion_segment_leaf_v5_statement_source_scope",
    "recursion_segment_leaf_v5_statement_source_index",
};
pub const CONSTRAINT_NAMES = [_][]const u8{
    "recursion.segment_leaf_v5.statement_source.active_boolean",
    "recursion.segment_leaf_v5.statement_source.extra_boolean",
    "recursion.segment_leaf_v5.statement_source.extra_requires_active",
    "recursion.segment_leaf_v5.statement_source.inactive_scope_zero",
    "recursion.segment_leaf_v5.statement_source.inactive_index_zero",
    "recursion.segment_leaf_v5.statement_source.inactive_value_zero",
};

pub const Definition = struct {
    arena: ir.Arena,
    main: types.ValueId,
    pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId,
    weight: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    event: types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try validate_mod.validate(&self.arena);
        const actual = try digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &actual.bytes, &SEMANTIC_DIGEST) or
            actual.format_version != digest.typed_effect_format_version or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidDirectStatementSource;
        try @import("../segment_leaf_outer_air_v2_contract.zig").validateInputs(&self.arena, &.{self.main}, &MAIN_COLUMN_NAMES, 0, null);
        try @import("../segment_leaf_outer_air_v2_contract.zig").validateInputs(&self.arena, &self.pp, &PREPROCESSED_COLUMN_NAMES, 1, 0);
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |id, root, name, index| {
            const item = self.arena.constraint(id) orelse return error.InvalidDirectStatementSource;
            if (types.idIndex(id) != index or item.root != root or item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, self.arena.name(item.name) orelse return error.InvalidDirectStatementSource, name))
                return error.InvalidDirectStatementSource;
        }
        try @import("../segment_leaf_outer_air_v2_contract.zig").validateEffect(
            &self.arena,
            self.event,
            0,
            .recursion_statement_word,
            .emit,
            self.weight,
            &.{ self.pp[2], self.pp[3], self.main },
        );
    }
};

pub const Runtime = interaction.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Plan = Runtime.Plan;
pub const Row = Runtime.Row;

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try digest.computeIdentity(&definition.arena)).bytes;
}

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, .{definition.event});
}

pub fn logicalRow(value: M31, active: M31, extra_use: M31, scope: M31, index: M31) Row {
    return .{ value, active, extra_use, scope, index };
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const value = try arena.input(MAIN_COLUMN_NAMES[0], .felt, span);
    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*item, name, index|
        item.* = try arena.input(name, if (index == 0) .selector else .felt, span);
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, pp[0], span);
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.mul(pp[0], try arena.sub(pp[0], one, span), span),
        try arena.mul(pp[1], try arena.sub(pp[1], one, span), span),
        try arena.mul(inactive, pp[1], span),
        try arena.mul(inactive, pp[2], span),
        try arena.mul(inactive, pp[3], span),
        try arena.mul(inactive, value, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*item, root, name|
        item.* = try arena.assertZero(name, root, null, .semantic, span);
    const weight = try arena.add(pp[0], pp[1], span);
    const event = try relation_effect.append(&arena, .{
        .domain = .recursion_statement_word,
        .role = .emit,
        .values = &.{ pp[2], pp[3], value },
        .weight = weight,
    }, span);
    return .{ .arena = arena, .main = value, .pp = pp, .weight = weight, .roots = roots, .constraints = constraints, .event = event };
}

/// Immutable V5 replacement for the old row36 source. Values remain the
/// exact old committed main values. The fixed preprocessed selector is one
/// precisely where the authenticated router adds a second statement use.
pub const Schedule = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    id: [32]u8,

    pub fn init(allocator: std.mem.Allocator, child: *const child_program.ProgramV1, old_rows: []const old.Row) !Schedule {
        const uses = try local.sourceUses(allocator, child);
        defer allocator.free(uses);
        const rows = try allocator.alloc(Row, old_rows.len);
        errdefer allocator.free(rows);
        const found = try allocator.alloc(bool, uses.len);
        defer allocator.free(found);
        @memset(found, false);
        for (old_rows, rows) |old_row, *new_row| {
            const active = old_row[1].toU32();
            if (active > 1) return error.InvalidDirectStatementSource;
            var extra: u32 = 0;
            if (active == 1) for (uses, found) |use, *seen| {
                if (use.scope == old_row[2].toU32() and use.index == old_row[3].toU32()) {
                    if (seen.* or use.count != 1) return error.InvalidDirectStatementSource;
                    seen.* = true;
                    extra = 1;
                    break;
                }
            };
            new_row.* = logicalRow(old_row[0], old_row[1], M31.fromCanonical(extra), old_row[2], old_row[3]);
        }
        for (found) |seen| if (!seen) return error.MissingDirectStatementProducer;
        var result = Schedule{ .allocator = allocator, .rows = rows, .id = undefined };
        result.id = scheduleId(rows);
        return result;
    }

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Schedule, child: *const child_program.ProgramV1, old_rows: []const old.Row) !void {
        var expected = try init(self.allocator, child, old_rows);
        defer expected.deinit();
        if (!std.meta.eql(self.id, expected.id) or self.rows.len != expected.rows.len)
            return error.InvalidDirectStatementSource;
        for (self.rows, expected.rows) |actual, wanted|
            if (!std.meta.eql(actual, wanted)) return error.InvalidDirectStatementSource;
    }
};

fn scheduleId(rows: []const Row) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SCHEDULE_DOMAIN);
    hash.update(&SEMANTIC_DIGEST);
    for (rows) |row| for (row[1..]) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word.toU32(), .little);
        hash.update(&bytes);
    };
    return hash.finalResult();
}

test "direct V5 Statement source pins exact extra fan-out and rejects missing or duplicate producers" {
    const fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const allocator = std.testing.allocator;
    var program = try child_program.ProgramV1.init(allocator, &fixture.components, &fixture.infra);
    defer program.deinit();
    const uses = try local.sourceUses(allocator, &program);
    defer allocator.free(uses);
    try std.testing.expectEqual(@as(usize, 56), uses.len);
    const original = try allocator.alloc(old.Row, uses.len + 1);
    defer allocator.free(original);
    for (uses, original[0..uses.len], 0..) |use, *row, index|
        row.* = old.logicalRow(M31.fromCanonical(@intCast(index + 1)), M31.one(), M31.fromCanonical(use.scope), M31.fromCanonical(use.index));
    original[uses.len] = old.logicalRow(M31.fromCanonical(97), M31.one(), M31.fromCanonical(123), M31.fromCanonical(456));
    var schedule = try Schedule.init(allocator, &program, original);
    defer schedule.deinit();
    try schedule.validateAgainst(&program, original);
    for (schedule.rows[0..uses.len]) |row| try std.testing.expectEqual(@as(u32, 1), row[2].toU32());
    try std.testing.expectEqual(@as(u32, 0), schedule.rows[uses.len][2].toU32());
    schedule.rows[0][2] = M31.zero();
    try std.testing.expectError(error.InvalidDirectStatementSource, schedule.validateAgainst(&program, original));
    schedule.rows[0][2] = M31.one();
    try std.testing.expectError(error.MissingDirectStatementProducer, Schedule.init(allocator, &program, original[1..]));
    original[uses.len] = original[0];
    try std.testing.expectError(error.InvalidDirectStatementSource, Schedule.init(allocator, &program, original));
}

test "direct V5 Statement AIR extra use closes exactly two consumers" {
    try std.testing.expectEqual(SEMANTIC_DIGEST, try computeSemanticDigest(std.testing.allocator));
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    const plan = try authenticate(&definition);
    const relation_interaction = @import("relation_interaction.zig");
    var ledger = relation_interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    const row = logicalRow(M31.fromCanonical(17), M31.one(), M31.one(), M31.fromCanonical(23), M31.fromCanonical(42));
    const mask = @as(u64, 1) << @intFromEnum(relation.Domain.recursion_statement_word);
    try plan.appendPreparedTupleContributions(&ledger, 36, &.{row}, mask);
    const QM31 = core.fields.qm31.QM31;
    const tuple = [_]QM31{ QM31.fromBase(M31.fromCanonical(23)), QM31.fromBase(M31.fromCanonical(42)), QM31.fromBase(M31.fromCanonical(17)) };
    try ledger.append(.recursion_statement_word, 11, 0, .consume, QM31.one().neg(), &tuple);
    try ledger.append(.recursion_statement_word, 47, 0, .consume, QM31.one().neg(), &tuple);
    try std.testing.expect(ledger.classify().isClosed());
    var missing = relation_interaction.TupleLedger.init(std.testing.allocator);
    defer missing.deinit();
    var mutated = row;
    mutated[2] = M31.zero();
    try plan.appendPreparedTupleContributions(&missing, 36, &.{mutated}, mask);
    try missing.append(.recursion_statement_word, 11, 0, .consume, QM31.one().neg(), &tuple);
    try missing.append(.recursion_statement_word, 47, 0, .consume, QM31.one().neg(), &tuple);
    try std.testing.expectEqual(@as(usize, 1), missing.classify().unmatched_by_domain[@intFromEnum(relation.Domain.recursion_statement_word)]);
}
