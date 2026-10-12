//! Direct-wrapper ProgramV2 word bridge. The word is a committed main value;
//! preprocessing fixes only the active row, scope, and canonical index.
//!
//! A versioned native transcript component must emit the NPV2 tuple from the
//! values it actually executes. Until that producer exists, this component's
//! first relation cannot close and this module grants no proof capability.

const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation_effect = @import("relation_effect.zig");
const interaction = @import("relation_interaction.zig");

const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.segment_v2.program_field_bridge.direct.v4";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_NATIVE_EXPORT_AVAILABLE = false;
pub const NATIVE_EXPORT_SCOPE: u32 = 0x4e50_5632; // NPV2
pub const HASH_INPUT_SCOPE: u32 = 0x5056_3257; // PV2W
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 3;
pub const LOGICAL_INPUT_COUNT: usize = 4;
pub const DIRECT_CONSTRAINT_COUNT: usize = 2;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX = "803a14f9800774185091ce846f15297e38409e9f99fe05fcb78bf3535747d585";
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid direct ProgramV2 bridge digest");
    break :blk result;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const PreprocessedRow = [PREPROCESSED_COLUMN_COUNT]M31;
pub const Runtime = interaction.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Plan = Runtime.Plan;

/// A key may be precompiled per admitted canonical-word count. The resulting
/// preprocessing contains no statement, instruction, PCS, or proof values;
/// every request with this word count has the same preprocessing rows.
pub const FixedSchedule = struct {
    word_count: u32,
    log_size: u8,

    pub fn init(word_count: usize) !FixedSchedule {
        if (word_count == 0 or word_count >= core.fields.m31.Modulus)
            return error.InvalidDirectProgramWordCount;
        const capacity = std.math.ceilPowerOfTwo(usize, @max(word_count, 16)) catch
            return error.InvalidDirectProgramWordCount;
        if (capacity > (@as(usize, 1) << 30))
            return error.InvalidDirectProgramWordCount;
        return .{
            .word_count = @intCast(word_count),
            .log_size = @intCast(std.math.log2_int(usize, capacity)),
        };
    }

    pub fn rowCapacity(self: FixedSchedule) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }

    pub fn preprocessedRow(self: FixedSchedule, row: usize) !PreprocessedRow {
        if (row >= self.rowCapacity()) return error.InvalidDirectProgramRow;
        if (row >= self.word_count) return [_]M31{M31.zero()} ** PREPROCESSED_COLUMN_COUNT;
        return .{
            M31.one(),
            M31.fromCanonical(HASH_INPUT_SCOPE),
            M31.fromCanonical(@intCast(row)),
        };
    }

    pub fn logicalRow(self: FixedSchedule, row: usize, value: M31) !Row {
        const fixed = try self.preprocessedRow(row);
        if (row >= self.word_count and !value.isZero())
            return error.NonzeroInactiveProgramWord;
        return .{ value, fixed[0], fixed[1], fixed[2] };
    }
};

comptime {
    if (NATIVE_EXPORT_SCOPE >= core.fields.m31.Modulus or
        HASH_INPUT_SCOPE >= core.fields.m31.Modulus or
        NATIVE_EXPORT_SCOPE == HASH_INPUT_SCOPE)
        @compileError("ProgramV2 bridge scopes must be distinct canonical M31 values");
}

pub const Definition = struct {
    arena: lang.ir.Arena,
    roots: [DIRECT_CONSTRAINT_COUNT]Id,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidDirectProgramFieldBridge;
        const actual = (try lang.digest.computeIdentity(&self.arena)).bytes;
        if (!std.mem.eql(u8, &actual, &SEMANTIC_DIGEST))
            return error.InvalidDirectProgramFieldBridge;
        for (self.roots, 0..) |root, index| {
            const constraint = self.arena.constraintsView()[index];
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
                return error.InvalidDirectProgramFieldBridge;
        }
        for (self.events, 0..) |event, index|
            if (lang.types.idIndex(event) != index)
                return error.InvalidDirectProgramFieldBridge;
    }
};

pub fn logicalRow(value: M31, active: u32, index: u32) Row {
    if (active == 0) return [_]M31{M31.zero()} ** LOGICAL_INPUT_COUNT;
    return .{ value, M31.one(), M31.fromCanonical(HASH_INPUT_SCOPE), M31.fromCanonical(index) };
}

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var result = try buildRaw(allocator);
    defer result.deinit();
    return (try lang.digest.computeIdentity(&result.arena)).bytes;
}

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, definition.events);
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = Span.generated();
    const value = try arena.input("direct_program_word.value", .felt, span);
    const active = try arena.input("direct_program_word.active", .selector, span);
    const hash_scope = try arena.input("direct_program_word.hash_scope", .felt, span);
    const index = try arena.input("direct_program_word.index", .felt, span);
    const one = try arena.constantField(1, span);
    const native_scope = try arena.constantField(NATIVE_EXPORT_SCOPE, span);
    const inactive = try arena.sub(one, active, span);
    const roots: [DIRECT_CONSTRAINT_COUNT]Id = .{
        try arena.mul(active, try arena.sub(active, one, span), span),
        try arena.mul(inactive, value, span),
    };
    for (roots, 0..) |root, i| {
        var name: [72]u8 = undefined;
        _ = try arena.assertZero(
            try std.fmt.bufPrint(&name, "direct_program_word.constraint_{d}", .{i}),
            root,
            null,
            .semantic,
            span,
        );
    }
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_vm_public_claim_word, .role = .consume, .values = &.{ native_scope, index, value }, .weight = active },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &.{ hash_scope, index, value }, .weight = active },
    }, span);
    return .{ .arena = arena, .roots = roots, .events = events };
}

test "direct ProgramV2 bridge requires an independent native producer" {
    const QM31 = core.fields.qm31.QM31;
    const relation = @import("../../air/lang/relation.zig");
    const allocator = std.testing.allocator;
    const domain = relation.Domain.recursion_vm_public_claim_word;
    const domain_mask: u64 = @as(u64, 1) << @intFromEnum(domain);
    const words = [_]M31{ M31.fromCanonical(17), M31.fromCanonical(59) };
    const fixed = try FixedSchedule.init(words.len);
    try std.testing.expectEqual(@as(usize, 16), fixed.rowCapacity());
    var rows: [16]Row = undefined;
    for (&rows, 0..) |*row, index|
        row.* = try fixed.logicalRow(index, if (index < words.len) words[index] else M31.zero());
    try std.testing.expectEqualDeep(rows[0][1..], (try fixed.logicalRow(0, M31.fromCanonical(999)))[1..]);
    try std.testing.expectError(error.NonzeroInactiveProgramWord, fixed.logicalRow(2, M31.one()));
    var definition = try build(allocator);
    defer definition.deinit();
    const actual_digest = try computeSemanticDigest(allocator);
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, actual_digest);
    const plan = try authenticate(&definition);

    var ledger = interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(&ledger, 42, &rows, domain_mask);
    try std.testing.expectEqual(@as(usize, 4), ledger.classify().unmatched_by_domain[@intFromEnum(domain)]);

    for (words, 0..) |word, index| {
        const idx = QM31.fromBase(M31.fromCanonical(@intCast(index)));
        const value = QM31.fromBase(word);
        const native_tuple = [_]QM31{ QM31.fromBase(M31.fromCanonical(NATIVE_EXPORT_SCOPE)), idx, value };
        const hash_tuple = [_]QM31{ QM31.fromBase(M31.fromCanonical(HASH_INPUT_SCOPE)), idx, value };
        try ledger.append(domain, 0, 0, .emit, QM31.fromBase(M31.one()), &native_tuple);
        try ledger.append(domain, 43, 0, .consume, QM31.fromBase(M31.one()).neg(), &hash_tuple);
    }
    try std.testing.expect(ledger.classify().isClosed());

    var changed = rows;
    changed[1][0] = changed[1][0].add(M31.one());
    var mutated = interaction.TupleLedger.init(allocator);
    defer mutated.deinit();
    try plan.appendPreparedTupleContributions(&mutated, 42, &changed, domain_mask);
    for (words, 0..) |word, index| {
        const idx = QM31.fromBase(M31.fromCanonical(@intCast(index)));
        const value = QM31.fromBase(word);
        const native_tuple = [_]QM31{ QM31.fromBase(M31.fromCanonical(NATIVE_EXPORT_SCOPE)), idx, value };
        const hash_tuple = [_]QM31{ QM31.fromBase(M31.fromCanonical(HASH_INPUT_SCOPE)), idx, value };
        try mutated.append(domain, 0, 0, .emit, QM31.fromBase(M31.one()), &native_tuple);
        try mutated.append(domain, 43, 0, .consume, QM31.fromBase(M31.one()).neg(), &hash_tuple);
    }
    try std.testing.expectEqual(@as(usize, 4), mutated.classify().unmatched_by_domain[@intFromEnum(domain)]);
}
