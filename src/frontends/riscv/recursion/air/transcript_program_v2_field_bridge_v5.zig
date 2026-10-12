//! Direct-wrapper ProgramV2 word bridge with key-fixed protocol words.
//! Dynamic values must arrive from the native NPV2 exporter. Protocol-invariant
//! values are constrained to independently compiled preprocessing instead.
//!
//! A versioned native transcript component must emit the NPV2 tuple from the
//! values it actually executes. Until that producer exists, this component's
//! first relation cannot close and this module grants no proof capability.

const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation_effect = @import("relation_effect.zig");
const interaction = @import("relation_interaction.zig");
const program_contract = @import("../transcript_program_v2_contract.zig");
const profile = @import("../segment_leaf_wrapper_protocol_direct_v4.zig");

const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.segment_v2.program_field_bridge.direct.v5";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_NATIVE_EXPORT_AVAILABLE = false;
pub const NATIVE_EXPORT_SCOPE: u32 = 0x4e50_5632; // NPV2
pub const HASH_INPUT_SCOPE: u32 = 0x5056_3257; // PV2W
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 5;
pub const LOGICAL_INPUT_COUNT: usize = 6;
pub const DIRECT_CONSTRAINT_COUNT: usize = 5;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX = "1bc668636b8a3a58f227b1149d9db95e82730843aa59277ad019be928baf1c44";
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

/// A key may be precompiled per admitted canonical-word count. Only fixed
/// schema/PCS values live in preprocessing. No leaf or proof values live here.
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
        const fixed = fixedValue(@intCast(row));
        return .{
            M31.one(),
            M31.fromCanonical(HASH_INPUT_SCOPE),
            M31.fromCanonical(@intCast(row)),
            M31.fromCanonical(@intFromBool(fixed != null)),
            M31.fromCanonical(fixed orelse 0),
        };
    }

    pub fn logicalRow(self: FixedSchedule, row: usize, value: M31) !Row {
        const fixed = try self.preprocessedRow(row);
        if (row >= self.word_count and !value.isZero())
            return error.NonzeroInactiveProgramWord;
        return .{ value, fixed[0], fixed[1], fixed[2], fixed[3], fixed[4] };
    }
};

/// Canonical ProgramV2 indices: format/schema (0,1) and PCS words (28..40).
/// Six low PCS words are exported by native row5; every other PCS word is a
/// key-fixed high limb or the lifting-presence Boolean. The wrapper target
/// profile is pinned at compile time, so these values cannot follow a proof.
pub fn fixedValue(index: u32) ?u32 {
    const pcs = profile.PCS_CONFIG;
    return switch (index) {
        0 => program_contract.FORMAT_VERSION,
        1 => program_contract.SCHEMA_VERSION,
        29 => pcs.pow_bits >> 16,
        31 => pcs.fri_config.log_blowup_factor >> 16,
        33 => @as(u32, @intCast(pcs.fri_config.n_queries)) >> 16,
        35 => pcs.fri_config.log_last_layer_degree_bound >> 16,
        37 => pcs.fri_config.fold_step >> 16,
        38 => @intFromBool(pcs.lifting_log_size != null),
        40 => @as(u32, pcs.lifting_log_size orelse 0) >> 16,
        else => null,
    };
}

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
    const fixed = fixedValue(index);
    return .{ value, M31.one(), M31.fromCanonical(HASH_INPUT_SCOPE), M31.fromCanonical(index), M31.fromCanonical(@intFromBool(fixed != null)), M31.fromCanonical(fixed orelse 0) };
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
    const fixed_mode = try arena.input("direct_program_word.fixed_mode", .selector, span);
    const fixed_expected = try arena.input("direct_program_word.fixed_expected", .felt, span);
    const one = try arena.constantField(1, span);
    const native_scope = try arena.constantField(NATIVE_EXPORT_SCOPE, span);
    const inactive = try arena.sub(one, active, span);
    const dynamic_mode = try arena.sub(one, fixed_mode, span);
    const roots: [DIRECT_CONSTRAINT_COUNT]Id = .{
        try arena.mul(active, try arena.sub(active, one, span), span),
        try arena.mul(inactive, value, span),
        try arena.mul(fixed_mode, try arena.sub(fixed_mode, one, span), span),
        try arena.mul(inactive, fixed_mode, span),
        try arena.mul(fixed_mode, try arena.sub(value, fixed_expected, span), span),
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
        .{ .domain = .recursion_vm_public_claim_word, .role = .consume, .values = &.{ native_scope, index, value }, .weight = try arena.mul(active, dynamic_mode, span) },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &.{ hash_scope, index, value }, .weight = active },
    }, span);
    return .{ .arena = arena, .roots = roots, .events = events };
}

test "NPV2 V5 bridge fixes profile words semantically and consumes only dynamic words" {
    const support = @import("test_support.zig");
    const types = lang.types;
    const allocator = std.testing.allocator;
    const schedule = try FixedSchedule.init(41);
    try std.testing.expectEqual(@as(usize, 64), schedule.rowCapacity());
    try std.testing.expectEqual(@as(?u32, program_contract.FORMAT_VERSION), fixedValue(0));
    try std.testing.expectEqual(@as(?u32, program_contract.SCHEMA_VERSION), fixedValue(1));
    try std.testing.expectEqual(@as(?u32, null), fixedValue(28));
    try std.testing.expectEqual(@as(?u32, null), fixedValue(39));
    try std.testing.expectEqual(@as(?u32, 0), fixedValue(40));
    var definition = try build(allocator);
    defer definition.deinit();
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, try computeSemanticDigest(allocator));
    const plan = try authenticate(&definition);
    var rows: [64]Row = undefined;
    for (&rows, 0..) |*row, index| {
        const word: u32 = fixedValue(@intCast(index)) orelse if (index == 10) 17 else 0;
        row.* = try schedule.logicalRow(index, M31.fromCanonical(word));
        const values = try support.evaluateArena(allocator, &definition.arena, row);
        defer allocator.free(values);
        for (definition.arena.constraintsView()) |constraint|
            try std.testing.expect(values[types.idIndex(constraint.root)].isZero());
    }
    try std.testing.expectError(error.NonzeroInactiveProgramWord, schedule.logicalRow(41, M31.one()));

    const relation = @import("../../air/lang/relation.zig");
    const domain = relation.Domain.recursion_vm_public_claim_word;
    const domain_mask: u64 = @as(u64, 1) << @intFromEnum(domain);
    var ledger = interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(&ledger, 42, &rows, domain_mask);
    // Forty-one PV2W emissions, but only 32 NPV2 consumptions: nine
    // key-fixed schema/PCS words cannot demand a fabricated native source.
    try std.testing.expectEqual(@as(usize, 73), ledger.classify().unmatched_by_domain[@intFromEnum(domain)]);

    var wrong_fixed = rows[0];
    wrong_fixed[0] = wrong_fixed[0].add(M31.one());
    const wrong_values = try support.evaluateArena(allocator, &definition.arena, &wrong_fixed);
    defer allocator.free(wrong_values);
    try std.testing.expect(!wrong_values[types.idIndex(definition.roots[4])].isZero());
    var forged_mode = rows[0];
    forged_mode[4] = M31.zero();
    // A verifier-owned preprocessing root rejects this mutation. The AIR
    // would also require a real NPV2 tuple in the dynamic branch.
    const forged_values = try support.evaluateArena(allocator, &definition.arena, &forged_mode);
    defer allocator.free(forged_values);
    try std.testing.expect(forged_values[types.idIndex(definition.roots[4])].isZero());
    try std.testing.expect(!std.meta.eql(forged_mode, rows[0]));
    var non_boolean = rows[0];
    non_boolean[4] = M31.fromCanonical(2);
    const non_boolean_values = try support.evaluateArena(allocator, &definition.arena, &non_boolean);
    defer allocator.free(non_boolean_values);
    try std.testing.expect(!non_boolean_values[types.idIndex(definition.roots[2])].isZero());
}
