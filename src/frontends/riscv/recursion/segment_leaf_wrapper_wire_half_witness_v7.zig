//! Diagnostic witness join for the native row5 u16 payloads and canonical
//! ProgramV2 wire words. Only typed AIR and exact lookup closure can authorize
//! this join; host equality is a construction preflight, not proof acceptance.

const std = @import("std");
const core = @import("stwo_core");
const base = @import("air/transcript_payload_relation.zig");
const payload = @import("air/transcript_payload_direct_v7.zig");
const schedule = @import("segment_leaf_wrapper_row5_halves_v7.zig");
const program = @import("air/transcript_program_v2_field_bridge_v6.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const Witness = struct {
    halves: schedule.Schedule,
    words: [schedule.WIRE_WORD_COUNT]program.Row,

    pub fn init(allocator: std.mem.Allocator, native_rows: []const base.Row, canonical_program_words: []const M31) !Witness {
        if (canonical_program_words.len < 18) return error.IncompleteCanonicalProgramWords;
        var halves = try schedule.Schedule.init(allocator, native_rows, canonical_program_words[10..18]);
        errdefer halves.deinit();
        var words: [schedule.WIRE_WORD_COUNT]program.Row = undefined;
        for (&words, canonical_program_words[10..18], 0..) |*row, value, index|
            row.* = program.logicalRow(value, 1, @intCast(10 + index));
        return .{ .halves = halves, .words = words };
    }

    pub fn deinit(self: *Witness) void {
        self.halves.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Witness, native_rows: []const base.Row, canonical_program_words: []const M31) !void {
        if (canonical_program_words.len < 18) return error.IncompleteCanonicalProgramWords;
        try self.halves.validateAgainst(native_rows, canonical_program_words[10..18]);
        for (self.words, canonical_program_words[10..18], 0..) |actual, value, index| {
            const expected = program.logicalRow(value, 1, @intCast(10 + index));
            if (!std.meta.eql(actual, expected)) return error.InvalidWireHalfWitness;
        }
    }
};

test "V7 half lookups and byte ranges close, forged half and modular alias fail" {
    const allocator = std.testing.allocator;
    const base_air = @import("air/transcript_payload.zig");
    const relation = @import("../air/lang/relation.zig");
    const ledger_mod = @import("air/relation_interaction.zig");
    const support = @import("air/test_support.zig");
    const types = @import("../air/lang/types.zig");
    var native = [_]base.Row{[_]M31{M31.zero()} ** base_air.LOGICAL_INPUT_COUNT} ** schedule.HALF_COUNT;
    var canonical = [_]M31{M31.zero()} ** 18;
    for (0..schedule.WIRE_WORD_COUNT) |i| canonical[10 + i] = M31.fromCanonical(@intCast(0x1234_0000 + i * 101));
    for (&native, 0..) |*row, limb| {
        const word = canonical[10 + limb / 2].toU32();
        const half: u32 = if (limb % 2 == 0) word & 0xffff else word >> 16;
        row[0] = M31.one();
        row[1] = M31.fromCanonical(half);
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT] = M31.one();
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 1] = M31.one();
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 11] = M31.fromCanonical(@intFromEnum(base_air.VerifierInputKind.statement));
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 12] = M31.one();
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 13] = M31.fromCanonical(@intCast(limb));
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 15] = M31.one();
        row[base_air.LOGICAL_INPUT_COUNT - 2] = M31.one();
    }
    var witness = try Witness.init(allocator, &native, &canonical);
    defer witness.deinit();
    try witness.validateAgainst(&native, &canonical);
    var native_definition = try payload.build(allocator);
    defer native_definition.deinit();
    const native_plan = try payload.authenticate(&native_definition);
    var program_definition = try program.build(allocator);
    defer program_definition.deinit();
    const program_plan = try program.authenticate(&program_definition);
    const mask: u64 = (@as(u64, 1) << @intFromEnum(relation.Domain.recursion_vm_public_claim_word)) |
        (@as(u64, 1) << @intFromEnum(relation.Domain.range_check_8_8));
    var ledger = ledger_mod.TupleLedger.init(allocator);
    defer ledger.deinit();
    try native_plan.appendPreparedTupleContributions(&ledger, 5, witness.halves.rows, mask);
    try program_plan.appendPreparedTupleContributions(&ledger, 42, &witness.words, mask);
    for (witness.words) |row| {
        const hash_tuple = [_]QM31{ .fromBase(M31.fromCanonical(program.HASH_INPUT_SCOPE)), .fromBase(row[11]), .fromBase(row[0]) };
        try ledger.append(.recursion_vm_public_claim_word, 43, 0, .consume, QM31.one().neg(), &hash_tuple);
        for ([_][2]usize{ .{ 3, 4 }, .{ 5, 6 }, .{ 8, 6 } }) |pair| {
            const bytes = [_]QM31{ .fromBase(row[pair[0]]), .fromBase(row[pair[1]]) };
            try ledger.append(.range_check_8_8, 35, 0, .emit, QM31.one(), &bytes);
        }
    }
    try std.testing.expect(ledger.classify().isClosed());

    var forged = witness.halves.rows[0];
    forged[1] = forged[1].add(M31.one());
    var mismatch = ledger_mod.TupleLedger.init(allocator);
    defer mismatch.deinit();
    var native_mutated = try allocator.dupe(payload.Row, witness.halves.rows);
    defer allocator.free(native_mutated);
    native_mutated[0] = forged;
    try native_plan.appendPreparedTupleContributions(&mismatch, 5, native_mutated, mask);
    try program_plan.appendPreparedTupleContributions(&mismatch, 42, &witness.words, mask);
    for (witness.words) |row| {
        const hash_tuple = [_]QM31{ .fromBase(M31.fromCanonical(program.HASH_INPUT_SCOPE)), .fromBase(row[11]), .fromBase(row[0]) };
        try mismatch.append(.recursion_vm_public_claim_word, 43, 0, .consume, QM31.one().neg(), &hash_tuple);
    }
    try std.testing.expect(mismatch.classify().unmatched_by_domain[@intFromEnum(relation.Domain.recursion_vm_public_claim_word)] > 0);

    var alias = witness.words[0];
    alias[0] = M31.one();
    alias[1] = M31.zero();
    alias[2] = M31.fromCanonical(32768);
    alias[3] = M31.zero();
    alias[4] = M31.zero();
    alias[5] = M31.zero();
    alias[6] = M31.fromCanonical(128);
    alias[7] = try M31.fromCanonical(65534).inv();
    alias[8] = M31.fromCanonical(256);
    const values = try support.evaluateArena(allocator, &program_definition.arena, &alias);
    defer allocator.free(values);
    for (program_definition.roots) |root|
        try std.testing.expect(values[types.idIndex(root)].isZero());
    // All direct equations still hold modulo p; the byte table is essential.
    var range_ledger = ledger_mod.TupleLedger.init(allocator);
    defer range_ledger.deinit();
    var aliased_words = witness.words;
    aliased_words[0] = alias;
    const range_mask: u64 = @as(u64, 1) << @intFromEnum(relation.Domain.range_check_8_8);
    try program_plan.appendPreparedTupleContributions(&range_ledger, 42, &aliased_words, range_mask);
    for (aliased_words) |row| for ([_][2]usize{ .{ 3, 4 }, .{ 5, 6 }, .{ 8, 6 } }) |pair| {
        if (row[pair[0]].toU32() > 255 or row[pair[1]].toU32() > 255) continue;
        const bytes = [_]QM31{ .fromBase(row[pair[0]]), .fromBase(row[pair[1]]) };
        try range_ledger.append(.range_check_8_8, 35, 0, .emit, QM31.one(), &bytes);
    };
    try std.testing.expectEqual(@as(usize, 1), range_ledger.classify().unmatched_by_domain[@intFromEnum(relation.Domain.range_check_8_8)]);
}
