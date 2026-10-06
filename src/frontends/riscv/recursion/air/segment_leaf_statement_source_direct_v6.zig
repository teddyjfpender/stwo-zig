//! Direct Statement source with exact native-link and local-router fan-out.
//! The old committed main value is preserved. A key-owned extra-use count
//! permits 0, 1, or 2 additional consumers, so total multiplicity is 1..3.

const std = @import("std");
const core = @import("stwo_core");
const old = @import("segment_leaf_statement_source_direct_v5.zig");
const native = @import("../segment_leaf_outer_air_v2.zig").Statement;
const link_program = @import("../ethereum_leaf_link_program_v3.zig");
const child_program = @import("../ethereum_leaf_child_field_program_v1.zig");
const local = @import("../segment_leaf_wrapper_local_identity_v5.zig");
const digest = @import("../../air/lang/digest.zig");
const validate_mod = @import("../../air/lang/validate.zig");

const M31 = core.fields.m31.M31;
pub const STABLE_NAME = "recursion.segment_leaf_v6.statement_source.direct";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const PHYSICAL_MAIN_COLUMN_COUNT = old.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = old.PREPROCESSED_COLUMN_COUNT;
pub const LOGICAL_INPUT_COUNT = old.LOGICAL_INPUT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = old.DIRECT_CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT = old.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE = old.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = old.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = old.INTERACTION_COLUMN_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST_HEX = "d1c41975c0681b567ee907fd49186bcb54ad232de0857296fce632ed2bc71fbc";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch @compileError("invalid V6 Statement digest");
    break :blk bytes;
};
pub const Row = old.Row;
pub const Definition = old.Definition;
pub const Runtime = old.Runtime;
pub const Plan = old.Plan;

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try old.buildRawForExtraLimit(allocator, 2);
    errdefer result.deinit();
    try validate(&result);
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
    var result = try old.buildRawForExtraLimit(allocator, 2);
    defer result.deinit();
    return (try digest.computeIdentity(&result.arena)).bytes;
}

pub fn validate(definition: *const Definition) !void {
    try validate_mod.validate(&definition.arena);
    const identity = try digest.computeIdentity(&definition.arena);
    if (definition.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
        definition.arena.effectsView().len != RELATION_EVENT_COUNT or
        !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST))
        return error.InvalidDirectStatementV6;
}

pub fn authenticate(definition: *const Definition) !Plan {
    try validate(definition);
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, .{definition.event});
}

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    id: [32]u8,
    link_uses: usize,
    local_uses: usize,
    overlaps: usize,

    pub fn init(allocator: std.mem.Allocator, link: *const link_program.ProgramV3, child: *const child_program.ProgramV1, old_rows: []const native.Row) !Schedule {
        try link.validate();
        const local_uses = try local.sourceUses(allocator, child);
        defer allocator.free(local_uses);
        const seen_local = try allocator.alloc(bool, local_uses.len);
        defer allocator.free(seen_local);
        @memset(seen_local, false);
        const seen_link = try allocator.alloc(bool, link.projection_rows.len);
        defer allocator.free(seen_link);
        @memset(seen_link, false);
        const rows = try allocator.alloc(Row, old_rows.len);
        errdefer allocator.free(rows);
        var link_count: usize = 0;
        var local_count: usize = 0;
        var overlap_count: usize = 0;
        for (old_rows, rows) |old_row, *new_row| {
            const active = old_row[1].toU32();
            if (active > 1) return error.InvalidDirectStatementV6Schedule;
            var link_extra: u32 = 0;
            var local_extra: u32 = 0;
            if (active == 1) {
                for (link.projection_rows, seen_link) |projection, *seen| {
                    if (projection.local_statement_mask == 0 or
                        projection.statement_scope != old_row[2].toU32() or
                        projection.statement_index != old_row[3].toU32()) continue;
                    if (projection.local_statement_mask != 1 or seen.* or link_extra != 0)
                        return error.InvalidDirectStatementV6Schedule;
                    seen.* = true;
                    link_extra = 1;
                    link_count += 1;
                }
                for (local_uses, seen_local) |use, *seen| {
                    if (use.scope != old_row[2].toU32() or use.index != old_row[3].toU32()) continue;
                    if (seen.* or use.count != 1 or local_extra != 0)
                        return error.InvalidDirectStatementV6Schedule;
                    seen.* = true;
                    local_extra = 1;
                    local_count += 1;
                }
            }
            if (link_extra == 1 and local_extra == 1) overlap_count += 1;
            new_row.* = old.logicalRow(old_row[0], old_row[1], M31.fromCanonical(link_extra + local_extra), old_row[2], old_row[3]);
        }
        for (seen_local) |seen| if (!seen) return error.MissingDirectStatementV6LocalProducer;
        for (link.projection_rows, seen_link) |projection, seen| {
            if (projection.local_statement_mask == 1 and !seen)
                return error.MissingDirectStatementV6LinkProducer;
        }
        var result = Schedule{ .allocator = allocator, .rows = rows, .id = undefined, .link_uses = link_count, .local_uses = local_count, .overlaps = overlap_count };
        result.id = result.scheduleId(link);
        return result;
    }

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Schedule, link: *const link_program.ProgramV3, child: *const child_program.ProgramV1, old_rows: []const native.Row) !void {
        var wanted = try init(self.allocator, link, child, old_rows);
        defer wanted.deinit();
        if (!std.meta.eql(self.id, wanted.id) or self.rows.len != wanted.rows.len or
            self.link_uses != wanted.link_uses or self.local_uses != wanted.local_uses or self.overlaps != wanted.overlaps)
            return error.InvalidDirectStatementV6Schedule;
        for (self.rows, wanted.rows) |actual, expected|
            if (!std.meta.eql(actual, expected)) return error.InvalidDirectStatementV6Schedule;
    }

    fn scheduleId(self: *const Schedule, link: *const link_program.ProgramV3) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/riscv-leaf-v6-statement-fanout\x00");
        hash.update(&SEMANTIC_DIGEST);
        hash.update(&link.schedule_id);
        for (self.rows) |row| for (row[1..]) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word.toU32(), .little);
            hash.update(&bytes);
        };
        return hash.finalResult();
    }
};

test "direct V6 Statement supports three exact consumers" {
    const actual = try computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, actual);
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    const plan = try authenticate(&definition);
    const row = old.logicalRow(M31.fromCanonical(19), M31.one(), M31.fromCanonical(2), M31.fromCanonical(7), M31.fromCanonical(8));
    const mask: u64 = @as(u64, 1) << @intFromEnum(@import("../../air/lang/relation.zig").Domain.recursion_statement_word);
    var ledger = @import("relation_interaction.zig").TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(&ledger, 36, &.{row}, mask);
    const tuple = [_]core.fields.qm31.QM31{
        .fromBase(M31.fromCanonical(7)), .fromBase(M31.fromCanonical(8)), .fromBase(M31.fromCanonical(19)),
    };
    inline for ([_]u8{ 11, 40, 47 }) |component|
        try ledger.append(.recursion_statement_word, component, 0, .consume, core.fields.qm31.QM31.one().neg(), &tuple);
    try std.testing.expect(ledger.classify().isClosed());
    var missing = row;
    missing[2] = M31.one();
    var changed = @import("relation_interaction.zig").TupleLedger.init(std.testing.allocator);
    defer changed.deinit();
    try plan.appendPreparedTupleContributions(&changed, 36, &.{missing}, mask);
    inline for ([_]u8{ 11, 40, 47 }) |component|
        try changed.append(.recursion_statement_word, component, 0, .consume, core.fields.qm31.QM31.one().neg(), &tuple);
    try std.testing.expectEqual(@as(usize, 1), changed.classify().unmatched_by_domain[29]);
}
