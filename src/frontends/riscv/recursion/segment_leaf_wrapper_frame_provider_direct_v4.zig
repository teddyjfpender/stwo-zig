//! Versioned row4 writer. The V2 owner supplies the native transcript rows;
//! this writer fixes eight Tree0 bridge selectors in preprocessing and
//! regenerates row4's interaction under the direct wrapper's challenges.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const air = @import("air/transcript_word_direct_v4.zig");
const old_air = @import("air/transcript_word.zig");
const old_witness = @import("air/transcript_word_witness.zig");
const source = @import("segment_transcript_outer_source_v2.zig");
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const universal = @import("air/universal_challenges.zig");
const DomainAudit = @import("air/relation_interaction.zig").DomainAudit;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW: usize = 4;
pub const ROOT_WORDS: usize = 8;
pub const ROOT_START_INDEX: u32 = 8;

pub const Provider = struct {
    allocator: std.mem.Allocator,
    rows: []air.Row,

    pub fn init(
        allocator: std.mem.Allocator,
        source_rows: []const source.TranscriptWordRowV2,
        hash_id: u32,
        root: [ROOT_WORDS]u32,
    ) !Provider {
        if (source_rows.len == 0) return error.InvalidDirectFrameSource;
        const rows = try allocator.alloc(air.Row, source_rows.len);
        errdefer allocator.free(rows);
        var seen: u8 = 0;
        for (source_rows, rows) |source_row, *target| {
            const old = try old_witness.logicalRow(source_row.preprocessing, source_row.value, .segment_leaf);
            const pp = source_row.preprocessing;
            var mask: u32 = 0;
            if (pp.verifier_id == 0 and pp.segment_mask == 1 and pp.hash_id == hash_id and
                pp.word_index >= ROOT_START_INDEX and pp.word_index < ROOT_START_INDEX + ROOT_WORDS)
            {
                const limb: u3 = @intCast(pp.word_index - ROOT_START_INDEX);
                const bit = @as(u8, 1) << limb;
                if (seen & bit != 0 or pp.row_mask != 1 or pp.is_payload != 1 or
                    source_row.value.add(M31.fromCanonical(pp.constant_value)).toU32() != root[limb])
                    return error.InvalidDirectFrameSource;
                seen |= bit;
                mask = 1;
            }
            @memcpy(target[0 .. old_air.PHYSICAL_MAIN_COLUMN_COUNT + old_air.PREPROCESSED_COLUMN_COUNT], old[0 .. old_air.PHYSICAL_MAIN_COLUMN_COUNT + old_air.PREPROCESSED_COLUMN_COUNT]);
            target[17] = M31.fromCanonical(mask);
            target[18] = old[17];
            target[19] = old[18];
        }
        if (seen != 0xff) return error.InvalidDirectFrameSource;
        return .{ .allocator = allocator, .rows = rows };
    }

    pub fn deinit(self: *Provider) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn fillPreprocessed(self: *const Provider, plan: *const plan_mod.Plan, destination: [][]M31) !void {
        try plan.validate();
        const placement = plan.placements[ROW].?;
        if (placement.geometry.preprocessed_columns != air.PREPROCESSED_COLUMN_COUNT or
            placement.preprocessed_offset + air.PREPROCESSED_COLUMN_COUNT > destination.len)
            return error.DirectFrameGeometryMismatch;
        const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
        const column = destination[placement.preprocessed_offset + 15];
        if (column.len != size or self.rows.len > size) return error.DirectFrameGeometryMismatch;
        for (column) |value| if (!value.isZero()) return error.DirectFrameDestinationNotFresh;
        for (self.rows, 0..) |row, index| column[index] = row[17];
    }

    pub fn fillInteraction(
        self: *const Provider,
        plan: *const plan_mod.Plan,
        relations: *const universal.UniversalRelations,
        destination: [][]M31,
    ) !ClaimAudit {
        try plan.validate();
        const placement = plan.placements[ROW].?;
        if (placement.geometry.interaction_columns != air.INTERACTION_COLUMN_COUNT or
            placement.interaction_offset + air.INTERACTION_COLUMN_COUNT > destination.len)
            return error.DirectFrameGeometryMismatch;
        var definition = try air.build(self.allocator);
        defer definition.deinit();
        const authenticated = try air.authenticate(&definition);
        var generated = try authenticated.generateInteraction(
            self.allocator,
            &definition.arena,
            air.SEMANTIC_DIGEST,
            definition.events,
            self.rows,
            placement.geometry.log_size,
            relations,
        );
        defer generated.deinit(self.allocator);
        const claim = generated.claims.total();
        const audit = try authenticated.auditPreparedDomainSums(self.allocator, self.rows, relations, claim);
        const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
        for (generated.columns, destination[placement.interaction_offset..][0..air.INTERACTION_COLUMN_COUNT]) |from, to| {
            if (from.len != size or to.len != size) return error.DirectFrameGeometryMismatch;
            for (to) |value| if (!value.isZero()) return error.DirectFrameDestinationNotFresh;
        }
        for (generated.columns, destination[placement.interaction_offset..][0..air.INTERACTION_COLUMN_COUNT]) |from, to|
            @memcpy(to, from);
        return .{ .claim = claim, .audit = audit };
    }
};

pub const ClaimAudit = struct { claim: QM31, audit: DomainAudit };

test "direct frame provider selects exactly eight authenticated root slots" {
    const allocator = std.testing.allocator;
    var source_rows: [ROOT_WORDS]source.TranscriptWordRowV2 = undefined;
    var root: [ROOT_WORDS]u32 = undefined;
    for (&source_rows, &root, 0..) |*row, *word, index| {
        word.* = @intCast(index + 1);
        row.* = .{
            .preprocessing = .{
                .row_mask = 1,
                .segment_mask = 1,
                .binary_mask = 0,
                .verifier_id = 0,
                .sequence = 0,
                .tag = 0,
                .args = .{ 0, 0, 0, 0 },
                .hash_id = 7,
                .word_index = @intCast(ROOT_START_INDEX + index),
                .is_payload = 1,
                .payload_index = @intCast(index),
                .constant_value = 0,
            },
            .value = M31.fromCanonical(word.*),
        };
    }
    var provider = try Provider.init(allocator, &source_rows, 7, root);
    defer provider.deinit();
    for (provider.rows) |row| try std.testing.expect(row[17].isOne());
    source_rows[0].preprocessing.hash_id = 8;
    try std.testing.expectError(error.InvalidDirectFrameSource, Provider.init(allocator, &source_rows, 7, root));
    source_rows[0].preprocessing.hash_id = 7;
    source_rows[1].preprocessing.word_index = ROOT_START_INDEX;
    try std.testing.expectError(error.InvalidDirectFrameSource, Provider.init(allocator, &source_rows, 7, root));
}
