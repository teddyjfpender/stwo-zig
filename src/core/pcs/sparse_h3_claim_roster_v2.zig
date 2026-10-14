//! Shared candidate roster for the accepted sparse Gate's explicit OOD claims.
//!
//! This is a shape and point-order check, not an authenticated source, a
//! polynomial evaluation check, or a PCS admission decision. The caller must
//! derive logs and mask offsets from one sealed key. A future producer can
//! check its sampled-point arrays against the same roster used by the owned
//! verifier before committing the candidate proof.
const std = @import("std");
const circle = @import("../circle.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const pcs_utils = @import("utils.zig");
const projection = @import("../vcs_lifted/sparse_h3_source_projection_v2.zig");

pub const tree_count = projection.source_tree_count;
pub const max_columns = projection.max_source_columns;
pub const claim_count: usize = 73;
pub const MaskOffsets = struct {
    count: u8,
    values: [2]i32,
};
pub const Error = error{
    InvalidClaimLayout,
    InvalidSampleShape,
    SamplePointMismatch,
    InvalidClaimIndex,
} || projection.Error;

pub const Claim = struct {
    tree: u8,
    column: u8,
    sample: u8,
    height: u8,
    offset: i32,
};

pub const ClaimRoster = struct {
    /// First claim for each source column; only entries below counts are set.
    starts: [tree_count][max_columns]u8,
    counts: [tree_count]usize,
    claims: [claim_count]Claim,

    /// Pin the complete accepted column order and expand one or two explicit
    /// claims per column. No periodicity claim is inserted here.
    pub fn init(
        logs: [tree_count][]const u32,
        offsets: [tree_count][]const MaskOffsets,
    ) Error!ClaimRoster {
        try projection.validateAcceptedH3Logs(logs);
        var out: ClaimRoster = undefined;
        out.starts = std.mem.zeroes([tree_count][max_columns]u8);
        var at: usize = 0;
        for (logs, offsets, 0..) |tree_logs, tree_offsets, tree| {
            if (tree_offsets.len != tree_logs.len) return error.InvalidClaimLayout;
            out.counts[tree] = tree_logs.len;
            for (tree_logs, tree_offsets, 0..) |height, entry, column| {
                const has_two = tree == 2 and ((column >= 4 and column <= 7) or column >= 16);
                if (entry.count != @as(u8, if (has_two) 2 else 1) or
                    (entry.count == 1 and entry.values[1] != 0) or
                    at + entry.count > claim_count)
                    return error.InvalidClaimLayout;
                out.starts[tree][column] = @intCast(at);
                for (0..entry.count) |sample| {
                    out.claims[at] = .{
                        .tree = @intCast(tree),
                        .column = @intCast(column),
                        .sample = @intCast(sample),
                        .height = @intCast(height),
                        .offset = entry.values[sample],
                    };
                    at += 1;
                }
            }
        }
        if (at != claim_count) return error.InvalidClaimLayout;
        return out;
    }

    /// Native PCS receives this top-height masked point before its sampled
    /// coefficient evaluator folds it down to the source column's height.
    pub fn producerPoint(
        self: *const ClaimRoster,
        claim_index: usize,
        ood_point: circle.CirclePointQM31,
        mask_log: u32,
    ) Error!circle.CirclePointQM31 {
        if (claim_index >= claim_count) return error.InvalidClaimIndex;
        if (mask_log != 16) return error.InvalidSampleShape;
        const shift = canonic.CanonicCoset.new(mask_log).step()
            .mulSigned(self.claims[claim_index].offset);
        return ood_point.add(.{
            .x = qm31.QM31.fromBase(shift.x),
            .y = qm31.QM31.fromBase(shift.y),
        });
    }

    /// The verifier's point for this explicit source-height quotient claim.
    pub fn normalizedClaimPoint(
        self: *const ClaimRoster,
        claim_index: usize,
        ood_point: circle.CirclePointQM31,
        mask_log: u32,
    ) Error!circle.CirclePointQM31 {
        const raw = try self.producerPoint(claim_index, ood_point, mask_log);
        return raw.repeatedDouble(17 - self.claims[claim_index].height);
    }

    /// Check the exact native prover TreeVec order and its normalized sample
    /// points. This deliberately cannot establish that a sampled value equals
    /// its committed source polynomial at that point.
    pub fn validateProducerSamples(
        self: *const ClaimRoster,
        ood_point: circle.CirclePointQM31,
        mask_log: u32,
        points: pcs_utils.TreeVec([][]circle.CirclePointQM31),
        values: pcs_utils.TreeVec([][]qm31.QM31),
    ) Error!void {
        if (mask_log != 16 or points.items.len != tree_count or values.items.len != tree_count)
            return error.InvalidSampleShape;
        for (self.counts, 0..) |count, tree| {
            if (points.items[tree].len != count or values.items[tree].len != count)
                return error.InvalidSampleShape;
            for (0..count) |column| {
                const start = self.starts[tree][column];
                const n: usize = if (start + 1 < claim_count and
                    self.claims[start + 1].tree == tree and
                    self.claims[start + 1].column == column) 2 else 1;
                if (points.items[tree][column].len != n or values.items[tree][column].len != n)
                    return error.InvalidSampleShape;
                for (0..n) |sample| {
                    const want = try self.producerPoint(start + sample, ood_point, mask_log);
                    if (!points.items[tree][column][sample].eql(want))
                        return error.SamplePointMismatch;
                }
            }
        }
    }
};

test "shared sparse claim roster checks native producer point order and shape" {
    const fixed = [_]u32{ 5, 5, 5, 11, 11, 11, 11, 11, 11, 11, 11, 17 };
    const main = [_]u32{ 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 17 };
    const interaction = [_]u32{ 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 17, 17, 17, 17 };
    const composition = [_]u32{17} ** 8;
    const logs = [tree_count][]const u32{ &fixed, &main, &interaction, &composition };
    var offsets: [tree_count][24]MaskOffsets = undefined;
    var offset_views: [tree_count][]const MaskOffsets = undefined;
    for (logs, 0..) |tree_logs, tree| {
        offset_views[tree] = offsets[tree][0..tree_logs.len];
        for (tree_logs, 0..) |_, column| {
            const two = tree == 2 and ((column >= 4 and column <= 7) or column >= 16);
            offsets[tree][column] = .{
                .count = if (two) 2 else 1,
                .values = .{ @intCast(tree * 100 + column), if (two) @intCast(tree * 100 + column + 1) else 0 },
            };
        }
    }
    const roster = try ClaimRoster.init(logs, offset_views);
    try std.testing.expectEqual(@as(u8, 21), roster.starts[1][9]);
    try std.testing.expectEqual(@as(u8, 33), roster.starts[2][4]);
    try std.testing.expectEqual(@as(u8, 2), roster.claims[34].tree);
    try std.testing.expectEqual(@as(u8, 4), roster.claims[34].column);
    try std.testing.expectEqual(@as(u8, 1), roster.claims[34].sample);

    const seed = qm31.QM31.fromU32Unchecked(9, 3, 7, 2);
    const ood_point = try circle.secureFieldPointFromRandomSeedChecked(seed);
    var point_storage: [tree_count][24][2]circle.CirclePointQM31 = undefined;
    var value_storage: [tree_count][24][2]qm31.QM31 = undefined;
    var point_views: [tree_count][24][]circle.CirclePointQM31 = undefined;
    var value_views: [tree_count][24][]qm31.QM31 = undefined;
    var point_trees: [tree_count][][]circle.CirclePointQM31 = undefined;
    var value_trees: [tree_count][][]qm31.QM31 = undefined;
    for (roster.counts, 0..) |count, tree| {
        point_trees[tree] = point_views[tree][0..count];
        value_trees[tree] = value_views[tree][0..count];
        for (0..count) |column| {
            const n = offsets[tree][column].count;
            point_views[tree][column] = point_storage[tree][column][0..n];
            value_views[tree][column] = value_storage[tree][column][0..n];
            for (0..n) |sample| {
                const index = roster.starts[tree][column] + sample;
                point_views[tree][column][sample] = try roster.producerPoint(index, ood_point, 16);
                value_views[tree][column][sample] = qm31.QM31.zero();
            }
        }
    }
    const points = pcs_utils.TreeVec([][]circle.CirclePointQM31).initOwned(&point_trees);
    const values = pcs_utils.TreeVec([][]qm31.QM31).initOwned(&value_trees);
    try roster.validateProducerSamples(ood_point, 16, points, values);
    point_views[2][4][1] = point_views[2][4][0];
    try std.testing.expectError(error.SamplePointMismatch, roster.validateProducerSamples(ood_point, 16, points, values));
    point_views[2][4][1] = try roster.producerPoint(34, ood_point, 16);
    const normalized = try roster.normalizedClaimPoint(34, ood_point, 16);
    try std.testing.expect(normalized.eql(point_views[2][4][1].repeatedDouble(17 - roster.claims[34].height)));
    value_views[2][4] = value_views[2][4][0..1];
    try std.testing.expectError(error.InvalidSampleShape, roster.validateProducerSamples(ood_point, 16, points, values));
    try std.testing.expectError(error.InvalidSampleShape, roster.validateProducerSamples(ood_point, 15, points, values));
    offsets[2][4].count = 1;
    try std.testing.expectError(error.InvalidClaimLayout, ClaimRoster.init(logs, offset_views));
}
