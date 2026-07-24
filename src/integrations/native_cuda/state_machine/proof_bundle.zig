//! state-machine statement policy for the shared one-read resident proof bundle.

const std = @import("std");
const geometry_mod = @import("geometry.zig");
const layout = @import("layout.zig");
const topology = @import("topology.zig");
const shared = @import("../common/proof_bundle.zig");

pub const magic = shared.magic;
pub const version = shared.version;
pub const fixed_header_words = shared.fixed_header_words;
pub const section_record_words = shared.section_record_words;
pub const SectionKind = shared.SectionKind;
pub const section_count = shared.section_count;
pub const header_words = shared.header_words;
pub const Section = shared.Section;

const Descriptor = struct {
    pub fn sectionLengths(
        logical: layout.Layout,
        decommit: topology.Decommit,
    ) ![section_count]usize {
        const geometry = logical.geometry;
        const last_coefficients = try shared.pow2(
            geometry.protocol.fri_config.log_last_layer_degree_bound,
        );
        return .{
            try shared.mul(geometry.committed_tree_count, 8),
            try shared.mul(geometry_mod.sampled_mask_points, 4),
            try shared.mul(geometry.fri_tree_count, 8),
            try shared.mul(last_coefficients, 4),
            2,
            decommit.assembly_words,
        };
    }

    pub fn fixedHeader(
        logical: layout.Layout,
        _: topology.Decommit,
        total_words: usize,
    ) ![fixed_header_words]u32 {
        const geometry = logical.geometry;
        const fri = geometry.protocol.fri_config;
        var header = [_]u32{0} ** fixed_header_words;
        header[0] = magic;
        header[1] = version;
        header[2] = try shared.u32Count(total_words);
        header[3] = section_count;
        header[4] = geometry.statement.log_n_rows;
        header[5] = 0;
        header[6] = geometry.protocol.pow_bits;
        header[7] = fri.log_blowup_factor;
        header[8] = fri.log_last_layer_degree_bound;
        header[9] = try shared.u32Count(fri.n_queries);
        header[10] = fri.fold_step;
        header[11] = if (geometry.protocol.lifting_log_size) |value|
            value
        else
            std.math.maxInt(u32);
        header[12] = try shared.u32Count(
            geometry.committed_tree_count,
        );
        header[13] = try shared.u32Count(geometry.fri_tree_count);
        header[14] = try shared.u32Count(geometry.decommit_tree_count);
        // The device finalizer replaces this poison with its degree verdict.
        header[15] = std.math.maxInt(u32);
        return header;
    }
};

pub const Bundle = shared.BundleFor(
    layout.Layout,
    topology.Decommit,
    Descriptor,
);

test "state-machine bundle preserves exact three-tree wire cardinalities" {
    const allocator = std.testing.allocator;
    const pcs = @import("stwo_core").pcs;
    const geometry = try geometry_mod.admit(
        .{
            .log_n_rows = 16,
            .initial_state = .{
                @import("stwo_core").fields.m31.M31.fromU64(9),
                @import("stwo_core").fields.m31.M31.fromU64(3),
            },
        },
        pcs.PcsConfig.default(),
    );
    var logical = try layout.Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    var openings = try topology.Decommit.init(allocator, logical);
    defer openings.deinit(allocator);
    var bundle = try Bundle.init(allocator, logical, openings);
    defer bundle.deinit(allocator);
    try bundle.validate(openings.assembly_words);

    try std.testing.expectEqual(
        @as(usize, 3 * 8),
        bundle.section(.trace_commitments).words,
    );
    try std.testing.expectEqual(
        @as(usize, 10 * 4),
        bundle.section(.sampled_values).words,
    );
    try std.testing.expectEqual(
        @as(usize, 16 * 8),
        bundle.section(.fri_commitments).words,
    );
    try std.testing.expectEqual(
        openings.assembly_words,
        bundle.section(.decommitment).words,
    );
    try std.testing.expectEqual(@as(u32, 16), bundle.static_header[4]);
    try std.testing.expectEqual(@as(u32, 0), bundle.static_header[5]);
    try std.testing.expectEqual(@as(u32, 3), bundle.static_header[12]);
    try std.testing.expectEqual(@as(u32, 19), bundle.static_header[14]);
    try std.testing.expectEqual(
        std.math.maxInt(u32),
        bundle.static_header[15],
    );
}
