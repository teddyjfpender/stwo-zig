//! Wide-Fibonacci header policy for the shared resident proof bundle.

const std = @import("std");
const layout = @import("layout.zig");
const request = @import("request.zig");
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
            geometry.protocol.log_last_layer_degree_bound,
        );
        return .{
            try shared.mul(geometry.committed_tree_count, 8),
            try shared.mul(geometry.sampled_value_count, 4),
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
        var header = [_]u32{0} ** fixed_header_words;
        header[0] = magic;
        header[1] = version;
        header[2] = try shared.u32Count(total_words);
        header[3] = section_count;
        header[4] = geometry.statement.log_n_rows;
        header[5] = geometry.statement.sequence_len;
        header[6] = geometry.protocol.pow_bits;
        header[7] = geometry.protocol.log_blowup_factor;
        header[8] = geometry.protocol.log_last_layer_degree_bound;
        header[9] = try shared.u32Count(geometry.protocol.n_queries);
        header[10] = geometry.protocol.fold_step;
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

test "wide proof sections preserve exact wire cardinalities" {
    const geometry = try request.admit(.{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    var logical = try layout.Layout.init(std.testing.allocator, geometry);
    defer logical.deinit(std.testing.allocator);
    var openings = try topology.Decommit.init(
        std.testing.allocator,
        logical,
    );
    defer openings.deinit(std.testing.allocator);
    var bundle = try Bundle.init(
        std.testing.allocator,
        logical,
        openings,
    );
    defer bundle.deinit(std.testing.allocator);
    try bundle.validate(openings.assembly_words);

    try std.testing.expectEqual(
        @as(usize, 3 * 8),
        bundle.section(.trace_commitments).words,
    );
    try std.testing.expectEqual(
        @as(usize, 108 * 4),
        bundle.section(.sampled_values).words,
    );
    try std.testing.expectEqual(
        openings.assembly_words,
        bundle.section(.decommitment).words,
    );
}
