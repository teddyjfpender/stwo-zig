//! Cairo cardinalities carried through the common resident proof container.

const std = @import("std");
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const common = @import("../../native_cuda/common/proof_bundle.zig");

pub const container_header_words = common.header_words;

pub const Layout = struct {
    protocol: compact.CompactProtocolV1,
};

pub const Decommit = struct {
    capacity_words: usize,
};

const Descriptor = struct {
    pub fn sectionLengths(
        logical: Layout,
        decommit: Decommit,
    ) ![common.section_count]usize {
        const protocol = logical.protocol;
        try protocol.validate();
        if (decommit.capacity_words != protocol.decommitment_capacity_words)
            return error.UnsupportedProtocol;
        return .{
            try mul(protocol.commitment_count, 8) +
                try mul(protocol.interaction_sum_count, 4),
            protocol.sampled_value_words,
            try mul(protocol.fri_tree_count, 8),
            try mul(protocol.final_line_coefficient_count, 4),
            4, // Interaction and query PoW nonces.
            decommit.capacity_words,
        };
    }

    pub fn fixedHeader(
        logical: Layout,
        _: Decommit,
        total_words: usize,
    ) ![common.fixed_header_words]u32 {
        const protocol = logical.protocol;
        return .{
            common.magic,
            common.version,
            try common.u32Count(total_words),
            common.section_count,
            protocol.commitment_count,
            protocol.interaction_sum_count,
            protocol.sampled_value_words,
            protocol.fri_tree_count,
            protocol.final_line_coefficient_count,
            protocol.query_count,
            protocol.query_pow_bits,
            protocol.interaction_pow_bits,
            protocol.max_log_degree_bound,
            protocol.log_blowup_factor,
            protocol.fri_fold_step,
            std.math.maxInt(u32),
        };
    }
};

pub const Bundle = common.BundleFor(Layout, Decommit, Descriptor);

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}
