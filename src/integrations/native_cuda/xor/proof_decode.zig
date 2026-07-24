//! Native XOR policy for descriptor-driven SWPC reconstruction.

const pcs = @import("stwo_core").pcs;
const geometry_mod = @import("geometry.zig");
const layout = @import("layout.zig");
const shared = @import("../common/proof_decode.zig");

pub const Error = shared.Error;

const Descriptor = struct {
    pub fn geometry(protocol: anytype) !geometry_mod.Geometry {
        return geometry_mod.admit(
            .{
                .log_size = protocol.log_n_rows,
                .log_step = protocol.sequence_len,
                // The public offset is transcript-bound by the caller. It does
                // not alter proof topology or reconstruction cardinalities.
                .offset = 0,
            },
            .{
                .pow_bits = protocol.pow_bits,
                .fri_config = .{
                    .log_blowup_factor = protocol.log_blowup_factor,
                    .log_last_layer_degree_bound = protocol.log_last_layer_degree_bound,
                    .n_queries = protocol.n_queries,
                    .fold_step = protocol.fold_step,
                },
                .lifting_log_size = protocol.lifting_log_size,
            },
        );
    }
};

const Decoder = shared.DecoderFor(layout.Layout, Descriptor);

pub const OwnedProofWire = Decoder.OwnedProofWire;
pub const decodeProof = Decoder.decodeProof;

test "XOR decoder descriptor admits the canonical protocol" {
    const protocol = @import("../../../backends/cuda/runtime/proof_assembly/stark_bundle.zig").Protocol{
        .log_n_rows = 14,
        .sequence_len = 2,
        .pow_bits = 10,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
        .lifting_log_size = null,
        .commitment_root_count = 3,
        .fri_root_count = 14,
        .decommit_tree_count = 17,
    };
    const geometry = try Descriptor.geometry(protocol);
    try @import("std").testing.expectEqual(@as(u32, 14), geometry.statement.log_size);
    try @import("std").testing.expectEqual(@as(u32, 2), geometry.statement.log_step);
    try @import("std").testing.expectEqual(pcs.PcsConfig.default(), geometry.protocol);
}
