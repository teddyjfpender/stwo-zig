//! Wide-Fibonacci policy for descriptor-driven SWPC reconstruction.

const shared = @import("../common/proof_decode.zig");
const layout = @import("layout.zig");
const request = @import("request.zig");

pub const Error = shared.Error;

const Descriptor = struct {
    pub fn geometry(protocol: anytype) !request.Geometry {
        return request.admit(.{
            .statement = .{
                .log_n_rows = protocol.log_n_rows,
                .sequence_len = protocol.sequence_len,
            },
            .protocol = .{
                .pow_bits = protocol.pow_bits,
                .log_blowup_factor = protocol.log_blowup_factor,
                .log_last_layer_degree_bound = protocol.log_last_layer_degree_bound,
                .n_queries = protocol.n_queries,
                .fold_step = protocol.fold_step,
                .lifting_log_size = protocol.lifting_log_size,
            },
        });
    }
};

const Decoder = shared.DecoderFor(layout.Layout, Descriptor);

pub const OwnedProofWire = Decoder.OwnedProofWire;
pub const decodeProof = Decoder.decodeProof;
