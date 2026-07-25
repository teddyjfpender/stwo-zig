//! Native Blake policy for descriptor-driven SWPC reconstruction.

const shared = @import("../common/proof_decode.zig");
const layout = @import("layout.zig");
const geometry_mod = @import("geometry.zig");
const pcs = @import("stwo_core").pcs;

pub const Error = shared.Error;

const Descriptor = struct {
    pub fn geometry(protocol: anytype) !geometry_mod.Geometry {
        return geometry_mod.admitRequest(.{
            .statement = .{
                .log_n_rows = protocol.log_n_rows,
                // SWPC names the second statement word generically. Blake
                // binds that word to the number of trace-generation rounds.
                .n_rounds = protocol.sequence_len,
            },
            .protocol = pcs.PcsConfig{
                .pow_bits = protocol.pow_bits,
                .fri_config = .{
                    .log_blowup_factor = protocol.log_blowup_factor,
                    .log_last_layer_degree_bound = protocol.log_last_layer_degree_bound,
                    .n_queries = protocol.n_queries,
                    .fold_step = protocol.fold_step,
                },
                .lifting_log_size = protocol.lifting_log_size,
            },
        });
    }
};

const Decoder = shared.DecoderFor(layout.Layout, Descriptor);

pub const OwnedProofWire = Decoder.OwnedProofWire;
pub const decodeProof = Decoder.decodeProof;
