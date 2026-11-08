const std = @import("std");
const m31 = @import("../fields/m31.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const config_v2_module = @import("config_v2.zig");
const shared = @import("mod.zig");
pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const M31 = m31.M31;
        pub const PcsConfig = shared.PcsConfig;
        /// The circuit-revision PCS config is field independent; the engine
        /// family's revision constructors name it through the family.
        pub const config_v2 = shared.config_v2;
        pub const TreeVec = shared.TreeVec;
        pub const TreeSubspan = shared.TreeSubspan;
        pub const utils = @import("utils.zig");
        pub const quotients = @import("quotients.zig").ForField(Secure);
        pub const verifier = @import("verifier.zig").ForField(Secure);
        const fri = @import("../fri.zig").ForField(Secure);
        const FriConfig = fri.FriConfig;
        const FriProof = fri.FriProof;
        const FriProofAux = fri.FriProofAux;
        pub fn CommitmentSchemeProof(comptime H: type) type {
            return struct {
                config: PcsConfig,
                commitments: TreeVec(H.Hash),
                sampled_values: TreeVec([][]QM31),
                decommitments: TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)),
                queried_values: TreeVec([][]M31),
                proof_of_work: u64,
                fri_proof: FriProof(H),
                /// The `proving_5a7c5ed` configuration of a revision proof: `config`
                /// is then its FRI/PoW view and the proof's own configuration, with
                /// both lifting heights, is this (the bincode `PcsConfig` of that
                /// revision). Null for the existing lanes, which `config` defines.
                revision_config: ?config_v2_module.PcsConfigV2 = null,

                const Self = @This();

                pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
                    self.commitments.deinit(allocator);
                    self.sampled_values.deinitDeep(allocator);
                    for (self.decommitments.items) |*decommitment| decommitment.deinit(allocator);
                    self.decommitments.deinit(allocator);
                    self.queried_values.deinitDeep(allocator);
                    self.fri_proof.deinit(allocator);
                    self.* = undefined;
                }
            };
        }

        pub fn CommitmentSchemeProofAux(comptime H: type) type {
            return struct {
                unsorted_query_locations: []usize,
                trace_decommitment: TreeVec(vcs_verifier.MerkleDecommitmentLiftedAux(H)),
                fri: FriProofAux(H),

                const Self = @This();

                pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
                    allocator.free(self.unsorted_query_locations);
                    for (self.trace_decommitment.items) |*decommitment_aux| decommitment_aux.deinit(allocator);
                    self.trace_decommitment.deinit(allocator);
                    self.fri.deinit(allocator);
                    self.* = undefined;
                }
            };
        }

        pub fn ExtendedCommitmentSchemeProof(comptime H: type) type {
            return struct {
                proof: CommitmentSchemeProof(H),
                aux: CommitmentSchemeProofAux(H),

                const Self = @This();

                pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
                    self.proof.deinit(allocator);
                    self.aux.deinit(allocator);
                    self.* = undefined;
                }
            };
        }
    };
}
