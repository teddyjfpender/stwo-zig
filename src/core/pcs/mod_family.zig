const std = @import("std");
const m31 = @import("../fields/m31.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
const config_v2 = @import("config_v2.zig");
const shared = @import("mod.zig");
pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const M31 = m31.M31;
        pub const PcsConfig = shared.PcsConfig;
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
                revision_config: ?config_v2.PcsConfigV2 = null,

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

        test "pcs config: security bits" {
            const cfg = PcsConfig{
                .pow_bits = 42,
                .fri_config = FriConfig.init(10, 10, 70) catch unreachable,
            };
            try @import("std").testing.expectEqual(@as(u32, 742), cfg.securityBits());
        }

        test "pcs proof containers: deinit owned memory" {
            const Hasher = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
            const Proof = CommitmentSchemeProof(Hasher);
            const ProofAux = CommitmentSchemeProofAux(Hasher);
            const ExtendedProof = ExtendedCommitmentSchemeProof(Hasher);
            const MerkleAux = vcs_verifier.MerkleDecommitmentLiftedAux(Hasher);
            const LayerAux = fri.FriLayerProofAux(Hasher);
            const alloc = std.testing.allocator;

            const commitments = TreeVec(Hasher.Hash).initOwned(try alloc.dupe(Hasher.Hash, &[_]Hasher.Hash{
                [_]u8{0} ** 32,
            }));
            const sampled_col = try alloc.dupe(QM31, &[_]QM31{QM31.one()});
            const sampled_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_col});
            const sampled_values = TreeVec([][]QM31).initOwned(try alloc.dupe([][]QM31, &[_][][]QM31{sampled_tree}));

            const decommitments = TreeVec(vcs_verifier.MerkleDecommitmentLifted(Hasher)).initOwned(
                try alloc.dupe(vcs_verifier.MerkleDecommitmentLifted(Hasher), &[_]vcs_verifier.MerkleDecommitmentLifted(Hasher){
                    .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                }),
            );

            const queried_col = try alloc.dupe(M31, &[_]M31{M31.one()});
            const queried_tree = try alloc.dupe([]M31, &[_][]M31{queried_col});
            const queried_values = TreeVec([][]M31).initOwned(try alloc.dupe([][]M31, &[_][][]M31{queried_tree}));

            const proof = Proof{
                .config = PcsConfig.default(),
                .commitments = commitments,
                .sampled_values = sampled_values,
                .decommitments = decommitments,
                .queried_values = queried_values,
                .proof_of_work = 7,
                .fri_proof = .{
                    .first_layer = .{
                        .fri_witness = try alloc.alloc(QM31, 0),
                        .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                        .commitment = [_]u8{1} ** 32,
                    },
                    .inner_layers = try alloc.alloc(fri.FriLayerProof(Hasher), 0),
                    .last_layer_poly = @import("../poly/line.zig").LinePoly.initOwned(
                        try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
                    ),
                },
            };

            const proof_aux = ProofAux{
                .unsorted_query_locations = try alloc.dupe(usize, &[_]usize{ 1, 0 }),
                .trace_decommitment = TreeVec(MerkleAux).initOwned(try alloc.dupe(MerkleAux, &[_]MerkleAux{
                    .{ .all_node_values = try alloc.alloc([]MerkleAux.NodeValue, 0) },
                })),
                .fri = .{
                    .first_layer = LayerAux{
                        .all_values = try alloc.alloc([]LayerAux.IndexedValue, 0),
                        .decommitment = MerkleAux{
                            .all_node_values = try alloc.alloc([]MerkleAux.NodeValue, 0),
                        },
                    },
                    .inner_layers = try alloc.alloc(LayerAux, 0),
                },
            };

            var ext = ExtendedProof{
                .proof = proof,
                .aux = proof_aux,
            };
            ext.deinit(alloc);
        }
    };
}
