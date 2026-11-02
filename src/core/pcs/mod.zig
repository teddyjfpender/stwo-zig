const std = @import("std");
const fri = @import("../fri.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");
pub const utils = @import("utils.zig");
pub const config_v2 = @import("config_v2.zig");
pub const quotients = @import("quotients.zig");
pub const verifier = @import("verifier.zig");

const FriConfig = fri.FriConfig;
const FriProof = fri.FriProof;
const FriProofAux = fri.FriProofAux;
const M31 = m31.M31;
const QM31 = qm31.QM31;
pub const TreeVec = utils.TreeVec;

pub const TreeSubspan = struct {
    tree_index: usize,
    col_start: usize,
    col_end: usize,
};

pub const PcsConfig = struct {
    pow_bits: u32,
    fri_config: FriConfig,
    lifting_log_size: ?u32 = null, // optional Merkle lifting size (stark-v fork)

    pub inline fn securityBits(self: PcsConfig) u32 {
        return self.pow_bits + self.fri_config.securityBits();
    }

    pub fn mixInto(self: PcsConfig, channel: anytype) void {
        const Channel = @typeInfo(@TypeOf(channel)).pointer.child;
        const F = if (@hasDecl(Channel, "SecureField")) Channel.SecureField else QM31;
        const degree = @typeInfo(@TypeOf(F.zero().toM31Array())).array.len;
        var coordinates = [_]M31{M31.zero()} ** degree;
        coordinates[0] = M31.fromU32Unchecked(self.pow_bits);
        coordinates[1] = M31.fromU32Unchecked(self.fri_config.log_blowup_factor);
        coordinates[2] = M31.fromU32Unchecked(@intCast(self.fri_config.n_queries));
        coordinates[3] = M31.fromU32Unchecked(self.fri_config.log_last_layer_degree_bound);
        const packed_config_1 = F.fromM31Array(coordinates);
        if (self.fri_config.fold_step != fri.FOLD_STEP or self.lifting_log_size != null) {
            coordinates = [_]M31{M31.zero()} ** degree;
            coordinates[0] = M31.fromU32Unchecked(self.fri_config.fold_step);
            coordinates[1] = M31.fromU32Unchecked(self.lifting_log_size orelse 0);
            channel.mixFelts(&[_]F{ packed_config_1, F.fromM31Array(coordinates) });
        } else {
            channel.mixFelts(&[_]F{packed_config_1});
        }
    }

    pub fn default() PcsConfig {
        return .{
            .pow_bits = 10,
            .fri_config = FriConfig.default(),
        };
    }
};

pub const ForField = @import("mod_family.zig").ForField;
const Default = ForField(QM31);
pub const CommitmentSchemeProof = Default.CommitmentSchemeProof;
pub const CommitmentSchemeProofAux = Default.CommitmentSchemeProofAux;
pub const ExtendedCommitmentSchemeProof = Default.ExtendedCommitmentSchemeProof;

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
