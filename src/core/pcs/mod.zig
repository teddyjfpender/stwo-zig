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
