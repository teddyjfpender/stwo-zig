//! Closed terminal-only suite. Inner native verifiers and public frames remain
//! Poseidon2; this proof is never consumed by a recursive P2 parent.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Kind = @import("arithmetic.zig").Kind;
pub const R6 = ForArithmetic(.r6);
pub const R7 = ForArithmetic(.r7);
pub const O = R6.O;
pub const H = R6.H;
pub const Channel = R6.Channel;
pub const MC = R6.MC;
pub const E = R6.E;
pub const fri_policy = R6.fri_policy;
pub const DOMAIN = R6.DOMAIN;
pub const security_label = R6.security_label;
pub const security_qualified = false;
pub const production_admission = false;
pub fn ForArithmetic(comptime kind: Kind) type {
    return struct {
        pub const O = Core.fields.om31.OM31;
        pub const H = Core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
        pub const Channel = Core.channel.raw_mod_m31.Om31Channel;
        pub const fri_policy = @import("../../op_profile.zig").Profile.op_control_b2_q144_p0_fold4_v1;
        pub const DOMAIN = if (kind == .r6) "opstack/terminal-only/R6/plain-blake2s256/raw-mod-OM31/b2-q144-p0-fold4/v1\x00" else "opstack/terminal-only/R7-inputs/plain-blake2s256/raw-mod-OM31/b2-q144-p0-fold4/v1\x00";
        pub const MC = struct {
            pub const Channel = Core.channel.raw_mod_m31.Om31Channel;
            pub const MerkleHasher = Core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
            pub const protocol_revision = Core.protocol_revision.Revision.stwo_7b211ed;
            pub fn mixRoot(channel: *Core.channel.raw_mod_m31.Om31Channel, root: Core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher.Hash) void {
                Core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleChannel.mixRoot(&channel.inner, root);
            }
            pub fn identity() [32]u8 {
                var h = std.crypto.hash.sha2.Sha256.init(.{});
                h.update(ForArithmetic(kind).DOMAIN);
                h.update(&Core.channel.raw_mod_m31.om31_profile.identity());
                h.update("Merkle:plain-blake2s256/roots32/stwo_7b211ed\x00");
                return h.finalResult();
            }
        };
        pub const E = Engine.engine.ForField(Core.fields.om31.OM31).ProverEngine(@import("stwo_cpu_backend").CpuBackend, ForArithmetic(kind).H, ForArithmetic(kind).MC, ForArithmetic(kind).Channel);
        pub const security_label = "128-bit security target under documented assumptions";
        pub const security_qualified = false;
        pub const production_admission = false;
    };
}
