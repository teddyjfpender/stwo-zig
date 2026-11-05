//! One physical protocol authority for CPU and truth workers. Immutable M31
//! setup is shared by identity; each request/channel/manifest/claim vector is
//! bound independently. This is the new explicit OM profile, not legacy Q.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Manifest = @import("manifest.zig");
pub const O = core.fields.om31.OM31;
pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const MC = struct {
    pub fn mixRoot(ch: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&ch.inner, root);
    }
};
pub const Prover = engine.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Channel);
pub const Scheme = Prover.Scheme;
pub const PcsConfig = core.pcs.ForField(O).PcsConfig;
pub const Proof = core.proof.ForField(O).StarkProof(H);
pub const Wire = @import("stwo_proof_wire").ForField(O);
/// Receiver-owned supported construction, shared by whole execution and every
/// physical worker entrypoint. This is the current experimental beta1 profile,
/// not admission of the separately unqualified beta2/128 candidate.
pub fn validateConfig(config: PcsConfig) !void {
    return validateAtRate(config, 1);
}
/// Engineering candidate only; callers also need independently reconstructed
/// fixed authority at the config's blowup. Never selected by control.
/// Blowup 2 keeps the historical beta2 structural family (the proven
/// beta2/q256/P0 profile plus fixture-sized query counts, unchanged bytes);
/// blowup 2 at rate 1 is admitted ONLY as the exact named conjectured128
/// b2/q108/P20/fold4 profile. Receivers (gkr_main) always use an exact
/// `om31_security_candidate.configFor(profile)`.
pub fn validateCandidateConfig(config: PcsConfig) !void {
    if (config.fri_config.log_blowup_factor == 1) {
        const profile = Candidate.profileFor(config) catch return error.UnsupportedWideServicesConfig;
        if (!profile.conjectured()) return error.UnsupportedWideServicesConfig;
        return validateAtRate(config, 1);
    }
    if (@import("keccak_family_profile.zig").isConfig(config)) return validateAtRate(config, 4);
    return validateAtRate(config, 2);
}
/// Named profile of an admitted candidate config, or null for the legacy
/// beta2 structural family (historical statement/channel bytes).
pub fn candidateProfile(config: PcsConfig) ?Candidate.Profile {
    return Candidate.profileFor(config) catch null;
}
pub const Candidate = @import("../../../word16_execution/om31_security_candidate.zig");
fn validateAtRate(config: PcsConfig, rate: u32) !void {
    const max_pow = core.channel.blake2s.pow_order.MAX_POW_BITS;
    if (config.pow_bits > max_pow or config.fri_config.n_queries == 0 or config.fri_config.n_queries > 1024 or
        config.fri_config.log_blowup_factor != rate or config.fri_config.log_last_layer_degree_bound != 0 or
        (config.fri_config.fold_step != 1 and config.fri_config.fold_step != 4) or config.lifting_log_size != null)
        return error.UnsupportedWideServicesConfig;
}
pub fn digest(ch: *Channel, value: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
/// Shared framing visitor. Only the ordinal and statement may be circuit
/// wires; kind/profile framing is independently admitted topology authority.
pub fn emitBegin(expected: anytype, writer: anytype) void {
    writer.header(&.{ 0x57474b4f, 1, 8, @intFromEnum(expected.kind) }, expected.ordinal);
    var profile: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(Manifest.PROFILE, &profile, .{});
    writer.constantDigest(profile);
    writer.publicDigest(expected.statement);
}
pub fn begin(config: PcsConfig, expected: Manifest.ExpectedWorker) Channel {
    var ch = Channel.init();
    config.mixInto(&ch);
    var writer = struct {
        ch: *Channel,
        pub fn header(self: *@This(), prefix: []const u32, ordinal: u32) void {
            std.debug.assert(prefix.len == 4);
            var words: [5]u32 = undefined;
            @memcpy(words[0..4], prefix);
            words[4] = ordinal;
            self.ch.mixU32s(&words);
        }
        pub fn constantDigest(self: *@This(), value: [32]u8) void {
            digest(self.ch, value);
        }
        pub fn publicDigest(self: *@This(), value: [32]u8) void {
            digest(self.ch, value);
        }
    }{ .ch = &ch };
    emitBegin(expected, &writer);
    return ch;
}
pub fn appendFixed(a: std.mem.Allocator, key: *const @import("../../keccak/shared/key.zig").Key, expected: [32]u8, scheme: *Scheme, ch: *Channel) !void {
    try validateConfig(scheme.config);
    if (!std.mem.eql(u8, &key.root, &expected) or scheme.trees.items.len != 0 or scheme.pending_commit != null or scheme.revision_config != null or scheme.config.fri_config.log_blowup_factor != key.suite.pcs.fri_config.log_blowup_factor) return error.WideWorkerFixedAuthorityMismatch;
    var tree = key.tree.retainShared();
    errdefer tree.deinit(key.allocator);
    try scheme.appendCommittedTree(a, tree, ch);
}
pub fn emitManifestAndClaims(manifest: anytype, claims: anytype, writer: anytype) void {
    writer.header(&.{ 0x57474b32, 1 }, @as(u32, @intCast(claims.len)));
    writer.publicDigest(manifest);
    writer.fields(claims);
}
pub fn mixManifestAndClaims(ch: *Channel, manifest: [32]u8, claims: []const O) void {
    var writer = struct {
        ch: *Channel,
        pub fn header(s: *@This(), prefix: []const u32, count: u32) void {
            std.debug.assert(prefix.len == 2);
            s.ch.mixU32s(&.{ prefix[0], prefix[1], count });
        }
        pub fn publicDigest(s: *@This(), value: [32]u8) void {
            digest(s.ch, value);
        }
        pub fn fields(s: *@This(), values: []const O) void {
            s.ch.mixFelts(values);
        }
    }{ .ch = ch };
    emitManifestAndClaims(manifest, claims, &writer);
}
pub fn encodePhysical(a: std.mem.Allocator, proof: Proof) ![]u8 {
    return Wire.encodeProofBytesBinary(a, proof);
}
pub fn decodePhysical(a: std.mem.Allocator, bytes: []const u8) !Proof {
    return Wire.decodeProofBytesBinary(a, bytes);
}
