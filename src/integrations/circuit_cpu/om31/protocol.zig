//! Concrete native OM31 circuit proof family; independent of legacy V2 proofs.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
pub const O = core.fields.om31.OM31;
pub const Q = core.fields.qm31.QM31;
pub const M = core.fields.m31.M31;
pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const MC = struct {
    pub fn mixRoot(ch: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&ch.inner, root);
    }
};
pub const Engine = prover.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Channel);
pub const Scheme = Engine.Scheme;
pub const Proof = core.proof.ForField(O).StarkProof(H);
pub const PcsConfig = core.pcs.ForField(O).PcsConfig;
/// Named outer (recursion-layer) PCS profiles. The outer profile is separate
/// from every native profile: native AOT catalogues/authorities are untouched.
/// Selection is process policy (driver/receiver), never proof bytes. The
/// profile's config is mixed into every outer channel, its domain string is
/// hashed into every outer authority identity, the wire header and the
/// transcript, and a proof's config must equal the receiver's exactly.
pub const Profile = enum {
    /// Historical accepted outer profile (r1): blowup 2, 108 queries, 20-bit PoW.
    /// Conjectured bits 1*108 + 20 = 128. Default; bytes unchanged.
    r1_b2_q108_p20_fold4,
    /// M3 recursion profile: blowup 4, 51 queries, 26-bit PoW, fold-4.
    /// Conjectured bits 2*51 + 26 = 128 under the same ethSTARK assumption.
    m3_b4_q51_p26_fold4,
    /// M3 alternative: blowup 8, 34 queries, 26-bit PoW. 3*34 + 26 = 128.
    m3_b8_q34_p26_fold4,
    /// M5 canonical recursion (canon-vk; profiles registry name
    /// `m5_outer_canonical_r1_b2_q108_p20_fold4_v1`): r1 PCS, every node
    /// padded to the uniform outer shape S_OUT_V1 (one fold VK per arity).
    m5_outer_canonical_r1_b2_q108_p20_fold4_v1,
    /// M5 canonical recursion under the m3 PCS (registry
    /// `m5_outer_canonical_m3_b4_q51_p26_fold4_v1`).
    m5_outer_canonical_m3_b4_q51_p26_fold4_v1,
    /// M6 recursion cell diet, stage 1 (diet-wire; component `kary-v1`, k = 3):
    /// r1 PCS, exact node shapes, every fold has arity 3 (the last fold of a
    /// level takes the 2-child remainder, ready_dag streaming carry). A 3-ary
    /// fold keeps the leaf's padded shape (blake_g_gate 2^23), so it fits the
    /// device where a 4-ary fold (8.68 M G rows -> 2^24) does not. Arity is a
    /// profile constant: STWO_RV64_FOLD_ARITY may only restate 3.
    m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1,
    /// M6 recursion cell diet, stage 2 (diet-wire; components `kary-v1` k = 4
    /// and `merkle-cap-v1` c = 3): r1 PCS, exact shapes, 4-ary folds whose
    /// in-circuit child verifier stops every Merkle path 3 levels below the
    /// root at a guessed, root-checked 8-node cap (rv64-m6-diet-wire.md
    /// section 5). Leaves are unchanged circuits (full paths) under this
    /// profile's domain.
    m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1,

    pub fn parse(text: []const u8) !Profile {
        inline for (@typeInfo(Profile).@"enum".fields) |field| {
            if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
        }
        if (std.mem.eql(u8, text, "r1")) return .r1_b2_q108_p20_fold4;
        if (std.mem.eql(u8, text, "m3")) return .m3_b4_q51_p26_fold4;
        return error.UnknownOm31OuterProfile;
    }
    pub fn name(self: Profile) []const u8 {
        return @tagName(self);
    }
    pub fn domainName(self: Profile) []const u8 {
        return switch (self) {
            .r1_b2_q108_p20_fold4 => "stwo/circuit/native-om31/q108-p20-fold4/lens-v1",
            .m3_b4_q51_p26_fold4 => "stwo/circuit/native-om31/m3-b4-q51-p26-fold4/lens-v1",
            .m3_b8_q34_p26_fold4 => "stwo/circuit/native-om31/m3-b8-q34-p26-fold4/lens-v1",
            .m5_outer_canonical_r1_b2_q108_p20_fold4_v1 => "stwo/circuit/native-om31/m5-canonical-q108-p20-fold4/lens-v1",
            .m5_outer_canonical_m3_b4_q51_p26_fold4_v1 => "stwo/circuit/native-om31/m5-canonical-m3-b4-q51-p26-fold4/lens-v1",
            .m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1 => "stwo/circuit/native-om31/m6-diet-k3-q108-p20-fold4/lens-v1",
            .m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 => "stwo/circuit/native-om31/m6-diet-k4-cap3-q108-p20-fold4/lens-v1",
        };
    }
    pub fn config(self: Profile) PcsConfig {
        const log_blowup: u32, const queries: usize, const pow: u32 = switch (self) {
            .r1_b2_q108_p20_fold4, .m5_outer_canonical_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 => .{ 1, 108, 20 },
            .m3_b4_q51_p26_fold4, .m5_outer_canonical_m3_b4_q51_p26_fold4_v1 => .{ 2, 51, 26 },
            .m3_b8_q34_p26_fold4 => .{ 3, 34, 26 },
        };
        var fri = core.fri.ForField(O).FriConfig.init(0, log_blowup, queries) catch unreachable;
        fri.fold_step = 4;
        return .{ .pow_bits = pow, .fri_config = fri };
    }
    /// M5 canonical recursion profiles pad every node to one outer shape.
    pub fn canonical(self: Profile) bool {
        return self == .m5_outer_canonical_r1_b2_q108_p20_fold4_v1 or self == .m5_outer_canonical_m3_b4_q51_p26_fold4_v1;
    }
    /// Fold arity fixed by the profile (null: the blowup default, 2 for b2 and
    /// 4 otherwise, which STWO_RV64_FOLD_ARITY may override).
    pub fn requiredFoldArity(self: Profile) ?usize {
        return switch (self) {
            .m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1 => 3,
            .m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 => 4,
            else => null,
        };
    }
    /// Merkle cap log of the in-circuit child verifier of FOLD circuits
    /// (0 = full authentication paths, every pre-M6 profile).
    pub fn foldMerkleCapLog(self: Profile) u32 {
        return switch (self) {
            .m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 => 3,
            else => 0,
        };
    }
    /// ethSTARK-style conjectured FRI bits: log_blowup * queries + PoW.
    pub fn conjecturedBits(self: Profile) u32 {
        const c = self.config();
        return c.fri_config.log_blowup_factor * @as(u32, @intCast(c.fri_config.n_queries)) + c.pow_bits;
    }
};
pub const DEFAULT_PROFILE: Profile = .r1_b2_q108_p20_fold4;
pub const PROFILE_ENV = "STWO_RV64_OUTER_PROFILE";
/// Historical r1 domain string. This is NOT the active outer profile: every
/// identity, wire header, transcript, class key and report must use
/// `domainName()` (adversarial review, canon-vk: a `pub const domain` kept the
/// old name and silently meant r1 under every other profile, so a consumer
/// built against it, e.g. a VK-table header, would label a canonical/m3 table
/// as r1). Renamed so such callers fail to compile instead.
pub const r1_domain = Profile.r1_b2_q108_p20_fold4.domainName();
const unset: u8 = 0xff;
var selected = std.atomic.Value(u8).init(unset);
var locked = std.atomic.Value(bool).init(false);
/// Process-wide outer profile. First use resolves `STWO_RV64_OUTER_PROFILE`
/// (default r1); afterwards the selection is fixed for the process.
pub fn active() Profile {
    const current = selected.load(.acquire);
    if (current != unset) {
        locked.store(true, .release);
        return @enumFromInt(current);
    }
    var buffer: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    // Only an absent variable selects the default; any other lookup failure
    // (e.g. a value longer than the buffer) fails closed like an unknown name.
    const resolved: Profile = if (std.process.getEnvVarOwned(fba.allocator(), PROFILE_ENV)) |text|
        Profile.parse(text) catch @panic("unknown STWO_RV64_OUTER_PROFILE")
    else |err| switch (err) {
        error.EnvironmentVariableNotFound => DEFAULT_PROFILE,
        else => @panic("unreadable STWO_RV64_OUTER_PROFILE"),
    };
    _ = selected.cmpxchgStrong(unset, @intFromEnum(resolved), .acq_rel, .acquire);
    locked.store(true, .release);
    return @enumFromInt(selected.load(.acquire));
}
/// Explicit receiver/driver policy. Refuses to change a profile already used.
pub fn select(profile: Profile) !void {
    if (locked.load(.acquire) and selected.load(.acquire) != @intFromEnum(profile)) return error.Om31OuterProfileLocked;
    selected.store(@intFromEnum(profile), .release);
}
/// Test-only override; production code must use `select` before first use.
pub fn selectForTesting(profile: Profile) void {
    if (!@import("builtin").is_test) @compileError("selectForTesting is test-only");
    selected.store(@intFromEnum(profile), .release);
}
/// Fallible env check for process entry points: an unknown or unreadable
/// `STWO_RV64_OUTER_PROFILE` is a clean error exit, never a panic (corpus P03).
pub fn checkEnv() !Profile {
    var buffer: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const text = std.process.getEnvVarOwned(fba.allocator(), PROFILE_ENV) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return DEFAULT_PROFILE,
        else => return error.UnreadableOm31OuterProfile,
    };
    return Profile.parse(text);
}
pub fn domainName() []const u8 {
    return active().domainName();
}
pub fn targetConfig() !PcsConfig {
    return active().config();
}
pub fn validateConfig(config: PcsConfig) !void {
    if (!std.meta.eql(config, try targetConfig())) return error.UnsupportedOm31CircuitProfile;
}
pub fn mixProfile(ch: *Channel) void {
    ch.mixU32s(&.{ 0x434f4d38, 1, 8 });
    var words: [8]u32 = undefined;
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(domainName(), &identity, .{});
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, identity[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
test "om31 outer profile is exact and separate from legacy" {
    const config = try targetConfig();
    try validateConfig(config);
    var bad = config;
    bad.fri_config.n_queries = 70;
    try std.testing.expectError(error.UnsupportedOm31CircuitProfile, validateConfig(bad));
    var original = Channel.init();
    const before = original.digestBytes();
    mixProfile(&original);
    try std.testing.expect(!std.mem.eql(u8, &before, &original.digestBytes()));
}
test "om31 outer profiles are 128 conjectured bits, distinct and exact" {
    for ([_]Profile{ .r1_b2_q108_p20_fold4, .m3_b4_q51_p26_fold4, .m3_b8_q34_p26_fold4 }) |profile| {
        try std.testing.expectEqual(@as(u32, 128), profile.conjecturedBits());
        try std.testing.expectEqual(profile, try Profile.parse(profile.name()));
    }
    const r1 = Profile.r1_b2_q108_p20_fold4.config();
    var historical = try core.fri.ForField(O).FriConfig.init(0, 1, 108);
    historical.fold_step = 4;
    try std.testing.expect(std.meta.eql(r1, PcsConfig{ .pow_bits = 20, .fri_config = historical }));
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/q108-p20-fold4/lens-v1", r1_domain);
    try std.testing.expect(!std.mem.eql(u8, Profile.m3_b4_q51_p26_fold4.domainName(), r1_domain));
    try std.testing.expectEqual(Profile.m3_b4_q51_p26_fold4, try Profile.parse("m3"));
    try std.testing.expectError(error.UnknownOm31OuterProfile, Profile.parse("m3_b4_q50_p26_fold4"));
    const before = active();
    defer selectForTesting(before);
    selectForTesting(.m3_b4_q51_p26_fold4);
    try std.testing.expectError(error.UnsupportedOm31CircuitProfile, validateConfig(r1));
    try validateConfig(Profile.m3_b4_q51_p26_fold4.config());
    try std.testing.expectError(error.Om31OuterProfileLocked, select(.r1_b2_q108_p20_fold4));
    var a = Channel.init();
    mixProfile(&a);
    selectForTesting(.r1_b2_q108_p20_fold4);
    var b = Channel.init();
    mixProfile(&b);
    try std.testing.expect(!std.mem.eql(u8, &a.digestBytes(), &b.digestBytes()));
}
test "om31 m5 canonical outer profiles: registry domains, base PCS configs, fail-closed parse" {
    const r = Profile.m5_outer_canonical_r1_b2_q108_p20_fold4_v1;
    const m = Profile.m5_outer_canonical_m3_b4_q51_p26_fold4_v1;
    try std.testing.expect(std.meta.eql(r.config(), Profile.r1_b2_q108_p20_fold4.config()));
    try std.testing.expect(std.meta.eql(m.config(), Profile.m3_b4_q51_p26_fold4.config()));
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m5-canonical-q108-p20-fold4/lens-v1", r.domainName());
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m5-canonical-m3-b4-q51-p26-fold4/lens-v1", m.domainName());
    try std.testing.expect(r.canonical() and m.canonical() and !Profile.r1_b2_q108_p20_fold4.canonical());
    try std.testing.expectEqual(@as(u32, 128), r.conjecturedBits());
    try std.testing.expectEqual(@as(u32, 128), m.conjecturedBits());
    try std.testing.expectEqual(r, try Profile.parse(r.name()));
    try std.testing.expectError(error.UnknownOm31OuterProfile, Profile.parse("m5_outer_canonical_r1"));
}
test "om31 m6 diet k3 outer profile: registry domain, r1 PCS, arity constant, fail-closed parse" {
    const d = Profile.m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1;
    try std.testing.expect(std.meta.eql(d.config(), Profile.r1_b2_q108_p20_fold4.config()));
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m6-diet-k3-q108-p20-fold4/lens-v1", d.domainName());
    try std.testing.expectEqual(@as(u32, 128), d.conjecturedBits());
    try std.testing.expect(!d.canonical());
    try std.testing.expectEqual(@as(?usize, 3), d.requiredFoldArity());
    try std.testing.expectEqual(@as(?usize, null), Profile.r1_b2_q108_p20_fold4.requiredFoldArity());
    try std.testing.expectEqual(d, try Profile.parse(d.name()));
    // T_rec outer_profile ids (= enum + 1) of the existing profiles are unchanged by the append.
    try std.testing.expectEqual(@as(usize, 4), @intFromEnum(Profile.m5_outer_canonical_m3_b4_q51_p26_fold4_v1));
    try std.testing.expectEqual(@as(usize, 5), @intFromEnum(d));
    inline for (@typeInfo(Profile).@"enum".fields) |field| {
        const other: Profile = @enumFromInt(field.value);
        if (other != d) try std.testing.expect(!std.mem.eql(u8, other.domainName(), d.domainName()));
    }
}
test "om31 m6 diet k4 cap3 outer profile: domain, r1 PCS, arity 4, cap 3 on folds only" {
    const d = Profile.m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1;
    try std.testing.expect(std.meta.eql(d.config(), Profile.r1_b2_q108_p20_fold4.config()));
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m6-diet-k4-cap3-q108-p20-fold4/lens-v1", d.domainName());
    try std.testing.expectEqual(@as(?usize, 4), d.requiredFoldArity());
    try std.testing.expectEqual(@as(u32, 3), d.foldMerkleCapLog());
    try std.testing.expectEqual(@as(u32, 0), Profile.m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1.foldMerkleCapLog());
    try std.testing.expectEqual(@as(u32, 0), Profile.r1_b2_q108_p20_fold4.foldMerkleCapLog());
    try std.testing.expectEqual(@as(usize, 6), @intFromEnum(d));
    try std.testing.expectEqual(d, try Profile.parse(d.name()));
}
