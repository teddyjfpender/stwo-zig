//! Receiver-derived fields of native protocol `rv64-m5-native-chi-chain/v1`
//! (stream canon-native; spec design/riscv/rv64-m5-canon-native.md
//! sec. 4, encodings ethereum/canon_native.zig). Every value comes from the
//! trusted setup, the admitted requests and the receiver's own fixed
//! authority, never from producer bytes. Selected by receiver/producer policy
//! `STWO_RV64_NATIVE_VERSION=m5-chi-chain-v1`; unset keeps the flat v1 digest
//! (historical bytes). Unknown values fail closed.
const std = @import("std");
const P = @import("../protocol.zig");
const R = @import("../roster.zig");
const T = @import("../types.zig");
const Wire = @import("../wire.zig");
const Manifest = @import("manifest.zig");
const Canon = @import("../../../../../products/ethereum/statement/cpu/word16_global_execution/ethereum/canon_native.zig");
const Rungs = @import("../../../../../products/ethereum/statement/cpu/word16_global_execution/ethereum/canon_native_rungs.zig");
const FixedSet = @import("fixed_authority_set.zig").Set;
const W = @import("worker_protocol.zig");
const Config = @import("stwo_core").pcs.ForField(@import("stwo_core").fields.om31.OM31).PcsConfig;

pub const VERSION_ENV = Policy.ENV;
pub const UNCLASSED: u32 = 0xFFFFFFFF;
const Policy = @import("../../../word16_execution/native_policy.zig");
pub const Version = Policy.Version;
/// Unknown values are refused with a clean error (never a panic: negative
/// corpus P03 counts a receiver abort as a FAIL).
pub fn select(value: ?[]const u8) !bool {
    return (try Policy.parse(value)).chained();
}
pub fn enabled() !bool {
    return (try Policy.current()).chained();
}
pub fn version() !Version {
    return Policy.current();
}
/// Chain IV input of the selected version (v1 or rv64-m6-native/v2).
pub fn versionIdentity(v: Version) ![32]u8 {
    return switch (v) {
        .flat => error.NativeChainMissing,
        .m5_chain_v1 => Canon.versionIdentity(Canon.RUNGS),
        .m6_v2_strict => Canon.versionIdentityV2(Canon.RUNGS, .strict_local),
        .m6_v2_gkr => Canon.versionIdentityV2(Canon.RUNGS, .native_gkr),
    };
}
/// v1: first class rung (table order) whose vector holds the declaration.
/// v2 (strict roster): the unique rung whose vector EQUALS the declaration.
/// The receiver derives it from the declaration alone.
pub fn cpuRungFor(v: Version, family: Canon.Family, d: Canon.CpuVector) u32 {
    for (Rungs.CPU) |e| if (e.family == family) {
        if (v.strictRoster()) return if (Canon.strictRung(e.rungs, d)) |r| @intCast(r) else UNCLASSED;
        for (e.rungs, 0..) |rung, r| if (rung[0] == d[0] and Canon.dominates(rung, d)) return @intCast(r);
    };
    return UNCLASSED;
}
pub fn cpuRung(family: Canon.Family, v: Canon.CpuVector) u32 {
    return cpuRungFor(.m5_chain_v1, family, v);
}
pub fn truthRung(family: Canon.Family, logs: [2]u32) u32 {
    for (Rungs.TRUTH) |e| if (e.family == family and e.aux == logs[1]) {
        for (e.logs, 0..) |l, r| if (l == logs[0]) return @intCast(r);
    };
    return UNCLASSED;
}
/// v2 class structure of a CPU rung (rung vector + layout flags). Exposed for
/// the native VK table builder (fold-v3 / rootverify) and its agreement test.
pub fn cpuClassStructure(family: Canon.Family, rung: u32, flags: u32) !Canon.Digest {
    for (Rungs.CPU) |e| if (e.family == family) {
        if (rung >= e.rungs.len) return error.NativeChainNotStrict;
        return Canon.cpuStructureV2(family, rung, e.rungs[rung], flags);
    };
    return error.NativeChainNotStrict;
}
pub fn truthClassStructure(family: Canon.Family, rung: u32, aux: u32) !Canon.Digest {
    for (Rungs.TRUTH) |e| if (e.family == family and e.aux == aux) {
        if (rung >= e.logs.len) return error.NativeChainNotStrict;
        return Canon.structureDigestV2(@intFromEnum(family), rung, &.{ 0, 1 }, &.{ e.logs[rung], aux }, 0);
    };
    return error.NativeChainNotStrict;
}
/// v2 vkhash of one class (NF2): suite identity, fixed identity/root and the
/// profile identity are REQUIRED (canon-native review A3).
pub fn classVk(family: Canon.Family, rung: u32, structure: [32]u8, suite: [32]u8, fixed_root: [32]u8, b: anytype) ![32]u8 {
    const p = b.profile orelse return error.NativeChainFixedAuthorityMissing;
    return (Canon.NativeVk{ .family = @intFromEnum(family), .rung = rung, .suite = suite, .fixed_identity = b.fixed_identity, .fixed_root = fixed_root, .profile_identity = W.Candidate.profileIdentity(p), .structure = structure }).hash();
}
/// One line per segment: the class and vkhash the chain hashes (block
/// independence check: equal (f, r) => equal vkhash across blocks).
fn logChain(v: Version, ordinal: usize, c: Manifest.Chain) void {
    std.debug.print("RV64_NATIVE_CHAIN version={s} ordinal={d} family={d} rung={d} vkhash={x}\n", .{ @tagName(v), ordinal, c.family, c.rung, &c.vkhash });
}
fn relations(r: Manifest.Relations) u32 {
    return @as(u32, @intFromBool(r.ram)) | (@as(u32, @intFromBool(r.kio)) << 1) | (@as(u32, @intFromBool(r.wire)) << 2);
}
fn mass(m: Manifest.Mass) Canon.Mass {
    return .{ .ram = m.ram, .kio = m.kio, .wire = m.wire };
}
fn vk(family: Canon.Family, rung: u32, structure: [32]u8, fixed_root: [32]u8, binding: anytype) [32]u8 {
    const zero: [32]u8 = @splat(0);
    var fixed_identity = zero;
    var profile_identity = zero;
    if (binding) |b| {
        fixed_identity = b.fixed_identity;
        if (b.profile) |p| profile_identity = W.Candidate.profileIdentity(p);
    }
    return (Canon.NativeVk{ .family = @intFromEnum(family), .rung = rung, .suite = zero, .fixed_identity = fixed_identity, .fixed_root = fixed_root, .profile_identity = profile_identity, .structure = structure }).hash();
}
pub fn assign(setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, first_ids: []const [T.FAMILIES]u32, workers: []Manifest.ExpectedWorker, config: Config, fixed: ?*const FixedSet) !void {
    _ = config;
    const v = try version();
    const strict = v.strictRoster();
    if (strict and fixed == null) return error.NativeChainFixedAuthorityMissing;
    if (setups.len == 0 or requests.len != setups.len or workers.len != setups.len + truths.len) return error.NativeChainRoster;
    var steps_in: u64 = 0;
    const last = requests[requests.len - 1].base.cpu;
    const final_state = Canon.stateDigest(last.final_pc, last.final_registers, true);
    for (setups, requests, 0..) |setup, request, i| {
        const family = Canon.Family.cpu(i, setups.len);
        const vector = Canon.cpuVector(.{ .geometry = setup.materials.geometry, .bridges = setup.bridges });
        const rung = cpuRungFor(v, family, vector);
        if (strict and (rung == UNCLASSED or setup.materials.geometry.omit_empty_division)) return error.NativeChainNotStrict;
        const w = &workers[i];
        const b = request.base;
        const stmt = (Canon.CpuStatement{
            .ordinal = @intCast(i),
            .cpu_ordinal = b.epoch,
            .steps_in = steps_in,
            .steps = b.cpu.steps,
            .ls_count = std.math.cast(u32, b.memory.ls_count) orelse return error.NativeChainCounterRange,
            .ls_dword = request.ls_dword,
            .calls = request.calls,
            .first_ids = first_ids[i],
            .sponge = .{ request.sponge.calls, request.sponge.perms, request.sponge.first_id },
            .bulk = .{ request.bulk.calls, request.bulk.copy_words, request.bulk.set_words, request.bulk.ucopy_rows, request.bulk.cmp_calls, request.bulk.cmp_words, request.bulk.jump_calls, request.bulk.jump_rows },
            .mass = mass(w.mass),
            .relations = relations(w.global_relations),
            .legacy = w.statement,
        }).digest();
        steps_in = try std.math.add(u64, steps_in, b.cpu.steps);
        // Defense in depth (binding 4.1 rule 5, state continuity): the chain
        // hashes s_in/s_out, so refuse a discontinuous roster here instead of
        // relying only on the admission that ran before.
        if (i + 1 < setups.len) {
            const next = requests[i + 1].base.cpu;
            if (b.cpu.final_pc != next.initial_pc or !std.mem.eql(u64, &b.cpu.final_registers, &next.initial_registers)) return error.NativeChainStateDiscontinuity;
        }
        w.chain = .{
            .family = @intFromEnum(family),
            .rung = rung,
            .vkhash = if (strict)
                try classVk(family, rung, try cpuClassStructure(family, rung, Canon.layoutFlags(setup.materials.geometry)), try setup.materials.suite.identity(), w.fixed, fixed.?.at(i))
            else
                vk(family, rung, Canon.cpuStructure(family, rung, vector), w.fixed, if (fixed) |authority| authority.at(i) else null),
            .stmt = stmt,
            .s_in = Canon.stateDigest(b.cpu.initial_pc, b.cpu.initial_registers, false),
            .s_out = if (i + 1 == setups.len) final_state else Canon.stateDigest(b.cpu.final_pc, b.cpu.final_registers, false),
        };
        logChain(v, i, w.chain.?);
    }
    for (truths, 0..) |truth, j| {
        const ordinal = setups.len + j;
        const d = Wire.TruthDeclaration.from(truth);
        const family = Canon.Family.truth(d.family);
        const rung = truthRung(family, d.logs);
        if (strict and rung == UNCLASSED) return error.NativeChainNotStrict;
        const w = &workers[ordinal];
        const stmt = (Canon.TruthStatement{ .ordinal = @intCast(ordinal), .family = @intFromEnum(family), .first_id = d.first_id, .calls = d.calls, .logs = d.logs, .mass = mass(w.mass), .relations = relations(w.global_relations), .legacy = w.statement }).digest();
        const structure = Canon.structureDigest(@intFromEnum(family), rung, &.{ 0, 1 }, &d.logs);
        // Non-CPU families never move machine state (binding F3): s_out = s_in.
        const vkhash = if (strict)
            try classVk(family, rung, try truthClassStructure(family, rung, d.logs[1]), try truth.key().suite.identity(), w.fixed, fixed.?.at(ordinal))
        else
            vk(family, rung, structure, w.fixed, if (fixed) |authority| authority.at(ordinal) else null);
        w.chain = .{ .family = @intFromEnum(family), .rung = rung, .vkhash = vkhash, .stmt = stmt, .s_in = final_state, .s_out = final_state };
        logChain(v, ordinal, w.chain.?);
    }
}
