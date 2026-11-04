//! Receiver-derived fields of native protocol `rv64-m5-native-chi-chain/v1`
//! (stream canon-native; spec design/riscv-proving-stack/rv64-m5-canon-native.md
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
const Canon = @import("../../ethereum/canon_native.zig");
const Rungs = @import("../../ethereum/canon_native_rungs.zig");
const FixedSet = @import("fixed_authority_set.zig").Set;
const W = @import("worker_protocol.zig");
const Config = @import("stwo_core").pcs.ForField(@import("stwo_core").fields.om31.OM31).PcsConfig;

pub const VERSION_ENV = "STWO_RV64_NATIVE_VERSION";
pub const UNCLASSED: u32 = 0xFFFFFFFF;
pub fn enabled() bool {
    const value = std.posix.getenv(VERSION_ENV) orelse return false;
    if (std.mem.eql(u8, value, Canon.VERSION_NAME) or std.mem.eql(u8, value, "m5-chi-chain-v1")) return true;
    if (value.len == 0 or std.mem.eql(u8, value, "v1-flat")) return false;
    @panic("unknown STWO_RV64_NATIVE_VERSION (expected m5-chi-chain-v1 or v1-flat)");
}
/// First class rung (table order) whose vector holds the declaration; the
/// receiver derives it from the declaration alone.
pub fn cpuRung(family: Canon.Family, v: Canon.CpuVector) u32 {
    for (Rungs.CPU) |e| if (e.family == family) {
        for (e.rungs, 0..) |rung, r| if (rung[0] == v[0] and Canon.dominates(rung, v)) return @intCast(r);
    };
    return UNCLASSED;
}
pub fn truthRung(family: Canon.Family, logs: [2]u32) u32 {
    for (Rungs.TRUTH) |e| if (e.family == family and e.aux == logs[1]) {
        for (e.logs, 0..) |l, r| if (l == logs[0]) return @intCast(r);
    };
    return UNCLASSED;
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
    if (setups.len == 0 or requests.len != setups.len or workers.len != setups.len + truths.len) return error.NativeChainRoster;
    var steps_in: u64 = 0;
    const last = requests[requests.len - 1].base.cpu;
    const final_state = Canon.stateDigest(last.final_pc, last.final_registers, true);
    for (setups, requests, 0..) |setup, request, i| {
        const family = Canon.Family.cpu(i, setups.len);
        const vector = Canon.cpuVector(.{ .geometry = setup.materials.geometry, .bridges = setup.bridges });
        const rung = cpuRung(family, vector);
        const w = &workers[i];
        const b = request.base;
        const stmt = (Canon.CpuStatement{
            .ordinal = @intCast(i),
            .cpu_ordinal = b.epoch,
            .steps_in = steps_in,
            .steps = b.cpu.steps,
            .ls_count = @intCast(b.memory.ls_count),
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
        w.chain = .{
            .family = @intFromEnum(family),
            .rung = rung,
            .vkhash = vk(family, rung, Canon.cpuStructure(family, rung, vector), w.fixed, if (fixed) |authority| authority.at(i) else null),
            .stmt = stmt,
            .s_in = Canon.stateDigest(b.cpu.initial_pc, b.cpu.initial_registers, false),
            .s_out = if (i + 1 == setups.len) final_state else Canon.stateDigest(b.cpu.final_pc, b.cpu.final_registers, false),
        };
    }
    for (truths, 0..) |truth, j| {
        const ordinal = setups.len + j;
        const d = Wire.TruthDeclaration.from(truth);
        const family = Canon.Family.truth(d.family);
        const rung = truthRung(family, d.logs);
        const w = &workers[ordinal];
        const stmt = (Canon.TruthStatement{ .ordinal = @intCast(ordinal), .family = @intFromEnum(family), .first_id = d.first_id, .calls = d.calls, .logs = d.logs, .mass = mass(w.mass), .relations = relations(w.global_relations), .legacy = w.statement }).digest();
        const structure = Canon.structureDigest(@intFromEnum(family), rung, &.{ 0, 1 }, &d.logs);
        // Non-CPU families never move machine state (binding F3): s_out = s_in.
        w.chain = .{ .family = @intFromEnum(family), .rung = rung, .vkhash = vk(family, rung, structure, w.fixed, if (fixed) |authority| authority.at(ordinal) else null), .stmt = stmt, .s_in = final_state, .s_out = final_state };
    }
}
