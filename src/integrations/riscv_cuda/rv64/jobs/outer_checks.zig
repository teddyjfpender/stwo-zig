//! Device acceptance checks of an outer node (GPU-native design §3.5,
//! recursion range of gpu_native.Check; kernels NAT/rv64/jobs/outer_checks.cu).
//!
//! lookup_sum: the node's LogUp closure (sum of the 11 claims and the output
//! terms == 0) as an enqueued single-thread kernel at the end of the node body,
//! reading the section's claims / z / alpha and the staged expected outputs,
//! writing one gpu_native.Verdict word plus the node's tag into the job slab.
//! It replaces the host `lookupSum` of outer_job.decode (H22) as the
//! authority; while the hybrid publishes from host containers, finish still
//! runs the host reference and requires agreement (a microsecond cross-check,
//! never a byte of the proof).
//!
//! STWO_RV64_M8_OUTER_DEVICE_CHECKS (default 0): "1" enqueues the device checks
//! (needs an addon exporting stwo_rv64_outer_lookup_sum_check_v1_on).
//! STWO_RV64_M8_OUTER_CHECK_FAULT_ORDINAL=n (negative test, default unset):
//! node n gets one corrupted lookup constant on the device side only; its
//! check must reject (detail 5, nonzero sum) and the request fail closed.
//! Fault injection is two-key: the ordinal is honoured only when
//! STWO_RV64_M8_FAULT_INJECTION=1 is also set (a leftover ordinal alone
//! cannot corrupt production requests; it fails closed at the first node
//! with error.M8FaultInjectionNotArmed instead of being silently ignored).
//!
//! The check field [verdict, tag] is set to `Verdict.unset` on the device
//! at the start of the node body, so a check kernel that never ran reads
//! unset whatever an arena-reused slab held (the tag alone was a 32-bit
//! XOR a stale accepted word could match).
const std = @import("std");
const Env = @import("outer_env.zig");
const G = @import("gpu_native.zig");

/// Mirrors StwoRv64OuterLookupConstants (outer_checks.cu).
pub const LookupConstants = extern struct {
    relation: u32,
    u_index: u32,
    u_value: [4]u32,
    n_outputs: u32,
    n_claims: u32,
    tag: u32,
    reserved: [3]u32 = @splat(0),
};
comptime {
    if (@sizeOf(LookupConstants) != 48) @compileError("outer lookup constants ABI changed");
}

/// Class-independent lookup constants of the om31 outer circuit (host values
/// of circuit component_list.GATE_RELATION_ID and witness/trace.zig
/// U_VAR_IDX / U_VALUE, filled by the pre-stage).
pub const LookupStatic = struct {
    relation: u32,
    u_index: u32,
    u_value: [4]u32,
};

pub const LookupFn = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, ?[*]const u32, *const LookupConstants, [*]u32) callconv(.c) c_int;

pub const Symbols = struct {
    lookup: LookupFn,
    pub fn load(addon: *std.DynLib) !Symbols {
        return .{ .lookup = addon.lookup(LookupFn, "stwo_rv64_outer_lookup_sum_check_v1_on") orelse return error.MissingOuterCheckKernel };
    }
};

pub fn selected() !bool {
    return Env.flag("STWO_RV64_M8_OUTER_DEVICE_CHECKS", false);
}
pub fn faultOrdinal() !?u32 {
    const n = try Env.optionalUnsigned(u32, "STWO_RV64_M8_OUTER_CHECK_FAULT_ORDINAL") orelse return null;
    if (!try Env.flag("STWO_RV64_M8_FAULT_INJECTION", false)) return error.M8FaultInjectionNotArmed;
    return n;
}

/// Slab field of the node's check words: [lookup verdict, lookup tag].
pub const field_index: u32 = 0x4348_4b31; // "CHK1"
pub const field_words: u32 = 2;

/// Per-node tag: the node's transcript checkpoint (distinct per statement)
/// mixed with its ordinal. Never `Verdict.unset`.
pub fn tagOf(checkpoint: *const [9]u32, ordinal: u32) u32 {
    const t = checkpoint[0] ^ checkpoint[8] ^ (ordinal *% 0x9e37_79b9) ^ 0x5a5a_0302;
    return if (t == G.Verdict.unset) 0x0302_0001 else t;
}

pub fn constants(s: LookupStatic, n_outputs: u32, n_claims: u32, tag: u32, fault: bool) LookupConstants {
    var c = LookupConstants{ .relation = s.relation, .u_index = s.u_index, .u_value = s.u_value, .n_outputs = n_outputs, .n_claims = n_claims, .tag = tag };
    // Negative test: an off-by-one public value is still canonical, so the
    // kernel computes a (wrong) sum and must reject it as nonzero.
    if (fault) c.u_value[0] = if (c.u_value[0] == 0) 1 else c.u_value[0] - 1;
    return c;
}

pub const Rejected = struct { check: G.Check, detail: u16 };

/// finish(): the node's check words after the job's single wait.
pub fn verdict(words: []const u32, tag: u32) !?Rejected {
    if (words.len < field_words) return error.OuterCheckFieldTooSmall;
    if (words[1] != tag) return error.OuterDeviceCheckDidNotRun;
    const w = words[0];
    if (w == G.Verdict.accepted) return null;
    if (w == G.Verdict.unset) return error.OuterDeviceCheckDidNotRun;
    return .{ .check = G.Verdict.checkOf(w) orelse return error.OuterDeviceCheckUnknownCode, .detail = @truncate(w) };
}

test "lookup check verdict: accepted, rejected, stale and unset words" {
    const t = std.testing;
    const cp: [9]u32 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const tag = tagOf(&cp, 3);
    try t.expect(tag != G.Verdict.unset);
    try t.expect(tag != tagOf(&cp, 4));
    try t.expectEqual(@as(?Rejected, null), try verdict(&.{ 0, tag }, tag));
    const r = (try verdict(&.{ G.Verdict.reject(.lookup_sum, 5), tag }, tag)).?;
    try t.expectEqual(G.Check.lookup_sum, r.check);
    try t.expectEqual(@as(u16, 5), r.detail);
    // A previous job's accepted word next to another node's tag never passes.
    try t.expectError(error.OuterDeviceCheckDidNotRun, verdict(&.{ 0, tag ^ 1 }, tag));
    try t.expectError(error.OuterDeviceCheckDidNotRun, verdict(&.{ G.Verdict.unset, tag }, tag));
    try t.expectError(error.OuterCheckFieldTooSmall, verdict(&.{0}, tag));
}

test "lookup fault perturbs exactly one canonical public limb" {
    const s = LookupStatic{ .relation = 378353459, .u_index = 2, .u_value = .{ 0, 0, 1, 0 } };
    const ok = constants(s, 4, 11, 7, false);
    const bad = constants(s, 4, 11, 7, true);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 1, 0 }, &ok.u_value);
    try std.testing.expectEqualSlices(u32, &.{ 1, 0, 1, 0 }, &bad.u_value);
    try std.testing.expectEqual(ok.tag, bad.tag);
}
