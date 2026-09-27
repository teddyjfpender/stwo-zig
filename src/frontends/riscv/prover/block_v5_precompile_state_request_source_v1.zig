//! PC/clock retirement of typed caller rows, opened at their original PCS point.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Program = @import("block_v5_program_extension_source_v1.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
pub const Retirement = struct { active: Q, consumed: [2]Q, emitted: [2]Q };

pub fn fromCommittedCaller(kind: Program.Kind, fixed: []const Q, main: []const Q) !Retirement {
    return fromCommittedCallerFor(Q, kind, fixed, main);
}
pub fn RetirementFor(comptime S: type) type {
    return if (S == Q) Retirement else struct { active: S, consumed: [2]S, emitted: [2]S };
}
pub fn fromCommittedCallerFor(comptime S: type, kind: Program.Kind, fixed: []const S, main: []const S) !RetirementFor(S) {
    // Reuse the exact geometry guards of the program caller projection.
    _ = try Program.fromCommittedCallerFor(S, kind, fixed, main);
    const active, const pc, const clock = switch (kind) {
        .sha => .{ fixed[0], main[sha.Layout.pc], main[sha.Layout.clock] },
        .keccak => .{ main[keccak.Layout.enabler], main[keccak.Layout.pc], main[keccak.Layout.execution_clock] },
        .signer => .{ main[signer.Layout.is_active], main[signer.Layout.pc], main[signer.Layout.execution_clock] },
    };
    return .{ .active = active, .consumed = .{ pc, clock }, .emitted = .{
        pc.add(S.fromBase(M.fromCanonical(4))), clock.add(S.one()),
    } };
}
