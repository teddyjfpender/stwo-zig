//! Independent key pin, artifact roundtrip and witness-free parent verification.
const std = @import("std");
const api = @import("../recursion/blake3_execution_parent_proof.zig");
const protocol = api.protocol;
const Cpu = api.ForBackend(@import("stwo_cpu_backend").CpuBackend);
pub fn check(a: std.mem.Allocator, prepared: *const api.preparation.Prepared) !void {
    const key = try Cpu.deriveKey(a, prepared);
    const expected = try key.identity();
    const admission = try protocol.Admission.init(key, expected);
    var changed = key;
    changed.context.child_key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
    changed = key;
    changed.context.graph_ids[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
    changed = key;
    changed.context.transcript_plan_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
    const plan = try Cpu.Plan.init(a, &prepared.rows, admission);
    var plan_alive = true;
    defer if (plan_alive) plan.deinit();
    var proof = try plan.prove(a, &prepared.rows);
    defer proof.deinit();
    // Independent verification must not rely on proving plans or witness state.
    plan.deinit();
    plan_alive = false;
    const bytes = try api.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    proof.deinit();
    var decoded = try api.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    var verified = try api.verify(&decoded, &admission);
    defer verified.deinit();
    try std.testing.expect(decoded.proof == null);
    try std.testing.expectEqualSlices(u8, &expected, &verified.key_id);
    try std.testing.expectEqual(@as(usize, 8), verified.capture.queries.raw.len);
    std.debug.print("EXECUTION_PARENT_PROOF verified=true artifact_bytes={d} queries={d} pow_bits={d} child_key_bound=true proving_plan_released=true\n", .{ bytes.len, verified.capture.queries.raw.len, key.config.pow_bits });
}
