//! Independent key pin, artifact roundtrip and witness-free parent verification.
const std = @import("std");
const api = @import("../recursion/blake3_execution_parent_proof.zig");
const protocol = api.protocol;
const Cpu = api.ForBackend(@import("stwo_cpu_backend").CpuBackend);
const Result = struct { admission: protocol.Admission, verified: @import("../recursion/blake3_native_parent_verifier.zig").Verified };
pub fn check(a: std.mem.Allocator, prepared: *const api.preparation.Prepared) !void {
    var first = try proveAndVerify(a, prepared);
    defer first.verified.deinit();
    try first.verified.validate(&first.admission, first.admission.expected_id);
    first.verified.capture.sampled_values[0] = first.verified.capture.sampled_values[0].add(@import("stwo_core").fields.qm31.QM31.one());
    try std.testing.expectError(error.InvalidBlake3ParentCapture, first.verified.validate(&first.admission, first.admission.expected_id));
    first.verified.capture.sampled_values[0] = first.verified.capture.sampled_values[0].sub(@import("stwo_core").fields.qm31.QM31.one());
    var next = try api.preparation.prepare(a, &first.admission, &first.verified, first.admission.expected_id, 2);
    defer next.deinit();
    try std.testing.expectEqualSlices(u8, &first.admission.expected_id, &next.context.child_key_id);
    try std.testing.expectEqualDeep(prepared.context.statement_identity, next.context.statement_identity);
    try std.testing.expectEqualDeep(prepared.context.span_binding_id, next.context.span_binding_id);
    var second = try proveAndVerify(a, &next);
    defer second.verified.deinit();
    try std.testing.expect(!std.mem.eql(u8, &first.admission.expected_id, &second.admission.expected_id));
    try second.verified.validate(&second.admission, second.admission.expected_id);
    std.debug.print("EXECUTION_PARENT_OF_PARENT verified=true distinct_keys=true levels=2 inputs={d} retained_bytes={d}\n", .{ next.rows.input_count, try next.rows.retainedBytes() });
}
fn proveAndVerify(a: std.mem.Allocator, prepared: *const api.preparation.Prepared) !Result {
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
    if (key.context.statement_identity != null) {
        changed = key;
        changed.context.statement_identity.?[31] ^= 1;
        try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
        changed = key;
        changed.context.span_binding_id.?[31] ^= 1;
        try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
    }
    if (key.context.aggregation != null) {
        changed = key;
        changed.context.aggregation.?.right_child_key_id[31] ^= 1;
        try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
        changed = key;
        changed.context.aggregation.?.right_config.pow_bits += 1;
        try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
        changed = key;
        changed.context.aggregation.?.right_graph_ids[0][31] ^= 1;
        try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
        changed = key;
        changed.context.aggregation.?.right_transcript_plan_id[31] ^= 1;
        try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
        inline for (.{ "child_statement_ids", "child_span_binding_ids", "namespace_ids" }) |field| for (0..2) |child| {
            changed = key;
            @field(changed.context.aggregation.?, field)[child][31] ^= 1;
            try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(changed, expected));
        };
    }
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
    errdefer verified.deinit();
    try std.testing.expect(decoded.proof == null);
    try std.testing.expectEqualSlices(u8, &expected, &verified.key_id);
    try std.testing.expectEqual(@as(usize, 8), verified.capture.queries.raw.len);
    std.debug.print("EXECUTION_PARENT_PROOF verified=true artifact_bytes={d} queries={d} pow_bits={d} child_key_bound=true proving_plan_released=true\n", .{ bytes.len, verified.capture.queries.raw.len, key.config.pow_bits });
    return .{ .admission = admission, .verified = verified };
}
