//! Complete seven-role fixture: public inputs/output are independently pinned,
//! so native dot debt must close through the actual generic/P2/OMUL components.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Common = @import("../../rv64_recursion/om31_poseidon/common.zig");
const C = @import("../context.zig");
const Scope = @import("scope.zig").Scope;
const K = @import("outer_authority.zig");
const W = @import("outer_witness.zig");
const P = @import("outer_proof.zig");
const M = Core.fields.m31.M31;
const Q = C.Q;
const O = Core.fields.om31.OM31;
fn number(n: u32) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = M.fromCanonical(n + @as(u32, @intCast(i)));
    return O.fromM31Array(coordinates);
}
fn expected() [10]Q {
    const x = number(3);
    const y = number(17);
    const result = x.mul(y).mulM31(M.fromCanonical(5)).add(x.mulM31(M.fromCanonical(16)));
    return .{ x.c0, x.c1, y.c0, y.c1, Q.fromBase(M.fromCanonical(5)), Q.fromBase(M.fromCanonical(11)), result.c0, result.c1, Q.zero(), Q.zero() };
}
fn source(a: std.mem.Allocator) !C.Context {
    var owner = try C.Context.init(a, 10);
    errdefer owner.deinit();
    var structural = Common.lane.StructuralScope.init();
    defer structural.deinit();
    var mul = @import("../native_omul/scope.zig").begin();
    defer mul.deinit();
    var dot = Scope.begin(&owner);
    defer dot.deinit();
    Common.begin(&owner);
    var active = true;
    defer if (active) Common.finish() catch {};
    const x = try Common.F.guess(owner.algebra(), number(3));
    const y = try Common.F.guess(owner.algebra(), number(17));
    const product = x.mul(y);
    const s0 = try owner.base.guess(Q.fromBase(M.fromCanonical(5)));
    const s1 = try owner.base.guess(Q.fromBase(M.fromCanonical(11)));
    const result = try @import("../../rv64_recursion/om31_native/deep_dot.zig").current().?(owner.algebra(), &.{ product, x, x }, &.{ s0, s1, s0 });
    const empty = try @import("../../rv64_recursion/om31_native/deep_dot.zig").current().?(owner.algebra(), &.{}, &.{});
    _ = try owner.permute(@splat(s0));
    try Common.finish();
    active = false;
    try owner.setOutputs(&.{ x.c0.v, x.c1.v, y.c0.v, y.c1.v, s0, s1, result.c0.v, result.c1.v, empty.c0.v, empty.c1.v });
    try owner.finalizeForNativeDot();
    return owner;
}
fn rejectMutation(a: std.mem.Allocator, ctx: *const C.Context, key: *const K.Key, mutation: P.Mutation) !void {
    if (P.proveMutation(a, ctx, key, &expected(), mutation)) |bytes| {
        defer a.free(bytes);
        if (P.verify(a, key, &expected(), bytes)) |_| return error.R7MutationAccepted else |err| {
            if (err == error.OutOfMemory) return err;
            std.debug.print("OP_R7_MUTATION mode={s} receiver={s}\n", .{ @tagName(mutation), @errorName(err) });
        }
    } else |err| {
        if (err == error.OutOfMemory) return err;
        std.debug.print("OP_R7_MUTATION mode={s} producer={s}\n", .{ @tagName(mutation), @errorName(err) });
    }
}
test "OP R7 seven role physical proof closes whole Var debt with fresh source authority" {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    {
        var ctx = try source(a);
        defer ctx.deinit();
        var key = try K.Key.init(a, &ctx, .op_target_b4_q72_p0_fold4_v1);
        var owned = true;
        defer if (owned) key.deinit();
        var timer = try std.time.Timer.start();
        const bytes = try P.prove(a, &ctx, &key, &expected());
        defer a.free(bytes);
        const prove_ns = timer.lap();
        const full = try P.proveFullStorageControl(a, &ctx, &key, &expected());
        defer a.free(full);
        try std.testing.expectEqualSlices(u8, bytes, full);
        if (std.posix.getenv("STWO_OP_R7_FIXTURE_OUTPUT")) |path| {
            var file = try std.fs.cwd().createFile(path, .{});
            defer file.close();
            try file.writeAll(bytes);
        }
        const identity = key.core.base.identity;
        key.deinit();
        owned = false;
        var fresh = try source(a);
        defer fresh.deinit();
        var receiver = try K.Key.init(a, &fresh, .op_target_b4_q72_p0_fold4_v1);
        defer receiver.deinit();
        try std.testing.expectEqualDeep(identity, receiver.core.base.identity);
        timer.reset();
        try P.verify(a, &receiver, &expected(), bytes);
        const verify_ns = timer.lap();
        // Independently altered source semantics keep input fanout unchanged,
        // but must derive a different authority/FIXED root and reject this proof.
        var wrong_source = try source(a);
        defer wrong_source.deinit();
        const terms = @constCast(wrong_source.native_dot_calls.items[0].terms);
        std.mem.swap(u32, &terms[0].weight[0], &terms[0].weight[1]);
        var wrong_key = try K.Key.init(a, &wrong_source, .op_target_b4_q72_p0_fold4_v1);
        defer wrong_key.deinit();
        try std.testing.expect(!std.mem.eql(u8, &wrong_key.core.base.identity, &receiver.core.base.identity));
        try std.testing.expectError(error.InvalidNativeDotR7Authority, P.verify(a, &wrong_key, &expected(), bytes));
        var wire = try P.Wire.decodeProofBytesBinary(a, bytes[P.HEADER_BYTES..]);
        defer wire.deinit(a);
        wire.commitment_scheme_proof.commitments.items[0][0] ^= 1;
        const wrong_body = try P.Wire.encodeProofBytesBinary(a, wire);
        defer a.free(wrong_body);
        const wrong_fixed = try a.alloc(u8, P.HEADER_BYTES + wrong_body.len);
        defer a.free(wrong_fixed);
        @memcpy(wrong_fixed[0..P.HEADER_BYTES], bytes[0..P.HEADER_BYTES]);
        @memcpy(wrong_fixed[P.HEADER_BYTES..], wrong_body);
        try std.testing.expectError(error.UntrustedPoseidonFixedCommitment, P.verify(a, &receiver, &expected(), wrong_fixed));
        var wrong = expected();
        wrong[4] = wrong[4].add(Q.one());
        if (P.verify(a, &receiver, &wrong, bytes)) |_| return error.R7WrongPublicInputAccepted else |err| if (err == error.OutOfMemory) return err;
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.InvalidNativeOmulWire, @import("../native_omul/proof.zig").verify(fail.allocator(), &receiver.core, &expected(), bytes));
        try std.testing.expect(!fail.has_induced_failure);
        for ([_]P.Mutation{ .port_extension, .native_result, .dot_accumulator, .dot_weight, .dot_scalar, .dot_prefix, .dot_claim_balanced, .dot_reset, .dot_empty, .omit_dot }) |mutation| try rejectMutation(a, &fresh, &receiver, mutation);
        std.debug.print("OP_R7_COMPLETE bytes={d} prove_s={d:.3} fresh_verify_s={d:.3} roles=7 dot_raw={d} dot_log={d} peak={d}\n", .{ bytes.len, @as(f64, @floatFromInt(prove_ns)) / 1e9, @as(f64, @floatFromInt(verify_ns)) / 1e9, receiver.dot_raw, receiver.dot_log, budget.snapshot().peak_live_bytes });
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}
