//! Six-component recursive fold, with independently reconstructed trace graph.
const std = @import("std");
const Core = @import("stwo_core");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Scope = @import("scope.zig");
const K = @import("authority.zig");
const Proof = @import("proof.zig");
const Fold = @import("fold.zig");
const Sponge = @import("../sponge.zig").ForContext(C.PoseidonContext);
const M = Core.fields.m31.M31;
fn source(a: std.mem.Allocator, seed: u32, trace: bool) !C.PoseidonContext {
    var structural = C.lane.StructuralScope.init();
    defer structural.deinit();
    var scope = Scope.begin();
    defer scope.deinit();
    var ctx = if (trace) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
    errdefer ctx.deinit();
    C.begin(&ctx);
    var active = true;
    defer if (active) C.finish() catch {};
    const x = try C.F.guess(ctx.algebra(), operand(seed));
    const y = try C.F.guess(ctx.algebra(), operand(seed + 17));
    const z = x.mul(y);
    var sponge = try Sponge.init(&ctx, .words);
    // Hash all eight base coordinates of the authenticated full product.
    const coordinates = try @import("stwo_circuit_frontend").builder.simd.unpack(C.Q, ctx.algebra(), @import("stwo_circuit_frontend").builder.simd.Simd.fromPacked(&[2]C.Var{ z.c0.v, z.c1.v }, 8));
    try sponge.absorbMany(coordinates);
    const out = try sponge.finish();
    try C.finish();
    active = false;
    try ctx.setOutputs(&out);
    try ctx.finalize();
    return ctx;
}
fn operand(seed: u32) C.O {
    var values: [8]M = undefined;
    for (&values, 0..) |*v, i| v.* = M.fromCanonical(seed + @as(u32, @intCast(i)) * 31);
    return C.O.fromM31Array(values);
}
fn expected(seed: u32) Fold.Digest {
    var sponge = Core.crypto.poseidon2_m31_sponge.Sponge.init(.words);
    for (operand(seed).mul(operand(seed + 17)).toM31Array()) |v| sponge.absorb(v);
    var out: Fold.Digest = undefined;
    for (&out, sponge.finish()) |*v, x| v.* = C.Q.fromBase(x);
    return out;
}
test "OP R6 source exact six-component children fold and trace parity" {
    const a = std.testing.allocator;
    var trace = try source(a, 0, true);
    defer trace.deinit();
    var key = try K.Key.init(a, &trace, .op_target_b4_q72_p0_fold4_v1);
    defer key.deinit();
    var leaves: [2]Proof.Captured = undefined;
    var made: usize = 0;
    defer for (leaves[0..made]) |*leaf| leaf.deinit(a);
    const outputs = [2]Fold.Digest{ expected(9), expected(87) };
    for ([2]u32{ 9, 87 }, outputs, &leaves) |seed, out, *leaf| {
        var actual = try source(a, seed, false);
        defer actual.deinit();
        const encoded = try Proof.prove(a, &actual, &key, &out);
        defer a.free(encoded);
        leaf.* = try Proof.verifyCaptured(a, &key, &out, encoded);
        made += 1;
    }
    // Both actual and source-only parent circuits need only verifier metadata.
    @import("verifier_key.zig").retireProverData(&key);
    const view = Fold.Source{ .children = .{ .{ .key = &key, .verified = &leaves[0], .output = outputs[0] }, .{ .key = &key, .verified = &leaves[1], .output = outputs[1] } } };
    var parent = try view.build(a, false);
    defer parent.deinit();
    var parent_trace = try (Fold.TraceSource{ .keys = .{ &key, &key } }).build(a);
    defer parent_trace.deinit();
    try std.testing.expectEqualDeep(try parent.rawCounts(), try parent_trace.rawCounts());
    try std.testing.expectEqualDeep(parent.native_mul_calls.items, parent_trace.native_mul_calls.items);
    const out = try view.expectedOutput();
    std.debug.print("OP_R6_FOLD_CIRCUIT raw={any} native_mul_calls={} valid=true trace_equal=true production_admission=false\n", .{ try parent.rawCounts(), parent.native_mul_calls.items.len });
    const selection = std.posix.getenv("STWO_OP_R6_FOLD_PHYSICAL") orelse return;
    if (!std.mem.eql(u8, selection, "1")) return error.InvalidR6PhysicalSelection;
    const path = std.posix.getenv("STWO_OP_R6_OUT") orelse return error.MissingR6ArtifactDirectory;
    try std.fs.cwd().makeDir(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    var authority = try K.Key.init(a, &parent_trace, .op_target_b4_q72_p0_fold4_v1);
    defer authority.deinit();
    const bytes = try Proof.prove(a, &parent, &authority, &out);
    defer a.free(bytes);
    try @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive(dir, "fold.bin", bytes);
    try Proof.verify(a, &authority, &out, bytes);
    var wrong = out;
    wrong[8] = wrong[8].add(C.Q.one());
    try std.testing.expect(std.meta.isError(Proof.verify(a, &authority, &wrong, bytes)));
    std.debug.print("OP_R6_FOLD_PHYSICAL bytes={} fresh_trace=true wrong_output_rejected=true production_admission=false\n", .{bytes.len});
}
