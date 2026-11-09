//! Pure-P2 child verifier and ordered two-child fold correctness gate.
//! Starts from source-owned physical algebraic children; not execution admission.
const std = @import("std");
const Core = @import("stwo_core");
const C = @import("full_p2_common.zig");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const Context = @import("context.zig").Context;
const Sponge = @import("sponge.zig").ForContext(Context);
const Proof = @import("proof.zig");
const Authority = @import("authority.zig").Authority;
const Statement = @import("pure_p2_outer_statement.zig").Statement;
const a = std.testing.allocator;
fn tinyLeaf(seed: u32, trace_only: bool) !Context {
    var owner = if (trace_only) try Context.initTraceOnly(a, 9) else try Context.init(a, 9);
    errdefer owner.deinit();
    var sponge = try Sponge.init(&owner, .words);
    for (0..15) |i| try sponge.absorb(try owner.algebra().guess(C.Q.fromBase(Core.fields.m31.M31.fromCanonical(seed + @as(u32, @intCast(i))))));
    const root = try sponge.finish();
    try owner.setOutputs(&root);
    try owner.finalize();
    return owner;
}
fn tinyOutput(seed: u32) [9]C.Q {
    var sponge = Core.crypto.poseidon2_m31_sponge.Sponge.init(.words);
    for (0..15) |i| sponge.absorb(Core.fields.m31.M31.fromCanonical(seed + @as(u32, @intCast(i))));
    var outputs: [9]C.Q = undefined;
    for (&outputs, sponge.finish()) |*out, value| out.* = C.Q.fromBase(value);
    return outputs;
}
fn foldDigest(left: [9]C.Q, right: [9]C.Q) [9]C.Q {
    var sponge = Core.crypto.poseidon2_m31_sponge.Sponge.init(.words);
    for ([_]u32{ 0x4f504632, 1, 2 }) |word| sponge.absorbU32(word);
    for ([_][9]C.Q{ left, right }) |root| for (root) |word| sponge.absorb(word.toM31Array()[0]);
    var outputs: [9]C.Q = undefined;
    for (&outputs, sponge.finish()) |*out, value| out.* = C.Q.fromBase(value);
    return outputs;
}
test "OP pure P2 physical children verify in source-exact fold circuit with ordered output" {
    var leaves = [_]Context{ try tinyLeaf(17, false), undefined };
    defer leaves[0].deinit();
    leaves[1] = try tinyLeaf(91, false);
    defer leaves[1].deinit();
    var source = try tinyLeaf(0, true);
    defer source.deinit();
    var key = try Authority.initForProfile(a, &source, .op_target_b4_q72_p0_fold4_v1);
    defer key.deinit();
    const outputs = [_][9]C.Q{ tinyOutput(17), tinyOutput(91) };
    var children: [2]Proof.Captured = undefined;
    var made: usize = 0;
    defer for (children[0..made]) |*child| child.deinit(a);
    for (&leaves, outputs, &children) |*leaf, expected, *child| {
        const encoded = try Proof.prove(a, leaf, &key, &expected);
        defer a.free(encoded);
        child.* = try Proof.verifyCaptured(a, &key, &expected, encoded);
        made += 1;
    }
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("pure_p2_outer_capture.zig").geometry(arena.allocator(), &key);
    var structural = @import("../rv64_recursion/circuit_lane.zig").StructuralScope.init();
    defer structural.deinit();
    var parent = try Context.init(a, 9);
    defer parent.deinit();
    @import("../rv64_recursion/om31_poseidon/common.zig").begin(&parent);
    var active = true;
    defer if (active) @import("../rv64_recursion/om31_poseidon/common.zig").finish() catch {};
    const ctx = parent.algebra();
    var roots: [2][9]C.Var = undefined;
    for (&children, outputs, &roots) |*child, expected, *root| {
        const values = try V.proof.fromNative(arena.allocator(), &child.proof, &child.capture, &shape);
        const wire = try V.proof.guess(ctx, &values, &shape);
        for (root, expected) |*port, value| port.* = try ctx.guess(value);
        var claims: [5]C.F = undefined;
        for (&claims, child.claims) |*claim, value| claim.* = try C.F.guess(ctx, value);
        var statement = Statement{ .key = &key, .fixed = wire.commitments[0], .outputs = root, .claims = claims };
        _ = try V.verify(ctx, &shape, &wire, &statement);
    }
    var sponge = try Sponge.init(&parent, .words);
    for ([_]u32{ 0x4f504632, 1, 2 }) |word| try sponge.absorbConstU32(word);
    for (roots) |root| try sponge.absorbMany(&root);
    const output = try sponge.finish();
    const expected = foldDigest(outputs[0], outputs[1]);
    for (output, expected) |port, value| try std.testing.expect(ctx.get(port).eql(value));
    try @import("../rv64_recursion/om31_poseidon/common.zig").finish();
    active = false;
    try parent.setOutputs(&output);
    try parent.finalize();
    try std.testing.expect(try parent.isCircuitValid());
    const saved = ctx.get(roots[0][8]);
    ctx.value_table.items[roots[0][8].idx] = saved.add(C.Q.one());
    try std.testing.expect(!try parent.isCircuitValid());
    ctx.value_table.items[roots[0][8].idx] = saved;
    const swapped = foldDigest(outputs[1], outputs[0]);
    try std.testing.expect(!std.mem.eql(u8, std.mem.asBytes(&expected), std.mem.asBytes(&swapped)));
    const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "two_physical_source_owned_algebraic_children_not_execution", .raw = try parent.rawCounts(), .cells = try parent.census(false), .native_in_circuit_exact = true, .ordered_digest = true, .production_admission_open = false }, .{});
    defer a.free(json);
    std.debug.print("OP_PURE_P2_FOLD_CIRCUIT {s}\n", .{json});
}
