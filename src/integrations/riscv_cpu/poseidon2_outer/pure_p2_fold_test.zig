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
    const Fold = @import("pure_p2_fold.zig");
    const source_fold = Fold.Source{ .children = .{
        .{ .key = &key, .verified = &children[0], .output = outputs[0] },
        .{ .key = &key, .verified = &children[1], .output = outputs[1] },
    } };
    var parent = try source_fold.build(a, false);
    defer parent.deinit();
    const expected = try source_fold.expectedOutput();
    const swapped = try Fold.digest(outputs[1], outputs[0]);
    try std.testing.expect(!std.mem.eql(u8, std.mem.asBytes(&expected), std.mem.asBytes(&swapped)));
    var nonbase = outputs[0];
    nonbase[8] = C.Q.fromM31Array(.{ Core.fields.m31.M31.zero(), Core.fields.m31.M31.one(), Core.fields.m31.M31.zero(), Core.fields.m31.M31.zero() });
    try std.testing.expectError(error.NonBaseFoldDigest, Fold.digest(nonbase, outputs[1]));
    const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "two_physical_source_owned_algebraic_children_not_execution", .raw = try parent.rawCounts(), .cells = try parent.census(false), .native_in_circuit_exact = true, .ordered_digest = true, .production_admission_open = false }, .{});
    defer a.free(json);
    std.debug.print("OP_PURE_P2_FOLD_CIRCUIT {s}\n", .{json});
}

test "OP pure P2 ordered tree carries odd leaves and rejects malformed digest" {
    const Fold = @import("pure_p2_fold.zig");
    const roots = [_]Fold.Digest{ tinyOutput(1), tinyOutput(2), tinyOutput(3) };
    try std.testing.expectError(error.EmptyFoldInventory, Fold.treeDigest(a, &.{}));
    try std.testing.expectEqualDeep(roots[0], try Fold.treeDigest(a, roots[0..1]));
    try std.testing.expectEqualDeep(try Fold.digest(try Fold.digest(roots[0], roots[1]), roots[2]), try Fold.treeDigest(a, &roots));
    const duplicated = [_]Fold.Digest{ roots[0], roots[1], roots[2], roots[2] };
    const carried = try Fold.treeDigest(a, &roots);
    const duplicate = try Fold.treeDigest(a, &duplicated);
    try std.testing.expect(!std.meta.eql(carried, duplicate));
    var malformed = roots;
    malformed[2][8] = C.Q.fromM31Array(.{ Core.fields.m31.M31.zero(), Core.fields.m31.M31.one(), Core.fields.m31.M31.zero(), Core.fields.m31.M31.zero() });
    try std.testing.expectError(error.NonBaseFoldDigest, Fold.treeDigest(a, &malformed));
}
