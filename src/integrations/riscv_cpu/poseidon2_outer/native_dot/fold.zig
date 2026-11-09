//! Closed R7 eight-role binary fold. Native Var debt and all eight claims
//! are verified in circuit; this synthetic fold is not execution admission.
const std = @import("std");
const Core = @import("stwo_core");
const C = @import("../full_p2_common.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const Context = @import("../context.zig").Context;
const Sponge = @import("../sponge.zig").ForContext(Context);
const Proof = @import("outer_proof.zig");
const Keys = @import("execution_keys.zig");
const Statement = @import("statement.zig").Statement;
pub const Digest = [9]C.Q;
pub const Child = struct { key: Keys.Ref, verified: Keys.Borrowed, output: Digest };
pub fn digest(left: Digest, right: Digest) !Digest {
    var sponge = Core.crypto.poseidon2_m31_sponge.Sponge.init(.words);
    for ([_]u32{ 0x4f504637, 2, 2 }) |word| sponge.absorbU32(word);
    for ([_]Digest{ left, right }) |root| for (root) |word| {
        const limbs = word.toM31Array();
        for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseFoldDigest;
        sponge.absorb(limbs[0]);
    };
    var out: Digest = undefined;
    for (&out, sponge.finish()) |*port, value| port.* = C.Q.fromBase(value);
    return out;
}
pub const Source = struct {
    children: [2]Child,
    pub fn expectedOutput(self: Source) !Digest {
        return digest(self.children[0].output, self.children[1].output);
    }
    pub fn build(self: Source, a: std.mem.Allocator, trace_only: bool) !Context {
        return self.buildMode(a, trace_only, true);
    }
    pub fn buildForProving(self: Source, a: std.mem.Allocator) !Context {
        return self.buildMode(a, false, false);
    }
    fn buildMode(self: Source, a: std.mem.Allocator, trace_only: bool, qualify: bool) !Context {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var views: [2]View = undefined;
        for (self.children, &views) |child, *view| {
            const shape = try arena.allocator().create(V.Shape);
            if (@intFromEnum(std.meta.activeTag(child.key)) != @intFromEnum(std.meta.activeTag(child.verified))) return error.R7ChildFormatMismatch;
            shape.* = try child.key.geometry(arena.allocator());
            const values = try arena.allocator().create(V.Captured);
            switch (child.verified) {
                .r6 => |verified| {
                    values.* = try V.proof.fromNative(arena.allocator(), &verified.proof, &verified.capture, shape);
                    view.* = .{ .key = child.key, .shape = shape, .values = values, .output = child.output, .claims = .{ .r6 = verified.claims } };
                },
                .r7 => |verified| {
                    values.* = try V.proof.fromNative(arena.allocator(), &verified.proof, &verified.capture, shape);
                    view.* = .{ .key = child.key, .shape = shape, .values = values, .output = child.output, .claims = .{ .r7 = verified.claims } };
                },
            }
        }
        return buildViews(a, trace_only, qualify, views);
    }
};
const View = struct { key: Keys.Ref, shape: *const V.Shape, values: *const V.Captured, output: Digest, claims: union(enum) { r6: [6]V.common.O, r7: [8]V.common.O } };
/// Immutable fold topology from source keys alone. No producer proof bytes,
/// claims, public values or proposed root verifier key enter this constructor.
pub const TraceSource = struct {
    keys: [2]Keys.Ref,
    pub fn build(self: TraceSource, a: std.mem.Allocator) !Context {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var views: [2]View = undefined;
        for (self.keys, &views) |key, *view| {
            if (key.nOutputs() != 9) return error.FoldSourceOutputArity;
            const shape = try arena.allocator().create(V.Shape);
            shape.* = try key.geometry(arena.allocator());
            const values = try arena.allocator().create(V.Captured);
            values.* = try @import("../pure_p2_trace_skeleton.zig").init(arena.allocator(), shape);
            view.* = .{ .key = key, .shape = shape, .values = values, .output = @splat(C.Q.zero()), .claims = switch (key) {
                .r6 => .{ .r6 = @splat(V.common.O.zero()) },
                .r7 => .{ .r7 = @splat(V.common.O.zero()) },
            } };
        }
        return buildViews(a, true, false, views);
    }
};
fn buildViews(a: std.mem.Allocator, trace_only: bool, qualify: bool, views: [2]View) !Context {
    var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
    defer structural.deinit();
    var native_scope = @import("../native_omul/scope.zig").begin();
    defer native_scope.deinit();
    var parent = if (trace_only) try Context.initTraceOnly(a, 9) else try Context.init(a, 9);
    errdefer parent.deinit();
    var dot_scope = @import("scope.zig").Scope.begin(&parent);
    defer dot_scope.deinit();
    V.common.begin(&parent);
    var active = true;
    defer if (active) V.common.finish() catch {};
    const ctx = parent.algebra();
    var roots: [2]DigestPorts = undefined;
    for (views, &roots) |child, *root| {
        const wire = try V.proof.guess(ctx, child.values, child.shape);
        for (root, child.output) |*port, value| port.* = try ctx.guess(value);
        switch (child.key) {
            .r7 => |key| {
                var claims: [8]C.F = undefined;
                for (&claims, child.claims.r7) |*claim, value| claim.* = try C.F.guess(ctx, value);
                var statement = Statement{ .key = key, .fixed = wire.commitments[0], .outputs = root, .claims = claims };
                _ = try V.verify(ctx, child.shape, &wire, &statement);
            },
            .r6 => |key| {
                var claims: [6]C.F = undefined;
                for (&claims, child.claims.r6) |*claim, value| claim.* = try C.F.guess(ctx, value);
                var statement = @import("../native_omul/statement.zig").Statement{ .key = key, .fixed = wire.commitments[0], .outputs = root, .claims = claims };
                _ = try V.verify(ctx, child.shape, &wire, &statement);
            },
        }
    }
    var sponge = try Sponge.init(&parent, .words);
    for ([_]u32{ 0x4f504637, 2, 2 }) |word| try sponge.absorbConstU32(word);
    for (roots) |root| try sponge.absorbMany(&root);
    const output = try sponge.finish();
    try V.common.finish();
    active = false;
    try parent.setOutputs(&output);
    try parent.finalizeForNativeDot();
    if (!trace_only) {
        for (output, try digest(views[0].output, views[1].output)) |port, value| if (!ctx.get(port).eql(value)) return error.FoldOutputMismatch;
        if (!qualify) return parent;
        if (!try parent.isCircuitValid()) return error.FoldCircuitInvalid;
        const saved = ctx.get(roots[0][8]);
        ctx.value_table.items[roots[0][8].idx] = saved.add(C.Q.one());
        const forged = try parent.isCircuitValid();
        ctx.value_table.items[roots[0][8].idx] = saved;
        if (forged) return error.FoldNinthChildLimbUnbound;
    }
    return parent;
}
const DigestPorts = [9]C.Var;
