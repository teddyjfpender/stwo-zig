//! Concrete source-owned binary native-proof fold. This authenticates ordered
//! child frame digests; execution admission belongs to the independent receiver.
const std = @import("std");
const Core = @import("stwo_core");
const C = @import("full_p2_common.zig");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const Context = @import("context.zig").Context;
const Sponge = @import("sponge.zig").ForContext(Context);
const Proof = @import("proof.zig");
const Authority = @import("authority.zig").Authority;
const Statement = @import("pure_p2_outer_statement.zig").Statement;
pub const Digest = [9]C.Q;
pub const Child = struct { key: *const Authority, verified: *const Proof.Captured, output: Digest };
pub fn digest(left: Digest, right: Digest) !Digest {
    var sponge = Core.crypto.poseidon2_m31_sponge.Sponge.init(.words);
    for ([_]u32{ 0x4f504632, 1, 2 }) |word| sponge.absorbU32(word);
    for ([_]Digest{ left, right }) |root| for (root) |word| {
        const limbs = word.toM31Array();
        for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseFoldDigest;
        sponge.absorb(limbs[0]);
    };
    var out: Digest = undefined;
    for (&out, sponge.finish()) |*port, value| port.* = C.Q.fromBase(value);
    return out;
}
/// Canonical ordered adjacent-pair tree. An odd final node is carried unchanged;
/// it is never duplicated. Receiver-owned inventory fixes count and order.
pub fn treeDigest(a: std.mem.Allocator, leaves: []const Digest) !Digest {
    if (leaves.len == 0) return error.EmptyFoldInventory;
    const work = try a.dupe(Digest, leaves);
    defer a.free(work);
    for (work) |leaf| for (leaf) |word| {
        const limbs = word.toM31Array();
        for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseFoldDigest;
    };
    var count = work.len;
    while (count > 1) {
        var next: usize = 0;
        var i: usize = 0;
        while (i + 1 < count) : (i += 2) {
            work[next] = try digest(work[i], work[i + 1]);
            next += 1;
        }
        if (i < count) {
            work[next] = work[i];
            next += 1;
        }
        count = next;
    }
    return work[0];
}
pub const Source = struct {
    children: [2]Child,
    pub fn expectedOutput(self: Source) !Digest {
        return digest(self.children[0].output, self.children[1].output);
    }
    pub fn build(self: Source, a: std.mem.Allocator, trace_only: bool) !Context {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var structural = @import("../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var parent = if (trace_only) try Context.initTraceOnly(a, 9) else try Context.init(a, 9);
        errdefer parent.deinit();
        V.common.begin(&parent);
        var active = true;
        defer if (active) V.common.finish() catch {};
        const ctx = parent.algebra();
        var roots: [2]DigestPorts = undefined;
        for (self.children, &roots) |child, *root| {
            const shape = try @import("pure_p2_outer_capture.zig").geometry(arena.allocator(), child.key);
            const values = try V.proof.fromNative(arena.allocator(), &child.verified.proof, &child.verified.capture, &shape);
            const wire = try V.proof.guess(ctx, &values, &shape);
            for (root, child.output) |*port, value| port.* = try ctx.guess(value);
            var claims: [5]C.F = undefined;
            for (&claims, child.verified.claims) |*claim, value| claim.* = try C.F.guess(ctx, value);
            var statement = Statement{ .key = child.key, .fixed = wire.commitments[0], .outputs = root, .claims = claims };
            _ = try V.verify(ctx, &shape, &wire, &statement);
        }
        var sponge = try Sponge.init(&parent, .words);
        for ([_]u32{ 0x4f504632, 1, 2 }) |word| try sponge.absorbConstU32(word);
        for (roots) |root| try sponge.absorbMany(&root);
        const output = try sponge.finish();
        try V.common.finish();
        active = false;
        try parent.setOutputs(&output);
        try parent.finalize();
        if (!trace_only) {
            for (output, try self.expectedOutput()) |port, value| if (!ctx.get(port).eql(value)) return error.FoldOutputMismatch;
            if (!try parent.isCircuitValid()) return error.FoldCircuitInvalid;
            const saved = ctx.get(roots[0][8]);
            ctx.value_table.items[roots[0][8].idx] = saved.add(C.Q.one());
            const forged = try parent.isCircuitValid();
            ctx.value_table.items[roots[0][8].idx] = saved;
            if (forged) return error.FoldNinthChildLimbUnbound;
        }
        return parent;
    }
};
const DigestPorts = [9]C.Var;
