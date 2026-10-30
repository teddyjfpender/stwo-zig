//! Test-only detached root evidence. Source proofs/captures need not survive
//! this producer; receiving uses only metadata, physical claim bytes and root.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Profile = @import("../../recursion/block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Multi = @import("../block_v7_multi_union_proof_v1.zig").ForMode(true);
const Statement = @import("../block_v7_multi_union_statement_v1.zig").ForMode(true);
const Claims = @import("../block_v7_union_claim_wire_v1.zig");
const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const Protocol = @import("../../recursion/block_v7_union_parent_protocol_v1.zig");
const Receiver = @import("../../recursion/block_v7_union_receiver_v1.zig");
pub const Evidence = struct {
    a: std.mem.Allocator,
    proof: []u8,
    claims: []u8,
    pub fn deinit(self: *Evidence) void {
        self.a.free(self.proof);
        self.a.free(self.claims);
        self.* = undefined;
    }
    pub fn verify(self: *const Evidence, metadata: *const Statement.Owned) !void {
        var arena = std.heap.ArenaAllocator.init(self.a);
        defer arena.deinit();
        var cursor = @import("../guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = self.claims };
        var count: usize = 1 << 18;
        const claims = try Claims.decode(Multi.Claims, arena.allocator(), &cursor, &count);
        if (cursor.position != self.claims.len) return error.NonCanonicalUnionClaimSuffix;
        const profile = try Profile.Owned.derive(self.a, metadata, &claims, .{ .original = .{ .max_retained_pcs_bytes = 8 << 30 } });
        defer profile.deinit();
        var verified = try Receiver.verify(self.a, self.proof, profile, &claims, 4, .diagnostic_q8_pow0, .{});
        defer verified.deinit();
        try std.testing.expectEqual(.declared_window, verified.summary.scope);
        try std.testing.expectEqual(metadata.trusted.window.?.boundary.cycles, verified.summary.cycles);
        // Preserve the aggregate while changing physical RAM claims. A fresh
        // independent compiler must not turn this into a valid parent input.
        const before = claims.ram[0].sums;
        claims.ram[0].sums[29] = before[29].add(core.fields.qm31.QM31.one());
        claims.ram[0].sums[30] = before[30].sub(core.fields.qm31.QM31.one());
        if (Receiver.verify(self.a, self.proof, profile, &claims, 4, .diagnostic_q8_pow0, .{})) |forged| {
            var accepted = forged;
            accepted.deinit();
            return error.AcceptedForgedRecursiveUnionClaims;
        } else |_| {}
        claims.ram[0].sums = before;
    }
};
pub fn produce(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture) !Evidence {
    var root = try @import("../../recursion/block_v7_union_pipeline_v1.zig").produce(a, profile, capture, .{ .profile = .diagnostic_q8_pow0 });
    errdefer root.deinit();
    if (std.process.hasEnvVarConstant("STWO_V7_UNION_COMPILER_PARITY")) {
        var control = try produceReference(a, profile, capture);
        defer control.deinit();
        try std.testing.expectEqualSlices(u8, control.proof, root.bytes);
        try std.testing.expectEqualSlices(u8, control.claims, root.claims);
    }
    return .{ .a = a, .proof = root.bytes, .claims = root.claims };
}
fn produceReference(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture) !Evidence {
    var cold = try @import("../../recursion/block_v7_union_fixed_roster_v1.zig").Owned.derive(a, profile, &capture.claims, 4, .{});
    defer cold.deinit();
    var ready = try @import("../../recursion/block_v7_union_preparation_v1.zig").prepare(a, profile, capture, 4, .{});
    defer ready.deinit();
    try cold.validateLive(&ready);
    const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, .diagnostic_q8_pow0);
    const roster = [_]Protocol.Bus.Expected{try Receiver.expected(profile)};
    const key = try Protocol.Key.fromGeometry(base, cold.wires, &roster);
    const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, .{ .children = &.{ready.values} }, &roster);
    const plan = try @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol).init(a, &ready.recursive.rows, admission);
    defer plan.deinit();
    var proof = try plan.prove(a, &ready.recursive.rows);
    defer proof.deinit();
    const bytes = try Parent.codec.encode(a, &proof, &admission);
    errdefer a.free(bytes);
    var writer = @import("../bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
    defer writer.deinit();
    var count: usize = 1 << 18;
    try Claims.encode(Multi.Claims, &writer, capture.claims, &count);
    return .{ .a = a, .proof = bytes, .claims = try writer.bytes.toOwnedSlice(a) };
}
