//! Actual CPU OWNER/GKR + Miller truth leaves, sharing one manifest, folded
//! through their distinct independently derived five-roster source keys.
const std = @import("std");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = @import("full_p2_common.zig");
const Join = @import("pure_p2_op_cpu_fixture.zig");
const CPU = @import("pure_p2_cpu_leaf_test.zig");
const Tower = @import("pure_p2_tower_leaf_test.zig");
const NativeTower = @import("pure_p2_tower_worker.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const Authority = @import("authority.zig").Authority;
const Proof = @import("proof.zig");
const Fold = @import("pure_p2_fold.zig");
const CpuSource = struct {
    view: CPU.ShapeView,
    pub fn build(self: @This(), a: std.mem.Allocator, trace: bool) !V.common.PoseidonContext {
        return self.view.build(a, trace, null);
    }
    pub fn expectedOutput(self: @This(), a: std.mem.Allocator) !Fold.Digest {
        return self.view.expectedOutput(a);
    }
};
const PhysicalChild = struct {
    key: Authority,
    captured: Proof.Captured,
    output: Fold.Digest,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.captured.deinit(a);
        self.key.deinit();
    }
};
fn child(a: std.mem.Allocator, source: anytype, profile: @import("op_profile.zig").Profile, label: []const u8) !PhysicalChild {
    var timer = try std.time.Timer.start();
    var owner = try source.build(a, false);
    var live = true;
    defer if (live) owner.deinit();
    const output = try source.expectedOutput(a);
    var identity: [32]u8 = undefined;
    const encoded = blk: {
        var producer_key = try Authority.initForProfile(a, &owner, profile);
        defer producer_key.deinit();
        identity = producer_key.identity;
        break :blk try Proof.prove(a, &owner, &producer_key, &output);
    };
    defer a.free(encoded);
    owner.deinit();
    live = false;
    const producer_ns = timer.lap();
    var trace = try source.build(a, true);
    defer trace.deinit();
    var key = try Authority.initForProfile(a, &trace, profile);
    errdefer key.deinit();
    try std.testing.expectEqualSlices(u8, &identity, &key.identity);
    var captured = try Proof.verifyCaptured(a, &key, &output, encoded);
    errdefer captured.deinit(a);
    std.debug.print("OP_PURE_P2_HETERO_CHILD kind={s} bytes={} producer_ns={} fresh_receiver_ns={}\n", .{ label, encoded.len, producer_ns, timer.lap() });
    return .{ .key = key, .captured = captured, .output = output };
}
const Hook = struct {
    pub fn run(a: std.mem.Allocator, join: Join.VerifiedJoin) !void {
        var cpu_native = try Protocol.W.Wire.decodeProofBytesBinary(a, join.encoded.bytes);
        defer cpu_native.deinit(a);
        var tower_capture: @import("stwo_core").pcs.ForField(Protocol.W.O).verifier.VerifiedProofCapture(Protocol.W.H) = undefined;
        _ = try NativeTower.verifyWithCapture(a, join.truth_key, join.truth_span, join.truth_expected, join.manifest, 1, join.truth_encoded, &tower_capture);
        defer tower_capture.deinit(a);
        var tower_native = try Protocol.W.Wire.decodeProofBytesBinary(a, join.truth_encoded.bytes);
        defer tower_native.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const cpu_shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), join.setup, join.key.profile.config());
        const cpu_values = try V.proof.fromNative(arena.allocator(), &cpu_native, join.capture, &cpu_shape);
        const cpu = CpuSource{ .view = .{ .op_span = join.span, .setup = join.setup, .request = join.request, .first = join.first_ids, .expected = join.expected, .key = join.key, .manifest = join.manifest.digest, .main = cpu_native.commitment_scheme_proof.commitments.items[1], .receipt = join.stage_one.local.?.receipt, .claims = join.encoded.claims, .child = join.stage_one.local.?.proof, .shape = &cpu_shape, .values = &cpu_values } };
        const tower_shape = try @import("pure_p2_tower_statement.zig").geometry(arena.allocator(), join.truth_key);
        const tower_values = try V.proof.fromNative(arena.allocator(), &tower_native, &tower_capture, &tower_shape);
        const tower = Tower.View{ .key = join.truth_key, .span = join.truth_span, .expected = join.truth_expected, .manifest = join.manifest.digest, .main = tower_native.commitment_scheme_proof.commitments.items[1], .claims = join.truth_encoded.claims, .shape = &tower_shape, .values = &tower_values };
        var left = try child(a, cpu, join.key.profile, "CPU");
        defer left.deinit(a);
        var right = try child(a, tower, join.truth_key.profile, "Miller");
        defer right.deinit(a);
        const source = Fold.Source{ .children = .{
            .{ .key = &left.key, .verified = &left.captured, .output = left.output },
            .{ .key = &right.key, .verified = &right.captured, .output = right.output },
        } };
        var timer = try std.time.Timer.start();
        var parent = try source.build(a, false);
        var live = true;
        defer if (live) parent.deinit();
        const raw = try parent.rawCounts();
        const cells = try parent.census(false);
        const output = try source.expectedOutput();
        var identity: [32]u8 = undefined;
        const encoded = blk: {
            var key = try Authority.initForProfile(a, &parent, join.key.profile);
            defer key.deinit();
            identity = key.identity;
            break :blk try Proof.prove(a, &parent, &key, &output);
        };
        defer a.free(encoded);
        parent.deinit();
        live = false;
        const producer_ns = timer.lap();
        var trace = try (Fold.TraceSource{ .keys = .{ &left.key, &right.key } }).build(a);
        defer trace.deinit();
        var receiver = try Authority.initForProfile(a, &trace, join.key.profile);
        defer receiver.deinit();
        try std.testing.expectEqualSlices(u8, &identity, &receiver.identity);
        try Proof.verify(a, &receiver, &output, encoded);
        const receiver_ns = timer.lap();
        const swapped = try Fold.digest(right.output, left.output);
        try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver, &swapped, encoded)));
        var ninth = output;
        ninth[8] = ninth[8].add(C.Q.one());
        try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver, &ninth, encoded)));
        const mutated = try a.dupe(u8, encoded);
        defer a.free(mutated);
        mutated[40] ^= 1;
        try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver, &output, mutated)));
        const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "actual_CPU_Miller_shared_manifest_heterogeneous_physical_fold", .bytes = encoded.len, .producer_ns = producer_ns, .fresh_receiver_ns = receiver_ns, .raw = raw, .cells = cells, .ordered = true, .ninth_limb_bound = true, .source_independent = true, .execution_admission = false, .production_admission_open = false }, .{});
        defer a.free(json);
        std.debug.print("OP_PURE_P2_HETERO_FOLD {s}\n", .{json});
    }
};
test "OP pure P2 actual heterogeneous CPU Miller physical fold and fresh receiver" {
    const gate = std.posix.getenv("STWO_OP_P2_HETERO_PHYSICAL") orelse return error.SkipZigTest;
    if (std.mem.eql(u8, gate, "0") or gate.len == 0) return error.SkipZigTest;
    if (!std.mem.eql(u8, gate, "1")) return error.InvalidOpP2HeterogeneousGate;
    try Join.exercise(Hook);
}
