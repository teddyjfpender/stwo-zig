//! All concrete runtime source kinds share exactly one verifier graph between
//! standalone and direct-group construction. No recursive proof is generated.
const std = @import("std");
const Capture = @import("captured_source.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Classic = @import("../pure_p2_truth_worker.zig");
const Tower = @import("../pure_p2_tower_worker.zig");
const Local = @import("../miller_local_gkr/worker.zig");
const Sink = struct {
    visited: bool = false,
    fn visit(raw: *anyopaque, a: std.mem.Allocator, member: Capture.View) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.visited) return error.SourceAdapterDuplicate;
        self.visited = true;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const normalized = try member.normalized(arena.allocator());
        try std.testing.expectEqual(member.ordinal(), normalized.ordinal());
        try std.testing.expectEqual(member.profile(), normalized.profile());
        try std.testing.expectEqualDeep(member.fixedIdentity(), normalized.fixedIdentity());
        switch (member) {
            inline .classic_truth, .classic_miller, .local_miller => |view| try std.testing.expectEqualDeep(view.expected.fixed_identity, member.fixedIdentity()),
            else => return error.UnexpectedSourceAdapterKind,
        }
        try std.testing.expectEqualDeep(member.manifest(), normalized.manifest());
        try std.testing.expectEqualDeep(try member.expected(a), try normalized.expected(a));
        // All fields of Expected, including source identity/mass/presence, are
        // independently re-derived before any verifier expression is emitted.
        var wrong = member;
        switch (wrong) {
            inline .classic_truth, .classic_miller, .local_miller => |*view| view.expected.statement[0] ^= 1,
            else => return error.UnexpectedSourceAdapterKind,
        }
        try std.testing.expect(std.meta.isError(wrong.normalized(arena.allocator())));
        const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
        var changed_values: V.Captured = switch (member) {
            inline else => |view| view.values.*,
        };
        changed_values.cap_log = 1;
        var capped = member;
        switch (capped) {
            inline else => |*view| view.values = &changed_values,
        }
        try std.testing.expectError(error.DetachedSourceCapVariant, capped.normalized(arena.allocator()));
        const G = @import("../native_group/source.zig");
        inline for (.{ true, false }) |trace_only| {
            var stream = try G.Stream.init(a, trace_only, member.ordinal(), 1, member.profile(), member.manifest());
            defer stream.deinit();
            try stream.append(member);
            var group = try stream.finish();
            defer group.deinit();
            var native = @import("../native_omul/scope.zig").begin();
            defer native.deinit();
            var standalone = switch (normalized) {
                inline else => |view| if (trace_only) try view.build(a, true) else try view.buildForProving(a),
            };
            defer standalone.deinit();
            try std.testing.expectEqualDeep(standalone.base.circuit, group.base.circuit);
            try std.testing.expectEqualDeep(standalone.calls.items, group.calls.items);
            try std.testing.expectEqualDeep(standalone.native_mul_calls.items, group.native_mul_calls.items);
            try std.testing.expectEqualDeep(try standalone.rawCounts(), try group.rawCounts());
            if (!trace_only) {
                try std.testing.expectEqualDeep(standalone.base.value_table.items, group.base.value_table.items);
                try std.testing.expect(try group.isCircuitValid());
            }
        }
        if (member == .local_miller) if (std.posix.getenv("STWO_OP_SOURCE_LOCAL_CONTROL")) |path| {
            var dir = try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            const bytes = try dir.readFileAlloc(a, "leaf.bin", 2 << 20);
            defer a.free(bytes);
            var key = try @import("../native_omul/topology.zig").SourceLeaf.initLocalMiller(a, member.local_miller);
            defer key.deinit();
            key.retireProverData();
            const output = try member.expected(a);
            try @import("../native_omul/proof.zig").verify(a, try key.key(), &output, bytes);
            var wrong_output = output;
            wrong_output[8] = wrong_output[8].add(@import("../full_p2_common.zig").Q.one());
            try std.testing.expect(std.meta.isError(@import("../native_omul/proof.zig").verify(a, try key.key(), &wrong_output, bytes)));
            std.debug.print("OP_ALL_SOURCE_RETAINED_LOCAL bytes={} fresh_source=true wrong_output_rejected=true\n", .{bytes.len});
        };
        std.debug.print("OP_ALL_SOURCE_ADAPTER kind={s} exact_standalone_group1_graph=true trace_numeric=true source_expected=true\n", .{@tagName(member)});
    }
    fn sink(self: *@This()) Capture.Sink {
        return .{ .context = self, .visit = visit };
    }
};
const ClassicHook = struct {
    pub fn run(a: std.mem.Allocator, key: *const Classic.Key, truth: R.Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Classic.Encoded, capture: anytype) !void {
        var parsed = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer parsed.deinit(a);
        var sink = Sink{};
        try Capture.classicTruth(a, key, truth, expected, pending.digest, parsed.commitment_scheme_proof.commitments.items[1], encoded, capture, sink.sink());
        try std.testing.expect(sink.visited);
    }
};
const TowerHook = struct {
    pub fn run(a: std.mem.Allocator, key: *const Tower.Key, span: Tower.Span, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Tower.Encoded, capture: anytype) !void {
        var parsed = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer parsed.deinit(a);
        var sink = Sink{};
        try Capture.classicMiller(a, key, span, expected, pending.digest, parsed.commitment_scheme_proof.commitments.items[1], encoded, capture, sink.sink());
        try std.testing.expect(sink.visited);
    }
};
const LocalHook = struct {
    pub fn run(a: std.mem.Allocator, key: *const Local.Key, span: Local.Span, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Local.Encoded, capture: anytype) !void {
        var parsed = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer parsed.deinit(a);
        var sink = Sink{};
        if (std.posix.getenv("STWO_OP_SOURCE_LOCAL_CONTROL")) |path| {
            var dir = try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            const retained = try dir.readFileAlloc(a, "native-envelope.bin", 2 << 20);
            defer a.free(retained);
            const fresh = try Local.encode(a, encoded);
            defer a.free(fresh);
            try std.testing.expectEqualSlices(u8, retained, fresh);
        }
        try Capture.localMiller(a, key, span, expected, pending.digest, parsed.commitment_scheme_proof.commitments.items[1], encoded, capture, sink.sink());
        try std.testing.expect(sink.visited);
    }
};
test "all runtime source adapters classic catalog exact standalone grouped graph" {
    var sha = try @import("../../word16_global_execution/sha256/roster.zig").TruthSetup.init(std.testing.allocator, 5);
    defer sha.deinit();
    try @import("../pure_p2_truth_catalog_test.zig").runWithHook(.{ .sha256 = .{ .setup = &sha, .first_id = 1, .calls = 1 } }, ClassicHook);
}
test "all runtime source adapters classic Miller exact standalone grouped graph" {
    try @import("../../delegations/op_tower/pure_p2_worker_test.zig").exercise(TowerHook);
}
test "all runtime source adapters local Miller exact standalone grouped graph" {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 8 << 30);
    defer budget.destroy();
    try Local.runWithHook(budget.allocator(), LocalHook);
}
const DetachedHook = struct {
    pub fn detached(a: std.mem.Allocator, worker: *const @import("../sponge_local_gkr/worker.zig").Worker, encoded: *const @import("../sponge_local_gkr/worker.zig").Encoded, manifest: [36]u8, main: [36]u8) !void {
        const D = @import("../sponge_local_gkr/worker.zig");
        var capture: @import("stwo_core").pcs.ForField(@import("../full_p2_common.zig").O).verifier.VerifiedProofCapture(Protocol.W.H) = undefined;
        _ = try D.verifyWithCapture(a, worker.geometry, worker.key, worker.expected.ordinal, manifest, main, encoded, &capture);
        defer capture.deinit(a);
        var sink = DetachedSink{};
        try Capture.detachedCaptured(a, worker.key, worker.geometry, worker.expected.ordinal, manifest, main, encoded, &capture, .{ .context = &sink, .visit = DetachedSink.visit });
        // Compatibility wrapper verifies once itself, then uses the same body.
        // Production callers with a fresh capture use only detachedCaptured.
        try Capture.detached(a, worker, encoded, manifest, main, .{ .context = &sink, .visit = DetachedSink.visit });
        try std.testing.expectEqual(@as(u32, 2), sink.count);
    }
};
const DetachedSink = struct {
    count: u32 = 0,
    output: ?[9]@import("../full_p2_common.zig").Q = null,
    fn visit(raw: *anyopaque, a: std.mem.Allocator, member: Capture.View) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (member != .detached) return error.UnexpectedSourceAdapterKind;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const view = try member.normalized(arena.allocator());
        const output = try view.expected(a);
        if (self.output) |old| try std.testing.expectEqualDeep(old, output);
        self.output = output;
        self.count += 1;
    }
};
test "all runtime source adapters detached existing capture compatibility" {
    try @import("join_test.zig").exerciseWithHook(true, DetachedHook);
}
