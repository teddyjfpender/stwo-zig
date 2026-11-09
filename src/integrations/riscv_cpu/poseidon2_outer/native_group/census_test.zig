//! Whole-source cost gate before admitting/proving a direct native group.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const S = @import("source.zig");
const Cost = @import("cost.zig");
const Capture = @import("../sponge_cpu/captured_source.zig");
const CPU = @import("../sponge_cpu/worker.zig");
const D = @import("../sponge_local_gkr/worker.zig");
const K = @import("../truth_local_gkr/worker.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const W = @import("../pure_p2_worker_protocol.zig").W;
const Manifest = @import("../pure_p2_manifest.zig");
const VCapture = core.pcs.ForField(C.O).verifier.VerifiedProofCapture(W.H);
const Collector = struct {
    a: std.mem.Allocator,
    physical_path: ?[]const u8 = null,
    source_owner: ?C.PoseidonContext = null,
    numeric_owner: ?C.PoseidonContext = null,
    baseline: [4]?@import("../native_omul/topology.zig").SourceLeaf = @splat(null),
    streams: [3]?S.Stream = @splat(null),
    numeric: ?S.Stream = null,
    models: [3]?Cost.Model = @splat(null),
    outputs: [3]?[9]C.Q = @splat(null),
    seen: u32 = 0,
    fn deinit(self: *Collector) void {
        for (&self.streams) |*stream| if (stream.*) |*value| value.deinit();
        if (self.numeric) |*value| value.deinit();
        if (self.source_owner) |*value| value.deinit();
        if (self.numeric_owner) |*value| value.deinit();
        for (&self.baseline) |*leaf| if (leaf.*) |*value| value.deinit();
    }
    fn sink(self: *Collector) Capture.Sink {
        return .{ .context = self, .visit = visit };
    }
    fn visit(raw: *anyopaque, _: std.mem.Allocator, member: Capture.View) !void {
        const self: *Collector = @ptrCast(@alignCast(raw));
        if (member.ordinal() != self.seen) return error.NativeGroupFixtureOrder;
        if (self.physical_path != null) {
            const Leaf = @import("../native_omul/topology.zig").SourceLeaf;
            var leaf = switch (member) {
                .cpu => |view| try Leaf.initSpongeCpu(self.a, view),
                .detached => |view| try Leaf.initDetachedSponge(self.a, view),
                .truth => |view| try Leaf.initLocalCatalog(self.a, view),
                .classic_truth => |view| try Leaf.initCatalog(self.a, view),
                .classic_miller => |view| try Leaf.initMiller(self.a, view),
                .local_miller => |view| try Leaf.initLocalMiller(self.a, view),
            };
            leaf.retireProverData();
            self.baseline[self.seen] = leaf;
        }
        if (self.seen == 0) {
            for (&self.streams, [_]u32{ 1, 2, 4 }) |*stream, count| stream.* = try S.Stream.init(self.a, true, 0, count, member.profile(), member.manifest());
            self.numeric = try S.Stream.init(self.a, false, 0, 4, member.profile(), member.manifest());
        }
        for (&self.streams, 0..) |*slot, index| {
            const stream = if (slot.*) |*value| value else continue;
            if (self.seen >= stream.count) continue;
            try stream.append(member);
            if (stream.appended == stream.count) {
                const expected = try stream.expectedOutput();
                var source = try stream.finish();
                var source_live = true;
                defer if (source_live) source.deinit();
                self.models[index] = try Cost.Model.derive(&source);
                self.outputs[index] = expected;
                if (stream.count == 1) {
                    // Exact standalone source graph, not merely row totals.
                    var native = @import("../native_omul/scope.zig").begin();
                    defer native.deinit();
                    var control = switch (member) {
                        inline else => |view| try view.build(self.a, true),
                    };
                    defer control.deinit();
                    try std.testing.expectEqualDeep(control.base.circuit, source.base.circuit);
                    try std.testing.expectEqualDeep(control.calls.items, source.calls.items);
                    try std.testing.expectEqualDeep(control.native_mul_calls.items, source.native_mul_calls.items);
                    try std.testing.expectEqualDeep(try control.rawCounts(), try source.rawCounts());
                }
                if (stream.count == 4 and self.physical_path != null) {
                    self.source_owner = source;
                    source_live = false;
                }
            }
        }
        if (self.numeric) |*stream| if (self.seen < stream.count) {
            try stream.append(member);
            if (stream.appended == stream.count) {
                const expected = try stream.expectedOutput();
                const source_ports = stream.mutation_ports;
                var owner = try stream.finish();
                var owner_live = true;
                defer if (owner_live) owner.deinit();
                try std.testing.expectEqualDeep(self.models[2].?, try Cost.Model.derive(&owner));
                try std.testing.expectEqualDeep(self.outputs[2].?, expected);
                try std.testing.expect(try owner.isCircuitValid());
                const port = source_ports[0][3];
                const ctx = owner.algebra();
                const old = ctx.get(port);
                ctx.value_table.items[port.idx] = old.add(C.Q.one());
                const accepted = try owner.isCircuitValid();
                ctx.value_table.items[port.idx] = old;
                try std.testing.expect(!accepted);
                if (self.physical_path != null) {
                    self.numeric_owner = owner;
                    owner_live = false;
                }
            }
        };
        self.seen += 1;
    }
    fn complete(self: *Collector, execution: [32]u8) !void {
        if (self.seen != 4) return error.NativeGroupFixtureCoverage;
        for (self.models) |model| if (model == null) return error.NativeGroupFixtureCoverage;
        const report = .{
            .scope = "direct_native_verifier_group_source_cost_no_physical_group_proof",
            .groups = self.models,
            .standalone_graph_exact = true,
            .group4_numerical_source_parity = true,
            .group4_member_ninth_limb_rejected = true,
            .canonical_binary_digest_exact = true,
            .physical_group_proof = false,
            .production_admission = false,
            .security_qualified = false,
        };
        const json = try std.json.Stringify.valueAlloc(self.a, report, .{ .whitespace = .indent_2 });
        defer self.a.free(json);
        std.debug.print("OP_DIRECT_NATIVE_GROUP_CENSUS {s}\n", .{json});
        if (std.posix.getenv("STWO_OP_NATIVE_GROUP_CENSUS_OUT")) |path| {
            var file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
            defer file.close();
            try file.writeAll(json);
            try file.sync();
        }
        if (self.physical_path) |path| {
            const baseline_path = std.posix.getenv("STWO_OP_NATIVE_GROUP_BASELINE_ROOT") orelse return error.MissingNativeGroupBaselineRoot;
            var sources: [4]@import("../native_omul/topology.zig").SourceLeaf = undefined;
            // Borrowed copies only. Collector owns and destroys these keys.
            for (&sources, self.baseline) |*source, leaf| source.* = leaf orelse return error.NativeGroupFixtureCoverage;
            try @import("physical.zig").run(self.a, &self.numeric_owner.?, &self.source_owner.?, self.numeric.?.profile, self.outputs[2].?, &sources, execution, path, baseline_path);
        }
    }
};
threadlocal var current: ?*Collector = null;
const Hook = struct {
    pub const workers = 8;
    pub const local_truth = true;
    pub const typed_manifest = true;
    pub fn verified(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, ordinal: u32, key: *const @import("../sponge_cpu/key.zig").Key, manifest: [36]u8, main: [36]u8, encoded: *const CPU.Encoded, capture: *const VCapture) !void {
        const collector = current orelse return error.MissingNativeGroupCollector;
        try Capture.cpu(a, setup, request, .{}, first, ordinal, key, manifest, main, encoded, capture, collector.sink());
    }
    pub fn detached(a: std.mem.Allocator, worker: *const D.Worker, encoded: *const D.Encoded, manifest: [36]u8, main: [36]u8) !void {
        const collector = current orelse return error.MissingNativeGroupCollector;
        try Capture.detached(a, worker, encoded, manifest, main, collector.sink());
    }
    pub fn truth(a: std.mem.Allocator, key: *const K.Key, declaration: R.Truth, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, encoded: *const K.Encoded, capture: *const VCapture) !void {
        const collector = current orelse return error.MissingNativeGroupCollector;
        try Capture.truth(a, key, declaration, expected, manifest, main, encoded, capture, collector.sink());
    }
    pub fn complete(_: std.mem.Allocator, execution: [32]u8, _: [36]u8, _: []const Manifest.Claims) !void {
        try (current orelse return error.MissingNativeGroupCollector).complete(execution);
    }
};
test "direct native group source census one two four preserves standalone and canonical frames" {
    const physical = std.posix.getenv("STWO_OP_NATIVE_GROUP_PHYSICAL_OUT");
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, if (physical != null) 32 << 30 else 12 << 30);
    defer budget.destroy();
    var collector = Collector{ .a = budget.allocator(), .physical_path = physical };
    var live = true;
    defer if (live) collector.deinit();
    current = &collector;
    defer current = null;
    try @import("../sponge_cpu/join_test.zig").exerciseWithHookBacking(false, Hook, budget.allocator());
    collector.deinit();
    live = false;
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    std.debug.print("OP_DIRECT_NATIVE_GROUP_BUDGET peak={} cap={} zero_end=true\n", .{ budget.snapshot().peak_live_bytes, budget.limit });
}
test "direct native group rejects unaligned empty oversized and truncated source scope" {
    const a = std.testing.failing_allocator;
    const profile = @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    const root = @import("../pure_p2_native.zig").hashWords(&.{ 1, 2 });
    for ([_][2]u32{ .{ 0, 0 }, .{ 0, 3 }, .{ 0, 8 }, .{ 1, 2 }, .{ 254, 4 } }) |pair| try std.testing.expectError(error.NativeGroupCoverage, S.Stream.init(a, true, pair[0], pair[1], profile, root));
}
