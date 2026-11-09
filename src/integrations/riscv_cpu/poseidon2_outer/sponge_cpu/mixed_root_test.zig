//! Explicit bounded pending root: two typed CPU-frontier proofs, detached
//! sponge and local-GKR Keccak. No production execution admission is implied.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = @import("../full_p2_common.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const Manifest = @import("../pure_p2_manifest.zig");
const CPU = @import("worker.zig");
const D = @import("../sponge_local_gkr/worker.zig");
const K = @import("../truth_local_gkr/worker.zig");
const CpuView = @import("leaf.zig").View;
const DetachedView = @import("../sponge_local_gkr/leaf.zig").View;
const KeccakView = @import("../truth_local_gkr/leaf_test.zig").View;
const Topology = @import("../native_omul/topology.zig");
const Proof = @import("../native_omul/proof.zig");
const Fold = @import("../native_omul/fold.zig");
const Authority = @import("../native_omul/authority.zig").Key;
const Source = union(enum) { cpu: CpuView, detached: DetachedView, keccak: KeccakView };
const Node = struct {
    key: *const Authority,
    bytes: []u8,
    captured: Proof.Captured,
    output: Fold.Digest,
    fn deinit(self: *Node, a: std.mem.Allocator) void {
        self.captured.deinit(a);
        a.free(self.bytes);
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    directory: std.fs.Dir,
    sources: [4]Topology.SourceLeaf = undefined,
    present: [4]bool = @splat(false),
    nodes: [7]?Node = @splat(null),
    altered: [4]Fold.Digest = undefined,
    manifest: ?[36]u8 = null,
    complete: bool = false,
    topology: ?Topology.Topology = null,
    fn deinit(self: *Collector) void {
        for (&self.nodes) |*node| if (node.*) |*value| value.deinit(self.a);
        if (self.topology) |*t| t.deinit();
        for (&self.sources, self.present) |*source, present| if (present) source.deinit();
        self.directory.close();
    }
    fn persist(self: *Collector, ordinal: usize, bytes: []const u8, recorder: *engine.stage_profile.Recorder) !void {
        const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
        const name = try std.fmt.allocPrint(self.a, "node-{d}.bin", .{ordinal});
        defer self.a.free(name);
        try write(self.directory, name, bytes);
        var stages = try recorder.snapshot(self.a);
        defer stages.deinit(self.a);
        const json = try std.json.Stringify.valueAlloc(self.a, stages, .{});
        defer self.a.free(json);
        const stage_name = try std.fmt.allocPrint(self.a, "node-{d}-stages.json", .{ordinal});
        defer self.a.free(stage_name);
        try write(self.directory, stage_name, json);
    }
    fn prove(self: *Collector, ordinal: usize, owner: *const @import("../context.zig").Context, key: *const Authority, output: Fold.Digest) !Node {
        var recorder = engine.stage_profile.Recorder.initWithOptions(self.a, "cpu", "op_detached_pending_root", .{ .capture_tasks = false, .capture_process_usage = true });
        defer recorder.deinit();
        var timer = try std.time.Timer.start();
        const bytes = try Proof.proveProfiled(self.a, owner, key, &output, &recorder);
        errdefer self.a.free(bytes);
        try self.persist(ordinal, bytes, &recorder);
        var captured = try Proof.verifyCaptured(self.a, key, &output, bytes);
        errdefer captured.deinit(self.a);
        std.debug.print("OP_SPONGE_MIXED_NODE ordinal={} bytes={} prove_receive_ns={}\n", .{ ordinal, bytes.len, timer.read() });
        return .{ .key = key, .bytes = bytes, .captured = captured, .output = output };
    }
    fn append(self: *Collector, ordinal: usize, manifest: [36]u8, source: Source) !void {
        if (ordinal >= 4 or self.present[ordinal]) return error.MixedRootLeafCoverage;
        if (self.manifest) |old| {
            if (!std.mem.eql(u8, &old, &manifest)) return error.MixedRootManifest;
        } else self.manifest = manifest;
        const leaf = switch (source) {
            .cpu => |v| try Topology.SourceLeaf.initSpongeCpu(self.a, v),
            .detached => |v| try Topology.SourceLeaf.initDetachedSponge(self.a, v),
            .keccak => |v| try Topology.SourceLeaf.initLocalCatalog(self.a, v),
        };
        self.sources[ordinal] = leaf;
        self.present[ordinal] = true;
        var scope = @import("../native_omul/scope.zig").begin();
        defer scope.deinit();
        var owner = switch (source) {
            inline else => |v| try v.buildForProving(self.a),
        };
        defer owner.deinit();
        const output = switch (source) {
            inline else => |v| try v.expectedOutput(self.a),
        };
        self.nodes[ordinal] = try self.prove(ordinal, &owner, try self.sources[ordinal].key(), output);
        try self.sources[ordinal].finishProving();
        self.altered[ordinal] = output;
        switch (source) {
            .cpu => |v| if (ordinal == 0) {
                var changed = v;
                const claims = try self.a.dupe(C.O, v.claims);
                defer self.a.free(claims);
                claims[claims.len - 1] = claims[claims.len - 1].add(C.O.one());
                changed.claims = claims;
                self.altered[ordinal] = try changed.expectedOutput(self.a);
            },
            .detached => |v| {
                var changed = v;
                changed.claims[0][2] = changed.claims[0][2].sub(C.O.one());
                self.altered[ordinal] = try changed.expectedOutput(self.a);
            },
            else => {},
        }
    }
    fn finish(self: *Collector, execution: [32]u8, manifest: [36]u8, claims: []const Manifest.Claims) !void {
        if (self.complete or claims.len != 4) return error.MixedRootLeafCoverage;
        for (self.present) |p| if (!p) return error.MixedRootLeafCoverage;
        if (!std.mem.eql(u8, &manifest, &self.manifest.?)) return error.MixedRootManifest;
        var shared = Manifest.Claims{ .ram = C.O.zero(), .kio = C.O.zero(), .wire = C.O.zero() };
        for (claims) |c| {
            shared.ram = shared.ram.add(c.ram);
            shared.kio = shared.kio.add(c.kio);
            shared.wire = shared.wire.add(c.wire);
        }
        if (!shared.ram.isZero() or !shared.kio.isZero() or !shared.wire.isZero()) return error.MixedRootGlobalClosure;
        const profile = Protocol.Profile.op_target_b4_q72_p0_fold4_v1;
        self.topology = try Topology.Topology.init(self.a, profile, execution, &self.sources);
        const topology = &self.topology.?;
        for ([_][3]usize{ .{ 0, 1, 4 }, .{ 2, 3, 5 }, .{ 4, 5, 6 } }, 0..) |pair, index| {
            const left = &self.nodes[pair[0]].?;
            const right = &self.nodes[pair[1]].?;
            const source = Fold.Source{ .children = .{ .{ .key = left.key, .verified = &left.captured, .output = left.output }, .{ .key = right.key, .verified = &right.captured, .output = right.output } } };
            var owner = try source.buildForProving(self.a);
            defer owner.deinit();
            const key = topology.owned.items[index];
            self.nodes[pair[2]] = try self.prove(pair[2], &owner, key, try source.expectedOutput());
            @import("../native_omul/verifier_key.zig").retireProverData(key);
        }
        const root = &self.nodes[6].?;
        var outputs: [4]Fold.Digest = undefined;
        for (&outputs, self.nodes[0..4]) |*out, node| out.* = node.?.output;
        try std.testing.expectEqualDeep(root.output, try Fold.treeDigest(self.a, &outputs));
        var fresh = try Topology.Topology.initForVerification(self.a, profile, execution, &self.sources);
        defer fresh.deinit();
        try std.testing.expectEqualSlices(u8, &topology.key().base.identity, &fresh.key().base.identity);
        try Proof.verify(self.a, fresh.key(), &root.output, root.bytes);
        // A valid same-profile proof under an unrelated algebraic source key
        // cannot replace the independently reconstructed complete topology.
        var unrelated = try @import("../context.zig").Context.init(self.a, 9);
        defer unrelated.deinit();
        var ports: [9]C.Var = undefined;
        for (&ports, root.output) |*port, value| port.* = try unrelated.algebra().guess(value);
        try unrelated.setOutputs(&ports);
        try unrelated.finalize();
        var unrelated_key = try Authority.init(self.a, &unrelated, profile);
        defer unrelated_key.deinit();
        const unrelated_proof = try Proof.prove(self.a, &unrelated, &unrelated_key, &root.output);
        defer self.a.free(unrelated_proof);
        try Proof.verify(self.a, &unrelated_key, &root.output, unrelated_proof);
        try std.testing.expect(std.meta.isError(Proof.verify(self.a, fresh.key(), &root.output, unrelated_proof)));
        const altered = try Fold.treeDigest(self.a, &self.altered);
        try std.testing.expect(std.meta.isError(Proof.verify(self.a, fresh.key(), &altered, root.bytes)));
        var swapped = outputs;
        std.mem.swap(Fold.Digest, &swapped[0], &swapped[1]);
        const wrong_order = try Fold.treeDigest(self.a, &swapped);
        try std.testing.expect(std.meta.isError(Proof.verify(self.a, fresh.key(), &wrong_order, root.bytes)));
        swapped = outputs;
        swapped[1] = swapped[0];
        const duplicated = try Fold.treeDigest(self.a, &swapped);
        try std.testing.expect(std.meta.isError(Proof.verify(self.a, fresh.key(), &duplicated, root.bytes)));
        const omitted = try Fold.treeDigest(self.a, outputs[0..3]);
        try std.testing.expect(std.meta.isError(Proof.verify(self.a, fresh.key(), &omitted, root.bytes)));
        const corrupt = try self.a.dupe(u8, root.bytes);
        defer self.a.free(corrupt);
        corrupt[corrupt.len - 1] ^= 1;
        try std.testing.expect(std.meta.isError(Proof.verify(self.a, fresh.key(), &root.output, corrupt)));
        const json = try std.json.Stringify.valueAlloc(self.a, .{ .schema = "op-detached-four-member-pending-root-v1", .members = 4, .reductions = 3, .root_bytes = root.bytes.len, .manifest = manifest, .outputs = outputs, .root = root.output, .source_fingerprint = fresh.leaf_fingerprint, .typed_manifest = true, .all_global_claims_close = true, .fresh_source_topology = true, .valid_same_profile_wrong_key_rejected = true, .balanced_Wire_reordering_duplicate_omission_corruption_rejected = true, .production_admission = false, .complete_execution = false, .security_qualified = false }, .{});
        defer self.a.free(json);
        try @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive(self.directory, "root.json", json);
        try @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive(self.directory, "root.bin", root.bytes);
        try std.posix.fsync(self.directory.fd);
        std.debug.print("OP_SPONGE_MIXED_ROOT {s}\n", .{json});
        self.complete = true;
    }
};
var current: ?*Collector = null;
const Hook = struct {
    pub const workers = 8;
    pub const local_truth = true;
    pub const typed_manifest = true;
    pub fn verified(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, ordinal: u32, key: *const @import("key.zig").Key, manifest: [36]u8, main: [36]u8, encoded: *const CPU.Encoded, capture: *const core.pcs.ForField(C.O).verifier.VerifiedProofCapture(W.H)) !void {
        const target = current orelse return error.MissingMixedCollector;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer parsed.deinit(a);
        var roster = try @import("frame.zig").Roster.init(a, setup, request.sponge.calls, key.frontier_log, request.base.epoch, ordinal);
        defer roster.deinit();
        var local = try @import("native.zig").decode(a, roster.instances, encoded.local);
        defer local.deinit();
        const shape = try @import("capture.zig").geometry(scratch, setup, key);
        const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
        try target.append(ordinal, manifest, .{ .cpu = .{ .setup = setup, .request = request, .span = .{}, .first = first, .key = key, .expected = .{ .ordinal = ordinal, .statement = try key.statement(setup, request, first, .{}, ordinal) }, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .child = &local.proof, .shape = &shape, .values = &values } });
    }
    pub fn detached(a: std.mem.Allocator, worker: *const D.Worker, encoded: *const D.Encoded, manifest: [36]u8, main: [36]u8) !void {
        const target = current orelse return error.MissingMixedCollector;
        var capture: core.pcs.ForField(C.O).verifier.VerifiedProofCapture(W.H) = undefined;
        _ = try D.verifyWithCapture(a, worker.geometry, worker.key, worker.expected.ordinal, manifest, main, encoded, &capture);
        defer capture.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer parsed.deinit(a);
        var local = try @import("../sponge_local_gkr/native.zig").decode(a, worker.geometry, encoded.local);
        defer local.deinit();
        const shape = try @import("../sponge_local_gkr/capture.zig").geometry(scratch, worker.geometry, worker.key);
        const values = try V.proof.fromNative(scratch, &parsed, &capture, &shape);
        try target.append(worker.expected.ordinal, manifest, .{ .detached = .{ .key = worker.key, .geometry = worker.geometry, .ordinal = worker.expected.ordinal, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .child = &local.proof, .shape = &shape, .values = &values } });
    }
    pub fn truth(a: std.mem.Allocator, key: *const K.Key, declaration: R.Truth, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, encoded: *const K.Encoded, capture: *const core.pcs.ForField(C.O).verifier.VerifiedProofCapture(W.H)) !void {
        const target = current orelse return error.MissingMixedCollector;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer parsed.deinit(a);
        const shapes = try @import("../truth_local_gkr/authority.zig").shapes(declaration);
        var local = try @import("../truth_local_gkr/native.zig").decode(a, shapes, encoded.local);
        defer local.deinit();
        const shape = try @import("../truth_local_gkr/statement.zig").geometry(scratch, key, declaration);
        const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
        try target.append(expected.ordinal, manifest, .{ .keccak = .{ .key = key, .truth = declaration, .expected = expected, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .local = &local.proof, .shape = &shape, .values = &values } });
    }
    pub fn complete(_: std.mem.Allocator, execution: [32]u8, manifest: [36]u8, claims: []const Manifest.Claims) !void {
        try (current orelse return error.MissingMixedCollector).finish(execution, manifest, claims);
    }
};
test "detached sponge four-member typed pending root serial physical qualification" {
    const path = std.posix.getenv("STWO_OP_SPONGE_MIXED_ROOT_OUT") orelse return error.SkipZigTest;
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 32 << 30);
    defer budget.destroy();
    try std.fs.cwd().makeDir(path);
    var collector = Collector{ .a = budget.allocator(), .directory = try std.fs.cwd().openDir(path, .{}) };
    var live = true;
    defer if (live) collector.deinit();
    current = &collector;
    defer current = null;
    try @import("join_test.zig").exerciseWithHookBacking(false, Hook, budget.allocator());
    try std.testing.expect(collector.complete);
    collector.deinit();
    live = false;
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    std.debug.print("OP_SPONGE_MIXED_BUDGET peak={} cap={}\n", .{ budget.snapshot().peak_live_bytes, budget.limit });
}
