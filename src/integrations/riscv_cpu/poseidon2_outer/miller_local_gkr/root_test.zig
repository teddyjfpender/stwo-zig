//! Complete synthetic CPU/Miller execution -> R6 root -> fresh root receiver.
//! This gate establishes protocol integration, not Kona or block throughput.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Bundle = @import("../pure_p2_op_bundle.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Fixture = @import("../pure_p2_op_cpu_fixture.zig");
const Source = @import("fixture_source.zig");
const ML = @import("worker.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const Cells = @import("../../word16_execution/cells_wire.zig");
const Root = @import("../native_omul/recursion.zig");
const Receiver = @import("../native_omul/root_runtime.zig");
const Header = struct { suite: @import("../pure_p2_source_suite.zig").Suite, metadata: Runtime.Metadata };

const Hook = struct {
    pub fn run(_: std.mem.Allocator, v: Fixture.VerifiedJoinFor(ML)) !void {
        const path = std.posix.getenv("STWO_OP_SUITE_ROOT_OUT") orelse return error.MissingOpRootFixtureDirectory;
        const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 12 << 30);
        defer budget.destroy();
        try produce(budget.allocator(), v, path);
        if (budget.snapshot().live_bytes != 0 or budget.snapshot().external_live_bytes != 0) return error.OpRootFixtureLeak;
    }
};
fn produce(a: std.mem.Allocator, v: Fixture.VerifiedJoinFor(ML), path: []const u8) !void {
    const declaration = Wire.CpuDeclaration{ .geometry = v.setup.materials.geometry, .bridges = v.setup.bridges };
    const request = Wire.CompactRequest.from(v.request);
    const metadata = Runtime.Metadata{ .schema = 3, .profile = v.key.profile, .cpus = &.{declaration}, .requests = &.{request}, .spans = &.{v.span}, .truths = &.{}, .miller = &.{.{ .calls = v.truth_span.calls, .first_id = v.truth_span.first_id, .frontier_log = v.truth_key.base.frontier_log, .arithmetic_log = v.truth_key.base.arithmetic_log }}, .memory_words = @intCast(v.terminal.len) };
    var source = try Source.Owner.init(a, metadata, v.request.base.memory.initial, v.terminal);
    defer source.deinit();
    const view = source.view();
    try std.testing.expectEqualSlices(u8, &v.inventory.?.execution, &view.inventory.execution);
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.truth_encoded.bytes);
    defer native.deinit(a);
    const stages = [_]Manifest.StageOne{ v.stage_one, .{ .main = native.commitment_scheme_proof.commitments.items[1], .local = null } };
    const stage_bytes = try @import("../pure_p2_manifest_wire.zig").encode(a, view.inventory.execution, view.inventory.workers, &stages);
    defer a.free(stage_bytes);
    const envelope = try ML.encode(a, v.truth_encoded);
    defer a.free(envelope);
    var claims = v.truth_encoded.claims;
    var proofs = [_]Bundle.Proof{ .{ .bytes = v.encoded.bytes, .claims = v.encoded.claims }, .{ .bytes = envelope, .claims = &claims } };
    const bundle = Bundle.Bundle{ .source_suite = Source.SUITE, .stage_one = stage_bytes, .proofs = &proofs };
    var result = try Root.proveFixture(a, view, &bundle, .{ .members = 2, .artifact_directory = path });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), result.members);
    try std.testing.expectEqual(@as(usize, 1), result.reductions);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
    const header = try std.json.Stringify.valueAlloc(a, Header{ .suite = Source.SUITE, .metadata = view.metadata }, .{});
    defer a.free(header);
    try write(dir, "fixture-source.json", header);
    try Cells.write(dir, view.initial, view.terminal);
    const durable = try Bundle.encodeForSuite(a, &bundle, .{ .bytes = 64 << 20, .proof_bytes = 32 << 20 }, Source.SUITE);
    defer a.free(durable);
    try write(dir, "native-op.bin", durable);
    try dir.makeDir("source-only");
    var source_dir = try dir.openDir("source-only", .{});
    defer source_dir.close();
    try dir.copyFile("fixture-source.json", source_dir, "fixture-source.json", .{});
    try dir.copyFile("cells.bin", source_dir, "cells.bin", .{});
    try std.testing.expectError(error.FileNotFound, source_dir.access("native-op.bin", .{}));
    try std.posix.fsync(source_dir.fd);
    try std.posix.fsync(dir.fd);
    std.debug.print("OP_MILLER_SUITE_ROOT members={} folds={} bytes={} recursion_ns={} toy_program=true kona_block=false security_qualified=false\n", .{ result.members, result.reductions, result.proof.len, result.total_ns });
}

test "OP Miller suite complete CPU and local GKR physical recursive root" {
    _ = std.posix.getenv("STWO_OP_SUITE_ROOT_OUT") orelse return error.SkipZigTest;
    try Fixture.exerciseLocal(Hook);
}

test "OP Miller suite fresh source-only physical root and adversaries" {
    const path = std.posix.getenv("STWO_OP_SUITE_ROOT_VERIFY") orelse return error.SkipZigTest;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 12 << 30);
    defer budget.destroy();
    {
        const a = budget.allocator();
        var pool: Engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
        defer pool.deinit();
        var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        var source_dir = try dir.openDir("source-only", .{});
        defer source_dir.close();
        try std.testing.expectError(error.FileNotFound, source_dir.access("native-op.bin", .{}));
        const header_bytes = try source_dir.readFileAlloc(a, "fixture-source.json", 1 << 20);
        defer a.free(header_bytes);
        const header = try std.json.parseFromSlice(Header, a, header_bytes, .{});
        defer header.deinit();
        try header.value.suite.requireExpected(Source.SUITE);
        const cells = try Cells.read(a, source_dir, 80);
        defer cells.deinit(a);
        var source = try Source.Owner.init(a, header.value.metadata, cells.initial, cells.terminal);
        defer source.deinit();
        const root = try dir.readFileAlloc(a, "root.bin", 2 << 20);
        defer a.free(root);
        const sidecar = try dir.readFileAlloc(a, "root-sidecar.bin", 64 << 20);
        defer a.free(sidecar);
        const shapes = try dir.readFileAlloc(a, "root-gkr-shapes.bin", @import("../pure_p2_gkr_templates_wire.zig").MAX_BYTES);
        defer a.free(shapes);
        const verified = try Receiver.verifyFixtureSource(a, source.view(), root, sidecar, shapes, true);
        try std.testing.expectEqual(@as(usize, 2), verified.members);
        std.debug.print("OP_MILLER_SUITE_FRESH_ROOT bytes={} members={} source_ns={} verify_and_adversaries_ns={} native_proof_absent=true toy_program=true security_qualified=false\n", .{ verified.root_bytes, verified.members, verified.source_ns, verified.root_verify_ns });
    }
    if (budget.snapshot().live_bytes != 0 or budget.snapshot().external_live_bytes != 0) return error.OpRootFixtureLeak;
}
