//! One native verification plus trace-only source construction. No recursive
//! Authority construction or physical proving; counts are actual emitted rows.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Core = @import("stwo_core");
const Runtime = @import("pure_p2_op_runtime.zig");
const Bundle = @import("pure_p2_op_bundle.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const Lane = @import("../rv64_recursion/om31_circuit_lane.zig");
const CPU = @import("pure_p2_cpu_leaf_test.zig");
const Catalog = @import("pure_p2_truth_leaf_test.zig");
const Miller = @import("pure_p2_tower_leaf_test.zig");
const Record = struct {
    kind: []const u8,
    ordinal: usize,
    raw: [5]u64,
    operations: Lane.Census,
    classified_qm31_rows: u64,
    unclassified_qm31_rows: u64,
    build_ns: u64,
    phases: ?CPU.CompleteCounts = null,
};
const Session = struct {
    records: std.ArrayList(Record) = .empty,
    fn deinit(self: *Session, a: std.mem.Allocator) void {
        self.records.deinit(a);
    }
    fn save(self: *Session, a: std.mem.Allocator, kind: []const u8, ordinal: usize, owner: anytype, counts: Lane.Census, build_ns: u64, phases: ?CPU.CompleteCounts) !void {
        const raw = try owner.rawCounts();
        const classified = counts.classifiedRows();
        if (classified > raw[1]) return error.DoubleCountedOm31Operations;
        try self.records.append(a, .{ .kind = kind, .ordinal = ordinal, .raw = raw, .operations = counts, .classified_qm31_rows = classified, .unclassified_qm31_rows = raw[1] - classified, .build_ns = build_ns, .phases = phases });
    }
    fn cpu(raw: ?*anyopaque, a: std.mem.Allocator, v: Bundle.CpuVerified) !void {
        const self: *Session = @ptrCast(@alignCast(raw.?));
        var proof = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
        defer proof.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), v.setup, v.key.profile.config());
        const values = try V.proof.fromNative(arena.allocator(), &proof, v.capture, &shape);
        const local = v.stage_one.local orelse return error.MissingOpCensusLocal;
        const view = CPU.ShapeView{ .op_span = v.span, .setup = v.setup, .request = v.request, .first = v.first_ids, .expected = v.expected, .key = v.key, .manifest = v.manifest.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .receipt = local.receipt, .claims = v.encoded.claims, .child = local.proof, .shape = &shape, .values = &values };
        var counts: Lane.Census = .{};
        var scope = Lane.CensusScope.init(&counts);
        defer scope.deinit();
        var phases: CPU.CompleteCounts = .{};
        var timer = try std.time.Timer.start();
        var owner = try view.build(a, true, &phases);
        defer owner.deinit();
        try self.save(a, "CPU", v.ordinal, &owner, counts, timer.read(), phases);
    }
    fn truth(raw: ?*anyopaque, a: std.mem.Allocator, v: Bundle.TruthVerified) !void {
        const self: *Session = @ptrCast(@alignCast(raw.?));
        var proof = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
        defer proof.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("pure_p2_truth_statement.zig").geometry(arena.allocator(), v.key, v.truth);
        const values = try V.proof.fromNative(arena.allocator(), &proof, v.capture, &shape);
        const view = Catalog.View{ .key = v.key, .truth = v.truth, .expected = v.expected, .manifest = v.manifest.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .claims = v.encoded.claims, .shape = &shape, .values = &values };
        var counts: Lane.Census = .{};
        var scope = Lane.CensusScope.init(&counts);
        defer scope.deinit();
        var timer = try std.time.Timer.start();
        var owner = try view.build(a, true);
        defer owner.deinit();
        try self.save(a, @tagName(v.truth.family()), v.ordinal, &owner, counts, timer.read(), null);
    }
    fn miller(raw: ?*anyopaque, a: std.mem.Allocator, v: Bundle.MillerVerified) !void {
        const self: *Session = @ptrCast(@alignCast(raw.?));
        var proof = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
        defer proof.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("pure_p2_tower_statement.zig").geometry(arena.allocator(), v.key);
        const values = try V.proof.fromNative(arena.allocator(), &proof, v.capture, &shape);
        const view = Miller.View{ .key = v.key, .span = v.span, .expected = v.expected, .manifest = v.manifest.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .claims = v.encoded.claims, .shape = &shape, .values = &values };
        var counts: Lane.Census = .{};
        var scope = Lane.CensusScope.init(&counts);
        defer scope.deinit();
        var timer = try std.time.Timer.start();
        var owner = try view.build(a, true);
        defer owner.deinit();
        try self.save(a, "Miller", v.ordinal, &owner, counts, timer.read(), null);
    }
};
test "OP actual OM31 operation census from admitted native fragments without recursive proving" {
    const config_path = std.posix.getenv("STWO_OP_OM31_CENSUS_CONFIG") orelse return error.SkipZigTest;
    const directory = std.posix.getenv("STWO_OP_OM31_CENSUS_NATIVE") orelse return error.MissingOpCensusNative;
    const report_path = std.posix.getenv("STWO_OP_OM31_CENSUS_REPORT") orelse return error.MissingOpCensusReport;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const bytes = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(bytes);
    const config = try std.json.parseFromSlice(@import("../rv64_ethereum_request.zig").Config, a, bytes, .{});
    defer config.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var session: Session = .{};
    defer session.deinit(a);
    var timer = try std.time.Timer.start();
    try Runtime.verifyDirectoryWithHooks(a, config.value, directory, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .fragments = .{ .context = &session, .cpu = Session.cpu, .truth = Session.truth, .miller = Session.miller } });
    const report = try std.json.Stringify.valueAlloc(a, .{ .scope = "actual_native_verified_source_graph_only_no_recursive_proving", .operation_order = std.meta.fieldNames(Lane.Operation), .records = session.records.items, .total_ns = timer.read(), .peak_requested_bytes = budget.snapshot().peak_live_bytes, .security_qualified = false }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    var file = try std.fs.cwd().createFile(report_path, .{});
    defer file.close();
    try file.writeAll(report);
    std.debug.print("OP_OM31_CENSUS members={} total_ns={} report={s}\n", .{ session.records.items.len, timer.read(), report_path });
}
