//! Source-exact actual-block census; no outer key, commitment or proof is built.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Bundle = @import("../pure_p2_op_bundle.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const Scope = @import("scope.zig");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const Catalog = @import("../pure_p2_truth_leaf_test.zig");
const Miller = @import("../pure_p2_tower_leaf_test.zig");
const Layout = @import("../layout.zig");
const Row = @import("row.zig");
fn report(a: std.mem.Allocator, kind: []const u8, ordinal: usize, owner: *const C.PoseidonContext) !void {
    const raw = try owner.rawCounts();
    var rows: [6]usize = undefined;
    var logs: [6]u32 = undefined;
    var main: u64 = 0;
    var inter: u64 = 0;
    var fixed: u64 = 0;
    for (raw, Layout.FACTS, 0..) |n, fact, i| {
        rows[i] = try std.math.ceilPowerOfTwo(usize, @max(if (i == 4) @as(usize, 65536) else 16, @as(usize, @intCast(n))));
        logs[i] = @intCast(std.math.log2_int(usize, rows[i]));
        main += rows[i] * fact.main;
        inter += rows[i] * fact.classic_interaction;
        fixed += rows[i] * fact.fixed;
    }
    rows[5] = try std.math.ceilPowerOfTwo(usize, @max(16, owner.native_mul_calls.items.len));
    logs[5] = @intCast(std.math.log2_int(usize, rows[5]));
    main += rows[5] * Row.MAIN;
    inter += rows[5] * Row.INTER;
    fixed += rows[5] * Row.FIXED;
    const json = try std.json.Stringify.valueAlloc(a, .{ .kind = kind, .ordinal = ordinal, .raw = raw, .native_omul_calls = owner.native_mul_calls.items.len, .rows = rows, .logs = logs, .main_cells = main, .interaction_cells = inter, .fixed_cells = fixed, .total_native_cells = main + inter + fixed, .source_only = true, .production_admission = false }, .{});
    defer a.free(json);
    std.debug.print("OP_R6_SOURCE_CENSUS {s}\n", .{json});
}
fn cpu(_: ?*anyopaque, a: std.mem.Allocator, v: Bundle.CpuVerified) !void {
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), v.setup, v.key.profile.config());
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const local = v.stage_one.local orelse return error.MissingReceipt;
    const source = CPU.ShapeView{ .op_span = v.span, .setup = v.setup, .request = v.request, .first = v.first_ids, .expected = v.expected, .key = v.key, .manifest = v.manifest.digest, .main = native.commitment_scheme_proof.commitments.items[1], .receipt = local.receipt, .claims = v.encoded.claims, .child = local.proof, .shape = &shape, .values = &values };
    var scope = Scope.begin();
    defer scope.deinit();
    var owner = try source.buildForProving(a);
    defer owner.deinit();
    try std.testing.expect(try owner.isCircuitValid());
    try report(a, "CPU", v.ordinal, &owner);
    try @import("source_physical.zig").maybe(a, "CPU", source, &owner);
}
fn truth(_: ?*anyopaque, a: std.mem.Allocator, v: Bundle.TruthVerified) !void {
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("../pure_p2_truth_statement.zig").geometry(arena.allocator(), v.key, v.truth);
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const source = Catalog.View{ .key = v.key, .truth = v.truth, .expected = v.expected, .manifest = v.manifest.digest, .main = native.commitment_scheme_proof.commitments.items[1], .claims = v.encoded.claims, .shape = &shape, .values = &values };
    var scope = Scope.begin();
    defer scope.deinit();
    var owner = try source.buildForProving(a);
    defer owner.deinit();
    try std.testing.expect(try owner.isCircuitValid());
    try report(a, @tagName(v.truth.family()), v.ordinal, &owner);
    try @import("source_physical.zig").maybe(a, @tagName(v.truth.family()), source, &owner);
}
fn miller(_: ?*anyopaque, a: std.mem.Allocator, v: Bundle.MillerVerified) !void {
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("../pure_p2_tower_statement.zig").geometry(arena.allocator(), v.key);
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const source = Miller.View{ .key = v.key, .span = v.span, .expected = v.expected, .manifest = v.manifest.digest, .main = native.commitment_scheme_proof.commitments.items[1], .claims = v.encoded.claims, .shape = &shape, .values = &values };
    var scope = Scope.begin();
    defer scope.deinit();
    var owner = try source.buildForProving(a);
    defer owner.deinit();
    try std.testing.expect(try owner.isCircuitValid());
    try report(a, "Miller", v.ordinal, &owner);
    try @import("source_physical.zig").maybe(a, "Miller", source, &owner);
}
test "OP R6 actual source census without outer proofs" {
    const config_path = std.posix.getenv("STWO_OP_R6_CONFIG") orelse return error.SkipZigTest;
    const native_path = std.posix.getenv("STWO_OP_R6_NATIVE") orelse return error.MissingOpNativeDirectory;
    const a = std.testing.allocator;
    const raw = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, a, raw, .{});
    defer config.deinit();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try Runtime.verifyDirectoryWithHooks(budget.allocator(), config.value, native_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .fragments = .{ .cpu = cpu, .truth = truth, .miller = miller } });
}
