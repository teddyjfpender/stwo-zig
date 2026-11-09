//! Source-owned full-height class model. No native proof is supplied and this
//! never accepts an execution. Only one selected native source key is bootstrapped.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Runtime = @import("../pure_p2_op_runtime.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const Local = @import("../pure_p2_gkr_template.zig");
const Key = @import("../pure_p2_fixed_key.zig").Key;
const SourceCPU = @import("../pure_p2_cpu_worker.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Old = @import("../../word16_global_execution/services/gkr_local/cpu_worker.zig");
/// Borrowed only for the callback; no execution or proof is accepted here.
pub const BorrowedClass = struct { view: CPU.ShapeView, metadata: *const Runtime.Metadata, ordinal: usize, setup_ns: u64 };
pub const ClassHook = *const fn (?*anyopaque, std.mem.Allocator, BorrowedClass) anyerror!void;
pub fn withClass(a: std.mem.Allocator, config: Request.Config, metadata: Runtime.Metadata, index: usize, context: ?*anyopaque, hook: ClassHook) !void {
    if (index >= metadata.cpus.len or metadata.requests.len != metadata.cpus.len or metadata.spans.len != metadata.cpus.len) return error.InvalidHeavyModelSource;
    const d = metadata.cpus[index];
    if (d.geometry.cpu_log != 22 or index == 0 or index + 1 == metadata.cpus.len) return error.HeavyModelNeedsFullHeightInterior;
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.initForOp(a, config);
    defer image.deinit();
    var cache = try @import("../../word16_execution/program_metadata.zig").Cache.init(a, 256 << 20);
    defer cache.deinit();
    var setup = try R.CpuSetup.initForOpWithAuthorityAndSuiteAndCaches(a, &image.authority, d.geometry, d.bridges, @import("../../word16_execution/pcs_suite.zig").Suite.production(), .{ .program = &cache });
    defer setup.deinit();
    var key = try Key.initForOpDigest(a, &setup, metadata.profile);
    defer key.deinit();
    try key.retireLegacySetup(&setup);
    const setup_ns = timer.lap();
    const requests = try a.alloc(P.Request, metadata.requests.len);
    defer a.free(requests);
    // Selected interior shapes have no public RAM sides. This is a cost model,
    // not source admission of the complete initial/terminal execution.
    for (metadata.requests, requests) |r, *out| out.* = r.expand(&.{}, &.{});
    const request = requests[index];
    const span = metadata.spans[index];
    const first = try P.firstIds(requests, index);
    const instances = try @import("../../word16_global_execution/services/gkr_local/roster.zig").fromOpSetup(a, &setup);
    defer a.free(instances);
    const expected = Manifest.Expected{ .kind = .cpu, .ordinal = @intCast(index), .profile = metadata.profile, .statement = try key.statementForOp(&setup, request, first, span), .fixed_identity = key.identity, .fixed = key.scope(), .local_instances = instances, .mass = try SourceCPU.cpuMass(&setup, request, span), .global_relations = .{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = Old.wirePresent(setup.bridges) or span.calls != 0 } };
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const lengths = try arena.allocator().alloc(u8, try Local.count(instances));
    @memset(lengths, 4);
    const local = try Local.skeleton(arena.allocator(), instances, lengths);
    const shape = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), &setup, metadata.profile.config());
    const values = try @import("../pure_p2_trace_skeleton.zig").init(arena.allocator(), &shape);
    var plan = try @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Plan.initForOp(a, &setup);
    defer plan.deinit();
    const claims = try arena.allocator().alloc(C.O, plan.claim_count);
    @memset(claims, C.O.zero());
    const view = CPU.ShapeView{ .op_span = span, .setup = &setup, .request = request, .first = first, .expected = expected, .key = &key, .manifest = @splat(0), .main = @splat(0), .receipt = @splat(0), .claims = claims, .child = &local, .shape = &shape, .values = &values };
    try hook(context, a, .{ .view = view, .metadata = &metadata, .ordinal = index, .setup_ns = setup_ns });
}
fn run(a: std.mem.Allocator, config: Request.Config, metadata: Runtime.Metadata, index: usize) !void {
    var timer = try std.time.Timer.start();
    try withClass(a, config, metadata, index, &timer, oldReport);
}
fn oldReport(context: ?*anyopaque, a: std.mem.Allocator, item: BorrowedClass) !void {
    const timer: *std.time.Timer = @ptrCast(@alignCast(context.?));
    const view = item.view;
    const index = item.ordinal;
    const metadata = item.metadata.*;
    const d = metadata.cpus[index];
    const span = metadata.spans[index];
    const key = view.key;
    const shape = view.shape.*;
    const instances = view.expected.local_instances.?;
    const setup_ns = item.setup_ns;
    var scope = @import("scope.zig").begin();
    defer scope.deinit();
    var phases: CPU.CompleteCounts = .{};
    var owner = try view.build(a, true, &phases);
    defer owner.deinit();
    const census = try @import("census.zig").derive(try owner.rawCounts(), owner.native_mul_calls.items.len);
    var widths: [4]usize = undefined;
    var samples: [4]usize = undefined;
    for (shape.tree_column_log_sizes, shape.mask_offsets, &widths, &samples) |columns, masks, *width, *n| {
        width.* = columns.len;
        n.* = 0;
        for (masks) |offsets| n.* += offsets.len;
    }
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-r6-heavy-source-class-model-v1", .ordinal = index, .source_native_key = std.fmt.bytesToHex(key.identity, .lower), .native_declaration = d, .request = metadata.requests[index], .span = span, .native_columns = widths, .native_oods_samples = samples, .native_gkr_instances = instances.len, .gkr_layers = try Local.layers(instances), .coefficient_lengths = try Local.count(instances), .gkr_shape = "legal-width4-every-round-not-an-actual-native-proof", .census = census, .phases = phases, .setup_ns = setup_ns, .source_trace_ns = timer.*.read(), .execution_verified = false, .native_proof_supplied = false, .outer_proof_produced = false, .security_qualified = false }, .{});
    defer a.free(report);
    std.debug.print("OP_R6_HEAVY_SOURCE_MODEL {s}\n", .{report});
}
test "OP R6 heavy full-height source class model without proving" {
    const config_path = std.posix.getenv("STWO_OP_R6_MODEL_CONFIG") orelse return error.SkipZigTest;
    const metadata_path = std.posix.getenv("STWO_OP_R6_MODEL_METADATA") orelse return error.MissingHeavyModelMetadata;
    const a = std.testing.allocator;
    const raw_config = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(raw_config);
    const config = try std.json.parseFromSlice(Request.Config, a, raw_config, .{});
    defer config.deinit();
    const raw_metadata = try std.fs.cwd().readFileAlloc(a, metadata_path, 4 << 20);
    defer a.free(raw_metadata);
    const metadata = try std.json.parseFromSlice(Runtime.Metadata, a, raw_metadata, .{});
    defer metadata.deinit();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 12 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    // Widest retained class and representative Miller-heavy class. Selection
    // follows committed capture cost data, not a guessed synthetic geometry.
    try run(budget.allocator(), config.value, metadata.value, 3);
    try run(budget.allocator(), config.value, metadata.value, 20);
}
