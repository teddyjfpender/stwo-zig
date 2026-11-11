//! Opt-in actual small execution gate. Never silently launches heavy proving.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("runtime.zig");
test "native grouped actual small complete execution root and independent receiver" {
    const path = std.posix.getenv("STWO_OP_DETACHED_CONFIG") orelse return error.SkipZigTest;
    const native = std.posix.getenv("STWO_OP_DETACHED_OUT") orelse return error.MissingOpNativeDirectory;
    const out = std.posix.getenv("STWO_OP_GROUP_ROOT_OUT") orelse return error.MissingOpNativeDirectory;
    const mode = std.posix.getenv("STWO_OP_GROUP_MODE") orelse "source";
    const physical = std.mem.eql(u8, mode, "prove");
    const attacks = std.mem.eql(u8, mode, "qualify");
    const verify_only = std.mem.eql(u8, mode, "verify") or attacks;
    if (!physical and !verify_only and !std.mem.eql(u8, mode, "source")) return error.InvalidOpGroupGateMode;
    const maximum = try std.fmt.parseInt(u32, std.posix.getenv("STWO_OP_GROUP_MAX") orelse "4", 10);
    const terminal = std.posix.getenv("STWO_OP_GROUP_TERMINAL") orelse "b4";
    const arithmetic = std.posix.getenv("STWO_OP_GROUP_ARITHMETIZATION") orelse "r6";
    const options = Runtime.Options{ .arithmetization = if (std.mem.eql(u8, arithmetic, "r7")) .r7 else if (std.mem.eql(u8, arithmetic, "r6")) .r6 else return error.InvalidOpGroupArithmeticGate, .terminal_outer_profile = if (std.mem.eql(u8, terminal, "b2")) .op_control_b2_q144_p0_fold4_v1 else if (std.mem.eql(u8, terminal, "b4")) null else return error.InvalidOpGroupTerminalGate };
    const a = std.testing.allocator;
    const raw = try std.fs.cwd().readFileAlloc(a, path, 16384);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, a, raw, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.SmallCapturePlanControlRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var bind = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer bind.deinit();
    var timer = try std.time.Timer.start();
    const profile = @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    if (!verify_only) try Runtime.produceWithOptions(budget.allocator(), parsed.value, native, out, profile, .{}, maximum, physical, options);
    const producer_ns = timer.lap();
    if (attacks) {
        const controls = try Runtime.qualifyWithOptions(budget.allocator(), parsed.value, native, out, profile, .{}, maximum, options);
        std.debug.print("OP_NATIVE_GROUP_PHYSICAL_ATTACKS controls={} restored_positive=true\n", .{controls});
    } else if (physical or verify_only) try Runtime.verifyWithOptions(budget.allocator(), parsed.value, native, out, profile, .{}, maximum, options);
    if (attacks) {
        var wrong = options;
        wrong.arithmetization = if (options.arithmetization == .r7) .r6 else .r7;
        try std.testing.expectError(error.NativeGroupReceiverPolicy, Runtime.verifyWithOptions(budget.allocator(), parsed.value, native, out, profile, .{}, maximum, wrong));
    }
    const receiver_ns = timer.lap();
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    std.debug.print("OP_NATIVE_GROUP_ACTUAL complete_physical={} source_only={} producer_ns={} fresh_receiver_ns={} peak={} cap={} final_live=0\n", .{ physical or verify_only, !physical and !verify_only, producer_ns, receiver_ns, budget.snapshot().peak_live_bytes, @as(usize, 32) << 30 });
}

test "native grouped terminal policy changes only final canonical node" {
    const P = @import("../op_profile.zig").Profile;
    const T = @import("topology.zig");
    const Plan = @import("plan.zig").Plan;
    const native = P.op_target_b4_q72_p0_fold4_v1;
    const terminal = P.op_control_b2_q144_p0_fold4_v1;
    try std.testing.expectEqual(native, try (Runtime.Options{}).resolve(native));
    try std.testing.expectEqual(terminal, try (Runtime.Options{ .terminal_outer_profile = terminal }).resolve(native));
    try std.testing.expectError(error.NativeGroupTerminalProfile, (Runtime.Options{ .terminal_outer_profile = .reference_b2_q24_p0 }).resolve(native));
    try std.testing.expectError(error.NativeGroupTerminalProfile, (Runtime.Options{ .terminal_outer_profile = native }).resolve(terminal));
    for (1..257) |n| for ([_]u32{ 1, 2, 4 }) |maximum| {
        const topology = T.Topology{ .allocator = std.testing.allocator, .plan = try Plan.init(@intCast(n), maximum), .profile = native, .terminal_outer_profile = terminal, .execution = @splat(0), .manifest = @splat(0) };
        for (topology.plan.ordered(), 0..) |_, i| try std.testing.expectEqual(if (i == topology.plan.root) terminal else native, topology.outerProfile(i));
    };
    // Same nominal FRI query/blowup product; not a whole-protocol certificate.
    try std.testing.expectEqual(native.config().fri_config.n_queries * native.config().fri_config.log_blowup_factor, terminal.config().fri_config.n_queries * terminal.config().fri_config.log_blowup_factor);
}
