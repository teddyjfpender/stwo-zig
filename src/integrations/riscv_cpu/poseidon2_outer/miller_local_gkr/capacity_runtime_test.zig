//! Synthetic real-Machine 1023-call capacity gate. This is not an OP block,
//! pairing-validity proof or production admission. No call/tape is fabricated.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Core = @import("stwo_core");
const Request = @import("../../rv64_ethereum_request.zig");
const Capture = @import("../pure_p2_op_capture_plan.zig");
const Runtime = @import("../sponge_cpu/runtime.zig");
const Frame = @import("../sponge_cpu/frame.zig");
const Group = @import("../native_group/runtime.zig");
const MA = @import("authority.zig");
const MW = @import("worker.zig");
const Expected = @import("../../word16_global_execution/ethereum/receiver.zig");
const Write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
const PROFILE = @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
const OPTIONS = Group.Options{ .arithmetization = .r7, .terminal_outer_profile = .op_control_b2_q144_p0_fold4_v1 };
const Reference = struct {
    calls: u32,
    expected_steps: u64,
    expected_pc: u64,
    expected_registers: [32]u64,
    final_packet_hex: []const u8,
    ordered_before_after_packet_sha256: []const u8,
};
fn plan(a: std.mem.Allocator, config: Request.Config, reference: Reference, dir: std.fs.Dir, resources: Runtime.Resources) !void {
    var timer = try std.time.Timer.start();
    var capture = try Capture.Owner.init(a, config, PROFILE, .{ .local_truth = true, .truth_limits = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .gkr_bytes = resources.gkr_bytes }, .detached_sponge = true, .extra_workers = 1 }, &timer);
    defer capture.deinit();
    try std.testing.expectEqual(@as(u32, 1023), reference.calls);
    try std.testing.expectEqual(reference.expected_steps, capture.captured.steps);
    try std.testing.expectEqual(@as(usize, 1), capture.captured.native.len);
    try std.testing.expectEqual(@as(usize, 0), capture.truths.len);
    try std.testing.expectEqual(@as(usize, 1), capture.tower.len);
    try std.testing.expectEqual(reference.calls, capture.spans[0].calls);
    try std.testing.expectEqual(@as(u32, 1), capture.spans[0].first_id);
    try std.testing.expectEqual(@as(u32, 15), capture.tower[0].frontier_log);
    try std.testing.expectEqual(@as(u32, 15), capture.tower[0].arithmetic_log);
    try std.testing.expectEqual(@as(?u32, 15), capture.declarations[0].bridges.tower);
    const boundary = capture.captured.native[0].cpu.?.public;
    try std.testing.expectEqual(reference.expected_pc, boundary.final_pc);
    try std.testing.expectEqualDeep(reference.expected_registers, boundary.final_registers);
    try std.testing.expectEqual(@as(u64, 0x200000), boundary.final_registers[10]);
    try std.testing.expectEqual(@as(u64, 0x40001), boundary.final_registers[17]);
    const calls = capture.captured.advice.tower[0];
    try std.testing.expectEqual(@as(usize, reference.calls), calls.len);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var word: [8]u8 = undefined;
    for (calls, 0..) |call, i| {
        try std.testing.expectEqual(@as(u64, 0x200000), call.pointer);
        try std.testing.expectEqual(@as(u24, @intCast(20 + 12 * i)), call.tick);
        for ([_][80]u64{ call.before, call.after }) |packet| for (packet) |value| {
            std.mem.writeInt(u64, &word, value, .little);
            hash.update(&word);
        };
    }
    const digest = std.fmt.bytesToHex(hash.finalResult(), .lower);
    try std.testing.expectEqualStrings(reference.ordered_before_after_packet_sha256, &digest);
    var final_packet: [640]u8 = undefined;
    for (calls[calls.len - 1].after, 0..) |value, i| std.mem.writeInt(u64, final_packet[8 * i ..][0..8], value, .little);
    const final_hex = std.fmt.bytesToHex(final_packet, .lower);
    try std.testing.expectEqualStrings(reference.final_packet_hex, &final_hex);
    const logs = [_]u32{5};
    const metadata = Runtime.Metadata{ .profile = PROFILE, .cpus = capture.declarations, .requests = capture.compact, .spans = capture.spans, .frontier_logs = &logs, .detached = &.{}, .truths = capture.truths, .miller = capture.tower, .memory_words = @intCast(capture.captured.advice.initial.len) };
    // Full source ledger and lookup/GKR envelope are checked before FIXED keys
    // by this existing source-only constructor, not imported from the producer.
    var authority = try Runtime.Authority.init(a, capture.image, capture.program.log_size, metadata, capture.requests, false, resources);
    defer authority.deinit();
    const expected = try Expected.expectedFromRequests(capture.image, capture.program.identity, capture.requests, config.max_steps, config.batch_steps, true);
    var inventory = try authority.inventory(PROFILE, expected);
    defer inventory.deinit();
    const security = try authority.checked(PROFILE, &inventory, metadata);
    try std.testing.expectEqual(@as(usize, 2), inventory.workers.len);
    try std.testing.expectEqual(@as(usize, 0), authority.detached.len);
    const miller = authority.catalog.miller[0];
    const resource = try MW.Resources.derive(miller.local_key.?, miller.span);
    try resource.admit(.{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .advice_bytes = resources.truth_advice_bytes, .gkr_bytes = resources.gkr_bytes });
    var roster = try Frame.Roster.init(a, authority.cpu[0].setup, 0, 5, capture.requests[0].base.epoch, 0);
    defer roster.deinit();
    var facts: usize = 0;
    var numerical = E.lookups.resource.ForField(Core.fields.om31.OM31).Plan{};
    for (roster.instances) |instance| {
        facts = try std.math.add(usize, facts, try instance.facts());
        try numerical.add(.{ .kind = .multiplicities, .variables = try instance.variables() });
    }
    try numerical.finish();
    const cpu_child_floor = try std.math.add(usize, try std.math.mul(usize, facts, 52), numerical.metadata_bytes + 65536);
    if (cpu_child_floor > resources.gkr_bytes) return error.MillerCapacityCpuGkrBudget;
    const cost = try MA.cost(.{ .calls = 1023, .first_id = 1, .frontier_log = 15, .arithmetic_log = 15 });
    const info = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-miller-capacity-actual-machine-plan/v1", .actual_steps = capture.captured.steps, .actual_pc = boundary.final_pc, .actual_registers = boundary.final_registers, .actual_calls = calls.len, .ordered_packet_trace_sha256 = digest, .cpu_declarations = capture.declarations, .miller_declarations = capture.tower, .native_workers = inventory.workers.len, .detached_workers = authority.detached.len, .memory_words = metadata.memory_words, .cpu_local_facts = facts, .cpu_checkpoint_working_floor = cpu_child_floor, .miller = resource, .miller_cost = cost, .limits = resources, .security = security, .plan_ns = timer.read(), .native_proof_accepted = false, .root_accepted = false, .production_admission = false }, .{ .whitespace = .indent_2 });
    defer a.free(info);
    try Write(dir, "admission.json", info);
    std.debug.print("OP_MILLER_CAPACITY_PLAN steps={} calls={} CPU=1 localMiller=1 detached=0 logs=15/15 child_floor={} CPU_child_floor={} image_and_terminal_pinned=true native_accepted=false root_accepted=false\n", .{ capture.captured.steps, calls.len, resource.child_peak_bytes, cpu_child_floor });
}
fn sourceOnly(a: std.mem.Allocator, parent: std.fs.Dir, native: []const u8, path: []const u8) !void {
    _ = parent;
    try std.fs.cwd().makeDir(path);
    var from = try std.fs.cwd().openDir(native, .{});
    defer from.close();
    var to = try std.fs.cwd().openDir(path, .{});
    defer to.close();
    for ([_][]const u8{ "detached-op.json", "cells.bin" }) |name| {
        const bytes = try from.readFileAlloc(a, name, 4 << 20);
        defer a.free(bytes);
        try Write(to, name, bytes);
    }
}
test "OP Miller full span actual Machine native and grouped R7 root qualification" {
    const config_path = std.posix.getenv("STWO_OP_MILLER_CAPACITY_CONFIG") orelse return error.SkipZigTest;
    const ref_path = std.posix.getenv("STWO_OP_MILLER_CAPACITY_REFERENCE") orelse return error.MissingMillerCapacityReference;
    const mode = std.posix.getenv("STWO_OP_MILLER_CAPACITY_MODE") orelse "plan";
    const a = std.testing.allocator;
    const raw = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer config.deinit();
    if (config.value.max_steps > 10000 or config.value.workers != 16) return error.MillerCapacityFixtureOnly;
    const ref_raw = try std.fs.cwd().readFileAlloc(a, ref_path, 8192);
    defer a.free(ref_raw);
    const reference = try std.json.parseFromSlice(Reference, a, ref_raw, .{ .ignore_unknown_fields = true });
    defer reference.deinit();
    const base = std.fs.path.dirname(config_path) orelse return error.MillerCapacityFixtureDirectory;
    const native = try std.fs.path.join(a, &.{ base, "native" });
    defer a.free(native);
    const src = try std.fs.path.join(a, &.{ base, "source-only" });
    defer a.free(src);
    const source_root = try std.fs.path.join(a, &.{ base, "group-source" });
    defer a.free(source_root);
    const root = try std.fs.path.join(a, &.{ base, "group-root" });
    defer a.free(root);
    var dir = try std.fs.cwd().openDir(base, .{});
    defer dir.close();
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    {
        var pool: E.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = 16 });
        defer pool.deinit();
        var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        const alloc = budget.allocator();
        if (std.mem.eql(u8, mode, "plan")) {
            try plan(alloc, config.value, reference.value, dir, .{});
        } else if (std.mem.eql(u8, mode, "native")) {
            try Runtime.produceDirectory(alloc, config.value, native, PROFILE, .{});
            try Runtime.verifyDirectory(alloc, config.value, native, PROFILE, .{});
            try sourceOnly(alloc, dir, native, src);
        } else if (std.mem.eql(u8, mode, "source")) {
            try Group.produceWithOptions(alloc, config.value, native, source_root, PROFILE, .{}, 4, false, OPTIONS);
        } else if (std.mem.eql(u8, mode, "root")) {
            try Group.produceWithOptions(alloc, config.value, native, root, PROFILE, .{}, 4, true, OPTIONS);
            try Group.verifyWithOptions(alloc, config.value, src, root, PROFILE, .{}, 4, OPTIONS);
        } else if (std.mem.eql(u8, mode, "verify")) {
            var no_native = try std.fs.cwd().openDir(src, .{});
            defer no_native.close();
            try std.testing.expectError(error.FileNotFound, no_native.openFile("detached-op.bin", .{}));
            const controls = try Group.qualifyWithOptions(alloc, config.value, src, root, PROFILE, .{}, 4, OPTIONS);
            try std.testing.expectEqual(@as(u32, 7), controls);
            std.debug.print("OP_MILLER_CAPACITY_ROOT controls={} source_only_native_absent=true restored_positive=true\n", .{controls});
        } else return error.MillerCapacityMode;
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    std.debug.print("OP_MILLER_CAPACITY_DONE mode={s} peak={} cap={} final_live=0 final_external=0 production_admission=false\n", .{ mode, budget.snapshot().peak_live_bytes, @as(usize, 32) << 30 });
}
