//! Nonproving shared setup, page parity, custody and rollback checks.
const std = @import("std");
const core = @import("stwo_core");
const Sha = @import("prover/block_v5_memory_source_packed_sha_columns_v1.zig");
const Source = @import("prover/block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("prover/block_v5_initial_sources_v1.zig");
const Schema = @import("prover/block_v5_memory_source_batch_raw_schema_v1.zig");

fn admission(bytes: []const u8) !Source.Admitted {
    const empty = Initial.sha256("");
    return Source.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 256, .output_len_addr = 768, .output_data_addr = 772, .output_base = 768, .output_end = 1024 },
        .initial_rw_root = @splat(1),
        .initial_registers = @splat(0),
        .public_input_sha256 = Initial.sha256(bytes),
        .public_input_len = bytes.len,
        .input_words = .{ .records = 0, .sha256 = empty },
        .rw_words = .{ .records = 0, .sha256 = empty },
        .first_touches = .{ .records = 0, .sha256 = empty },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = @splat(1), .endpoints = .{ .records = 0, .sha256 = empty } }, @splat(8), .{});
}

const ReadBytes = struct {
    bytes: []const u8,
    pub fn read(context: *anyopaque, stream: Source.Stream, offset: u64, out: []u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (stream != .public_input or offset > self.bytes.len or out.len > self.bytes.len - @as(usize, @intCast(offset))) return error.InvalidSetupTestRead;
        @memcpy(out, self.bytes[@intCast(offset)..][0..out.len]);
    }
};

fn rawColumns(a: std.mem.Allocator, admitted: Source.Admitted, bytes: []const u8) !Schema.Columns.Columns {
    const limits = Schema.Protocol.Limits{ .page_row_log = 2 };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const plan = try Schema.Protocol.init(&admitted, config, limits);
    const page = try plan.page(0);
    var raw = try Schema.Columns.Columns.init(a, &admitted, plan, page, limits);
    errdefer raw.deinit();
    var reader = ReadBytes{ .bytes = bytes };
    var cursor = try Schema.cursorInit(admitted, .{ .context = &reader, .read = ReadBytes.read });
    for (0..page.chunks) |_| try raw.append(&admitted, (try cursor.next()).?);
    return raw;
}

test "packed hash setup: SHA pages preserve original columns and allocator custody after coordinator release" {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const a = std.testing.allocator;
    const bytes: [56]u8 = @splat(0x65); // Genuine double-compression padding edge.
    const admitted = try admission(&bytes);
    var raw = try rawColumns(a, admitted, &bytes);
    defer raw.deinit();
    const budget = try Budget.create(a, 64 << 20);
    var owns_budget = true;
    defer if (owns_budget) budget.destroy();
    const observer = budget.retain();
    defer observer.destroy();
    const setup = try Sha.Setup.create(budget.allocator());
    var owns_setup = true;
    defer if (owns_setup) setup.release();
    var cached = try Sha.Columns.regenerateWithSetup(budget.allocator(), &admitted, &raw, .{}, setup);
    var owns_cached = true;
    defer if (owns_cached) cached.deinit();
    var cold = try Sha.Columns.regenerate(a, &admitted, &raw, .{});
    defer cold.deinit();
    try std.testing.expectEqual(cold.snapshot(), cached.snapshot());
    setup.release();
    owns_setup = false;
    budget.destroy();
    owns_budget = false;
    inline for (0..Sha.Airs.len) |i| try cached.definitions[i].validate();
    cached.deinit();
    owns_cached = false;
    try std.testing.expectEqual(@as(usize, 0), observer.snapshot().live_bytes);
}

fn shaColumnAllocation(a: std.mem.Allocator, setup: *const Sha.Setup, admitted: *const Source.Admitted, raw: *const Schema.Columns.Columns) !void {
    var columns = try Sha.Columns.regenerateWithSetup(a, admitted, raw, .{}, setup);
    defer columns.deinit();
}

test "packed hash setup: every SHA page allocation failure releases lease and local buffers" {
    const a = std.testing.allocator;
    const admitted = try admission("");
    var raw = try rawColumns(a, admitted, "");
    defer raw.deinit();
    const setup = try Sha.Setup.create(a);
    defer setup.release();
    try std.testing.checkAllAllocationFailures(a, shaColumnAllocation, .{ setup, &admitted, &raw });
    try std.testing.expectEqual(@as(usize, 1), setup.references.load(.monotonic));
}

test "packed hash setup: genuine SHA create and cached regeneration production bodies retained" {
    inline for (.{ &Sha.Setup.create, &Sha.Setup.lease, &Sha.Setup.release, &Sha.Columns.regenerateWithSetup, &Sha.Columns.deinit }) |body| std.mem.doNotOptimizeAway(body);
}

test "packed hash setup: cached collection and durable replay preserve all six original roots" {
    const Stage = @import("prover/block_v5_memory_source_packed_sha_replay_v1.zig");
    const Api = Stage.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const Kernel = @import("prover/block_v5_memory_source_packed_sha_proof_v1.zig");
    const a = std.testing.allocator;
    const bytes: [56]u8 = @splat(0x65);
    const admitted = try admission(&bytes);
    const limits = Stage.Limits{ .first = .{ .page_row_log = 3 } };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const plan = try Schema.Protocol.init(&admitted, config, limits.first);
    const setup = try Sha.Setup.create(a);
    defer setup.release();
    var reader = ReadBytes{ .bytes = &bytes };
    var collector = try Schema.Round.Collector.init(admitted, .{ .context = &reader, .read = ReadBytes.read }, plan, limits.first);
    const cached = try Api.collectWithSetup(a, &collector, limits, setup);
    var owns_cached = true;
    defer if (owns_cached) cached.deinit() catch unreachable;
    const pin = cached.pin.?;
    try std.testing.expect(cached.cores.?.setup_lease != null);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const stored = try Api.persist(tmp.dir, "page.raw", cached, &admitted, plan, pin, limits);
    var cold_reader = ReadBytes{ .bytes = &bytes };
    var cold_collector = try Schema.Round.Collector.init(admitted, .{ .context = &cold_reader, .read = ReadBytes.read }, plan, limits.first);
    const cold = try Api.collect(a, &cold_collector, limits);
    defer cold.deinit() catch unreachable;
    try std.testing.expect(std.meta.eql(pin, cold.pin.?));
    const replay = try Api.replayWithSetup(a, tmp.dir, "page.raw", &admitted, plan, pin, stored, limits, setup);
    defer replay.deinit() catch unreachable;
    try std.testing.expect(std.meta.eql(pin, replay.pin.?));
    const claim = @import("prover/block_v5_memory_source_sha_connector_interaction_v1.zig").Claim{ .sums = @splat(core.fields.qm31.QM31.zero()), .wire_requests = @as(u64, pin.geometry.compressions) * 32 };
    const relations = @import("recursion/air/universal_challenges.zig").UniversalRelations.dummy();
    const prepared = try Kernel.ComponentOwner.initPrepared(a, pin, relations, @splat(core.fields.qm31.QM31.zero()), claim, .{ .operands = limits }, &cached.cores.?);
    defer prepared.deinit();
    const independent = try Kernel.ComponentOwner.init(a, pin, relations, @splat(core.fields.qm31.QM31.zero()), claim, .{ .operands = limits });
    defer independent.deinit();
    const shared = try Kernel.ComponentOwner.initWithSetup(a, pin, relations, @splat(core.fields.qm31.QM31.zero()), claim, .{ .operands = limits }, setup);
    defer shared.deinit();
    // Construction proposals only: no claims here are verified receipts. Exact
    // copied scalar programs must survive release of their source page arenas.
    try cached.deinit();
    owns_cached = false;
    const old_handles = try independent.verifiers();
    for ([_][Kernel.COMPONENT_COUNT]core.air.components.Component{ try prepared.verifiers(), try shared.verifiers() }) |new_handles| {
        const old_components = core.air.components.Components{ .components = &old_handles, .n_preprocessed_columns = Schema.FIXED_COUNT };
        const new_components = core.air.components.Components{ .components = &new_handles, .n_preprocessed_columns = Schema.FIXED_COUNT };
        var old_logs = try old_components.columnLogSizes(a);
        defer old_logs.deinitDeep(a);
        var new_logs = try new_components.columnLogSizes(a);
        defer new_logs.deinitDeep(a);
        try std.testing.expectEqual(old_logs.items.len, new_logs.items.len);
        for (old_logs.items, new_logs.items) |old, new| try std.testing.expectEqualSlices(u32, old, new);
        const maximum = old_components.compositionLogDegreeBound() - Kernel.COMPOSITION_SPLIT;
        var old_masks = try old_components.maskPoints(a, .zero(), maximum, false);
        defer old_masks.deinitDeep(a);
        var new_masks = try new_components.maskPoints(a, .zero(), maximum, false);
        defer new_masks.deinitDeep(a);
        try std.testing.expectEqual(old_masks.items.len, new_masks.items.len);
        for (old_masks.items, new_masks.items) |old_tree, new_tree| for (old_tree, new_tree) |old, new| try std.testing.expectEqualSlices(core.circle.CirclePointQM31, old, new);
    }
}

test "packed hash setup: actual cached PAGE producer and independent fresh receiver bodies retained" {
    const Stage = @import("prover/block_v5_memory_source_packed_sha_replay_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const Kernel = @import("prover/block_v5_memory_source_packed_sha_proof_v1.zig");
    inline for (.{ &Stage.collectWithSetup, &Stage.replayWithSetup, &Kernel.ForBackend(@import("stwo_cpu_backend").CpuBackend).prove, &Kernel.verifyOwned, &Kernel.verifyOwnedWithSetup }) |body| std.mem.doNotOptimizeAway(body);
}

comptime {
    _ = @import("block_v5_memory_source_packed_blake_columns_test_root.zig");
}
