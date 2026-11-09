//! Frozen heavy classes only: legal skeleton source, never execution/proving.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Model = @import("../native_omul/heavy_model_test.zig");
const R6 = @import("../native_omul/census.zig");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const Counts = @import("cpu_source_test.zig").Counts;
const Record = struct { ordinal: usize, source_native_key: [32]u8, old: R6.Census, r7: Counts, setup_ns: u64, phases: CPU.CompleteCounts };
const State = struct { records: [2]Record = undefined, made: usize = 0 };
fn pin(raw: []const u8, expected: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected)) return error.R7FrozenSourceInputChanged;
}
fn source(raw: ?*anyopaque, a: std.mem.Allocator, item: Model.BorrowedClass) !void {
    const state: *State = @ptrCast(@alignCast(raw.?));
    const baseline = if (item.ordinal == 3) [5]u64{ 36418, 4809612, 2522, 80066, 65536 } else if (item.ordinal == 20) [5]u64{ 35736, 4554842, 2474, 76886, 65536 } else return error.R7UnpinnedHeavyClass;
    const expected_key = if (item.ordinal == 3) "b9c4fc6bbd7aa514a7a70f512aed206a3bab04c15f475584754e85497af9442d" else "229cc42b39b4a8f8e540deb99b23eea4453a6d726a976ba73255e146b416b666";
    try std.testing.expectEqualStrings(expected_key, &std.fmt.bytesToHex(item.view.key.identity, .lower));
    var record: Record = undefined;
    record.ordinal = item.ordinal;
    record.source_native_key = item.view.key.identity;
    record.setup_ns = item.setup_ns;
    {
        var mul = @import("../native_omul/scope.zig").begin();
        defer mul.deinit();
        var owner = try item.view.build(a, true, null);
        defer owner.deinit();
        try std.testing.expectEqualDeep(baseline, try owner.rawCounts());
        try std.testing.expectEqual(if (item.ordinal == 3) @as(usize, 174158) else 167853, owner.native_mul_calls.items.len);
        record.old = try R6.derive(try owner.rawCounts(), owner.native_mul_calls.items.len);
    }
    record.phases = .{};
    {
        var owner = try @import("cpu_source.zig").build(a, item.view, true, &record.phases);
        defer owner.deinit();
        record.r7 = try Counts.derive(&owner);
    }
    state.records[state.made] = record;
    state.made += 1;
}
test "OP R7 heavy classes source-only actual lowering without execution or proof" {
    const config_path = std.posix.getenv("STWO_OP_R7_HEAVY_CONFIG") orelse return error.SkipZigTest;
    const metadata_path = std.posix.getenv("STWO_OP_R7_HEAVY_METADATA") orelse return error.MissingHeavyModelMetadata;
    const report_path = std.posix.getenv("STWO_OP_R7_HEAVY_REPORT") orelse return error.MissingR7Report;
    const a = std.testing.allocator;
    const raw_config = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(raw_config);
    try pin(raw_config, "024b95f333c623a59748ba3e7dcef830e6541591690c29e444a9ed5ad41c641d");
    const config = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, a, raw_config, .{});
    defer config.deinit();
    const raw_metadata = try std.fs.cwd().readFileAlloc(a, metadata_path, 4 << 20);
    defer a.free(raw_metadata);
    try pin(raw_metadata, "60bf99b17f88c02537e78bbbca2fbe182e22d4ff95a29b8d0f7aa6076e20865d");
    const metadata = try std.json.parseFromSlice(Runtime.Metadata, a, raw_metadata, .{});
    defer metadata.deinit();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 12 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var state: State = .{};
    try Model.withClass(budget.allocator(), config.value, metadata.value, 3, &state, source);
    try Model.withClass(budget.allocator(), config.value, metadata.value, 20, &state, source);
    try std.testing.expectEqual(@as(usize, 2), state.made);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-r7-heavy-source-only-v1", .records = state.records, .peak_live_bytes = budget.snapshot().peak_live_bytes, .source_only = true, .execution_verified = false, .native_proof_supplied = false, .outer_proof_produced = false, .production_admitted = false }, .{ .whitespace = .indent_2 });
    defer a.free(json);
    var file = try std.fs.cwd().createFile(report_path, .{});
    defer file.close();
    try file.writeAll(json);
    std.debug.print("OP_R7_HEAVY_SOURCE {s}\n", .{json});
}
