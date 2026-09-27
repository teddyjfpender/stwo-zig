//! Metadata, real row-validator and early failure lifetime fixtures only.
//! No setup commitment, worker proof, FRI, guest or device is invoked here.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Module = @import("block_v5_native_recursive_setup_cache_v1.zig");
const Cache = Module.ForRangeBackend(Cpu);
const Bus = @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_range16_parent_protocol_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
const Stage = @import("block_v5_range16_recursive_stage_v1.zig").ForBackend(Cpu);
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const wires = [_]Bus.Wire{
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 0, .uses = 2, .source = .sealed, .coordinate = 0 },
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 8, .uses = 2, .source = .plan, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 1, .uses = 1, .source = .sum, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 2, .uses = 1, .source = .count, .coordinate = 0 },
};
fn values() Bus.Values {
    return .{ .template = @splat(1), .sealed = @splat(2), .plan = @splat(3), .roots = .{ @splat(4), @splat(5) }, .shard = .{ .index = 2, .first_instance = 4, .instance_count = 3, .request_count = 37 }, .sum = Q.fromU32Unchecked(19, 20, 21, 22), .count = 37 };
}
fn key() !Protocol.Key {
    return Protocol.Key.fromGeometry(.{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = values().template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(1), .preprocessed_root = @splat(10) }, &wires);
}
/// Borrows all metadata: ONLY matchingAdmission is allowed to inspect this
/// view. Undefined rows/budget are deliberately never used as proof input.
fn metadata(k: Protocol.Key, v: Bus.Values, schedule: []Bus.Wire) Bus.Prepared {
    return .{ .allocator = std.testing.allocator, .budget = undefined, .recursive = .{ .rows = undefined, .context = k.context }, .wires = schedule, .values = v };
}
test "range cache: shared factory is one typed kernel and all changing public values replace admission" {
    comptime {
        if (Cache != Module.ForModules(Cpu, Bus, Protocol)) @compileError("duplicated range cache kernel");
        if (Cache != Stage.SetupCache) @compileError("range publication uses a different cache");
        if (Cache == Module.ForBackend(Cpu) or Cache == Module.ForCapacityBackend(Cpu)) @compileError("provider cache authority aliases a native protocol");
    }
    const k = try key();
    const id = try k.identity();
    var schedule = wires;
    var prepared = metadata(k, values(), &schedule);
    const first = (try Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared)).?;
    inline for (.{ "sealed", "plan", "fixed", "main", "sum", "count", "index", "first", "instances" }) |field| {
        prepared.values = values();
        if (comptime std.mem.eql(u8, field, "fixed")) prepared.values.roots[0][0] ^= 1 else if (comptime std.mem.eql(u8, field, "main")) prepared.values.roots[1][0] ^= 1 else if (comptime std.mem.eql(u8, field, "sum")) prepared.values.sum = prepared.values.sum.add(Q.one()) else if (comptime std.mem.eql(u8, field, "count")) {
            prepared.values.count += 1;
            prepared.values.shard.request_count += 1;
        } else if (comptime std.mem.eql(u8, field, "index")) prepared.values.shard.index += 1 else if (comptime std.mem.eql(u8, field, "first")) prepared.values.shard.first_instance += 1 else if (comptime std.mem.eql(u8, field, "instances")) prepared.values.shard.instance_count += 1 else @field(prepared.values, field)[0] ^= 1;
        const changed = (try Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared)).?;
        try std.testing.expectEqualDeep(k, changed.key);
        try std.testing.expectEqualDeep(prepared.values, changed.values);
        try std.testing.expect(!std.meta.eql(try first.publicInputIdentity(), try changed.publicInputIdentity()));
    }
    prepared.values = values();
    prepared.values.count += 1;
    try std.testing.expectError(error.InvalidRangePublicInputs, Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared));
    prepared.values = values();
    prepared.values.template[0] ^= 1;
    try std.testing.expectError(error.UntrustedRangeRecursiveTemplate, Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared));
}
test "range cache: exact structural schedule security and independently pinned key must match" {
    const k = try key();
    const id = try k.identity();
    var schedule = wires;
    var prepared = metadata(k, values(), &schedule);
    inline for (.{ "child_key_id", "graph_ids", "transcript_plan_id" }) |field| {
        prepared.recursive.context = k.context;
        if (comptime std.mem.eql(u8, field, "graph_ids")) prepared.recursive.context.graph_ids[1][0] ^= 1 else @field(prepared.recursive.context, field)[0] ^= 1;
        try std.testing.expect((try Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared)) == null);
    }
    prepared.recursive.context = k.context;
    schedule[0].uses += 1;
    try std.testing.expect((try Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared)) == null);
    // A changed owned schedule cannot be admitted merely because the current
    // schedule digest still matches the key.
    schedule = wires;
    var owned = wires;
    owned[0].uses += 1;
    try std.testing.expect((try Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &owned, &prepared)) == null);
    schedule[2].coordinate = 1;
    try std.testing.expectError(error.InvalidRangePublicSchedule, Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared));
    schedule = wires;
    var stale = id;
    stale[0] ^= 1;
    try std.testing.expectError(error.UntrustedReusableRangeParentKey, Cache.matchingAdmission(.diagnostic_q8_pow0, k, stale, &wires, &prepared));
    prepared.recursive.context.child_config.pow_bits += 1;
    try std.testing.expectError(error.V5NativeSetupCacheSecurityMismatch, Cache.matchingAdmission(.diagnostic_q8_pow0, k, id, &wires, &prepared));
}
fn sourceRows(a: std.mem.Allocator) !Storage.Prepared {
    var rows = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (Storage.Airs, 0..) |_, i| rows.fixed[i] = &.{};
    errdefer rows.deinit();
    inline for (Storage.Airs, 0..) |Air, i| {
        rows.main[i] = try a.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (rows.main[i]) |*column| column.* = .{ .log_size = 1, .values = &.{} };
        for (rows.main[i]) |*column| column.values = try a.dupe(M, &.{ M.zero(), M.one() });
        rows.fixed[i] = try a.alloc(Storage.FixedRow(Air), 1);
        rows.fixed[i][0] = @splat(M.zero());
    }
    return rows;
}
fn validateInventory(a: std.mem.Allocator) !void {
    var rows = try sourceRows(a);
    defer rows.deinit();
    const k = try key();
    // Only validateRows fields are initialized. This is not a live Plan/cache
    // entry or proof, and deinit/prove must never be called on it.
    var view: Plan = undefined;
    view.admission = try Protocol.Admission.init(k, try k.identity(), &wires, values());
    inline for (Storage.Airs, 0..) |_, i| {
        view.fixed_rows[i] = rows.fixed[i].len;
        var hash = std.crypto.hash.Blake3.init(.{});
        hash.update("stwo.parent.fixed-metadata.v1");
        hash.update(std.mem.sliceAsBytes(rows.fixed[i]));
        hash.final(&view.fixed_digests[i]);
    }
    try view.validateRows(&rows);
    inline for (Storage.Airs, 0..) |Air, i| {
        if (Air.PHYSICAL_MAIN_COLUMN_COUNT != 0) {
            {
                rows.main[i][0].log_size += 1;
                defer rows.main[i][0].log_size -= 1;
                try std.testing.expectError(error.InvalidBlake3ParentRows, view.validateRows(&rows));
            }
            {
                const full = rows.main[i][0].values;
                rows.main[i][0].values = full[0..1];
                defer rows.main[i][0].values = full;
                try std.testing.expectError(error.InvalidBlake3ParentRows, view.validateRows(&rows));
            }
            {
                const columns = rows.main[i];
                rows.main[i] = columns[0 .. columns.len - 1];
                defer rows.main[i] = columns;
                try std.testing.expectError(error.InvalidBlake3ParentRows, view.validateRows(&rows));
            }
        }
        if (@typeInfo(Storage.FixedRow(Air)).array.len != 0) {
            rows.fixed[i][0][0] = M.one();
            defer rows.fixed[i][0][0] = M.zero();
            try std.testing.expectError(error.InvalidBlake3ParentRows, view.validateRows(&rows));
        }
        {
            const fixed = rows.fixed[i];
            rows.fixed[i] = fixed[0..0];
            defer rows.fixed[i] = fixed;
            try std.testing.expectError(error.InvalidBlake3ParentRows, view.validateRows(&rows));
        }
    }
    try view.validateRows(&rows);
}
test "range cache: actual row validator checks every cohort fixed content inventory and log with allocation failures" {
    try validateInventory(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, validateInventory, .{});
}
fn options() Module.Options {
    return .{ .profile = .diagnostic_q8_pow0, .aggregate_host_byte_limit = 1 << 20, .worker_options = .{ .worker_count = 1, .host_byte_limit = 1 << 20, .retained_scratch_limit = 0 } };
}
fn cacheAllocation(a: std.mem.Allocator) !void {
    var cache = try Cache.init(a, options());
    defer cache.deinit();
    try std.testing.expectEqual(@as(usize, 0), cache.stats.hits);
    try std.testing.expectEqual(@as(usize, 0), cache.stats.misses);
    try std.testing.expectEqual(@as(usize, 1 << 20), cache.budget.snapshot().limit);
    try std.testing.expect(cache.entry == null);
    try std.testing.expectEqual(@as(u64, 0), cache.request_lane.snapshot().starts);
}
test "range cache: configured aggregate worker caps remain bounded and failed cache initialization cleans up" {
    try cacheAllocation(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cacheAllocation, .{});
    inline for (.{ "entries", "aggregate", "worker", "scratch" }) |field| {
        var invalid = options();
        if (comptime std.mem.eql(u8, field, "entries")) invalid.max_entries = 2 else if (comptime std.mem.eql(u8, field, "aggregate")) invalid.aggregate_host_byte_limit = 0 else if (comptime std.mem.eql(u8, field, "worker")) invalid.worker_options.host_byte_limit += 1 else invalid.worker_options.retained_scratch_limit = invalid.worker_options.host_byte_limit + 1;
        try std.testing.expectError(error.InvalidV5NativeSetupCacheLimits, Cache.init(std.testing.allocator, invalid));
    }
}
fn failureLifetime(a: std.mem.Allocator) !void {
    var cache = try Cache.init(a, options());
    defer cache.deinit();
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, 1 << 20);
    var owns_budget = true;
    defer if (owns_budget) budget.destroy();
    const bounded = budget.allocator();
    var rows = try sourceRows(bounded);
    var owns_rows = true;
    defer if (owns_rows) rows.deinit();
    const k = try key();
    const schedule = try bounded.dupe(Bus.Wire, &wires);
    var prepared = Bus.Prepared{ .allocator = bounded, .budget = budget, .recursive = .{ .rows = rows, .context = k.context }, .wires = schedule, .values = values() };
    owns_budget = false;
    owns_rows = false;
    defer prepared.deinit();
    cache.requests.lock();
    defer cache.requests.unlock();
    try std.testing.expectError(error.V5NativeSetupCacheAlreadyLeased, cache.provePreparedConsuming(&prepared));
    inline for (Storage.Airs, 0..) |_, i| {
        try std.testing.expectEqual(@as(usize, 0), prepared.recursive.rows.main[i].len);
        try std.testing.expectEqual(@as(usize, 0), prepared.recursive.rows.fixed[i].len);
    }
    try std.testing.expectEqual(wires.len, prepared.wires.len);
    for (wires, prepared.wires) |expected, actual| try std.testing.expectEqualDeep(expected, actual);
    try std.testing.expectEqualDeep(values(), prepared.values);
    try std.testing.expectEqualDeep(k.context, prepared.recursive.context);
    try std.testing.expectEqual(@as(u64, 0), cache.request_lane.snapshot().starts);
}
test "range cache: consuming request rejection frees source rows retains public routing and never launches worker" {
    try failureLifetime(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, failureLifetime, .{});
}
test "range cache: stage rejects cache profile before reading borrowed proof or publishing" {
    var cache = try Cache.init(std.testing.allocator, options());
    defer cache.deinit();
    try (Stage.Options{ .profile = .diagnostic_q8_pow0, .cache = &cache }).validate(Base.PCS_CONFIG);
    try (Stage.Options{ .profile = .csp_q70_pow26 }).validate(Base.CSP_CONFIG);
    cache.options.profile = .csp_q70_pow26;
    try std.testing.expectError(error.RangeRecursiveSecurityMismatch, (Stage.Options{ .profile = .diagnostic_q8_pow0, .cache = &cache }).validate(Base.PCS_CONFIG));
    const Reject = struct {
        fn put(_: *anyopaque, _: u32, _: *@import("block_v5_range16_recursive_stage_v1.zig").Artifact) anyerror!void {
            return error.UnexpectedRangePublication;
        }
    };
    var admitted: @import("block_v5_range16_recursive_admission_v1.zig").Prepared = undefined;
    admitted.config = Base.PCS_CONFIG;
    var placeholder: u8 = 0;
    try std.testing.expectError(error.RangeRecursiveSecurityMismatch, Stage.publish(std.testing.allocator, undefined, &admitted, .{ .profile = .diagnostic_q8_pow0, .cache = &cache }, .{ .context = &placeholder, .put_range = Reject.put }));
}
