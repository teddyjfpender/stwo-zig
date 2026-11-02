//! Full native services workers, shared manifest, physical proofs and receiver.
//! q12 fixtures are correctness tests, never a 128-bit security claim.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const C = @import("coordinator.zig");
const Wire = @import("bundle_wire.zig");
const F = @import("../bulk_fixture.zig");
const a = std.testing.allocator;
fn keys(comptime Fixture: type, captured: *const Fixture.Captured) ![2]R.CpuSetup {
    var result: [2]R.CpuSetup = undefined;
    var done: usize = 0;
    errdefer for (result[0..done]) |*s| s.deinit();
    for (&result, 0..) |*s, i| {
        s.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Fixture.WORDS }, try captured.native[i].geometry(), Fixture.bridges[i]);
        done += 1;
    }
    return result;
}
fn cfg() !@import("worker_protocol.zig").PcsConfig {
    return @import("coordinator_fixture.zig").config();
}
fn run(comptime Fixture: type) !void {
    var captured = try Fixture.Captured.init(a);
    defer captured.deinit();
    var setups = try keys(Fixture, &captured);
    defer for (&setups) |*s| s.deinit();
    var fresh = try keys(Fixture, &captured);
    defer for (&fresh) |*s| s.deinit();
    const pointers = [_]*const R.CpuSetup{ &setups[0], &setups[1] };
    const fresh_pointers = [_]*const R.CpuSetup{ &fresh[0], &fresh[1] };
    const expected = Fixture.expectedFor(captured.program.identity);
    // Byte-cap admission must fail before consuming any capture ownership.
    try std.testing.expectError(error.BoundedWideCoordinatorRetainedLimit, C.produce(a, &pointers, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try cfg(), .{ .max_retained_frontend_bytes = 1, .gkr_budget = 2 << 30 }));
    try std.testing.expect(captured.native[0].cpu != null and captured.native[1].cpu != null);
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try C.Store.initFullyParked(path, 512 << 20);
    defer store.deinit();
    var timings: [2]C.WorkerTiming = undefined;
    var bundle = try C.produce(a, &pointers, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try cfg(), .{ .gkr_budget = 2 << 30, .retained_store = &store, .defer_local_binding = true, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 }, .worker_timings = &timings, .stage2_order = &.{ 1, 0 } });
    defer bundle.deinit(a);
    const verified = try bundle.verify(a, &fresh_pointers, &.{}, expected, try cfg());
    try std.testing.expect(verified.completed and verified.physical_proofs == 2);
    for (timings) |t| try std.testing.expect(t.stage1_completed and t.stage2_completed and t.completed_worker_retired);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    var transport = std.testing.tmpDir(.{});
    defer transport.cleanup();
    try Wire.write(a, transport.dir, &pointers, &.{}, &bundle);
    var loaded = try Wire.read(a, transport.dir, .{});
    defer loaded.deinit(a);
    _ = try loaded.bundle.verify(a, &fresh_pointers, &.{}, expected, try cfg());
    const raw_metadata = try transport.dir.readFileAlloc(a, "bundle.json", 4 << 20);
    defer a.free(raw_metadata);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, raw_metadata, .{});
    defer parsed.deinit();
    parsed.value.object.getPtr("profile").?.* = .{ .string = @import("manifest.zig").PROFILE };
    const downgraded = try std.json.Stringify.valueAlloc(a, parsed.value, .{});
    defer a.free(downgraded);
    try transport.dir.writeFile(.{ .sub_path = "bundle.json", .data = downgraded });
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.read(a, transport.dir, .{}));
    var changed_logs = Fixture.bridges[0];
    if (changed_logs.bulk.desc != null) changed_logs.bulk.desc.? += 1 else changed_logs.bulk.jdesc.? += 1;
    var changed_key = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Fixture.WORDS }, fresh[0].materials.geometry, changed_logs);
    defer changed_key.deinit();
    if (bundle.verify(a, &.{ &changed_key, &fresh[1] }, &.{}, expected, try cfg())) |_| return error.AcceptedRekeyedBulkGeometry else |_| {}
    for (bundle.requests, 0..) |request, i| {
        const declarations = [_]@import("../wire.zig").CpuDeclaration{ .{ .geometry = setups[0].materials.geometry, .bridges = setups[0].bridges }, .{ .geometry = setups[1].materials.geometry, .bridges = setups[1].bridges } };
        var report = try @import("source_bounds.zig").derive(a, setups[0].materials.program.log_size, &declarations, &.{}, bundle.requests);
        defer report.deinit();
        try report.conditional_degrees.requireLookupOnlyBits(128);
        try std.testing.expect(!report.security_qualified);
        const support = report.cpu_scopes[i].owner_table;
        if (request.bulk.jump()) {
            try std.testing.expectEqual(@as(u64, A.crypto.bulk_memory.types.TABLE_ENTRIES), support.valid_provider_support);
            try std.testing.expectEqual(@as(u64, 32 * 64), support.unit_consumer_mass);
        }
        var plan = try @import("cpu_components.zig").Plan.init(a, &setups[i]);
        defer plan.deinit();
        const retention = try @import("retention_plan.zig").forCpu(a, &setups[i], request, try cfg(), 2 << 30, 1 << 30);
        var actual: usize = 0;
        inline for (@import("../types.zig").bulk_kinds) |kind| if (setups[i].bridges.bulk.at(kind)) |log| {
            var src = try A.crypto.bulk_memory.source.Source.init(a, kind, captured.advice.bulk[i].calls, captured.advice.bulk[i].words, log);
            defer src.deinit();
            @import("bulk_metadata.zig").retireLocal(&src);
            const bytes = try @import("bulk_metadata.zig").retainedBytes(&src);
            try std.testing.expect(bytes <= try @import("bulk_metadata.zig").requestUpperBound(request.bulk, kind));
            actual += bytes;
        };
        try std.testing.expect(actual <= retention.global_metadata_bytes);
    }
    const original = bundle.cpus[0].claims[0];
    bundle.cpus[0].claims[0] = original.add(@import("worker_protocol.zig").O.one());
    if (bundle.verify(a, &fresh_pointers, &.{}, expected, try cfg())) |_| return error.AcceptedChangedRamDebt else |_| {}
    bundle.cpus[0].claims[0] = original;
    std.mem.swap(@TypeOf(bundle.cpus[0]), &bundle.cpus[0], &bundle.cpus[1]);
    if (bundle.verify(a, &fresh_pointers, &.{}, expected, try cfg())) |_| return error.AcceptedSwappedBulkShards else |_| {}
    std.mem.swap(@TypeOf(bundle.cpus[0]), &bundle.cpus[0], &bundle.cpus[1]);
    const count = bundle.requests[0].bulk;
    bundle.requests[0].bulk = .{};
    if (bundle.verify(a, &fresh_pointers, &.{}, expected, try cfg())) |_| return error.AcceptedOmittedBulkRows else |_| {}
    bundle.requests[0].bulk = count;
    std.debug.print("BULK_EXECUTION fixture={s} fresh_receiver=true parked=true deferred=true reverse_stage2=true complete=true\n", .{@typeName(Fixture)});
}
test "bulk coordinator closes cross-epoch memset memcpy and LS through fresh transport receiver" {
    try run(F);
}
test "bulk coordinator closes unaligned memcpy memcmp and LS through fresh transport receiver" {
    try run(@import("../bulk_ext_fixture.zig"));
}
test "bulk coordinator closes JUMPDEST weighted support across epochs through fresh transport receiver" {
    try run(@import("../jumpdest_fixture.zig"));
}

test "balanced cross-shard bulk corruptions cannot close global RAM despite valid component proofs" {
    for (0..3) |attack| {
        var captured = try F.Captured.init(a);
        defer captured.deinit();
        var setups = try keys(F, &captured);
        defer for (&setups) |*s| s.deinit();
        const pointers = [_]*const R.CpuSetup{ &setups[0], &setups[1] };
        var fresh = try keys(F, &captured);
        defer for (&fresh) |*s| s.deinit();
        const fresh_pointers = [_]*const R.CpuSetup{ &fresh[0], &fresh[1] };
        const copy = &captured.advice.bulk[1];
        switch (attack) {
            0 => { // Match the forged copy with its forged public terminal word.
                copy.words[2].src.value ^= 1;
                for (captured.advice.terminal) |*cell| if (cell.address == F.B + 0x210) {
                    cell.state.value ^= 1;
                };
            },
            1 => { // Copy an initial value instead of the prior epoch's write.
                copy.words[1].src = .{ .value = (F.B + 0x108) *% 0x9E3779B97F4A7C15, .rights = 3 };
                for (captured.advice.terminal) |*cell| if (cell.address == F.B + 0x208) {
                    cell.state.value = copy.words[1].src.value;
                };
            },
            2 => { // Make the entire memset agree with a falsified packet read.
                const set = &captured.advice.bulk[0].calls[0];
                set.word1 = 0x5B;
                set.packet[1].value = 0x5B;
            },
            else => unreachable,
        }
        const expected = F.expectedFor(captured.program.identity);
        var bundle = try C.produce(a, &pointers, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try cfg(), .{ .gkr_budget = 2 << 30 });
        defer bundle.deinit(a);
        try std.testing.expectError(error.UnclosedGlobalGkrRam, bundle.verify(a, &fresh_pointers, &.{}, expected, try cfg()));
        std.debug.print("BULK_BALANCED_CHAIN attack={d} individually_proved=true fresh_receiver=UnclosedGlobalGkrRam\n", .{attack});
    }
}

fn allocationCase(allocator: std.mem.Allocator, kind: A.crypto.bulk_memory.layout.Kind, calls: []const A.crypto.bulk_memory.types.Call, words: []const A.crypto.bulk_memory.types.Word, log: u32) !void {
    var src = try A.crypto.bulk_memory.source.Source.init(allocator, kind, calls, words, log);
    defer src.deinit();
    const main = try src.takeMain();
    defer allocator.free(main);
    @import("bulk_metadata.zig").retireLocal(&src);
    @import("bulk_metadata.zig").retireLocal(&src);
}
test "bulk source allocation failure and owned MAIN transfer preserve destruction across all nine kinds" {
    inline for (.{ F, @import("../bulk_ext_fixture.zig"), @import("../jumpdest_fixture.zig") }) |Fixture| {
        var captured = try Fixture.Captured.init(a);
        defer captured.deinit();
        for (Fixture.bridges, 0..) |logs, i| {
            inline for (@import("../types.zig").bulk_kinds) |kind| if (logs.bulk.at(kind)) |log| {
                try std.testing.checkAllAllocationFailures(a, allocationCase, .{ kind, captured.advice.bulk[i].calls, captured.advice.bulk[i].words, log });
            };
        }
    }
}
