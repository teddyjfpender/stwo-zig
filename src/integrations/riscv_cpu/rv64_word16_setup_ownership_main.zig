//! Retained immutable setup payload audit. Constructs no execution witness.
const std = @import("std");
const R = @import("rv64_ethereum_request.zig");
const Image = @import("word16_execution/expected_image.zig");
const Program = @import("word16_execution/program.zig");
const Keys = @import("word16_global_execution/ethereum/keys.zig").Owner;
const W = @import("word16_global_execution/services/wire.zig");
const Audit = @import("word16_setup_audit/ownership.zig");
const NativeCache = @import("word16_execution/fixed_native_cache.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 3 or args.len > 5) return error.ExpectedTrustedConfigAndBundle;
    var retire = false;
    var cache_bytes: ?usize = null;
    for (args[3..]) |arg| {
        if (std.mem.eql(u8, arg, "--retire-fixed-witness")) {
            if (retire) return error.InvalidAuditOption;
            retire = true;
        } else if (std.mem.startsWith(u8, arg, "--fixed-native-cache-mib=")) {
            if (cache_bytes != null) return error.InvalidAuditOption;
            const mib = try std.fmt.parseInt(usize, arg[25..], 10);
            if (mib == 0 or mib > 4096) return error.InvalidAuditOption;
            cache_bytes = try std.math.mul(usize, mib, 1024 * 1024);
        } else return error.InvalidAuditOption;
    }
    var native_cache = try NativeCache.Cache.init(a, cache_bytes orelse 0);
    defer native_cache.deinit();
    const config_raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    defer a.free(config_raw);
    const config = try std.json.parseFromSlice(R.Config, a, config_raw, .{});
    defer config.deinit();
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16 << 20);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, raw, .{});
    defer parsed.deinit();
    const cv = parsed.value.object.get("cpus") orelse return error.MissingCpuDeclarations;
    const tv = parsed.value.object.get("truths") orelse return error.MissingTruthDeclarations;
    if (cv.array.items.len == 0 or cv.array.items.len > 256 or tv.array.items.len > 256) return error.AuditDeclarationBudget;
    const cpus = try a.alloc(W.CpuDeclaration, cv.array.items.len);
    defer a.free(cpus);
    const truths = try a.alloc(W.TruthDeclaration, tv.array.items.len);
    defer a.free(truths);
    for (cv.array.items, cpus) |v, *out| {
        const p = try std.json.parseFromValue(W.CpuDeclaration, a, v.object.get("declaration") orelse return error.MissingDeclaration, .{});
        defer p.deinit();
        out.* = p.value;
    }
    for (tv.array.items, truths) |v, *out| {
        const p = try std.json.parseFromValue(W.TruthDeclaration, a, v.object.get("declaration") orelse return error.MissingDeclaration, .{});
        defer p.deinit();
        out.* = p.value;
    }
    const Work = @import("stwo_prover_engine").work_pool;
    var pool: Work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try R.effectiveWorkers(config.value), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var image = try Image.Owner.init(a, config.value);
    defer image.deinit();
    var timer = try std.time.Timer.start();
    var keys = if (cache_bytes != null) try Keys.initWithNativeCache(a, &image, cpus, truths, &native_cache) else try Keys.init(a, &image, cpus, truths);
    defer keys.deinit();
    const setup_ns = timer.read();
    if (cache_bytes != null) {
        const stats = native_cache.snapshot();
        if (stats.observed_spans == 0) return error.NativeCacheNotUsed;
        if (stats.groups == 0 or stats.native_backing_bytes == 0) return error.NativeCacheNoAdoptedPayload;
        if (keys.cpu_owners.items.len > 1 and (stats.hits == 0 or stats.duplicate_native_bytes_released == 0)) return error.NativeCacheNoUsefulDeduplication;
    }
    if (retire) for (keys.cpu_owners.items) |setup| try setup.releaseFixedWitness();
    const roots = (parsed.value.object.get("roots") orelse return error.MissingCommitmentRoots).array.items;
    if (roots.len != keys.cpus.len + keys.truths.len) return error.RootInventoryMismatch;
    for (keys.cpus, 0..) |setup, i| try checkRoot(a, roots[i], setup.key.root);
    for (keys.truths, keys.cpus.len..) |truth, i| try checkRoot(a, roots[i], truth.key().root);
    var account = Audit.Accountant{ .allocator = a };
    defer account.deinit();
    const records = try a.alloc(Audit.Record, keys.cpu_owners.items.len + keys.keccak_owners.items.len + keys.secp_owners.items.len + 1 + @intFromBool(cache_bytes != null));
    defer a.free(records);
    var at: usize = 0;
    if (cache_bytes != null) {
        var record = Audit.Record{ .kind = "shared_fixed_native_cache", .index = 0 };
        const allocations = try native_cache.ownedAllocations(a);
        defer a.free(allocations);
        for (allocations) |allocation| switch (allocation.kind) {
            .native => try account.addAddress(&record, "coefficients", allocation.address, allocation.bytes),
            .metadata => try account.addAddress(&record, "headers", allocation.address, allocation.bytes),
        };
        if (record.payload.total() != native_cache.snapshot().retained_bytes) return error.NativeCacheAuditMismatch;
        records[at] = record;
        at += 1;
    }
    for (keys.cpu_owners.items, 0..) |s, i| {
        records[at] = try account.cpu(i, s);
        at += 1;
    }
    for (keys.keccak_owners.items, 0..) |s, i| {
        records[at] = try account.keccak(i, s);
        at += 1;
    }
    for (keys.secp_owners.items, 0..) |s, i| {
        records[at] = try account.secp(i, s);
        at += 1;
    }
    var registry = Audit.Record{ .kind = "registry_headers", .index = 0 };
    try account.add(&registry, "headers", keys.cpus);
    try account.add(&registry, "headers", keys.truths);
    try account.add(&registry, "headers", keys.cpu_owners.items.ptr[0..keys.cpu_owners.capacity]);
    try account.add(&registry, "headers", keys.keccak_owners.items.ptr[0..keys.keccak_owners.capacity]);
    try account.add(&registry, "headers", keys.secp_owners.items.ptr[0..keys.secp_owners.capacity]);
    records[at] = registry;
    const output = try std.json.Stringify.valueAlloc(a, .{ .scope = "live unique setup allocation payloads; excludes allocator rounding, trusted Image, proof data, witnesses, mapped advice and RSS", .fixed_witness_retired = retire, .native_coefficient_cache = if (cache_bytes != null) native_cache.snapshot() else null, .no_vm_or_tape_or_main_witness = true, .all_fixed_roots_match_retained_bundle = true, .cpu_setups = keys.cpu_owners.items.len, .keccak_setups = keys.keccak_owners.items.len, .secp_setups = keys.secp_owners.items.len, .feature_entry_size = @sizeOf(Program.Entry), .setup_ns = setup_ns, .owned_payload = account.totals, .owned_payload_total = account.totals.total(), .records = records }, .{ .whitespace = .indent_2 });
    defer a.free(output);
    try std.fs.File.stdout().writeAll(output);
}

fn checkRoot(a: std.mem.Allocator, value: std.json.Value, expected: [32]u8) !void {
    const fixed = value.object.get("fixed") orelse return error.MissingFixedRoot;
    const parsed = try std.json.parseFromValue([32]u8, a, fixed.object.get("bytes") orelse return error.MissingRootBytes, .{});
    defer parsed.deinit();
    if (!std.mem.eql(u8, &parsed.value, &expected)) return error.ReconstructedSetupRootMismatch;
}
