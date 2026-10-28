//! Direct aggregate over genuine RAM/caller executions, joined to a fresh
//! complete global receiver. Base files originate in the comparison driver;
//! this is receiver qualification, not a replacement-driver timing claim.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Global = @import("../block_v5_global_receiver_v1.zig");
const Store = @import("../block_v5_cpu_bundle_store_v1.zig");
const Policy = @import("../block_v5_cpu_bundle_policy_v1.zig");
const Native = @import("../block_v5_native_execution_proof_v3.zig");
const Prep = @import("../../recursion/block_v6_native_batch_prepare_v1.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;

pub fn qualify(backing: std.mem.Allocator, dir: std.fs.Dir, pins: Global.Pins, manifest: [32]u8, limits: Store.Limits, input: []const u8, profile: Profile) !void {
    const engine = @import("stwo_prover_engine");
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 40 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const sealed = try pins.validate();
    const policies = try Policy.build(a, pins, limits);
    defer a.free(policies);
    var files = try Store.readPins(a, dir, manifest, limits);
    defer files.deinit();
    var store = try Store.Store.initReader(a, dir, policies, files.files, pins.tables.seal.config, limits);
    defer store.deinit();
    const count = pins.tables.executions.len;
    const prepared = try a.alloc(Prep.NativeAdmission, count);
    defer a.free(prepared);
    const captured = try a.alloc(Prep.Capture, count);
    defer a.free(captured);
    const admissions = try a.alloc(*const Prep.NativeAdmission, count);
    defer a.free(admissions);
    const captures = try a.alloc(*const Prep.Capture, count);
    defer a.free(captures);
    var prepared_count: usize = 0;
    defer for (prepared[0..prepared_count]) |*value| value.deinit();
    var capture_count: usize = 0;
    defer for (captured[0..capture_count]) |*value| value.deinit();
    var timer = try std.time.Timer.start();
    for (pins.tables.executions, 0..) |pin, index| {
        prepared[index] = try Prep.NativeAdmission.init(a, pin.shape, pin.admission, pin.template, pin.template_id, @intCast(index), sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
        prepared_count += 1;
        prepared[index].reusable_public_inputs = true;
        captured[index] = try Native.ForBackend(Cpu).verifyCaptureOwnedWithCatalog(a, try store.take(.native, @intCast(index)), pin.shape, pin.admission, pin.template, pin.template_id, pin.profile, @intCast(index), sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
        capture_count += 1;
        admissions[index] = &prepared[index];
        captures[index] = &captured[index];
    }
    const capture_ns = timer.lap();
    var batch = try @import("block_v6_native_batch_proof_test.zig").qualifyRetained(a, admissions, captures, profile, 0);
    defer batch.deinit();
    const batch_wall_ns = timer.lap();
    const batch_pins = Global.NativeBatchPins{ .key = batch.expected.key, .expected_id = batch.expected.expected_id, .schedule = batch.expected.schedule };
    const fresh = try receive(a, dir, pins, manifest, limits, input, batch_pins, batch.encoded);
    const receive_ns = timer.lap();
    try std.testing.expectEqualDeep(batch.measurement.span, fresh.globals.span);
    try std.testing.expectEqual(@as(u32, @intCast(count)), fresh.globals.execution_count);
    try std.testing.expectEqual(.pending, fresh.globals.exact_recursive_forest);
    var wrong = batch_pins;
    wrong.key.child_count -= 1;
    try std.testing.expectError(error.IncompleteV6NativeBatch, receive(a, dir, pins, manifest, limits, input, wrong, batch.encoded));
    wrong = batch_pins;
    wrong.expected_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeBatchKey, receive(a, dir, pins, manifest, limits, input, wrong, batch.encoded));
    wrong = batch_pins;
    wrong.key.config.pow_bits += 1;
    try std.testing.expectError(error.NativeBatchSecurityMismatch, receive(a, dir, pins, manifest, limits, input, wrong, batch.encoded));
    // Change two physical recursive claims while preserving their sum. This
    // exercises transcript binding past envelope validation and public closure.
    // The codec fixes the first two claim limbs at these byte offsets.
    const M = @import("stwo_core").fields.m31.M31;
    const first = std.mem.readInt(u32, batch.encoded[44..48], .little);
    const second = std.mem.readInt(u32, batch.encoded[60..64], .little);
    std.mem.writeInt(u32, batch.encoded[44..48], M.fromCanonical(first).add(M.one()).v, .little);
    std.mem.writeInt(u32, batch.encoded[60..64], M.fromCanonical(second).sub(M.one()).v, .little);
    try std.testing.expectError(error.OodsNotMatching, receive(a, dir, pins, manifest, limits, input, batch_pins, batch.encoded));
    std.debug.print("BLOCK_V6_COMPLETE_BATCH_NEGATIVE tampered_proof=rejected error=OodsNotMatching\n", .{});
    std.mem.writeInt(u32, batch.encoded[44..48], first, .little);
    std.mem.writeInt(u32, batch.encoded[60..64], second, .little);
    std.debug.print("BLOCK_V6_COMPLETE_BATCH verified=true profile={s} segments={d} capture_ns={d} batch_wall_ns={d} recursive_phase_ns={d} complete_receive_ns={d} recursive_cells={d} g_rows={d} charged_peak_bytes={d} batch_bytes={d} standalone_root=false replacement_driver=false\n", .{ @tagName(profile), count, capture_ns, batch_wall_ns, batch.measurement.recursive_ns, receive_ns, batch.measurement.costs.cells, batch.measurement.costs.g_rows, budget.snapshot().peak_live_bytes, batch.encoded.len });
}

fn receive(a: std.mem.Allocator, dir: std.fs.Dir, pins: Global.Pins, manifest: [32]u8, limits: Store.Limits, input: []const u8, batch: Global.NativeBatchPins, bytes: []const u8) !Global.VerifiedNativeBatchBundle {
    const policies = try Policy.build(a, pins, limits);
    defer a.free(policies);
    var files = try Store.readPins(a, dir, manifest, limits);
    defer files.deinit();
    var store = try Store.Store.initReader(a, dir, policies, files.files, pins.tables.seal.config, limits);
    defer store.deinit();
    var sources: [4]std.fs.File = undefined;
    var initialized: usize = 0;
    defer for (sources[0..initialized]) |file| file.close();
    for (@import("../block_v5_memory_source_writer_v1.zig").filenames, &sources) |name, *file| {
        file.* = try dir.openFile(name, .{});
        initialized += 1;
    }
    const result = try Global.ForBackend(Cpu).verifyCompleteNativeBatch(a, pins, .{ .public_input = input, .endpoint_sources = .{ .initial = .{ .input_words = sources[0], .rw_words = sources[1], .first_touches = sources[2] }, .endpoints = sources[3] }, .memory = store.packedMemoryLoader(), .execution_memory = store.executionMemoryLoader(), .tables = store.tableLoader(), .programs = store.programLoader() }, batch, bytes);
    try store.requireConsumed();
    return result;
}
