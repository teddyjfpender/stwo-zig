//! Hostile replay of the genuine fused artifacts, after complete reception.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Global = @import("../block_v5_global_receiver_v1.zig");
const Store = @import("../block_v5_cpu_bundle_store_v1.zig");
const Native = @import("../block_v5_native_execution_proof_v3.zig");
const Fused = @import("../block_v5_native_projection_fused_proof_v2.zig");
const Receiver = @import("../block_v5_native_projection_fused_receiver_v2.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");

pub fn qualify(a: std.mem.Allocator, dir: std.fs.Dir, pins: Global.Pins, manifest_sha: [32]u8, limits: Store.Limits) !void {
    const sealed = try pins.validate();
    const windows = try a.dupe(@import("../block_v5_register_windows_v1.zig").Window, pins.tables.register_windows.?.windows);
    defer a.free(windows);
    var changed = pins;
    windows[0].final_clocks[5] += 1;
    changed.tables.register_windows.?.windows = windows;
    try std.testing.expectError(error.UntrustedV5RegisterWindowPlan, changed.validate());
    changed = pins;
    changed.tables.register_windows = null;
    try std.testing.expectError(error.MissingV5RegisterWindowPlan, changed.validate());

    const policies = try @import("../block_v5_cpu_bundle_policy_v1.zig").build(a, pins, limits);
    defer a.free(policies);
    var files = try Store.readPins(a, dir, manifest_sha, limits);
    defer files.deinit();
    var store = try Store.Store.initReader(a, dir, policies, files.files, pins.tables.seal.config, limits);
    defer store.deinit();
    const pin = pins.tables.executions[0];
    const fused_pin = Receiver.InstancePin{ .shape = pin.shape, .admission = pin.admission, .template = pin.template, .template_id = pin.template_id, .profile = pin.profile };
    const fresh = try Native.ForBackend(Cpu).verifyOwnedWithCatalog(a, try store.take(.native, 0), pin.shape, pin.admission, pin.template, pin.template_id, pin.profile, 0, sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
    const memory = Receiver.MemoryPin{ .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = pin.shape.public_data.clock }, .expected_events = pins.memory.ordinary_events[0], .witness_root = pins.memory.opcode_witness_roots[0] };
    const slots = try Source.slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, 1);
    defer a.free(slots);
    var received = try store.take(.native_fused, 0);
    defer received.deinit(a);
    var indices: [2]usize = undefined;
    var found: usize = 0;
    for (slots, 0..) |slot, index| {
        if (slot.kind == .lookup and (slot.kind.lookup.partition == .register_memory_access or slot.kind.lookup.partition == .register_clock_memory_access)) {
            if (found < indices.len) indices[found] = index;
            found += 1;
        }
    }
    try std.testing.expect(found >= 2);
    var forged = try clone(a, received);
    forged.claims[indices[0]].sum = forged.claims[indices[0]].sum.add(core.fields.qm31.QM31.one());
    forged.claims[indices[1]].sum = forged.claims[indices[1]].sum.sub(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.OodsNotMatching, Receiver.ForBackend(Cpu).verifyAfterFreshNative(a, forged, &fresh, 0, fused_pin, memory, sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog));
    std.debug.print("BLOCK_V6_REGISTER_NEGATIVE cancelling_claims=rejected error=OodsNotMatching\n", .{});
    var verified = try Receiver.ForBackend(Cpu).verifyAfterFreshNative(a, try clone(a, received), &fresh, 0, fused_pin, memory, sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
    defer verified.deinit(a);
    try std.testing.expect(verified.projections != null and verified.memory != null);
}

fn clone(a: std.mem.Allocator, original: Fused.Proof) !Fused.Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, original.stark);
    var reader = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, reader.reader());
    errdefer stark.deinit(a);
    const claims = try a.dupe(Fused.Claim, original.claims);
    errdefer a.free(claims);
    return .{ .stark = stark, .claims = claims, .memory_claims = try a.dupe(@TypeOf(original.memory_claims[0]), original.memory_claims) };
}
