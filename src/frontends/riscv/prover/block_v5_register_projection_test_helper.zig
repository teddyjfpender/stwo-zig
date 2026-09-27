//! Reload actual production artifacts; no additional proof generation. This
//! helper qualifies the new register partitions, not complete authority.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Global = @import("block_v5_global_receiver_v1.zig");
const Store = @import("block_v5_cpu_bundle_store_v1.zig");
const Projection = @import("block_v5_native_lookup_request_proof_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Source = @import("block_v5_native_lookup_request_source_v1.zig");
const CallerProjection = @import("block_v5_precompile_lookup_proof_v1.zig");
const CallerSource = @import("block_v5_precompile_lookup_source_v1.zig");
const Q = core.fields.qm31.QM31;

pub fn qualify(a: std.mem.Allocator, dir: std.fs.Dir, pins: Global.Pins, manifest_sha: [32]u8, limits: Store.Limits, index: u32) !void {
    const sealed = try pins.validate();
    if (sealed.register_custody_mode != 1) return error.RegisterProjectionTestRequiresMode1;
    const policies = try @import("block_v5_cpu_bundle_policy_v1.zig").build(a, pins, limits);
    defer a.free(policies);
    var files = try Store.readPins(a, dir, manifest_sha, limits);
    defer files.deinit();
    var store = try Store.Store.initReader(a, dir, policies, files.files, pins.tables.seal.config, limits);
    defer store.deinit();
    const pin = pins.tables.executions[index];
    const native = try Native.ForBackend(Cpu).verifyOwnedWithCatalog(a, try store.take(.native, index), pin.shape, pin.admission,
        pin.template, pin.template_id, pin.profile, index, sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
    const slots = try Source.slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, 1);
    defer a.free(slots);
    const fixed = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
    defer a.free(fixed);
    const main = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
    defer a.free(main);
    const received = try store.take(.native_projection, index);
    var owns_received = true;
    defer if (owns_received) { var proof = received; proof.deinit(a); };
    var forged = try clone(Projection.Proof, a, received);
    var found = false;
    for (slots, forged.claims) |slot, *claim| if (slot.partition == .register_memory_access) {
        claim.sum = claim.sum.add(Q.one()); found = true; break;
    };
    if (!found) { forged.deinit(a); return error.MissingProvedNativeRegisterPartition; }
    if (Projection.ForBackend(Cpu).verifyOwned(a, forged, sealed, index, pin.template_id, native.instance_id, slots, fixed, main,
        native.first_roots, native.first_roots, pins.tables.seal.config)) |_| return error.AcceptedForgedNativeRegisterClaim else |_| {}
    owns_received = false;
    const fresh = try Projection.ForBackend(Cpu).verifyOwned(a, received, sealed, index, pin.template_id, native.instance_id, slots, fixed, main,
        native.first_roots, native.first_roots, pins.tables.seal.config);
    var register_sum = fresh.register_memory_sum.add(fresh.register_clock_memory_sum);
    for (pins.tables.extensions) |extension| {
        if (extension.execution_index != index) continue;
        const Caller = @import("block_v5_precompile_family_proof_v1.zig");
        const caller = try Caller.ForBackend(Cpu).verifyOwned(a, try store.take(.caller, index), extension.statement, extension.total_steps,
            extension.expected_key_id, native.instance_id, index, sealed, pins.tables.seal, pins.tables.roster);
        const received_caller = try store.take(.caller_tables, index);
        var owns_caller = true;
        defer if (owns_caller) { var proof = received_caller; proof.deinit(a); };
        var forged_caller = try clone(CallerProjection.Proof, a, received_caller);
        const owner = try CallerSource.Owner.init(a);
        defer owner.destroy(a);
        const caller_slots = try owner.slotsForMode(a, extension.statement, 1);
        defer a.free(caller_slots);
        found = false;
        for (caller_slots, forged_caller.claims) |slot, *claim| if (slot.table == .register_memory) {
            claim.sum = claim.sum.add(Q.one()); found = true; break;
        };
        if (!found) { forged_caller.deinit(a); return error.MissingProvedCallerRegisterPartition; }
        if (CallerProjection.ForBackend(Cpu).verifyOwned(a, forged_caller, sealed, pins.tables.seal, pins.tables.roster, &caller,
            extension.statement, extension.total_steps)) |_| return error.AcceptedForgedCallerRegisterClaim else |_| {}
        owns_caller = false;
        const fresh_caller = try CallerProjection.ForBackend(Cpu).verifyOwned(a, received_caller, sealed, pins.tables.seal, pins.tables.roster,
            &caller, extension.statement, extension.total_steps);
        register_sum = register_sum.add(fresh_caller.register_memory_sum);
    }
    var channel = sealed.sharedChannel();
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const native_relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&relations);
    const compensation = try pins.tables.register_windows.?.compensation(index, &native_relations.native);
    try std.testing.expect(register_sum.add(compensation).isZero());
}
fn clone(comptime T: type, a: std.mem.Allocator, proof: T) !T {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var reader = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, reader.reader());
    errdefer stark.deinit(a);
    return .{ .stark = stark, .claims = try a.dupe(@TypeOf(proof.claims[0]), proof.claims) };
}
