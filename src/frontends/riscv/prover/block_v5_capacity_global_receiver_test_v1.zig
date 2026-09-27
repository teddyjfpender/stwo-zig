//! Nonproving fresh-hook contract tests. Metadata/receipt fixtures are not
//! verifier authority; no native, provider, recursive or Complete proof runs.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Tables = @import("block_v5_capacity_native_table_join_v1.zig");
const Memory = @import("block_v5_capacity_word_memory_join_v1.zig");
const Programs = @import("block_v5_program_native_capacity_batch_receiver_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const Leaf = @import("../recursion/block_v5_reusable_capacity_parent_protocol_v1.zig");
const Bus = @import("../recursion/block_v5_capacity_recursive_public_bus_v1.zig");
const Open = @import("../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const OpenBus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const Exact = @import("../recursion/block_v5_capacity_exact_forest_receiver_v1.zig");
const Q = core.fields.qm31.QM31;
fn frameShape(rows: u32) @import("../air/statement.zig").Blake3ExecutionStatement {
    var shape = Fixture.shape(rows);
    shape.n_components = 0;
    shape.final_pc = 4;
    shape.public_data.final_pc = 4;
    shape.public_data.completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(4);
    return shape;
}
const Metadata = struct {
    record: [1]Catalog.Record,
    pin: Programs.InstancePin,
    roster: [5]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    memory: @import("block_v5_native_capacity_fused_receiver_v1.zig").MemoryPin,
    receipt: Native.OpenReceipt,
    fn init(a: std.mem.Allocator, shape: *@import("../air/statement.zig").Blake3ExecutionStatement) !Metadata {
        const context = Public.Context{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = shape.total_steps };
        const admission = try Public.Admission.init(context, &shape.public_data);
        const template = try Protocol.Template.fromShape(shape, shape.total_steps, Parent.PCS_CONFIG, .rv32im_zkvm_v1, @splat(4));
        const record = [_]Catalog.Record{try Catalog.Record.fromTemplate(0, template)};
        const roots: Seal.Roots = .{ template.fixed_root, @splat(20) };
        const id = try Protocol.instanceId(record[0].template_id, shape, shape.total_steps, admission, roots, 0);
        const execution = Seal.Entry{ .family = .execution, .index = 0, .instance_id = id, .roots = roots };
        const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = shape.total_steps };
        const access = try Source.emptyEntry(a, shape, shape.total_steps, frame, execution, 0, 0);
        const roster = [_]Seal.Entry{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            execution,
            access,
            Fused.entry(record[0].template_id, id, roots, access.roots[0], 0, frame, &.{}, &.{}),
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (roster) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        const pins = Seal.Pins{ .job_id = context.job_id, .source_image_digest = context.source_image_digest, .program_root = context.program_root, .program_plan_digest = context.program_plan_digest, .memory_plan_digest = context.memory_plan_digest, .initial_source_plan_digest = context.initial_source_plan_digest, .rw_endpoint_plan_digest = context.rw_endpoint_plan_digest, .native_template_catalog_digest = try (Catalog.Admission{ .records = &record }).digest(), .config = Parent.PCS_CONFIG, .counts = counts };
        const sealed = try Seal.seal(pins, &roster);
        var channel = sealed.sharedChannel();
        const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
        const relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
        return .{ .record = record, .pin = .{ .shape = shape, .external_retirements = shape.total_steps, .admission = admission, .template = template, .template_id = record[0].template_id, .profile = .rv32im_zkvm_v1 }, .roster = roster, .pins = pins, .sealed = sealed, .memory = .{ .frame = frame, .expected_events = 0, .witness_root = access.roots[0] }, .receipt = .{ .template_id = record[0].template_id, .instance_id = id, .first_roots = roots, .sealed_digest = sealed.digest, .exact_geometry_digest = try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(shape, shape.total_steps), .open_sum = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &shape.public_data, &relations.native) } };
    }
};
fn noProvider(_: *anyopaque, _: u32) anyerror!@import("block_v5_native_lookup_proof_v1.zig").Proof {
    return error.UnexpectedCapacityProviderLoad;
}
fn expectRejection(expected: anyerror, result: anyerror!void) !void {
    result catch |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(expected, err);
        return;
    };
    return error.TestExpectedError;
}
fn emptyHook(a: std.mem.Allocator) !void {
    var shape = frameShape(3);
    const metadata = try Metadata.init(a, &shape);
    var native_claims: [1][6]Q = .{@splat(Q.one())};
    var state: [1]Q = .{Q.zero()};
    var registers: [1]Q = .{Q.one()};
    var events: [1]u64 = .{0};
    var calls: usize = 0;
    var join = Tables.ForBackend(Cpu){ .a = a, .pins = .{ .seal = metadata.pins, .roster = &metadata.roster, .catalog = .{ .records = &metadata.record }, .executions = &.{metadata.pin}, .ordinary_events = &events, .extensions = &.{}, .providers = &.{} }, .sealed = metadata.sealed, .loader = .{ .context = &calls, .take_provider = noProvider }, .provider_claims = &.{}, .native_claims = &native_claims, .state_claims = &state, .register_claims = &registers, .expected_events = &events, .auxiliary_clock_memory_sum = Q.one(), .register_compensation_sum = Q.one() };
    try join.onFusedNative(a, 0, metadata.pin, &metadata.receipt, metadata.memory, null);
    try std.testing.expectEqual(@as(u32, 1), join.next_native);
    try std.testing.expect(!metadata.receipt.open_sum.isZero());
    try std.testing.expectEqualDeep(metadata.receipt.open_sum, state[0]);
    for (native_claims[0]) |claim| try std.testing.expect(claim.isZero());
    try std.testing.expectEqualDeep(Q.one(), registers[0]);
    try std.testing.expectEqualDeep(Q.one(), join.auxiliary_clock_memory_sum);
    try std.testing.expectEqualDeep(Q.one(), join.register_compensation_sum);
    try std.testing.expectEqual(@as(usize, 0), calls);
    // A forged open sum must not erase the frame obligation on the empty path.
    join.next_native = 0;
    var forged = metadata.receipt;
    forged.open_sum = forged.open_sum.add(Q.one());
    try expectRejection(error.UntrustedV5EmptyNativeOpenClaim, join.onFusedNative(a, 0, metadata.pin, &forged, metadata.memory, null));
    try std.testing.expectEqual(@as(u32, 0), join.next_native);
    forged = metadata.receipt;
    forged.exact_geometry_digest[0] ^= 1;
    try expectRejection(error.UntrustedV5TableNativeHook, join.onFusedNative(a, 0, metadata.pin, &forged, metadata.memory, null));
    var callback = metadata.pin;
    callback.limits.max_projection_slots = 0;
    try expectRejection(error.UntrustedV5TableNativeHook, join.onFusedNative(a, 0, callback, &metadata.receipt, metadata.memory, null));
    var wrong_frame = metadata.memory;
    wrong_frame.frame.global_first_cycle += 1;
    try expectRejection(error.UntrustedV5FullFusedPin, join.onFusedNative(a, 0, metadata.pin, &metadata.receipt, wrong_frame, null));
}
test "capacity globals: typed empty table hook retains frame register and auxiliary obligations and rejects altered receipts" {
    try emptyHook(std.testing.allocator);
}
test "capacity globals: empty hook allocation failures do not publish or leak owned source schedules" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, emptyHook, .{});
}
test "capacity globals: separate legacy opcode and table loaders remain unsupported before touching receipt or join" {
    var memory: Memory.ForBackend(Cpu) = undefined;
    var tables: Tables.ForBackend(Cpu) = undefined;
    const pin: Programs.InstancePin = undefined;
    const receipt: Native.OpenReceipt = undefined;
    try std.testing.expectError(error.UnsupportedCapacitySeparateProjection, memory.onNative(std.testing.allocator, 0, pin, &receipt));
    try std.testing.expectError(error.UnsupportedCapacitySeparateProjection, tables.onNative(std.testing.allocator, 0, pin, &receipt));
}
fn outerKey() !Exact.NodePin {
    const schedule = &[_]OpenBus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .kind = .frame_cell, .child = 0, .coordinate = 0 }};
    const geometry = Parent.Key{ .context = .{ .child_key_id = @splat(21), .child_config = Parent.PCS_CONFIG, .graph_ids = .{ @splat(22), @splat(23), @splat(24) }, .transcript_plan_id = @splat(25) }, .log_sizes = @splat(1), .preprocessed_root = @splat(26) };
    const key = try Open.Key.fromGeometry(geometry, schedule);
    return .{ .key = key, .expected_id = try key.identity(), .schedule = schedule };
}
test "capacity globals: complete recursion security and full width dynamic schedule validate before any proof loader" {
    const schedule = &[_]Bus.Wire{.{ .circuit = 4_200_004, .wire = 258, .uses = 1, .source = .row_count, .coordinate = 256 }};
    const geometry = Parent.Key{ .context = .{ .child_key_id = @splat(21), .child_config = Parent.PCS_CONFIG, .graph_ids = .{ @splat(22), @splat(23), @splat(24) }, .transcript_plan_id = @splat(25) }, .log_sizes = @splat(1), .preprocessed_root = @splat(26) };
    const key = try Leaf.Key.fromGeometry(geometry, schedule);
    var leaf = [_]Global.RecursiveLeafPin{.{ .key = key, .expected_id = try key.identity(), .schedule = schedule }};
    const outer = try outerKey();
    var pins = Global.RecursivePins{ .leaves = &leaf, .parents = &.{}, .outer = outer, .file = .{ .byte_len = 1, .sha256 = @splat(1) } };
    try pins.validate(Parent.PCS_CONFIG, 1);
    leaf[0].key.context.child_config.pow_bits += 1;
    try std.testing.expectError(error.V5CompleteRecursiveSecurityMismatch, pins.validate(Parent.PCS_CONFIG, 1));
    leaf[0].key.context.child_config = Parent.PCS_CONFIG;
    var alternate = schedule[0];
    alternate.coordinate = 255;
    leaf[0].schedule = &.{alternate};
    try std.testing.expectError(error.UntrustedV5CompleteRecursiveKey, pins.validate(Parent.PCS_CONFIG, 1));
    leaf[0].schedule = schedule;
    pins.outer.key.context.child_config.pow_bits += 1;
    try std.testing.expectError(error.V5CompleteRecursiveSecurityMismatch, pins.validate(Parent.PCS_CONFIG, 1));
}
test "capacity globals: legacy exports preserve nominal shared types while capacity receipts and loader signatures stay distinct" {
    const Old = @import("block_v5_global_receiver_v1.zig");
    const OldMemory = @import("block_v5_word_memory_join_v1.zig");
    const OldTables = @import("block_v5_native_table_join_v1.zig");
    try std.testing.expect(@TypeOf(@as(Old.Pins, undefined).memory) == OldMemory.Pins);
    try std.testing.expect(@TypeOf(@as(Old.Pins, undefined).tables) == OldTables.Pins);
    try std.testing.expect(@TypeOf(@as(Global.Pins, undefined).memory) == Memory.Pins);
    try std.testing.expect(@TypeOf(@as(Global.Pins, undefined).tables) == Tables.Pins);
    try std.testing.expect(Native.OpenReceipt != @import("block_v5_native_execution_proof_v3.zig").OpenReceipt);
    try std.testing.expect(Programs.InstancePin != @import("block_v5_program_native_batch_receiver_v3.zig").InstancePin);
    try std.testing.expect(Global.Inputs != Old.Inputs);
    try std.testing.expect(Global.RecursiveLeafPin != Old.RecursiveLeafPin);
}
fn ownedPreparation(a: std.mem.Allocator) !void {
    var shape = frameShape(3);
    const metadata = try Metadata.init(a, &shape);
    var prepared = try Global.prepareRecursive(a, metadata.pin, 0, metadata.sealed, metadata.pins, &metadata.roster, .{ .records = &metadata.record });
    defer prepared.deinit();
    try prepared.validate(metadata.pin.template_id);
    try std.testing.expectEqual(metadata.pin.external_retirements, prepared.external_retirements);
    try std.testing.expectEqualDeep(metadata.pin.limits.native, prepared.limits);
    var limited = metadata.pin;
    limited.limits.native.max_main_cells = 0;
    try std.testing.expectError(error.NativeCapacityResourceLimit, Global.prepareRecursive(a, limited, 0, metadata.sealed, metadata.pins, &metadata.roster, .{ .records = &metadata.record }));
}
test "capacity globals: complete policy reconstruction owns capacity geometry uses independent external count and native limits with rollback" {
    try ownedPreparation(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownedPreparation, .{});
}
