//! One real ordinary callback/proof cycle. No recursive/global fixture is
//! repeated: the hook replaces manual projection from a warm native tree.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const Fixture = @import("block_v5_lightweight_native_proof_test.zig").Fixture;
const Seal = @import("../block_v5_source_seal_v1.zig");
const Catalog = @import("../block_v5_native_template_catalog_v1.zig");
const Native = @import("../block_v5_native_execution_proof_v3.zig");
const Template = @import("../block_v5_native_template_protocol_v3.zig");
const Projection = @import("../block_v5_native_lookup_request_proof_v1.zig");
const Source = @import("../block_v5_native_lookup_request_source_v1.zig");
const Stage = @import("../block_v5_native_lookup_stage_v1.zig");
const LeafStage = @import("../block_v5_native_recursive_leaf_stage_v1.zig");
const Files = @import("../block_v5_open_forest_stage_v1.zig");
const Producer = @import("../block_v5_block_producer_v1.zig").ForLightweightBackend(Cpu);
const Transport = struct {
    projection: ?Projection.Proof = null,
    leaf: ?LeafStage.Artifact = null,
    dir: ?std.fs.Dir = null,
    leaf_file: ?@import("../../recursion/block_v5_open_exact_forest_receiver_v1.zig").FilePin = null,
    fn put(raw: *anyopaque, index: u32, proof: *Projection.Proof) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.projection != null) return error.InvalidWarmLookupSinkOrder;
        self.projection = proof.*;
    }
    fn putLeaf(raw: *anyopaque, index: u32, artifact: *LeafStage.Artifact) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.leaf != null or self.dir == null) return error.InvalidWarmLeafSinkOrder;
        var buffer: [80]u8 = undefined;
        self.leaf_file = try Files.writeProof(self.dir.?, try Files.leafPath(index, &buffer), artifact.bytes, 1024 * 1024);
        self.leaf = artifact.*;
    }
    fn release(_: *anyopaque, _: *@import("../block_v5_block_producer_v1.zig").LightweightReplay) void {}
};
const Hooks = struct {
    lookup: *Stage.ForBackend(Cpu),
    leaf: *LeafStage.ForBackend(Cpu),
    fn hooks(self: *Hooks) Producer.Hooks {
        return .{ .context = self, .on_first_round = first, .on_proof = proof };
    }
    fn first(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmExecution) !void {
        const self: *Hooks = @ptrCast(@alignCast(raw));
        const callback = self.lookup.hooks();
        try callback.on_first_round.?(callback.context, a, warm);
    }
    fn proof(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmExecution, native_proof: *const Native.Proof) !void {
        const self: *Hooks = @ptrCast(@alignCast(raw));
        const callback = self.leaf.hooks();
        try callback.on_proof.?(callback.context, a, warm, native_proof);
    }
};
fn qualify(comptime with_leaf: bool) !void {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const instructions = [_]u32{ 0x00500093, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(1);
    defer segment.deinit();
    var counts: [Seal.family_count]u32 = @splat(0);
    counts[@intFromEnum(Seal.Family.program) - 1] = 1;
    counts[@intFromEnum(Seal.Family.execution) - 1] = 1;
    counts[@intFromEnum(Seal.Family.execution_sidecar) - 1] = 1;
    counts[@intFromEnum(Seal.Family.program_request) - 1] = 1;
    counts[@intFromEnum(Seal.Family.memory) - 1] = 1;
    var pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = @import("../../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG, .counts = counts };
    var fixture = try Fixture.init(a, &segment, pins);
    defer fixture.deinit();
    const Api = Native.ForBackend(Cpu);
    var first = try Api.commitFirstRound(a, fixture.owner, fixture.pin, pins.config, .rv32im_zkvm_v1, 0);
    defer first.deinit(a);
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = first.template_id, .geometry_digest = first.template.geometry_digest, .fixed_root = first.roots[0] }};
    const catalog = Catalog.Admission{ .records = &records };
    pins.native_template_catalog_digest = try catalog.digest();
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        first.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
    };
    const sealed = try Seal.seal(pins, &entries);
    var replay = @import("../block_v5_block_producer_v1.zig").LightweightReplay{ .owner = fixture.owner, .admission = fixture.pin, .profile = .rv32im_zkvm_v1, .context = &fixture, .release = Transport.release };
    const warm = Producer.WarmExecution{ .index = 0, .replay = &replay, .first = &first, .sealed = sealed, .pins = pins, .entries = &entries, .catalog = catalog };
    var transport = Transport{ .dir = tmp.dir };
    defer if (transport.projection) |*proof| proof.deinit(a);
    defer if (transport.leaf) |*artifact| artifact.deinit(a);
    var stage = Stage.ForBackend(Cpu){ .sink = .{ .context = &transport, .put_projection = Transport.put } };
    var leaf_stage = LeafStage.ForBackend(Cpu){ .options = .{ .profile = .diagnostic_q8_pow0 }, .sink = .{ .context = &transport, .put_leaf = Transport.putLeaf } };
    var composed = Hooks{ .lookup = &stage, .leaf = &leaf_stage };
    const hooks = if (with_leaf) composed.hooks() else stage.hooks();
    var wrong = warm;
    wrong.index = 1;
    try std.testing.expectError(error.UntrustedV5WarmNativeLookup, hooks.on_first_round.?(hooks.context, a, wrong));
    try std.testing.expect(transport.projection == null);
    const pointers = .{ first.scheme.trees.items[0].columns[0].values.ptr, first.scheme.trees.items[1].columns[0].values.ptr };
    try hooks.on_first_round.?(hooks.context, a, warm);
    try std.testing.expect(first.owns_scheme and first.scheme.trees.items.len == 2);
    try std.testing.expect(first.scheme.trees.items[0].columns[0].values.ptr == pointers[0] and first.scheme.trees.items[1].columns[0].values.ptr == pointers[1]);
    const native_proof = try Api.proveWithCatalog(a, &first, sealed, pins, &entries, catalog);
    var native_owned = true;
    defer if (native_owned) {
        var owned = native_proof;
        owned.deinit(a);
    };
    if (with_leaf) {
        leaf_stage.options.profile = .csp_q70_pow26;
        try std.testing.expectError(error.V5NativeLeafStageSecurityMismatch, hooks.on_proof.?(hooks.context, a, warm, &native_proof));
        try std.testing.expect(transport.leaf == null);
        leaf_stage.options.profile = .diagnostic_q8_pow0;
        try hooks.on_proof.?(hooks.context, a, warm, &native_proof);
    }
    native_owned = false;
    const fresh = try Api.verifyOwnedWithCatalog(a, native_proof, &fixture.owner.statement, fixture.pin, first.template, first.template_id, .rv32im_zkvm_v1, 0, sealed, pins, &entries, catalog);
    const slots = try Source.slotsFromShape(a, &fixture.owner.statement, 0);
    defer a.free(slots);
    const fixed = try Template.columnLogs(a, &fixture.owner.statement, 0, .fixed);
    defer a.free(fixed);
    const main = try Template.columnLogs(a, &fixture.owner.statement, 0, .main);
    defer a.free(main);
    const projection = transport.projection orelse return error.MissingWarmNativeLookupProjection;
    transport.projection = null;
    const fresh_projection = try Projection.ForBackend(Cpu).verifyOwned(a, projection, sealed, 0, first.template_id, fresh.instance_id, slots, fixed, main, fresh.first_roots, fresh.first_roots, pins.config);
    try std.testing.expectEqualDeep(fresh.first_roots, fresh_projection.native_roots);
    const challenges = try @import("../block_memory_relation_v2.zig").Challenges.draw(a, sealed);
    const shared = try @import("../../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&challenges.universal_prefix);
    const compensation = try @import("../../air/public_logup_arithmetic.zig").registersStateSumFor(core.fields.qm31.QM31, &fixture.owner.statement.public_data, &shared.native);
    try std.testing.expect(compensation.add(fresh_projection.registers_state_sum).isZero());
    if (with_leaf) {
        const output = transport.leaf orelse return error.MissingWarmNativeRecursiveLeaf;
        try std.testing.expectEqualDeep(fresh, output.native);
        var admitted = try @import("../block_v5_native_recursive_admission_v3.zig").Prepared.init(a, &fixture.owner.statement, fixture.pin, first.template, first.template_id, 0, sealed, pins, &entries, catalog);
        defer admitted.deinit();
        var name_buffer: [80]u8 = undefined;
        const reopened = try Files.openPinned(a, tmp.dir, try Files.leafPath(0, &name_buffer), transport.leaf_file.?, 1024 * 1024);
        defer a.free(reopened);
        var equation = try @import("../../recursion/block_v5_reusable_native_leaf_v1.zig").verify(a, reopened, output.key, output.expected_key_id, output.schedule, &admitted, fresh);
        defer equation.deinit();
        try std.testing.expectEqualDeep(output.span, equation.pc_clock_span.?);
        std.debug.print("BLOCK_V5_WARM_NATIVE_LEAF verified=true lookup_slots={d} native_produced_once=true original_native_preserved=true strict_native_codec_clone=true actual_recursive_equation=true leaf_file_bytes={d} profile_mismatch_rejected=true sink_owned_no_borrowed_trace=true global_claims_open=true\n", .{ slots.len, reopened.len });
    }
    std.debug.print("BLOCK_V5_WARM_NATIVE_LOOKUP verified=true native_version=3 slots={d} immutable_fixed_main_leases=true native_scheme_preserved=true fresh_native=true fresh_projection=true pc_partition_closed=true provisional_only=true\n", .{slots.len});
}

test "block-v5 warm native lookup stage shares roots then fresh verifies projection and native" {
    try qualify(false);
}

test "block-v5 warm native lookup and recursive leaf stages publish genuine file without consuming native" {
    try qualify(true);
}
