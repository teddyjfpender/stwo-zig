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
const Projection = @import("../block_v5_native_projection_fused_proof_v1.zig");
const Source = @import("../block_v5_native_lookup_request_source_v1.zig");
const Stage = @import("../block_v5_native_projection_fused_stage_v1.zig");
const Producer = @import("../block_v5_block_producer_v1.zig").ForLightweightBackend(Cpu);
const Receiver = @import("../block_v5_native_projection_fused_receiver_v1.zig");
const FusedSource = @import("../block_v5_native_projection_fused_source_v1.zig");
const ProgramSource = @import("../block_v5_program_request_source_v1.zig");
const Program = @import("../block_v5_program_request_proof_v1.zig");
const Q = core.fields.qm31.QM31;
const Transport = struct {
    proof: ?Projection.Proof = null,
    fn put(raw: *anyopaque, index: u32, proof: *Projection.Proof) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != 0 or self.proof != null) return error.InvalidFusedProjectionSinkOrder;
        self.proof = proof.*;
    }
    fn release(_: *anyopaque, _: *@import("../block_v5_block_producer_v1.zig").LightweightReplay) void {}
};
test "block-v5 fused native projections use one PCS proof and fresh native admission" {
    const a = std.testing.allocator;
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
    const slots = try FusedSource.slotsFromShapeForMode(a, &fixture.owner.statement, 0, 0);
    defer a.free(slots);
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        first.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .program_request, .index = 0, .instance_id = Receiver.instanceId(first.template_id, first.instance_id, 0, slots), .roots = first.roots },
        .{ .family = .memory, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
    };
    const sealed = try Seal.seal(pins, &entries);
    const pin = Receiver.InstancePin{ .shape = &fixture.owner.statement, .admission = fixture.pin, .template = first.template, .template_id = first.template_id, .profile = .rv32im_zkvm_v1 };
    var wrong_entries = entries;
    wrong_entries[3].instance_id = @splat(19);
    const wrong_sealed = try Seal.seal(pins, &wrong_entries);
    try std.testing.expectError(error.UntrustedV5FusedProjectionEntry, Receiver.admit(0, pin, wrong_sealed, pins, &wrong_entries, catalog, slots));
    const original_program_slots = try Program.slotsFromStatement(a, &fixture.owner.statement);
    defer a.free(original_program_slots);
    try std.testing.expect(!std.meta.eql(entries[3].instance_id, Program.nativeV5InstanceId(first.template_id, first.instance_id, 0, original_program_slots)));
    var replay = @import("../block_v5_block_producer_v1.zig").LightweightReplay{ .owner = fixture.owner, .admission = fixture.pin, .profile = .rv32im_zkvm_v1, .context = &fixture, .release = Transport.release };
    const warm = Producer.WarmExecution{ .index = 0, .replay = &replay, .first = &first, .sealed = sealed, .pins = pins, .entries = &entries, .catalog = catalog };
    var transport = Transport{};
    defer if (transport.proof) |*proof| proof.deinit(a);
    var stage = Stage.ForBackend(Cpu){ .sink = .{ .context = &transport, .put_fused = Transport.put } };
    const hooks = stage.hooks();
    var wrong = warm;
    wrong.index = 1;
    try std.testing.expectError(error.UntrustedV5WarmFusedProjection, hooks.on_first_round.?(hooks.context, a, wrong));
    const main_pointer = first.scheme.trees.items[1].columns[0].values.ptr;
    try hooks.on_first_round.?(hooks.context, a, warm);
    try std.testing.expect(first.owns_scheme);
    try std.testing.expectEqual(@as(usize, 2), first.scheme.trees.items.len);
    try std.testing.expect(main_pointer == first.scheme.trees.items[1].columns[0].values.ptr);
    const projection = transport.proof orelse return error.MissingFusedProjection;
    try std.testing.expectEqual(@as(usize, 4), projection.stark.commitment_scheme_proof.commitments.items.len);
    var relation_channel = sealed.sharedChannel();
    const relations = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &relation_channel);
    // Independent exact host sum from original typed source, not the fused
    // generator's running prefix or its transported public claim.
    var oracle: [FusedSource.PARTITION_COUNT]Q = @splat(Q.zero());
    var program_sum = Q.zero();
    const framework = @import("../../recursion/air/framework_interaction.zig");
    const Opcode = @import("../../runner/trace.zig");
    for (slots) |slot| {
        var sum = Q.zero();
        for (0..(@as(usize, 1) << @intCast(slot.log_size))) |logical| {
            var row: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            const physical = framework.committedRow(logical, slot.log_size);
            for (row[0..slot.width], fixture.owner.main.items[slot.main_offset..][0..slot.width]) |*value, column| value.* = Q.fromBase(column.values[physical]);
            switch (slot.kind) {
                .program => |family| {
                    const request = try ProgramSource.fromCommittedOpcodeMain(Q, family, row[0..slot.width]);
                    sum = sum.add(request.numerator.mul(try (try relations.get(.program_access).combineSecure(&request.tuple)).inv()));
                },
                .lookup => |lookup| {
                    const pair = try Source.fromCommittedMain(lookup, row[0..slot.width], &relations);
                    sum = sum.add(pair.numerator().mul(try pair.denominator().inv()));
                },
            }
        }
        switch (slot.kind) {
            .program => program_sum = program_sum.add(sum),
            .lookup => |lookup| oracle[@intFromEnum(lookup.partition)] = oracle[@intFromEnum(lookup.partition)].add(sum),
        }
    }
    const fixed = try Template.columnLogs(a, &fixture.owner.statement, 0, .fixed);
    defer a.free(fixed);
    const main = try Template.columnLogs(a, &fixture.owner.statement, 0, .main);
    defer a.free(main);
    for ([_]usize{ 0, slots.len - 1 }) |changed| {
        var bad = try cloneProjection(a, projection);
        bad.claims[changed].sum = bad.claims[changed].sum.add(Q.one());
        const result = Projection.ForBackend(Cpu).verifyOwned(a, bad, sealed, 0, first.template_id, first.instance_id, slots, fixed, main, first.roots, first.roots, pins.config);
        if (result) |_| return error.AcceptedChangedFusedBusClaim else |_| {}
    }
    var bad_census = try cloneProjection(a, projection);
    bad_census.claims[0].row_count += 1;
    try std.testing.expectError(error.InvalidV5FusedProjectionCensus, Projection.ForBackend(Cpu).verifyOwned(a, bad_census, sealed, 0, first.template_id, first.instance_id, slots, fixed, main, first.roots, first.roots, pins.config));
    const native_proof = try Api.proveWithCatalog(a, &first, sealed, pins, &entries, catalog);
    transport.proof = null;
    const fresh = try Receiver.ForBackend(Cpu).verifyOwned(a, native_proof, projection, 0, pin, sealed, pins, &entries, catalog);
    try std.testing.expectEqualDeep(program_sum, fresh.projections.program_sum);
    try std.testing.expectEqualDeep(oracle[0..6].*, fresh.projections.claims);
    try std.testing.expectEqualDeep(oracle[@intFromEnum(Source.Partition.registers_state)], fresh.projections.registers_state_sum);
    try std.testing.expectEqualDeep(oracle[@intFromEnum(Source.Partition.clock_memory_access)], fresh.projections.auxiliary_clock_memory_sum);
    try std.testing.expectEqualDeep(oracle[@intFromEnum(Source.Partition.register_memory_access)], fresh.projections.register_memory_sum);
    try std.testing.expectEqualDeep(oracle[@intFromEnum(Source.Partition.register_clock_memory_access)], fresh.projections.register_clock_memory_sum);
    try std.testing.expectEqual(@as(u64, 1), fresh.projections.fetch_count);
    try std.testing.expectEqualDeep(fresh.native.first_roots, fresh.projections.native_roots);
    std.debug.print("BLOCK_V5_FUSED_NATIVE_PROJECTIONS one_stark=true one_interaction_tree=true fresh_native=true program_and_all_native_partitions=true leases_preserved=true claim_census_id_mutations_rejected=true global_memory_and_provider_closure_open=true\n", .{});
}
fn cloneProjection(a: std.mem.Allocator, proof: Projection.Proof) !Projection.Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    return .{ .stark = stark, .claims = try a.dupe(Projection.Claim, proof.claims) };
}
