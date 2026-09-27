//! Pure metadata/fault/codegen tests. No guest, PCS commitment, STARK, FRI,
//! device or block execution is invoked. Literal roots are proposals only.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Collect = @import("block_v5_cpu_collect_v1.zig");
const Assembly = @import("block_v5_cpu_assembly_v1.zig");
const Program = @import("block_v5_program_first_round_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Proof = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Root = @import("block_v5_cpu_capacity_root_proposal_v1.zig");
const Stage = @import("block_v5_native_capacity_fused_stage_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Fetch = @import("block_v5_program_census_v1.zig").Fetch;
const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 3 };
const leaves = [_]Tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 } };

fn programMetadata(a: std.mem.Allocator) !void {
    const root = try Tree.TreeHasher.init(.program).root(&leaves);
    var source = Fixture.shape(3);
    const fetches = [_]Fetch{.{ .address = 0, .multiplicity = 4 }};
    var capacity = try Program.ForCapacity(true).ForBackend(Cpu).init(a, root, &leaves, 1);
    defer capacity.deinit();
    var legacy = try Program.ForBackend(Cpu).init(a, root, &leaves, 1);
    defer legacy.deinit();
    const witness = try Source.emptyWitnessRoot(1);
    const roots: Seal.Roots = .{ @splat(7), @splat(8) };
    try capacity.addLightweightFused(&fetches, &source, @splat(9), @splat(10), roots, roots, 0, 1, frame, witness);
    try legacy.addLightweightFused(&fetches, &source, @splat(9), @splat(10), roots, roots, 0, 1, frame, witness);
    const projections = try Source.slotsFromShapeForMode(a, &source, 0, 1);
    defer a.free(projections);
    const memory = try Source.memorySlots(a, &source, 0, frame, 1);
    defer a.free(memory);
    try std.testing.expectEqual(@as(usize, 0), memory.len);
    try std.testing.expectEqualDeep(Proof.entry(@splat(9), @splat(10), roots, witness, 0, frame, projections, memory), capacity.requestEntries()[0]);
    try std.testing.expect(!std.meta.eql(capacity.requestEntries()[0], legacy.requestEntries()[0]));
    try std.testing.expectEqualSlices(u64, legacy.census.counts, capacity.census.counts);
    try std.testing.expectEqual(@as(u64, 4), capacity.census.total_fetches);
    try std.testing.expectEqual(@as(u32, 1), capacity.census.segments);
    try std.testing.expectError(error.CapacityProgramRequiresFusedStage, capacity.addLightweight(&fetches, &source, @splat(9), @splat(10), roots, roots));
    try capacity.addLightweightExtension(0, &fetches, &.{}, 0, null);
    const plan = try capacity.census.smallestTablePlan(1, 4);
    const entry = Seal.Entry{ .family = .program, .index = 0, .instance_id = try @import("block_v5_program_table_proof_v1.zig").instanceId(plan), .roots = .{ @splat(11), @splat(12) } };
    var changed = entry;
    changed.roots[0] = @splat(0);
    try std.testing.expectError(error.UntrustedV5CollectedProgramRoots, capacity.finishCollected(4, Fixture.config, changed));
    try std.testing.expect(capacity.table_roots == null);
    try std.testing.expectEqualDeep(entry, try capacity.finishCollected(4, Fixture.config, entry));
    try std.testing.expectError(error.IncompleteV5ProgramFirstRound, capacity.finishCollected(4, Fixture.config, entry));
}
test "capacity collection: fused ROM ledger uses genuine distinct identity and counts once" {
    try programMetadata(std.testing.allocator);
}
test "capacity collection: fused ROM metadata allocation failures preserve owned ledgers" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, programMetadata, .{});
}

fn entries(a: std.mem.Allocator) !void {
    var source = Fixture.shape(3);
    const context = Public.Context{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = 1, .execution_index = 0, .first_cycle = 1, .last_cycle = 3 };
    const template = try Protocol.Template.fromShape(&source, 0, Fixture.config, .rv32im_zkvm_v1, @splat(9));
    const metadata = @import("block_v5_native_capacity_proof_v1.zig").Proposal{ .allocator = a, .shape = source, .template = template, .template_id = try template.identity(), .roots = .{ template.fixed_root, @splat(10) }, .index = 0, .public_digest = Public.publicDigest(&source.public_data), .external_retirements = 0 };
    const slots = try Source.memorySlots(a, &source, 0, frame, 1);
    var ordinary = Stage.Proposal{ .allocator = a, .slots = slots, .index = 0, .frame = frame, .register_custody_mode = 1, .native_roots = metadata.roots, .template_id = metadata.template_id, .public_digest = metadata.public_digest, .witness_root = try Source.emptyWitnessRoot(1), .byte_snapshot = @splat(11), .event_count = 0 };
    defer ordinary.deinit();
    const access = try ordinary.memoryEntry(a, &metadata, context);
    const projection = try ordinary.projectionEntry(a, &metadata, context);
    try std.testing.expectEqual(Seal.Family.execution_sidecar, access.family);
    try std.testing.expectEqual(Seal.Family.program_request, projection.family);
    var changed_context = context;
    changed_context.first_cycle += 1;
    try std.testing.expectError(error.ChangedCapacityFusedProposal, ordinary.memoryEntry(a, &metadata, changed_context));
    const saved = ordinary.witness_root;
    ordinary.witness_root[0] ^= 1;
    try std.testing.expectError(error.ChangedCapacityFusedProposal, ordinary.memoryEntry(a, &metadata, context));
    ordinary.witness_root = saved;
    ordinary.event_count = 1;
    try std.testing.expectError(error.InvalidCapacityFusedAbsence, ordinary.memoryEntry(a, &metadata, context));
}
test "capacity collection: real proposal binding rejects wrong frame witness and zero-RW census" {
    try entries(std.testing.allocator);
}
test "capacity collection: late-bound entry allocations transfer no root ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, entries, .{});
}

test "capacity collection: typed full production bodies retained without invocation" {
    inline for (.{ &Collect.ForCapacity(false).collect, &Collect.ForCapacity(true).collect, &Assembly.ForCapacity(false).assemble, &Assembly.ForCapacity(true).assemble }) |body| std.mem.doNotOptimizeAway(body);
    comptime {
        if (Collect.Collected != Collect.ForCapacity(false).Collected or Assembly.Assembly != Assembly.ForCapacity(false).Assembly) @compileError("legacy aliases changed");
        if (Collect.Collected == Collect.ForCapacity(true).Collected or Assembly.Assembly == Assembly.ForCapacity(true).Assembly) @compileError("capacity custody was relabeled");
        if (Program.ForBackend(Cpu) != Program.ForCapacity(false).ForBackend(Cpu)) @compileError("legacy ROM producer changed");
        if (@TypeOf(@as(Collect.ForCapacity(true).Collected, undefined).ordinary) != []Stage.Proposal) @compileError("capacity ordinary source is not actual B5CF");
        if (@TypeOf(@as(@import("block_v5_cpu_driver_admission_v1.zig").ForCapacity(true).Record, undefined).physical) != Root.Proposal) @compileError("capacity native proposal is not genuinely owned");
    }
}

test "capacity collection: roster caps include sparse caller and provider families before allocation" {
    const capacity = Assembly.ForCapacity(true);
    const legacy = Assembly.ForCapacity(false);
    try std.testing.expectEqual(@as(usize, 21), try capacity.requiredEntryCount(6, 4, 1, 21));
    try std.testing.expectEqual(try legacy.requiredEntryCount(6, 4, 1, 21), try capacity.requiredEntryCount(6, 4, 1, 21));
    try std.testing.expectError(error.V5CpuRosterResourceLimit, capacity.requiredEntryCount(6, 4, 1, 20));
    try std.testing.expectError(error.V5CpuRosterResourceLimit, capacity.requiredEntryCount(6, 4, 5, 100));
    try std.testing.expectError(error.V5CpuRosterResourceLimit, capacity.requiredEntryCount(6, 0, 0, 100));
    try std.testing.expectError(error.Overflow, capacity.requiredEntryCount(std.math.maxInt(usize), 1, 0, std.math.maxInt(usize)));
}
