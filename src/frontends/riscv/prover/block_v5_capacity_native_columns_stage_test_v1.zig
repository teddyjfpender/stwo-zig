//! Pure proposal/owned-file reconstruction fixtures. Literal roots here are
//! unverified proposals, not commitments. No guest, PCS, STARK or device runs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Root = @import("block_v5_cpu_capacity_root_proposal_v1.zig");
const Stage = @import("block_v5_capacity_native_columns_stage_v1.zig");
const Rebuild = @import("block_v5_native_columns_rebuild_v1.zig");
const Store = @import("block_v5_witness_columns_store_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Tables = @import("../air/lookups/tables/counter.zig");
const Witness = @import("../air/lang/typed_base_alu_imm_witness.zig");
const Addi = @import("../air/lang/typed_addi.zig");
const Support = @import("../air/lang/typed_base_alu_imm_witness_test_support.zig");
const Clock = @import("../air/clock_update_interaction.zig");
const limits = Stage.Limits{ .columns = .{ .max_columns = 1024, .max_log_size = 4, .max_file_bytes = 64 << 10, .max_loaded_bytes = 64 << 10 }, .max_public_words = 16, .max_public_bytes = 128 };
const root_limits = Root.Limits{ .native = .{ .max_public_words = 16, .max_metadata_bytes = 1 << 20 }, .max_metadata_bytes = 1 << 20 };
fn proposal(a: std.mem.Allocator, source: Shape, external: u32, index: u32, first: u64) !Root.Proposal {
    var shape = source;
    shape.public_data.io_entries.input_words = try a.dupe(u32, source.public_data.io_entries.input_words);
    errdefer a.free(shape.public_data.io_entries.input_words);
    shape.public_data.io_entries.output_words = try a.dupe(@import("../air/public_data.zig").OutputWord, source.public_data.io_entries.output_words);
    errdefer a.free(shape.public_data.io_entries.output_words);
    const template = try Protocol.Template.fromShape(&shape, external, Fixture.config, .rv32im_zkvm_v1, @splat(17));
    var physical = Native.Proposal{ .allocator = a, .shape = shape, .external_retirements = external, .template = template, .template_id = try template.identity(), .roots = .{ template.fixed_root, @splat(18) }, .index = index, .public_digest = Public.publicDigest(&shape.public_data) };
    return Root.Proposal.take(&physical, first, root_limits);
}
fn context(value: *const Root.Proposal) Public.Context {
    return .{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = value.physical.index, .first_cycle = value.first_cycle, .last_cycle = value.last_cycle };
}
test "capacity staged: first pass span ordinal catalog public and metadata bounds are independently late bound" {
    var source = Fixture.shape(3);
    source.public_data.io_entries.input_words = &.{ 9, 10 };
    source.public_data.io_entries.input_len = 8;
    var value = try proposal(std.testing.allocator, source, 0, 3, 9);
    defer value.deinit();
    const candidate = try value.bind(context(&value));
    try std.testing.expectEqual(@as(u64, 11), value.last_cycle);
    try std.testing.expectEqual(@as(u32, 3), candidate.entry.index);
    try std.testing.expectEqualDeep(value.candidate_catalog, candidate.catalog_record);
    try std.testing.expectEqualDeep(value.physical.roots, candidate.entry.roots);
    try std.testing.expectEqualDeep(try Protocol.instanceId(value.physical.template_id, &value.physical.shape, 0, candidate.admission, value.physical.roots, 3), candidate.entry.instance_id);
    for (0..3) |mutation| {
        var wrong = context(&value);
        switch (mutation) {
            0 => wrong.execution_index += 1,
            1 => wrong.first_cycle += 1,
            else => wrong.last_cycle += 1,
        }
        try std.testing.expectError(error.ChangedCapacityRootProposalSpan, value.bind(wrong));
    }
    var changed = value;
    changed.candidate_catalog.index += 1;
    try std.testing.expectError(error.ChangedCapacityRootProposal, changed.validate());
    changed = value;
    changed.metadata_bytes += 1;
    try std.testing.expectError(error.ChangedCapacityRootProposal, changed.validate());
    changed = value;
    changed.physical.roots[0][0] ^= 1;
    try std.testing.expectError(error.ChangedCapacityRootProposal, changed.validate());
    changed = value;
    changed.physical.public_digest[0] ^= 1;
    try std.testing.expectError(error.ChangedCapacityRootProposal, changed.validate());
    var physical = value.physical; // borrowed mutation copy, never deinitialized
    try std.testing.expectError(error.InvalidCapacityRootProposalSpan, Root.Proposal.take(&physical, 0, root_limits));
    try std.testing.expectEqualDeep(value.physical.public_digest, physical.public_digest);
    try std.testing.expectError(error.Overflow, Root.Proposal.take(&physical, std.math.maxInt(u64), root_limits));
    var capped = root_limits;
    capped.max_metadata_bytes = @sizeOf(Root.Proposal) - 1;
    try std.testing.expectError(error.InvalidCapacityRootProposalLimits, Root.Proposal.take(&physical, 9, capped));
    capped = root_limits;
    capped.native.max_public_words = 1;
    try std.testing.expectError(error.NativeCapacityResourceLimit, Root.Proposal.take(&physical, 9, capped));
    try std.testing.expectEqualSlices(u32, &.{ 9, 10 }, physical.shape.public_data.io_entries.input_words);
}
const Replay = struct {
    pin: Public.Admission,
    template: Protocol.Template,
    template_id: [32]u8,
    received: @import("block_v5_source_seal_v1.zig").Entry,
    pub fn entry(self: *const @This()) @import("block_v5_source_seal_v1.zig").Entry {
        return self.received;
    }
};
test "capacity staged: empty physical capacity reuse retains changing counts and exact replay span" {
    var small = Fixture.shape(3);
    small.n_components = 0;
    var large = Fixture.shape(7);
    large.n_components = 0;
    var one = try proposal(std.testing.allocator, small, 3, 0, 1);
    defer one.deinit();
    var two = try proposal(std.testing.allocator, large, 7, 1, 4);
    defer two.deinit();
    try std.testing.expectEqualDeep(one.physical.template_id, two.physical.template_id);
    const first = try one.bind(context(&one));
    const second = try two.bind(context(&two));
    try std.testing.expect(!std.meta.eql(first.entry.instance_id, second.entry.instance_id));
    var replay = Replay{ .pin = first.admission, .template = one.physical.template, .template_id = one.physical.template_id, .received = first.entry };
    try one.requireReplay(&replay);
    replay.received.roots[1][0] ^= 1;
    try std.testing.expectError(error.CapacityRootProposalReplayMismatch, one.requireReplay(&replay));
}
fn compareCounters(left: *const Tables.Set, right: *const Tables.Set) !void {
    for (left.counters, right.counters) |original, reconstructed| try std.testing.expectEqualSlices(M, original.values, reconstructed.values);
}
test "capacity staged: bounded original main file rebuild preserves typed opcode counters clock counters public copies and ownership aliases" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var definition = try Addi.build(a, .generated);
    const binding = try Witness.WitnessBinding.canonical(&definition);
    const executor = try Witness.Executor.init(&definition, &binding);
    definition.deinit();
    const rows = [_]Witness.TraceRow{
        Support.makeRow(.ADDI, 1, 0, 0, 1, 1, 0, 0, 0, 0),
        Support.makeRow(.XORI, 2, 0, 0, 2, 2, 4, 0, 0, 0),
        Support.makeRow(.ORI, 3, 0, 0, 3, 3, 8, 0, 0, 0),
    };
    var logical: [Witness.MAIN_COLUMN_COUNT][4]M = undefined;
    var views: [Witness.MAIN_COLUMN_COUNT][]M = undefined;
    for (&logical, &views) |*storage, *view| view.* = storage;
    try executor.generateMainInto(&views, &rows, 2);
    var shape = Fixture.shape(3);
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = Clock.N_MAIN_COLUMNS };
    shape.public_data.io_entries.input_words = &.{ 9, 10 };
    shape.public_data.io_entries.input_len = 8;
    var value = try proposal(std.testing.allocator, shape, 0, 0, 1);
    defer value.deinit();
    const main = try a.alloc(engine.pcs.ColumnEvaluation, Witness.MAIN_COLUMN_COUNT + Clock.N_MAIN_COLUMNS);
    for (main[0..Witness.MAIN_COLUMN_COUNT], views) |*column, input| {
        const output = try a.alloc(M, 4);
        for (input, 0..) |cell, logical_row| output[core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical_row, 2), 2)] = cell;
        column.* = .{ .log_size = 2, .values = output };
    }
    const clock_row = [_]u32{ 1, 1, 0x3000, 17, 1, 2, 3, 4, 17, 0 };
    for (main[Witness.MAIN_COLUMN_COUNT..], clock_row) |*column, cell| {
        const output = try a.alloc(M, 2);
        @memset(output, M.zero());
        output[0] = M.fromCanonical(cell);
        column.* = .{ .log_size = 1, .values = output };
    }
    var expected = try Tables.Set.init(a);
    for (rows) |row| {
        const relations = try executor.generateRelationRow(row);
        for (relations.events) |event| if (Tables.kindForDomain(@enumFromInt(@intFromEnum(event.domain)))) |kind| {
            var tuple: [Witness.MAX_EVENT_ARITY]Q = undefined;
            for (event.values[0..event.arity], tuple[0..event.arity]) |cell, *lifted| lifted.* = Q.fromBase(cell);
            try expected.get(kind).registerRaw(Q.fromBase(event.signedNumerator()), tuple[0..event.arity]);
        };
    }
    // Clock's independent typed Row supplies the range events, rather than
    // accepting a stored counter or rescanning the file as expected authority.
    const clock_entries = Clock.orderedEntries(.{ .enabler = Q.one(), .addr_space = Q.one(), .addr = Q.fromBase(M.fromCanonical(0x3000)), .clock_prev = Q.fromBase(M.fromCanonical(17)), .value = .{ Q.one(), Q.fromBase(M.fromCanonical(2)), Q.fromBase(M.fromCanonical(3)), Q.fromBase(M.fromCanonical(4)) }, .clock_prev_low20 = Q.fromBase(M.fromCanonical(17)), .clock_prev_high6 = Q.zero() });
    try expected.registerList(clock_entries);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pin = try Store.write(std.testing.allocator, tmp.dir, "base.columns", Stage.scope(&value), main, limits.columns);
    const owner = try Stage.rebuildOwner(std.testing.allocator, tmp.dir, "base.columns", &value, pin, limits);
    defer owner.deinit();
    try std.testing.expect(owner.tables_ready and owner.native_only_v5 and !owner.interaction_ready and !owner.failed);
    try std.testing.expectEqualDeep(value.physical.public_digest, Public.publicDigest(&owner.statement.public_data));
    try std.testing.expect(owner.statement.public_data.io_entries.input_words.ptr != value.physical.shape.public_data.io_entries.input_words.ptr);
    try compareCounters(&expected, &owner.opcode_columns.lookup_counters.?);
    for (main, owner.main.items) |original, loaded| try std.testing.expectEqualSlices(M, original.values, loaded.values);
    for (owner.opcode_columns.components[0].columns[0..Witness.MAIN_COLUMN_COUNT], owner.main.items[0..Witness.MAIN_COLUMN_COUNT]) |alias, committed| try std.testing.expect(alias.ptr == committed.values.ptr);
    for (owner.clock_main, owner.main.items[Witness.MAIN_COLUMN_COUNT..]) |alias, committed| try std.testing.expect(alias.ptr == committed.values.ptr);
    _ = try Stage.write(std.testing.allocator, tmp.dir, "reconstructed.columns", owner, &value, limits);
    var wrong = value;
    wrong.first_cycle += 1;
    wrong.last_cycle += 1;
    try std.testing.expectError(error.ChangedV5WitnessScope, Stage.rebuildOwner(std.testing.allocator, tmp.dir, "base.columns", &wrong, pin, limits));
    var changed_pin = pin;
    changed_pin.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5WitnessFile, Stage.rebuildOwner(std.testing.allocator, tmp.dir, "base.columns", &value, changed_pin, limits));
    var capped = limits;
    capped.columns.max_loaded_bytes = 0;
    try std.testing.expectError(error.V5WitnessColumnLimit, Stage.rebuildOwner(std.testing.allocator, tmp.dir, "base.columns", &value, pin, capped));
    capped = limits;
    capped.max_public_words = 1;
    try std.testing.expectError(error.V5StagedNativePublicLimit, Stage.rebuildOwner(std.testing.allocator, tmp.dir, "base.columns", &value, pin, capped));
}
fn frameRebuild(a: std.mem.Allocator) !void {
    var shape = Fixture.shape(3);
    shape.n_components = 0;
    shape.public_data.io_entries.input_words = &.{ 9, 10 };
    shape.public_data.io_entries.input_len = 8;
    var value = try proposal(a, shape, 3, 0, 1);
    defer value.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pin = try Store.write(a, tmp.dir, "empty.columns", Stage.scope(&value), &.{}, limits.columns);
    const owner = try Stage.rebuildOwner(a, tmp.dir, "empty.columns", &value, pin, limits);
    defer owner.deinit();
    try std.testing.expectEqual(@as(usize, 0), owner.main.items.len);
    try std.testing.expectEqual(@as(u32, 3), owner.external_retirements);
    try std.testing.expect(owner.tables_ready and owner.native_only_v5);
    try std.testing.expectEqualSlices(u32, &.{ 9, 10 }, owner.statement.public_data.io_entries.input_words);
}
test "capacity staged: empty original file remains a real frame proposal and allocation failures release reconstructed owner" {
    try frameRebuild(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, frameRebuild, .{});
}
test "capacity staged: legacy stage API delegates to the same bounded owner reconstruction" {
    const Legacy = @import("block_v5_native_columns_stage_v1.zig");
    try std.testing.expect(Legacy.Limits == Rebuild.Limits);
    try std.testing.expect(Stage.Limits == Rebuild.Limits);
    try std.testing.expect(Legacy.Pin == Stage.Pin);
    try std.testing.expect(Root.Proposal != @import("block_v5_cpu_native_root_proposal_v1.zig").Proposal);
}
