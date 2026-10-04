//! Integration assertions invoked with the shared admitted memory/program fixture.
const std = @import("std");
const core = @import("stwo_core");
const columns = @import("../blake3_commitment_columns.zig");
const components = @import("../blake3_commitment_components.zig");
const Witness = @import("../blake3_commitment_witness.zig").Witness;
const Admission = @import("../blake3_commitment_plan.zig").Admission;
pub fn check(a: std.mem.Allocator, source: *Witness, admission: Admission) !void {
    const owner = try columns.Owner.init(a, admission);
    defer owner.deinit();
    try std.testing.expectError(error.CommitmentMainNotReady, owner.main());
    try owner.prepareMain(source);
    const storage = (try owner.main())[0].values.ptr;
    var comparison = Compare{ .owner = owner };
    try components.emit(a, source, &comparison);
    try std.testing.expectEqualDeep(owner.counts, comparison.at);
    inline for (components.Airs, 0..) |Air, i| {
        const view = try owner.view(Air);
        const size = @as(usize, 1) << @intCast(owner.logs[i]);
        for (owner.counts[i]..size) |logical| {
            const index = @import("../../recursion/air/framework_interaction.zig").committedRow(logical, owner.logs[i]);
            for (view.columns) |values| try std.testing.expect(values[index].isZero());
        }
    }
    const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
    var counters = [2]Counter{ try Counter.init(a, .bitwise), try Counter.init(a, .range_check_8_8) };
    defer for (&counters) |*counter| counter.deinit(a);
    try owner.registerLookups(&counters);
    var channel = core.channel.blake3.Channel{};
    const relations = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    // Exercise partial device failure, mixed ownership and a later CPU retry.
    // The mock output is deliberately not used as a proof witness.
    try std.testing.expectError(error.InjectedDeviceFailure, owner.interactionsForBackend(FailingDevice, a, &relations));
    for (owner.initialized_workspaces) |initialized| try std.testing.expect(!initialized);
    {
        var mixed = try owner.interactionsForBackend(MixedDevice, a, &relations);
        defer mixed.deinit();
        try std.testing.expect(!owner.initialized_workspaces[0]);
        for (owner.initialized_workspaces[1..]) |initialized| try std.testing.expect(initialized);
    }
    var generated = try owner.interactions(a, &relations);
    defer generated.deinit();
    const statement_mod = @import("../../air/statement.zig");
    var execution: statement_mod.Blake3ExecutionStatement = undefined;
    execution.initializeDescriptorStorage();
    execution.n_components = 1;
    execution.n_infra = 0;
    execution.initial_pc = 0x1000;
    execution.final_pc = 0x1004;
    execution.total_steps = 1;
    execution.component_descs[0] = .{ .family = .base_alu_imm, .log_size = 1, .n_rows = 1, .n_columns = @intCast(@import("../../air/lang/opcode_composition_manifest.zig").mainColumnCount(.base_alu_imm)) };
    execution.public_data = .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 1,
        .initial_regs = @splat(0),
        .final_regs = @splat(0),
        .reg_last_clock = @splat(0),
        .program_root = admission.plan.roots[0],
        .initial_rw_root = admission.plan.roots[1],
        .final_rw_root = admission.plan.roots[2],
        .completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{ .input_start = 0, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0, .output_data_addr = 0, .output_words = &.{} },
    };
    var execution_claims = std.mem.zeroes(statement_mod.RiscVInteractionClaim);
    execution_claims.n_components = 1;
    const joined = try @import("../blake3_execution_components.zig").Owner.init(a, &execution, &execution_claims, relations, admission);
    defer joined.deinit();
    try joined.bindCommitments(owner, generated.claims);
    const first = try owner.manifest().placement(@enumFromInt(0));
    try std.testing.expectEqual(execution.nMainColumns(), first.main_offset);
    try std.testing.expectEqual(execution.nPreprocessedColumns(), first.preprocessed_offset);
    try std.testing.expectEqual(execution.nInteractionColumns(), first.interaction_offset);
    _ = try joined.publicCompensation();
    var overflowing = owner.manifest();
    overflowing.origin.columns[0] = std.math.maxInt(u32);
    try std.testing.expectError(error.Overflow, overflowing.placement(@enumFromInt(0)));
    execution.initial_pc = 1 << 30;
    execution.public_data.initial_pc = execution.initial_pc;
    try std.testing.expectError(error.InvalidStatement, execution.validateBlake3Execution());
    execution.initial_pc = 0x1000;
    execution.public_data.initial_pc = 0x1000;
    execution.n_infra = 1;
    inline for (.{ .program, .memory, .merkle, .poseidon2 }) |kind| {
        execution.infra_descs[0] = .{ .kind = kind, .log_size = 1, .n_rows = 1, .n_columns = 1 };
        try std.testing.expectError(error.LegacyCommitmentInBlake3Execution, execution.validateBlake3Execution());
    }

    try std.testing.expectEqual(components.Airs.len, (try owner.provers()).len);
    try std.testing.expectEqual(components.Airs.len, (try owner.verifiers()).len);
    var interaction_offset: usize = 0;
    inline for (components.Airs, 0..) |Air, i| {
        const view = try owner.view(Air);
        const rows = try a.alloc(Air.Row, view.count);
        defer a.free(rows);
        for (rows, 0..) |*row, index| row.* = view.read(index, owner.logs[i]);
        const Runtime = @import("../../recursion/air/framework_interaction.zig").Runtime(@import("../../recursion/air/universal_relation_binding.zig").Binding(Air).Runtime);
        var reference = try Runtime.generatePreparedWithPadding(a, &owner.plans[i], rows, owner.logs[i], &relations, @as(Air.Row, @splat(core.fields.m31.M31.zero())));
        defer reference.deinit(a);
        try std.testing.expectEqual(reference.claimed_sum, generated.claims[i]);
        for (reference.columns, generated.columns.items[interaction_offset..][0..Runtime.INTERACTION_COLUMN_COUNT]) |expected, actual| {
            try std.testing.expectEqualSlices(core.fields.m31.M31, expected, actual.values);
        }
        interaction_offset += Runtime.INTERACTION_COLUMN_COUNT;
    }
    try std.testing.expectEqual(generated.columns.items.len, interaction_offset);
    // Failed re-admission cannot expose stale buffers/components as a new proof.
    const saved = source.programs[0].multiplicity;
    source.programs[0].multiplicity += 1;
    try std.testing.expectError(error.UntrustedCommitmentPlan, owner.prepareMain(source));
    try std.testing.expectError(error.CommitmentMainNotReady, owner.main());
    try std.testing.expectError(error.CommitmentComponentsNotBound, owner.provers());
    source.programs[0].multiplicity = saved;
    try owner.prepareMain(source);
    try std.testing.expectEqual(storage, (try owner.main())[0].values.ptr);
}
const Compare = struct {
    owner: *columns.Owner,
    at: columns.Counts = @splat(0),
    pub fn append(self: *Compare, comptime Air: type, rows: []const Air.Row) !void {
        const i = columns.indexOf(Air);
        const view = try self.owner.view(Air);
        for (rows) |row| {
            try std.testing.expectEqualDeep(row, view.read(self.at[i], self.owner.logs[i]));
            self.at[i] += 1;
        }
    }
};

const MixedDevice = struct {
    pub fn supportsFrameworkInteractionProgram(_: std.mem.Allocator, _: anytype, counts: []const usize) !bool {
        return counts[1] == components.Airs[0].PHYSICAL_MAIN_COLUMN_COUNT;
    }
    pub fn generateFrameworkInteractionInto(_: std.mem.Allocator, _: anytype, _: []const usize, _: anytype, _: anytype, destination: []const []core.fields.m31.M31) error{ InjectedDeviceFailure, FrameworkInteractionZeroDenominator }!core.fields.qm31.QM31 {
        for (destination) |column| @memset(column, core.fields.m31.M31.zero());
        return core.fields.qm31.QM31.zero();
    }
};
const FailingDevice = struct {
    pub const supportsFrameworkInteractionProgram = MixedDevice.supportsFrameworkInteractionProgram;
    pub fn generateFrameworkInteractionInto(_: std.mem.Allocator, _: anytype, _: []const usize, _: anytype, _: anytype, _: []const []core.fields.m31.M31) error{ InjectedDeviceFailure, FrameworkInteractionZeroDenominator }!core.fields.qm31.QM31 {
        return error.InjectedDeviceFailure;
    }
};
