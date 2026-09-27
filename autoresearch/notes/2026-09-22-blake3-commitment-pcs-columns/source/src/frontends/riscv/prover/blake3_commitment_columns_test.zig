//! Integration assertions invoked with the shared admitted memory/program fixture.
const std = @import("std");
const core = @import("stwo_core");
const columns = @import("blake3_commitment_columns.zig");
const components = @import("blake3_commitment_components.zig");
const Witness = @import("blake3_commitment_witness.zig").Witness;
const Admission = @import("blake3_commitment_plan.zig").Admission;
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
            const index = @import("../recursion/air/framework_interaction.zig").committedRow(logical, owner.logs[i]);
            for (view.columns) |values| try std.testing.expect(values[index].isZero());
        }
    }
    const Counter = @import("../air/lookups/tables/counter.zig").Counter;
    var counters = [2]Counter{ try Counter.init(a, .bitwise), try Counter.init(a, .range_check_8_8) };
    defer for (&counters) |*counter| counter.deinit(a);
    try owner.registerLookups(&counters);
    var channel = core.channel.blake3.Channel{};
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    var generated = try owner.interactions(a, &relations);
    defer generated.deinit();
    try owner.bind(relations, generated.claims);
    try std.testing.expectEqual(components.Airs.len, (try owner.provers()).len);
    try std.testing.expectEqual(components.Airs.len, (try owner.verifiers()).len);
    const memory_air = @import("../recursion/air/blake3_memory_boundary.zig");
    const i = comptime columns.indexOf(memory_air);
    const view = try owner.view(memory_air);
    const rows = try a.alloc(memory_air.Row, view.count);
    defer a.free(rows);
    for (rows, 0..) |*row, index| row.* = view.read(index, owner.logs[i]);
    const Runtime = @import("../recursion/air/framework_interaction.zig").Runtime(@import("../recursion/air/universal_relation_binding.zig").Binding(memory_air).Runtime);
    var reference = try Runtime.generatePreparedWithPadding(a, &owner.plans[i], rows, owner.logs[i], &relations, @as(memory_air.Row, @splat(core.fields.m31.M31.zero())));
    defer reference.deinit(a);
    try std.testing.expectEqual(reference.claimed_sum, generated.claims[i]);
    try std.testing.expectEqualSlices(core.fields.m31.M31, reference.storage, generated.storage[i]);
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
