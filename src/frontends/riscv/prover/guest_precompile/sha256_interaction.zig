//! Owned SHA interaction columns for the joined native Ethereum leaf.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const profile = @import("../../air/guest_precompile/sha256_component_profile.zig");
const universal = @import("../../recursion/air/universal_challenges.zig");
const binding = @import("../../recursion/air/universal_relation_binding.zig");
const framework = @import("../../recursion/air/framework_interaction.zig");
pub const Generated = struct {
    columns: []engine.pcs.ColumnEvaluation,
    claims: [profile.Airs.len]core.fields.qm31.QM31,
    storage: [profile.Airs.len][]core.fields.m31.M31,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        for (self.storage) |block| a.free(block);
        a.free(self.columns);
        self.* = undefined;
    }
    pub fn total(self: *const Generated) core.fields.qm31.QM31 {
        var sum = core.fields.qm31.QM31.zero();
        for (self.claims) |claim| sum = sum.add(claim);
        return sum;
    }
};
pub fn generate(a: std.mem.Allocator, rows: anytype, relations: *const universal.UniversalRelations) !Generated {
    const Airs = profile.AirsForRecipe(@TypeOf(rows.*).local_zero_custody);
    const column_count = comptime blk: {
        var count: usize = 0;
        for (Airs) |Air| count += Air.INTERACTION_COLUMN_COUNT;
        break :blk count;
    };
    const columns = try a.alloc(engine.pcs.ColumnEvaluation, column_count);
    var written: usize = 0;
    var built: usize = 0;
    var storage: [profile.Airs.len][]core.fields.m31.M31 = undefined;
    errdefer {
        for (storage[0..built]) |block| a.free(block);
        a.free(columns);
    }
    var claims: [profile.Airs.len]core.fields.qm31.QM31 = undefined;
    const tuple = rows.tuple();
    inline for (Airs, 0..) |Air, i| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const plan = try binding.Binding(Air).authenticate(&definition);
        const generated = try framework.Runtime(binding.Binding(Air).Runtime).generatePrepared(a, &plan, tuple[i], rows.geometry.logs[i], relations);
        claims[i] = generated.claimed_sum;
        storage[i] = generated.storage;
        built += 1;
        for (generated.columns) |values| {
            columns[written] = .{ .log_size = rows.geometry.logs[i], .values = values };
            written += 1;
        }
    }
    return .{ .columns = columns, .claims = claims, .storage = storage };
}

fn allocationCase(a: std.mem.Allocator) !void {
    var rows = try @import("../../air/guest_precompile/sha256_memory_rows.zig").prepare(a, &.{}, 0);
    defer rows.deinit();
    var channel = core.proof_suites.Blake3.Channel{};
    const vm = try universal.UniversalRelations.draw(a, &channel);
    const relations = try @import("../../air/guest_precompile/sha256_relations.zig").draw(a, &channel, vm);
    var generated = try generate(a, &rows, &relations);
    defer generated.deinit(a);
}

test "SHA combined interaction ownership releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
