//! Versioned direct row35 range table with row41 arithmetic requests.
//!
//! The original SegmentV2 table remains untouched. This writer snapshots its
//! native 2^16 counter, subtracts exactly the authenticated row41 request
//! entries, then uses the existing native table AIR for committed columns.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const arithmetic = @import("air/ethereum_leaf_link_arithmetic_v1.zig");
const bridge = @import("air/range_check_8_8_bridge.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const relation = @import("../air/lang/relation.zig");
const shared = @import("air/universal_provider_relations.zig");
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const framework = @import("air/framework_interaction.zig");
const DomainAudit = @import("air/relation_interaction.zig").DomainAudit;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW: usize = 35;

pub const Provider = struct {
    allocator: std.mem.Allocator,
    batch: bridge.PreparedBatch,
    appended_requests: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        base: *const bridge.PreparedBatch,
        rows: *const [16]arithmetic.Row,
    ) !Provider {
        try base.validate();
        var definition = try arithmetic.build(allocator);
        defer definition.deinit();
        const authenticated = try arithmetic.authenticate(&definition);
        const values = try allocator.dupe(M31, base.counter.values);
        defer allocator.free(values);
        var count: u32 = 0;
        for (rows, 0..) |row, index| {
            if (index < 4 and !row[arithmetic.ACTIVE].isOne())
                return error.InvalidDirectRangeSource;
            if (index >= 4) for (row) |value| {
                if (!value.isZero()) return error.InvalidDirectRangeSource;
            };
            for (authenticated.preparedEntries(row)) |entry| {
                if (entry.domain != .range_check_8_8) continue;
                if (entry.role != .request or entry.arity != 2)
                    return error.InvalidDirectRangeSource;
                if (entry.numerator.isZero()) continue;
                if (!entry.numerator.eql(QM31.one().neg()))
                    return error.InvalidDirectRangeSource;
                const low = try canonicalByte(entry.values[0]);
                const high = try canonicalByte(entry.values[1]);
                const at = @as(usize, low) | (@as(usize, high) << 8);
                values[at] = values[at].sub(M31.one());
                count = try std.math.add(u32, count, 1);
            }
        }
        if (count == 0) return error.InvalidDirectRangeSource;
        const counter = counter_mod.Counter{ .kind = bridge.TABLE_KIND, .values = values };
        const batch = try bridge.PreparedBatch.init(allocator, &counter);
        return .{ .allocator = allocator, .batch = batch, .appended_requests = count };
    }

    pub fn deinit(self: *Provider) void {
        self.batch.deinit();
        self.* = undefined;
    }

    pub fn fillMain(self: *const Provider, plan: *const plan_mod.Plan, destination: [][]M31) !void {
        try plan.validate();
        const placement = plan.placements[ROW].?;
        if (placement.geometry.log_size != bridge.LOG_SIZE or
            placement.geometry.main_columns != bridge.PHYSICAL_MAIN_COLUMN_COUNT or
            placement.main_offset >= destination.len)
            return error.DirectRangeGeometryMismatch;
        var columns = [bridge.PHYSICAL_MAIN_COLUMN_COUNT][]M31{destination[placement.main_offset]};
        var definition = try bridge.build(self.allocator);
        defer definition.deinit();
        const binding = try bridge.Binding.canonical(&definition);
        const executor = try bridge.Executor.init(&definition, &binding);
        try executor.generateMainInto(&self.batch, &columns);
    }

    pub fn fillInteraction(
        self: *const Provider,
        plan: *const plan_mod.Plan,
        provider_relations: *const shared.SharedProviderRelations,
        destination: [][]M31,
    ) !ClaimAudit {
        try plan.validate();
        try provider_relations.validate();
        const placement = plan.placements[ROW].?;
        if (placement.geometry.log_size != bridge.LOG_SIZE or
            placement.geometry.interaction_columns != bridge.INTERACTION_COLUMN_COUNT or
            placement.interaction_offset > destination.len or
            bridge.INTERACTION_COLUMN_COUNT > destination.len - placement.interaction_offset)
            return error.DirectRangeGeometryMismatch;
        var generated = try self.batch.generateNativeInteraction(self.allocator, &provider_relations.native);
        defer generated.deinit(self.allocator);
        const size = @as(usize, 1) << bridge.LOG_SIZE;
        for (generated.columns, destination[placement.interaction_offset..][0..bridge.INTERACTION_COLUMN_COUNT]) |source, target| {
            if (source.len != size or target.len != size)
                return error.DirectRangeGeometryMismatch;
            for (target) |value| if (!value.isZero())
                return error.DirectRangeDestinationNotFresh;
        }
        for (generated.columns, destination[placement.interaction_offset..][0..bridge.INTERACTION_COLUMN_COUNT]) |source, target|
            @memcpy(target, source);
        var audit = DomainAudit{
            .values = @splat(QM31.zero()),
            .total = generated.claim,
            .logical_rows = size,
            .event_terms = size,
        };
        audit.values[@intFromEnum(relation.Domain.range_check_8_8)] = generated.claim;
        return .{ .claim = generated.claim, .audit = audit };
    }
};

pub const ClaimAudit = struct { claim: QM31, audit: DomainAudit };

fn canonicalByte(value: QM31) !u8 {
    const limbs = value.toM31Array();
    if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero() or
        limbs[0].toU32() > 255)
        return error.InvalidDirectRangeSource;
    return @intCast(limbs[0].toU32());
}

test "direct row35 adds only authenticated arithmetic byte requests" {
    const allocator = std.testing.allocator;
    var counter = try counter_mod.Counter.init(allocator, bridge.TABLE_KIND);
    defer counter.deinit(allocator);
    var base = try bridge.PreparedBatch.init(allocator, &counter);
    defer base.deinit();
    const logical = @import("air/ethereum_leaf_link_arithmetic_witness_v1.zig");
    var rows = [_]arithmetic.Row{[_]M31{M31.zero()} ** arithmetic.LOGICAL_INPUT_COUNT} ** 16;
    rows[0] = try logical.logicalRow(.entry_root, 7, false, 0, 0);
    rows[1] = try logical.logicalRow(.exit_root, 9, false, 0, 0);
    rows[2] = try logical.logicalRow(.completion, 0, true, 0, 0);
    rows[3] = try logical.logicalRow(.position, 0, false, 100, 11);
    var direct = try Provider.init(allocator, &base, &rows);
    defer direct.deinit();
    try std.testing.expect(direct.appended_requests > 0);
    try std.testing.expectEqual(@as(u32, 0), base.counter.values[7].toU32());
    try std.testing.expect(!direct.batch.counter.values[7].isZero());
    rows[4][arithmetic.ACTIVE] = M31.one();
    try std.testing.expectError(error.InvalidDirectRangeSource, Provider.init(allocator, &base, &rows));
}
