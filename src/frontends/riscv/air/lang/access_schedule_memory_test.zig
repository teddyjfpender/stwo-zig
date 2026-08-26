const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const production_clock = @import("../../access_clock.zig");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const manifest = @import("manifest.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "fixed memory plans preserve exact streams and prepared physical order" {
    for ([_]effects.AccessPlanKind{ .load, .store }) |kind| {
        var fixture = try Fixture.init(std.testing.allocator, .{ .kind = kind });
        defer fixture.deinit();
        try std.testing.expectEqual(@as(usize, 10), fixture.arena.effectsView().len);
        try std.testing.expectEqual(@as(usize, 46), fixture.arena.effectValuesView().len);
        try std.testing.expectEqual(@as(usize, 0), fixture.arena.constraintsView().len);
        try std.testing.expectEqual(@as(usize, 11), fixture.nodes_after_plan - fixture.nodes_before_plan);
        try std.testing.expectEqual(kind, fixture.plan.kind);
        try std.testing.expectEqual(@as(usize, 3), types.idIndex(fixture.plan.aligned_range));
        try std.testing.expect(fixture.arena.effectsView()[3].access_ordinal == null);

        const starts = [3]usize{ 0, 4, 7 };
        const phases: [3]types.AccessPhase = switch (kind) {
            .load => .{ .first, .third, .second },
            .store => .{ .first, .second, .third },
        };
        for (fixture.plan.groups, starts, phases, 0..) |group, start, phase, index| {
            try std.testing.expectEqual(start, types.idIndex(group.consume));
            try std.testing.expectEqual(@as(u8, @intCast(index + 1)), @intFromEnum(group.ordinal));
            try std.testing.expectEqual(phase, group.phase);
        }
        const prepared = try effects.prepareAccessPlan(&fixture.arena);
        const phase_starts: [3]usize = switch (kind) {
            .load => .{ 0, 7, 4 },
            .store => starts,
        };
        for ([_]types.AccessPhase{ .first, .second, .third }, phase_starts) |phase, start|
            try std.testing.expectEqual(start, types.idIndex(prepared.groupAtPhase(phase).first_effect));
    }
}

test "aligned address and load/store clocks replay at uint20 boundaries" {
    for ([_]effects.AccessPlanKind{ .load, .store }) |kind| {
        var fixture = try Fixture.init(std.testing.allocator, .{ .kind = kind });
        defer fixture.deinit();
        const values = try std.testing.allocator.alloc(M31, fixture.arena.nodeCount());
        defer std.testing.allocator.free(values);
        for ([_]u32{ 0, 1, (1 << 20) - 1 }) |word_index| {
            @memset(values, M31.zero());
            values[types.idIndex(fixture.clock)] = M31.fromU64(257);
            values[types.idIndex(fixture.active)] = M31.one();
            values[types.idIndex(fixture.word_index)] = M31.fromU64(word_index);
            for (fixture.previous_clocks, [_]u32{ 3, 7, 11 }) |id, previous|
                values[types.idIndex(id)] = M31.fromU64(previous);
            try replayMachineNodes(&fixture.arena, values);
            try std.testing.expectEqual(
                M31.fromU64(word_index).mul(M31.fromCanonical(4)),
                values[types.idIndex(fixture.plan.aligned_address)],
            );
            for (fixture.plan.groups, 0..) |group, ordinal_index| {
                const current = fixture.values(types.idIndex(group.emit))[2];
                const ordinal: production_clock.Ordinal = switch (group.phase) {
                    .first => .first,
                    .second => .second,
                    .third => .third,
                };
                const expected = production_clock.encode(257, ordinal);
                try std.testing.expectEqual(expected, values[types.idIndex(current)].toU32());
                const gap = fixture.values(types.idIndex(group.clock_gap))[0];
                const expected_gap = M31.fromU64(expected)
                    .sub(M31.fromU64(([_]u32{ 3, 7, 11 })[ordinal_index])).sub(M31.one());
                try std.testing.expectEqual(expected_gap, values[types.idIndex(gap)]);
            }
        }
        try std.testing.expectError(
            error.ConstantOutOfRange,
            fixture.arena.constantUnsigned(.uint20, 1 << 20, source.SourceSpan.generated()),
        );
    }
}

test "memory plans compose with independent ranges before and after" {
    for ([_]RangePlacement{ .before, .after, .both }) |placement| {
        var fixture = try Fixture.init(std.testing.allocator, .{ .ranges = placement });
        defer fixture.deinit();
        const prepared = try effects.prepareAccessPlan(&fixture.arena);
        try std.testing.expectEqual(fixture.plan.aligned_range, prepared.aligned_range);
        try std.testing.expectEqual(
            fixture.plan_effect_start + 3,
            types.idIndex(prepared.aligned_range),
        );
        try std.testing.expectEqual(@as(usize, 10) + placement.count(), fixture.arena.effectsView().len);
    }
}

test "dynamic register aliases retain distinct relation and physical orders" {
    var fixture = try Fixture.init(std.testing.allocator, .{ .alias_registers = true });
    defer fixture.deinit();
    const prepared = try effects.prepareAccessPlan(&fixture.arena);
    try std.testing.expectEqual(
        prepared.groups_by_ordinal[0].address,
        prepared.groups_by_ordinal[2].address,
    );
    try std.testing.expectEqual(
        types.AccessOrdinal.third,
        prepared.groupAtPhase(.second).ordinal,
    );
    try std.testing.expectEqual(
        types.AccessOrdinal.second,
        prepared.groupAtPhase(.third).ordinal,
    );
}

test "whole-program validation rejects malformed memory plans" {
    const Mutation = enum {
        ordinal_hole,
        address_space,
        raw_unaligned_address,
        range_liveness,
        range_binding,
        range_word,
        missing_range,
        load_read_limb,
        store_read_limb,
        mixed_signature,
        incomplete_signature,
        orphan_address,
    };
    inline for (std.meta.tags(Mutation)) |mutation| {
        const kind: effects.AccessPlanKind = if (mutation == .store_read_limb) .store else .load;
        var fixture = try Fixture.init(std.testing.allocator, .{ .kind = kind });
        defer fixture.deinit();
        const start = fixture.plan_effect_start;
        const range_index = start + 3;
        switch (mutation) {
            .ordinal_hole => for (fixture.arena.effects.items[start + 4 .. start + 7]) |*effect| {
                effect.access_ordinal = 3;
            },
            .address_space => for (fixture.arena.effects.items[start + 4 .. start + 6]) |effect| {
                fixture.arena.effect_values.items[effect.values.start] = fixture.values(start)[0];
            },
            .raw_unaligned_address => {
                const forged = try fixture.arena.constantUnsigned(.address, 2, source.SourceSpan.generated());
                for (fixture.arena.effects.items[start + 4 .. start + 6]) |effect|
                    fixture.arena.effect_values.items[@as(usize, effect.values.start) + 1] = forged;
            },
            .range_liveness => fixture.arena.effects.items[range_index].liveness =
                try fixture.arena.input("other_active", .bit, source.SourceSpan.generated()),
            .range_binding => fixture.arena.effects.items[range_index].binding.?.role = .consume,
            .range_word => fixture.arena.effect_values.items[fixture.arena.effects.items[range_index].values.start] =
                try fixture.arena.constantUnsigned(.uint20, 1, source.SourceSpan.generated()),
            .missing_range => fixture.arena.effects.items[range_index].kind = .public_consume,
            .load_read_limb => fixture.setEmitByte(start + 4, fixture.next_value[0]),
            .store_read_limb => fixture.setEmitByte(start + 4, fixture.next_value[0]),
            .mixed_signature => for (fixture.arena.effects.items[start + 7 .. start + 10]) |*effect| {
                effect.kind = .memory_write;
            },
            .incomplete_signature => fixture.arena.effects.items[start + 8].kind = .public_produce,
            .orphan_address => {
                const other_word = try fixture.arena.input("orphan_word", .uint20, source.SourceSpan.generated());
                _ = try fixture.arena.alignedWordAddress(other_word, source.SourceSpan.generated());
            },
        }
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
    }
}

test "every noncanonical load phase permutation rejects" {
    const permutations = [_][3]types.AccessPhase{
        .{ .first, .second, .third },
        .{ .second, .first, .third },
        .{ .second, .third, .first },
        .{ .third, .first, .second },
        .{ .third, .second, .first },
    };
    for (permutations) |permutation| {
        var fixture = try Fixture.init(std.testing.allocator, .{});
        defer fixture.deinit();
        const currents = [3]types.ValueId{
            fixture.currentAtPhase(.first),
            fixture.currentAtPhase(.second),
            fixture.currentAtPhase(.third),
        };
        for (fixture.plan.groups, permutation, 0..) |group, phase, index| {
            const current = currents[@intFromEnum(phase) - 1];
            const gap = try fixture.arena.strictClockGap(
                current,
                fixture.previous_clocks[index],
                fixture.active,
                phase,
                source.SourceSpan.generated(),
            );
            fixture.setValue(types.idIndex(group.emit), 2, current);
            fixture.setValue(types.idIndex(group.clock_gap), 0, gap);
        }
        try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
        try std.testing.expectError(error.InvalidEffect, digest.computeV4(&fixture.arena));
    }
}

test "memory identity v4 is stable under exact node reuse history" {
    var load = try Fixture.init(std.testing.allocator, .{});
    defer load.deinit();
    var reused = try Fixture.init(std.testing.allocator, .{ .preintern_plan_nodes = true });
    defer reused.deinit();
    var store = try Fixture.init(std.testing.allocator, .{ .kind = .store });
    defer store.deinit();
    try std.testing.expectError(
        error.MemoryAccessRequiresManifestV6,
        manifest.serializeAllocV5(std.testing.allocator, &load.arena),
    );
    try std.testing.expectError(error.InvalidEffect, digest.computeV3(&load.arena));
    const encoded = try manifest.serializeAllocV6(std.testing.allocator, &load.arena);
    defer std.testing.allocator.free(encoded);
    const reused_encoded = try manifest.serializeAllocV6(std.testing.allocator, &reused.arena);
    defer std.testing.allocator.free(reused_encoded);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &load.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, encoded, reused_encoded);
    try std.testing.expectEqualSlices(u8, encoded, current);
    try std.testing.expectEqual(manifest.memory_access_format_version, std.mem.readInt(u16, encoded[8..10], .little));
    try std.testing.expectEqual(manifest.memory_access_logical_schema_version, std.mem.readInt(u16, encoded[10..12], .little));
    const semantic = try digest.computeV4(&load.arena);
    try std.testing.expectEqual(semantic, try digest.computeV4(&reused.arena));
    try std.testing.expect(!std.mem.eql(u8, &semantic, &(try digest.computeV4(&store.arena))));
    const identity = try digest.computeIdentity(&load.arena);
    try std.testing.expectEqual(digest.memory_access_format_version, identity.format_version);
    try std.testing.expectEqual(semantic, identity.bytes);

    var manifest_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &manifest_hash, .{});
    const rendered_digest = std.fmt.bytesToHex(semantic, .lower);
    const rendered_manifest = std.fmt.bytesToHex(manifest_hash, .lower);
    try std.testing.expectEqualStrings(
        "eda46ee7401b3b3582e74e1f084b163e331967e57f60495fc4e3b6f25d0e4702",
        &rendered_digest,
    );
    try std.testing.expectEqual(@as(usize, 887), encoded.len);
    try std.testing.expectEqualStrings(
        "fd5768d860cc1acabefae829d30eb729b63dcd5cd315d9d65560624fd6c0d2fa",
        &rendered_manifest,
    );
}

test "fixed memory plan rollback is exact under every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "prepared memory plan validation allocates zero bytes" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var fixture = try Fixture.init(failing.allocator(), .{});
        defer fixture.deinit();
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        const allocated = failing.allocated_bytes;
        _ = try effects.prepareAccessPlan(&fixture.arena);
        try std.testing.expectEqual(allocated, failing.allocated_bytes);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

const RangePlacement = enum {
    none,
    before,
    after,
    both,

    fn count(self: RangePlacement) usize {
        return switch (self) {
            .none => 0,
            .before, .after => 1,
            .both => 2,
        };
    }
};

const Config = struct {
    kind: effects.AccessPlanKind = .load,
    alias_registers: bool = false,
    preintern_plan_nodes: bool = false,
    ranges: RangePlacement = .none,
};

const Fixture = struct {
    arena: ir.Arena,
    clock: types.ValueId,
    active: types.ValueId,
    word_index: types.ValueId,
    previous_clocks: [3]types.ValueId,
    next_value: [4]types.ValueId,
    plan: effects.LoadStoreAccessPlan,
    plan_effect_start: usize,
    nodes_before_plan: usize,
    nodes_after_plan: usize,

    fn init(allocator: std.mem.Allocator, config: Config) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = source.SourceSpan.generated();
        const clock = try arena.input("memory_clock", .clock, span);
        const active = try arena.input("memory_active", .bit, span);
        const rs1_index = try arena.input("memory_rs1", .register_index, span);
        const other_index = if (config.alias_registers)
            rs1_index
        else
            try arena.input("memory_other_register", .register_index, span);
        const word_index = try arena.input("memory_word", .uint20, span);
        const previous_clocks = [3]types.ValueId{
            try arena.input("memory_clock_before_1", .clock, span),
            try arena.input("memory_clock_before_2", .clock, span),
            try arena.input("memory_clock_before_3", .clock, span),
        };
        const previous_value = try byteInputs(&arena, "memory_previous", span);
        const next_value = try byteInputs(&arena, "memory_next", span);
        if (config.preintern_plan_nodes) {
            _ = try arena.constantField(0, span);
            _ = try arena.constantField(1, span);
            _ = try arena.alignedWordAddress(word_index, span);
            _ = try arena.registerAddress(rs1_index, span);
            _ = try arena.registerAddress(other_index, span);
        }
        if (config.ranges == .before or config.ranges == .both)
            _ = try appendRange(&arena, active, 17, span);
        const plan_effect_start = arena.effectsView().len;
        const nodes_before_plan = arena.nodeCount();
        var schedule = try effects.AccessSchedule.begin(&arena, clock, active, span);
        const rs1 = effects.RegisterReadInput{
            .index = rs1_index,
            .previous_clock = previous_clocks[0],
            .value = previous_value,
        };
        const plan = switch (config.kind) {
            .load => try schedule.load(.{
                .rs1 = rs1,
                .src = .{
                    .word_index = word_index,
                    .previous_clock = previous_clocks[1],
                    .value = previous_value,
                },
                .dst = .{
                    .index = other_index,
                    .previous_clock = previous_clocks[2],
                    .previous = previous_value,
                    .next = next_value,
                },
            }, span),
            .store => try schedule.store(.{
                .rs1 = rs1,
                .src = .{
                    .index = other_index,
                    .previous_clock = previous_clocks[1],
                    .value = previous_value,
                },
                .dst = .{
                    .word_index = word_index,
                    .previous_clock = previous_clocks[2],
                    .previous = previous_value,
                    .next = next_value,
                },
            }, span),
        };
        const nodes_after_plan = arena.nodeCount();
        if (config.ranges == .after or config.ranges == .both)
            _ = try appendRange(&arena, active, 23, span);
        try validate.validate(&arena);
        return .{
            .arena = arena,
            .clock = clock,
            .active = active,
            .word_index = word_index,
            .previous_clocks = previous_clocks,
            .next_value = next_value,
            .plan = plan,
            .plan_effect_start = plan_effect_start,
            .nodes_before_plan = nodes_before_plan,
            .nodes_after_plan = nodes_after_plan,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn values(self: *const Fixture, effect_index: usize) []const types.ValueId {
        return self.arena.effectValues(types.idFromIndex(types.EffectId, effect_index) catch unreachable).?;
    }

    fn setValue(self: *Fixture, effect_index: usize, field_index: usize, value: types.ValueId) void {
        const range = self.arena.effects.items[effect_index].values;
        self.arena.effect_values.items[@as(usize, range.start) + field_index] = value;
    }

    fn setEmitByte(self: *Fixture, group_start: usize, value: types.ValueId) void {
        self.setValue(group_start + 1, 3, value);
    }

    fn currentAtPhase(self: *const Fixture, phase: types.AccessPhase) types.ValueId {
        for (self.plan.groups) |group| if (group.phase == phase)
            return self.values(types.idIndex(group.emit))[2];
        unreachable;
    }
};

fn appendRange(
    arena: *ir.Arena,
    active: types.ValueId,
    value: u32,
    span: source.SourceSpan,
) !types.EffectId {
    const schema = relation.get(.range_check_20);
    const range_value = try arena.constantUnsigned(.uint20, value, span);
    const values = [_]types.ValueId{range_value};
    return arena.addBoundEffectUnchecked(.range_request, .{
        .schema = schema.id,
        .schema_version = schema.version,
        .role = .request,
    }, &values, active, null, span);
}

fn byteInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var result: [4]types.ValueId = undefined;
    inline for (&result, 0..) |*value, index|
        value.* = try arena.input(
            std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
            .byte,
            span,
        );
    return result;
}

fn replayMachineNodes(arena: *const ir.Arena, values: []M31) !void {
    if (values.len != arena.nodeCount()) return error.InvalidReplayBuffer;
    for (arena.nodesView(), 0..) |node, index| values[index] = switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field, .unsigned => |value| M31.fromU64(value),
        },
        .input => values[index],
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| values[types.idIndex(address.index)],
            .aligned_word_address => |address| values[types.idIndex(address.word_index)]
                .mul(M31.fromCanonical(4)),
            .access_clock => |clock| values[types.idIndex(clock.instruction_clock)]
                .sub(M31.one()).mul(M31.fromCanonical(4))
                .add(M31.fromCanonical(@intFromEnum(clock.phase))),
            .strict_clock_gap => |gap| values[types.idIndex(gap.current_clock)]
                .sub(values[types.idIndex(gap.previous_clock)]).sub(M31.one()),
            .instruction_next_pc => |next| values[types.idIndex(next.current)]
                .add(M31.fromCanonical(4)),
            .instruction_next_clock => |next| values[types.idIndex(next.current)]
                .add(M31.one()),
        },
        else => return error.UnsupportedReplayNode,
    };
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const clock = try arena.input("clock", .clock, span);
    const active = try arena.input("active", .bit, span);
    const rs1 = try arena.input("rs1", .register_index, span);
    const rd = try arena.input("rd", .register_index, span);
    const word = try arena.input("word", .uint20, span);
    const previous_clocks = [3]types.ValueId{
        try arena.input("previous_1", .clock, span),
        try arena.input("previous_2", .clock, span),
        try arena.input("previous_3", .clock, span),
    };
    const previous = try byteInputs(&arena, "previous_value", span);
    const next = try byteInputs(&arena, "next_value", span);
    const pc = try arena.input("pc", .pc, span);
    const felt = try arena.input("felt", .felt, span);
    _ = try effects.programFetch(&arena, .{
        .pc = pc,
        .opcode_id = felt,
        .rd = felt,
        .rs1 = felt,
        .operand = felt,
    }, active, span);
    var schedule = try effects.AccessSchedule.begin(&arena, clock, active, span);
    const nodes_before = arena.nodeCount();
    const effect_before = arena.effects.items[0];
    const values_before = arena.effect_values.items[0..5].*;
    _ = schedule.load(.{
        .rs1 = .{ .index = rs1, .previous_clock = previous_clocks[0], .value = previous },
        .src = .{ .word_index = word, .previous_clock = previous_clocks[1], .value = previous },
        .dst = .{
            .index = rd,
            .previous_clock = previous_clocks[2],
            .previous = previous,
            .next = next,
        },
    }, span) catch |err| {
        try std.testing.expectEqual(nodes_before, arena.nodeCount());
        try std.testing.expectEqual(@as(usize, 1), arena.effectsView().len);
        try std.testing.expectEqual(@as(usize, 5), arena.effectValuesView().len);
        try std.testing.expectEqual(effect_before, arena.effects.items[0]);
        try std.testing.expectEqualSlices(types.ValueId, &values_before, arena.effect_values.items);
        try std.testing.expectEqual(@as(u8, 1), schedule.next_ordinal);
        try validate.validate(&arena);
        return err;
    };
    try std.testing.expectEqual(@as(usize, 11), arena.nodeCount() - nodes_before);
    try validate.validate(&arena);
}
