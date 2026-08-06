const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const core_utils = @import("stwo_core").utils;
const reviewed = @import("typed_air_h009_artifacts");
const compat = @import("typed_poseidon2_compat.zig");
const cut_set = @import("materialization_cut_set.zig");
const executor_mod = @import("typed_poseidon2_layout_executor.zig");
const frontier = @import("materialization_frontier_manifest.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "proposal layout authenticates the first H-009 frontier identity" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator, .{ .frontier = 0 });
    defer executor.deinit();

    const identity = try executor.identity();
    try expectDigest(
        identity.semantic_execution_digest,
        "6fe46c3c4dfc48b9dccc248ae23af8f246a83de3ec03b97274f6b7f90dbb9b88",
    );
    try expectDigest(
        identity.frontier_identity_digest,
        "d85aa12bb4de8b676d88e184558bf2ef047cf286fab2f6b7ee4e3825001faa68",
    );
    try expectDigest(
        identity.cost_model_digest,
        "12670408a3c3020c62d279c997338d9c427d0755697aca2a954f6a1d88a9ba11",
    );
    try expectDigest(
        identity.proposal_digest,
        "009f28b183b765331f19cb21f939aa2c08c58fe0ab5b133476d713e897919ab1",
    );
    try std.testing.expect(!std.mem.allEqual(u8, &identity.layout_digest, 0));

    try std.testing.expectEqualDeep(executor_mod.StorageProfile{
        .main_columns = 445,
        .materializations = 426,
        .semantic_instructions = 2_171,
        .semantic_scratch_elements = 2_171,
        .field_element_bytes = 4,
    }, executor.storageProfile());
    try std.testing.expectEqual(
        executor.materializationOrdinal(1_656),
        harness.firstAddedOrdinal(),
    );
    try std.testing.expect(executor.materializationOrdinal(1_689) == null);

    var second = try harness.makeExecutor(std.testing.allocator, .{ .frontier = 0 });
    defer second.deinit();
    try std.testing.expectEqualDeep(identity, try second.identity());
}

test "proposal rows match typed evaluation and every available production materialization" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    const calls = [_]production.Call{
        production.Call.narrow(0, 0),
        production.Call.narrowWithOutput(11, 22, 0x1234_5678),
        .{
            .input = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            .wide = true,
        },
        .{
            .input = .{ 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
            .io = true,
        },
        .{
            .input = .{std.math.maxInt(u32)} ** poseidon.WIDTH,
            .wide = true,
            .io = true,
        },
    };

    inline for (.{
        executor_mod.ProposalSelection.baseline,
        executor_mod.ProposalSelection{ .frontier = 0 },
    }) |selection| {
        var executor = try harness.makeExecutor(std.testing.allocator, selection);
        defer executor.deinit();
        for (calls) |call| {
            var row = [_]M31{M31.fromCanonical(0x5151)} ** executor_mod.N_MAIN_COLUMNS;
            try executor.fillRow(&row, call);
            const typed = try evaluateArena(
                std.testing.allocator,
                &harness.arena,
                harness.gate,
                harness.definition,
                call.input,
            );
            defer std.testing.allocator.free(typed);
            const produced = production.fill(call);

            try std.testing.expect(row[compat.ENABLER_COLUMN].isOne());
            for (call.input, 0..) |input, lane| try std.testing.expectEqual(
                M31.fromU64(input),
                row[compat.INPUT_START + lane],
            );
            try std.testing.expectEqual(
                M31.fromU64(@intFromBool(call.wide)),
                row[compat.WIDE_COLUMN],
            );
            try std.testing.expectEqual(
                M31.fromU64(@intFromBool(call.io)),
                row[compat.IO_COLUMN],
            );

            var production_matches: usize = 0;
            for (executor.selected_values, 0..) |raw, ordinal| {
                const actual = row[compat.TEMPORARY_START + ordinal];
                try std.testing.expectEqual(typed[raw], actual);
                if (harness.productionOrdinal(raw)) |production_ordinal| {
                    try std.testing.expectEqual(
                        produced[compat.TEMPORARY_START + production_ordinal],
                        actual,
                    );
                    production_matches += 1;
                }
            }
            try std.testing.expectEqual(
                if (selection == .baseline) @as(usize, 426) else 425,
                production_matches,
            );
            try std.testing.expectEqualSlices(
                M31,
                &production.output(produced),
                &(try executor.outputs(&row)),
            );
            try std.testing.expect((try executor.diagnoseRow(call, &row)) == null);
            for (try executor.rootResiduals(call, &row)) |residual| {
                try std.testing.expect(residual.isZero());
            }
        }
    }
}

test "proposal trace uses production placement and zeroes every padding row" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator, .{ .frontier = 0 });
    defer executor.deinit();
    const calls = [_]production.Call{
        production.Call.narrow(1, 2),
        .{ .input = .{3} ** poseidon.WIDTH, .wide = true },
        .{ .input = .{4} ** poseidon.WIDTH, .io = true },
        .{ .input = .{5} ** poseidon.WIDTH, .wide = true, .io = true },
        production.Call.narrowWithOutput(6, 7, 123),
    };
    const sentinel = M31.fromCanonical(0x6262);
    var columns = try OwnedColumns.init(std.testing.allocator, 8, sentinel);
    defer columns.deinit();
    const prepared = try executor.prepareMain(&columns.views, &calls, 3);
    prepared.execute();

    var enabled = [_]bool{false} ** 8;
    for (calls, 0..) |call, logical_row| {
        const committed = committedRow(logical_row, 3);
        enabled[committed] = true;
        var expected: [executor_mod.N_MAIN_COLUMNS]M31 = undefined;
        try executor.fillRow(&expected, call);
        for (columns.views, expected) |column, value| {
            try std.testing.expectEqual(value, column[committed]);
        }
    }
    for (enabled, 0..) |is_enabled, row| {
        if (is_enabled) continue;
        for (columns.views) |column| try std.testing.expect(column[row].isZero());
    }
}

test "proposal execution rejects digest shape and alias failures before mutation" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator, .{ .frontier = 0 });
    defer executor.deinit();
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const calls = [_]production.Call{
        production.Call.narrow(1, 2),
        production.Call.narrow(3, 4),
        production.Call.narrow(5, 6),
        production.Call.narrow(7, 8),
        production.Call.narrow(9, 10),
    };

    executor.cut_digest[0] ^= 1;
    try std.testing.expectError(
        error.CutDigestMismatch,
        executor.generateMainInto(&columns.views, calls[0..1], 2),
    );
    try columns.expectValue(sentinel);
    executor.cut_digest[0] ^= 1;

    executor.proposal_digest[0] ^= 1;
    try std.testing.expectError(
        error.LayoutDigestMismatch,
        executor.generateMainInto(&columns.views, calls[0..1], 2),
    );
    try columns.expectValue(sentinel);
    executor.proposal_digest[0] ^= 1;

    const original_column = columns.views[17];
    columns.views[17] = original_column[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, calls[0..1], 2),
    );
    try columns.expectValue(sentinel);
    columns.views[17] = original_column;
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &calls, 2),
    );
    try columns.expectValue(sentinel);

    const original_second = columns.views[1];
    columns.views[1] = columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, calls[0..1], 2),
    );
    try columns.expectValue(sentinel);
    columns.views[1] = original_second;

    var changed_instruction = false;
    for (executor.semantic.instructions) |*instruction| switch (instruction.*) {
        .add => |binary| {
            const saved = instruction.*;
            instruction.* = .{ .sub = binary };
            try std.testing.expectError(
                error.CorruptExecutor,
                executor.generateMainInto(&columns.views, calls[0..1], 2),
            );
            try columns.expectValue(sentinel);
            instruction.* = saved;
            changed_instruction = true;
            break;
        },
        else => {},
    };
    try std.testing.expect(changed_instruction);
}

test "newly selected materialization has deterministic failure attribution" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator, .{ .frontier = 0 });
    defer executor.deinit();
    const call = production.Call{
        .input = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .wide = true,
    };
    var row: [executor_mod.N_MAIN_COLUMNS]M31 = undefined;
    try executor.fillRow(&row, call);
    const zero_digest = try executor.rootResidualDigest(call, &row);

    const added_ordinal = executor.materializationOrdinal(1_656).?;
    const column = compat.TEMPORARY_START + @as(usize, added_ordinal);
    const original = row[column];
    row[column] = original.add(M31.one());
    const failure = (try executor.diagnoseRow(call, &row)).?;
    try std.testing.expectEqual(@as(u16, @intCast(column)), failure.column);
    switch (failure.role) {
        .materialization => |role| {
            try std.testing.expectEqual(added_ordinal, role.ordinal);
            try std.testing.expectEqual(@as(u32, 1_656), role.value_id);
        },
        else => return error.WrongFailureAttribution,
    }
    try std.testing.expectEqual(original, failure.expected);
    try std.testing.expectEqual(row[column], failure.actual);
    for (try executor.rootResiduals(call, &row)) |residual| {
        try std.testing.expect(residual.isZero());
    }

    row[column] = original;
    const root_ordinal = executor.root_ordinals[0];
    const root_column = compat.TEMPORARY_START + @as(usize, root_ordinal);
    row[root_column] = row[root_column].add(M31.one());
    const residuals = try executor.rootResiduals(call, &row);
    try std.testing.expect(!residuals[0].isZero());
    for (residuals[1..]) |residual| try std.testing.expect(residual.isZero());
    try std.testing.expect(!std.mem.eql(
        u8,
        &zero_digest,
        &(try executor.rootResidualDigest(call, &row)),
    ));
}

test "proposal executor construction releases every partial allocation" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        executorAllocationFailureCase,
        .{&harness},
    );
}

fn executorAllocationFailureCase(
    allocator: std.mem.Allocator,
    harness: *const Harness,
) !void {
    var executor = try harness.makeExecutor(allocator, .{ .frontier = 0 });
    defer executor.deinit();
}

const Harness = struct {
    allocator: std.mem.Allocator,
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,
    plan: materializer.Plan,
    binding: compat.OwnedBinding,
    baseline_cut: cut_set.CutSet,
    first_cut: cut_set.CutSet,
    decoded: frontier.Decoded,

    fn init(allocator: std.mem.Allocator) !Harness {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource("air/components/poseidon2_m31.typed.zig");
        const gate = try arena.input(
            compat.ENABLER_NAME,
            .selector,
            try spanAt(source_id, 1),
        );
        const spans = try distinctSpans(source_id);
        const definition = try poseidon.define(&arena, spans);
        const roots = poseidon.values(definition.outputs);
        var plan = try materializer.plan(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
        });
        errdefer plan.deinit();
        var schedule = try compat.generate(allocator);
        defer schedule.deinit(allocator);
        var binding = try compat.bindPlan(
            allocator,
            &arena,
            definition,
            spans,
            schedule,
            &plan,
        );
        errdefer binding.deinit(allocator);
        var baseline_cut = try cut_set.fromDegree3Plan(allocator, &arena, &plan);
        errdefer baseline_cut.deinit();
        var decoded = try frontier.decodeAlloc(
            allocator,
            reviewed.h009_poseidon2_frontier,
        );
        errdefer decoded.deinit();
        var selected: [compat.N_MATERIALIZATIONS]types.ValueId = undefined;
        for (decoded.frontier[0].selected_values, &selected) |raw, *value| {
            value.* = try types.idFromIndex(types.ValueId, raw);
        }
        const first_cut = try cut_set.build(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
            .policy = plan.policy,
        }, &selected);
        return .{
            .allocator = allocator,
            .arena = arena,
            .gate = gate,
            .spans = spans,
            .definition = definition,
            .plan = plan,
            .binding = binding,
            .baseline_cut = baseline_cut,
            .first_cut = first_cut,
            .decoded = decoded,
        };
    }

    fn deinit(self: *Harness) void {
        self.first_cut.deinit();
        self.baseline_cut.deinit();
        self.binding.deinit(self.allocator);
        self.plan.deinit();
        self.arena.deinit();
        self.decoded.deinit();
        self.* = undefined;
    }

    fn makeExecutor(
        self: *const Harness,
        allocator: std.mem.Allocator,
        selection: executor_mod.ProposalSelection,
    ) !executor_mod.Executor {
        return executor_mod.Executor.init(
            allocator,
            &self.arena,
            self.definition,
            self.spans,
            &self.plan,
            &self.binding,
            switch (selection) {
                .baseline => &self.baseline_cut,
                .frontier => &self.first_cut,
            },
            self.decoded.view(),
            selection,
        );
    }

    fn productionOrdinal(self: *const Harness, raw: u32) ?usize {
        for (self.binding.entries) |entry| {
            if (@intFromEnum(entry.value) == raw) return entry.materialization.ordinal;
        }
        return null;
    }

    fn firstAddedOrdinal(self: *const Harness) ?u16 {
        const raw = self.decoded.frontier[0].provenance.added orelse return null;
        for (self.decoded.frontier[0].selected_values, 0..) |value, ordinal| {
            if (value == raw) return @intCast(ordinal);
        }
        return null;
    }
};

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    views: [executor_mod.N_MAIN_COLUMNS][]M31,

    fn init(
        allocator: std.mem.Allocator,
        len: usize,
        initial: M31,
    ) !OwnedColumns {
        const count = try std.math.mul(usize, executor_mod.N_MAIN_COLUMNS, len);
        const storage = try allocator.alloc(M31, count);
        @memset(storage, initial);
        var views: [executor_mod.N_MAIN_COLUMNS][]M31 = undefined;
        for (&views, 0..) |*view, column| {
            view.* = storage[column * len ..][0..len];
        }
        return .{ .allocator = allocator, .storage = storage, .views = views };
    }

    fn deinit(self: *OwnedColumns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn expectValue(self: *const OwnedColumns, expected: M31) !void {
        for (self.storage) |actual| try std.testing.expectEqual(expected, actual);
    }
};

fn evaluateArena(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    gate: types.ValueId,
    definition: poseidon.Definition,
    input: [poseidon.WIDTH]u32,
) ![]M31 {
    const values = try allocator.alloc(M31, arena.nodeCount());
    errdefer allocator.free(values);
    const inputs = poseidon.values(definition.inputs);
    for (arena.nodesView(), 0..) |node, index| {
        values[index] = switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field => |value| M31.fromCanonical(value),
                .unsigned => |value| M31.fromU64(value),
            },
            .input => blk: {
                const id: types.ValueId = @enumFromInt(index);
                if (id == gate) break :blk M31.one();
                break :blk M31.fromU64(input[
                    inputLane(&inputs, id) orelse
                        return error.UnknownPoseidonInput
                ]);
            },
            .add => |binary| values[types.idIndex(binary.lhs)].add(
                values[types.idIndex(binary.rhs)],
            ),
            .sub => |binary| values[types.idIndex(binary.lhs)].sub(
                values[types.idIndex(binary.rhs)],
            ),
            .mul => |binary| values[types.idIndex(binary.lhs)].mul(
                values[types.idIndex(binary.rhs)],
            ),
            .neg => |operand| values[types.idIndex(operand)].neg(),
            .select => |selection| if (!values[types.idIndex(selection.selector)].isZero())
                values[types.idIndex(selection.when_true)]
            else
                values[types.idIndex(selection.when_false)],
            .hint_output, .call_output => return error.UnsupportedPoseidonExpression,
        };
    }
    return values;
}

fn inputLane(inputs: *const [poseidon.WIDTH]types.ValueId, value: types.ValueId) ?usize {
    for (inputs, 0..) |candidate, lane| if (candidate == value) return lane;
    return null;
}

fn expectDigest(actual: frontier.Digest, expected_hex: *const [64]u8) !void {
    var expected: frontier.Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

fn distinctSpans(source_id: types.SourceId) !poseidon.DefinitionSpans {
    var next_line: u32 = 2;
    const declaration = try spanAt(source_id, next_line);
    next_line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, next_line);
        next_line += 1;
    }
    const initial_linear = try spanAt(source_id, next_line);
    next_line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}

inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}
