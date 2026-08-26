const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const compat = @import("typed_poseidon2_compat.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const witness = @import("typed_poseidon2_witness.zig");

test "typed Poseidon2 witness writes exact production rows in every mode" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
    defer executor.deinit();

    try std.testing.expectEqual(@as(usize, 2_171), executor.instructionCount());
    try std.testing.expect(executor.instructionCount() < harness.fixture.arena.nodeCount());
    const calls = [_]production.Call{
        production.Call.narrow(0, 0),
        production.Call.narrow(1, 2),
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

    for (calls) |call| {
        var actual = try OwnedColumns.init(std.testing.allocator, 1, M31.fromCanonical(19));
        defer actual.deinit();
        try executor.generateMainInto(&actual.views, &.{call}, 0);
        const expected = production.fill(call);
        for (actual.views, expected) |column, value| {
            try std.testing.expectEqual(value, column[0]);
        }
    }
}

test "typed Poseidon2 witness is byte-exact for randomized traces and zero padding" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
    defer executor.deinit();

    var prng = std.Random.DefaultPrng.init(0x4830_3035_2d726f77);
    const random = prng.random();
    const log_sizes = [_]u32{ 0, 1, 2, 4, 6 };
    var call_storage: [64]production.Call = undefined;
    for (log_sizes) |log_size| {
        const size = @as(usize, 1) << @intCast(log_size);
        const call_count = if (size == 1) 1 else size - size / 4;
        for (call_storage[0..call_count], 0..) |*call, row| {
            var input: [poseidon.WIDTH]u32 = undefined;
            for (&input) |*value| value.* = random.int(u32);
            call.* = .{
                .input = input,
                .wide = row % 5 == 1 or row % 17 == 0,
                .io = row % 5 == 2 or row % 19 == 0,
                .narrow_output = if (row % 3 == 0) random.int(u32) else null,
            };
        }
        const calls = call_storage[0..call_count];
        var actual = try OwnedColumns.init(
            std.testing.allocator,
            size,
            M31.fromCanonical(0x5151),
        );
        defer actual.deinit();
        var expected = try OwnedColumns.init(
            std.testing.allocator,
            size,
            M31.fromCanonical(0x6262),
        );
        defer expected.deinit();

        try executor.generateMainInto(&actual.views, calls, log_size);
        try production.generateMainInto(
            std.testing.allocator,
            &expected.views,
            calls,
            log_size,
        );
        for (actual.views, expected.views) |actual_column, expected_column| {
            try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected_column), std.mem.sliceAsBytes(actual_column));
        }
        var enabled: usize = 0;
        for (actual.views[compat.ENABLER_COLUMN]) |value| {
            if (value.isOne()) enabled += 1 else try std.testing.expect(value.isZero());
        }
        try std.testing.expectEqual(call_count, enabled);
    }
}

test "typed Poseidon2 witness rejects shape and aliases before mutation" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
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

    const original_column = columns.views[17];
    columns.views[17] = original_column[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, calls[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[17] = original_column;

    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &calls, 2),
    );
    try columns.expectStorageValue(sentinel);
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, calls[0..1], @bitSizeOf(usize) - 1),
    );
    try columns.expectStorageValue(sentinel);

    const original_second = columns.views[1];
    columns.views[1] = columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, calls[0..1], 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[1] = original_second;
}

test "typed Poseidon2 witness rejects call-storage alias before mutation" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
    defer executor.deinit();

    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try OwnedColumns.init(std.testing.allocator, 32, sentinel);
    defer columns.deinit();
    const overlapping_calls: []const production.Call =
        @as([*]const production.Call, @ptrCast(columns.storage[0].ptr))[0..1];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&columns.views, overlapping_calls, 5),
    );
    try columns.expectStorageValue(sentinel);

    const descriptor_calls: []const production.Call =
        @as([*]const production.Call, @ptrCast(&columns.views))[0..1];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&columns.views, descriptor_calls, 5),
    );
    try columns.expectStorageValue(sentinel);

    const executor_calls: []const production.Call =
        @as([*]const production.Call, @ptrCast(&executor))[0..1];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&columns.views, executor_calls, 5),
    );
    try columns.expectStorageValue(sentinel);

    const instruction_calls: []const production.Call =
        @as([*]const production.Call, @ptrCast(executor.instructions.ptr))[0..1];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&columns.views, instruction_calls, 5),
    );
    try columns.expectStorageValue(sentinel);

    const scratch_calls: []const production.Call =
        @as([*]const production.Call, @ptrCast(executor.scratch.ptr))[0..1];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&columns.views, scratch_calls, 5),
    );
    try columns.expectStorageValue(sentinel);
}

test "typed Poseidon2 witness preserves guards while writing padded final storage" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
    defer executor.deinit();

    const guard = M31.fromCanonical(0x3c3c);
    const interior = M31.fromCanonical(0x4d4d);
    var guarded: [compat.N_MAIN_COLUMNS][6]M31 = undefined;
    var columns: [compat.N_MAIN_COLUMNS][]M31 = undefined;
    for (&guarded, &columns) |*storage, *column| {
        @memset(storage, guard);
        @memset(storage[1..5], interior);
        column.* = storage[1..5];
    }
    const calls = [_]production.Call{
        production.Call.narrow(11, 22),
        .{ .input = .{7} ** poseidon.WIDTH, .wide = true },
        .{ .input = .{9} ** poseidon.WIDTH, .io = true },
    };
    try executor.generateMainInto(&columns, &calls, 2);

    var expected = try OwnedColumns.init(std.testing.allocator, 4, interior);
    defer expected.deinit();
    try production.generateMainInto(
        std.testing.allocator,
        &expected.views,
        &calls,
        2,
    );
    for (guarded, columns, expected.views) |storage, actual, expected_column| {
        try std.testing.expectEqual(guard, storage[0]);
        try std.testing.expectEqual(guard, storage[5]);
        try std.testing.expectEqualSlices(M31, expected_column, actual);
    }
}

test "typed Poseidon2 witness reauthenticates exact owned identity" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
    defer executor.deinit();

    try executor.reauthenticate(
        std.testing.allocator,
        &harness.fixture.arena,
        harness.fixture.definition,
        harness.fixture.spans,
        &harness.plan,
        &harness.binding,
    );
    const saved = harness.binding.entries[0].value;
    harness.binding.entries[0].value = harness.binding.entries[1].value;
    try std.testing.expectError(
        error.PlanBindingMismatch,
        executor.reauthenticate(
            std.testing.allocator,
            &harness.fixture.arena,
            harness.fixture.definition,
            harness.fixture.spans,
            &harness.plan,
            &harness.binding,
        ),
    );
    harness.binding.entries[0].value = saved;
    try executor.reauthenticate(
        std.testing.allocator,
        &harness.fixture.arena,
        harness.fixture.definition,
        harness.fixture.spans,
        &harness.plan,
        &harness.binding,
    );
}

test "typed Poseidon2 witness detects executable corruption before mutation" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
    defer executor.deinit();
    const sentinel = M31.fromCanonical(0x5e5e);
    var columns = try OwnedColumns.init(std.testing.allocator, 1, sentinel);
    defer columns.deinit();
    const calls = [_]production.Call{production.Call.narrow(1, 2)};

    std.mem.swap(
        u32,
        &executor.materialization_slots[0],
        &executor.materialization_slots[1],
    );
    try std.testing.expectError(
        error.CorruptExecutor,
        executor.generateMainInto(&columns.views, &calls, 0),
    );
    try columns.expectStorageValue(sentinel);
    std.mem.swap(
        u32,
        &executor.materialization_slots[0],
        &executor.materialization_slots[1],
    );

    var changed_instruction = false;
    for (executor.instructions) |*instruction| switch (instruction.*) {
        .add => |binary| {
            const saved = instruction.*;
            instruction.* = .{ .sub = binary };
            try std.testing.expectError(
                error.CorruptExecutor,
                executor.generateMainInto(&columns.views, &calls, 0),
            );
            try columns.expectStorageValue(sentinel);
            instruction.* = saved;
            changed_instruction = true;
            break;
        },
        else => {},
    };
    try std.testing.expect(changed_instruction);
    try executor.generateMainInto(&columns.views, &calls, 0);
}

test "typed Poseidon2 witness reauthentication recompiles instructions and slot maps" {
    var harness = try Harness.init(std.testing.allocator);
    defer harness.deinit();
    var executor = try harness.makeExecutor(std.testing.allocator);
    defer executor.deinit();

    std.mem.swap(
        u32,
        &executor.materialization_slots[0],
        &executor.materialization_slots[1],
    );
    try std.testing.expectError(
        error.ExecutionPlanMismatch,
        executor.reauthenticate(
            std.testing.allocator,
            &harness.fixture.arena,
            harness.fixture.definition,
            harness.fixture.spans,
            &harness.plan,
            &harness.binding,
        ),
    );
    std.mem.swap(
        u32,
        &executor.materialization_slots[0],
        &executor.materialization_slots[1],
    );

    var changed_instruction = false;
    for (executor.instructions) |*instruction| switch (instruction.*) {
        .add => |binary| {
            const saved = instruction.*;
            instruction.* = .{ .sub = binary };
            try std.testing.expectError(
                error.ExecutionPlanMismatch,
                executor.reauthenticate(
                    std.testing.allocator,
                    &harness.fixture.arena,
                    harness.fixture.definition,
                    harness.fixture.spans,
                    &harness.plan,
                    &harness.binding,
                ),
            );
            instruction.* = saved;
            changed_instruction = true;
            break;
        },
        else => {},
    };
    try std.testing.expect(changed_instruction);
    try executor.reauthenticate(
        std.testing.allocator,
        &harness.fixture.arena,
        harness.fixture.definition,
        harness.fixture.spans,
        &harness.plan,
        &harness.binding,
    );
}

test "typed Poseidon2 witness construction releases every partial allocation" {
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
    var executor = try harness.makeExecutor(allocator);
    defer executor.deinit();
}

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: [compat.N_MAIN_COLUMNS][]M31,
    views: [compat.N_MAIN_COLUMNS][]M31,

    fn init(
        allocator: std.mem.Allocator,
        len: usize,
        initial: M31,
    ) !OwnedColumns {
        var storage: [compat.N_MAIN_COLUMNS][]M31 = undefined;
        var views: [compat.N_MAIN_COLUMNS][]M31 = undefined;
        var initialized: usize = 0;
        errdefer for (storage[0..initialized]) |column| allocator.free(column);
        for (&storage, &views) |*owned, *view| {
            owned.* = try allocator.alloc(M31, len);
            initialized += 1;
            @memset(owned.*, initial);
            view.* = owned.*;
        }
        return .{ .allocator = allocator, .storage = storage, .views = views };
    }

    fn deinit(self: *OwnedColumns) void {
        for (self.storage) |column| self.allocator.free(column);
        self.* = undefined;
    }

    fn expectStorageValue(self: *const OwnedColumns, expected: M31) !void {
        for (self.storage) |column| {
            for (column) |actual| try std.testing.expectEqual(expected, actual);
        }
    }
};

const Harness = struct {
    fixture: Fixture,
    plan: materializer.Plan,
    binding: compat.OwnedBinding,

    fn init(allocator: std.mem.Allocator) !Harness {
        var fixture = try Fixture.init(allocator);
        errdefer fixture.deinit();
        var plan = try fixture.makePlan(allocator);
        errdefer plan.deinit();
        var schedule = try compat.generate(allocator);
        defer schedule.deinit(allocator);
        const binding = try compat.bindPlan(
            allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &plan,
        );
        return .{ .fixture = fixture, .plan = plan, .binding = binding };
    }

    fn deinit(self: *Harness) void {
        self.binding.deinit(self.fixture.arena.allocator);
        self.plan.deinit();
        self.fixture.deinit();
        self.* = undefined;
    }

    fn makeExecutor(
        self: *const Harness,
        allocator: std.mem.Allocator,
    ) !witness.Executor {
        return witness.Executor.init(
            allocator,
            &self.fixture.arena,
            self.fixture.definition,
            self.fixture.spans,
            &self.plan,
            &self.binding,
        );
    }
};

const Fixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,

    fn init(allocator: std.mem.Allocator) !Fixture {
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
        return .{
            .arena = arena,
            .gate = gate,
            .spans = spans,
            .definition = definition,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn makePlan(
        self: *const Fixture,
        allocator: std.mem.Allocator,
    ) !materializer.Plan {
        const roots = poseidon.values(self.definition.outputs);
        return materializer.plan(allocator, &self.arena, .{
            .roots = &roots,
            .gate = self.gate,
        });
    }
};

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
