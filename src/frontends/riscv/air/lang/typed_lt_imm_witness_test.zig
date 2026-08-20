const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const Opcode = @import("../../runner/decode.zig").Opcode;
const legacy_oracle = @import("../../runner/witness/lt_imm_legacy_test_oracle.zig");
const typed = @import("typed_lt_imm.zig");
const witness = @import("typed_lt_imm_witness.zig");

test "typed LT_IMM witness binding is pinned source independent and self-contained" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/compare/lt_imm.air",
        .start = .{ .byte_offset = 144, .line = 17, .column = 3 },
        .end = .{ .byte_offset = 148, .line = 17, .column = 7 },
    } });
    defer moved.deinit();

    var binding = try witness.WitnessBinding.canonical(&generated);
    const executor = try witness.Executor.init(&generated, &binding);
    const moved_binding = try witness.WitnessBinding.canonical(&moved);
    const moved_executor = try witness.Executor.init(&moved, &moved_binding);
    try std.testing.expectEqual(
        witness.WITNESS_BINDING_FORMAT_VERSION,
        binding.format_version,
    );
    try std.testing.expectEqual(binding.identityDigest(), executor.identityDigest());
    try std.testing.expectEqual(witness.WITNESS_BINDING_DIGEST, executor.identityDigest());
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    for (binding.slots, witness.CANONICAL_RECIPE, 0..) |slot, recipe, column| {
        try std.testing.expectEqual(column, slot.column);
        try std.testing.expectEqual(column, @intFromEnum(slot.value));
        try std.testing.expectEqual(recipe, slot.source);
    }
    try std.testing.expectEqual(typed.SLTI_OPCODE_ID, binding.operations[0].opcode_id);
    try std.testing.expectEqual(typed.SLTIU_OPCODE_ID, binding.operations[1].opcode_id);

    // Ownership is by value: both source arena and caller binding may die or
    // mutate after construction without changing executable identity.
    binding.slots[0].source = .trace_pc;
    generated.deinit();
    var columns = try OwnedColumns.init(std.testing.allocator, 2, M31.zero());
    defer columns.deinit();
    const row = makeRow(.{
        .opcode = .SLTI,
        .rd = 4,
        .rs1 = 3,
        .source = 0xffff_ffff,
        .immediate = 0,
        .clock = 1,
    });
    try executor.generateMainInto(&columns.views, &.{row}, 1);
    try expectLegacyColumns(&.{row}, 1, &columns.views);
}

test "typed LT_IMM witness binding rejects every identity dimension" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try witness.WitnessBinding.canonical(&definition);

    var forged = canonical;
    forged.format_version +%= 1;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.semantic_format_version +%= 1;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.slots[0].column = 1;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.slots[0].value = forged.slots[1].value;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.slots[0].source = .trace_pc;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.operations[0].opcode_id = typed.SLTIU_OPCODE_ID;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.operations[0].flag_column = 28;
    try expectInvalidBinding(&definition, &forged);
    forged = canonical;
    forged.operations[0].comparison = .unsigned_u32;
    try expectInvalidBinding(&definition, &forged);
}

test "typed LT_IMM exhaustively matches legacy for every immediate and signedness" {
    var actual_storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var expected_storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var actual: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var expected: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&actual, &actual_storage) |*view, *storage| view.* = storage;
    for (&expected, &expected_storage) |*view, *storage| view.* = storage;

    var visited: usize = 0;
    var immediate: i32 = -2048;
    while (immediate <= 2047) : (immediate += 1) {
        inline for (.{ Opcode.SLTI, Opcode.SLTIU }) |opcode| {
            const bits: u32 = @bitCast(immediate);
            const source = switch (visited % 8) {
                0 => bits,
                1 => bits -% 1,
                2 => bits +% 1,
                3 => 0,
                4 => 0x7fff_ffff,
                5 => 0x8000_0000,
                6 => 0xffff_ffff,
                else => bits ^ 0x8080_0080,
            };
            const row = makeRow(.{
                .opcode = opcode,
                .rd = if (visited % 17 == 0) 0 else @intCast(1 + visited % 31),
                .rs1 = @intCast(1 + (visited * 7) % 31),
                .source = source,
                .immediate = immediate,
                .clock = @intCast(1 + visited % 1024),
                .pc = @truncate(0x1000 +% visited *% 4),
                .rd_previous = @truncate(visited *% 0x1020_3041),
            });
            witness.writeActiveRow(&actual, 0, row);
            legacy_oracle.writeRow(&expected, 0, row);
            inline for (0..witness.MAIN_COLUMN_COUNT) |column| {
                if (!actual[column][0].eql(expected[column][0])) {
                    std.log.err(
                        "LT_IMM exhaustive mismatch immediate={d} opcode={s} column={d}",
                        .{ immediate, @tagName(opcode), column },
                    );
                    return error.WitnessCellMismatch;
                }
            }
            visited += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 8192), visited);
}

test "typed LT_IMM ordered relation rows match production entries" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var columns = try OwnedColumns.init(std.testing.allocator, 128, M31.zero());
    defer columns.deinit();

    var prng = std.Random.DefaultPrng.init(0x4c54_494d_4d2d_4546);
    const random = prng.random();
    var rows: [96]witness.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        row.* = makeRow(.{
            .opcode = if ((index & 1) == 0) .SLTI else .SLTIU,
            .rd = random.int(u5),
            .rs1 = @intCast(1 + random.uintLessThan(u5, 31)),
            .source = random.int(u32),
            .immediate = random.intRangeAtMost(i16, -2048, 2047),
            .clock = @intCast(index + 1),
            .pc = random.int(u32),
            .rd_previous = random.int(u32),
        });
    }
    try executor.generateMainInto(&columns.views, &rows, 7);
    try expectLegacyColumns(&rows, 7, &columns.views);

    for (rows, 0..) |row, row_index| {
        var main: [witness.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&main, columns.views) |*value, column|
            value.* = QM31.fromBase(column[row_index]);
        const expected = try opcode_entries.fromMain(.lt_imm, &main);
        const actual = try executor.generateRelationRow(row);
        try std.testing.expectEqual(@as(usize, witness.EVENT_COUNT), expected.len);
        try std.testing.expectEqual(@as(usize, witness.EVENT_COUNT), actual.events.len);
        for (expected.entries[0..expected.len], actual.events) |entry, event| {
            try std.testing.expectEqualStrings(@tagName(entry.domain), @tagName(event.domain));
            try std.testing.expectEqualStrings(@tagName(entry.role), @tagName(event.role));
            try std.testing.expectEqual(entry.arity, event.arity);
            try std.testing.expectEqual(entry.access_ordinal, event.access_ordinal);
            try std.testing.expect(entry.numerator.eql(QM31.fromBase(event.signedNumerator())));
            for (entry.values[0..entry.arity], event.values[0..event.arity]) |
                expected_value,
                actual_value,
            | try std.testing.expect(expected_value.eql(QM31.fromBase(actual_value)));
        }
    }
}

test "typed LT_IMM production source is singular pinned and allocator-free" {
    const witness_source = @embedFile("typed_lt_imm_witness.zig");
    const trace_source = @embedFile("../../runner/trace.zig");
    const execute_source = @embedFile("../../runner/execute.zig");
    const retirement_source = @embedFile("../../runner/generated_retirement.zig");
    const constraint_source = @embedFile("../constraint_program_constructors.zig");
    const semantics_registry = @embedFile("../semantics/mod.zig");

    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".lt_imm => LT_IMM_AUTHORITY.writeActiveRow",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        trace_source,
        ".lt_imm => typed_lt_imm_witness.writeActiveRow",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        execute_source,
        ".SLTI, .SLTIU => return error.GeneratedRetirementRequired",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        retirement_source,
        ".slti, .sltiu => try lt_imm.retireAtomic",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        constraint_source,
        ".lt_imm => constructLtImm(section, columns, is_active)",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        constraint_source,
        ".lt_imm => constructFamily(section, .lt_imm",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        semantics_registry,
        "pub const lt_imm =",
    ) == null);
    try std.testing.expect(std.mem.indexOf(u8, witness_source, "legacy_test_oracle") == null);
    try std.testing.expect(std.mem.indexOf(u8, witness_source, "allocator.alloc") == null);
    try std.testing.expect(std.mem.indexOf(u8, witness_source, "ArrayList") == null);
}

test "typed LT_IMM writer covers signed unsigned alias x0 and comparison boundaries" {
    const rows = [_]witness.TraceRow{
        makeRow(.{ .opcode = .SLTI, .rd = 0, .rs1 = 0, .source = 0, .immediate = 0, .clock = 1 }),
        makeRow(.{ .opcode = .SLTI, .rd = 5, .rs1 = 5, .source = 0x8000_0000, .immediate = 0, .clock = 2 }),
        makeRow(.{ .opcode = .SLTIU, .rd = 31, .rs1 = 1, .source = 0, .immediate = -1, .clock = 3 }),
        makeRow(.{ .opcode = .SLTIU, .rd = 7, .rs1 = 2, .source = 0xffff_ffff, .immediate = -1, .clock = 4 }),
        makeRow(.{ .opcode = .SLTI, .rd = 8, .rs1 = 3, .source = 0x7fff_ffff, .immediate = 2047, .clock = 5 }),
        makeRow(.{ .opcode = .SLTI, .rd = 9, .rs1 = 4, .source = 0xffff_f800, .immediate = -2048, .clock = 6 }),
    };
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var columns = try OwnedColumns.init(std.testing.allocator, 8, M31.fromCanonical(0x5353));
    defer columns.deinit();
    try executor.generateMainInto(&columns.views, &rows, 3);
    try expectLegacyColumns(&rows, 3, &columns.views);
    for (columns.views) |column| for (column[rows.len..]) |padding|
        try std.testing.expect(padding.isZero());
}

test "typed LT_IMM rejects malformed rows and shapes before mutation" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x1ace);
    var columns = try OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const row = makeRow(.{
        .opcode = .SLTI,
        .rd = 2,
        .rs1 = 1,
        .source = 7,
        .immediate = -1,
        .clock = 1,
    });

    const original_last = columns.views[witness.MAIN_COLUMN_COUNT - 1];
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = original_last[0..3];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns.views, &.{row}, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[witness.MAIN_COLUMN_COUNT - 1] = original_last;

    inline for (.{
        "opcode",
        "immediate",
        "clock",
        "next_pc",
        "result",
        "source_x0",
        "destination_x0",
        "alias_value",
        "alias_clock",
        "source_gap",
        "destination_gap",
    }) |mutation| {
        var forged = row;
        if (std.mem.eql(u8, mutation, "opcode")) forged.opcode = .ADDI;
        if (std.mem.eql(u8, mutation, "immediate")) forged.imm = 2048;
        if (std.mem.eql(u8, mutation, "clock")) forged.clk = 0;
        if (std.mem.eql(u8, mutation, "next_pc")) forged.next_pc +%= 4;
        if (std.mem.eql(u8, mutation, "result")) forged.rd_val ^= 1;
        if (std.mem.eql(u8, mutation, "source_x0")) {
            forged.rs1 = 0;
            forged.rs1_val = 1;
        }
        if (std.mem.eql(u8, mutation, "destination_x0")) {
            forged.rd = 0;
            forged.rd_prev_val = 1;
            forged.rd_val = 0;
        }
        if (std.mem.eql(u8, mutation, "alias_value")) {
            forged.rd = forged.rs1;
            forged.rd_prev_val = forged.rs1_val ^ 1;
        }
        if (std.mem.eql(u8, mutation, "alias_clock")) {
            forged.rd = forged.rs1;
            forged.rd_prev_val = forged.rs1_val;
            forged.rd_prev_clk = 0;
        }
        if (std.mem.eql(u8, mutation, "source_gap")) forged.rs1_prev_clk = 1;
        if (std.mem.eql(u8, mutation, "destination_gap")) forged.rd_prev_clk = 2;
        try std.testing.expectError(
            error.InvalidTraceRow,
            executor.generateMainInto(&columns.views, &.{forged}, 2),
        );
        try columns.expectStorageValue(sentinel);
    }
}

test "typed LT_IMM rejects destination and input aliases before mutation" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x2bad);
    var columns = try OwnedColumns.init(std.testing.allocator, 4, sentinel);
    defer columns.deinit();
    const row = makeRow(.{
        .opcode = .SLTIU,
        .rd = 3,
        .rs1 = 2,
        .source = 0x1234,
        .immediate = -4,
        .clock = 1,
    });

    const original_second = columns.views[1];
    columns.views[1] = columns.views[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&columns.views, &.{row}, 2),
    );
    try columns.expectStorageValue(sentinel);
    columns.views[1] = original_second;

    var aliased = try OwnedColumns.init(std.testing.allocator, 64, sentinel);
    defer aliased.deinit();
    comptime {
        if (@sizeOf(witness.TraceRow) > 64 * @sizeOf(M31))
            @compileError("input-alias fixture is too small");
    }
    const row_pointer: *witness.TraceRow = @ptrCast(@alignCast(aliased.storage[0].ptr));
    row_pointer.* = row;
    var before: [64]M31 = undefined;
    @memcpy(&before, aliased.storage[0]);
    const overlapping_rows = @as([*]const witness.TraceRow, @ptrCast(row_pointer))[0..1];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&aliased.views, overlapping_rows, 6),
    );
    try std.testing.expectEqualSlices(M31, &before, aliased.storage[0]);
}

test "typed LT_IMM construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "typed LT_IMM hot rows retain paired legacy throughput and scaling" {
    if (builtin.mode != .ReleaseFast) return;

    const allocator = std.testing.allocator;
    const log_rows = [_]u32{ 10, 14, 18 };
    const row_count: usize = @as(usize, 1) << log_rows[log_rows.len - 1];
    const rows = try allocator.alloc(witness.TraceRow, row_count);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| {
        row.* = makeRow(.{
            .opcode = if ((index & 1) == 0) .SLTI else .SLTIU,
            .rd = @intCast(index % 32),
            .rs1 = @intCast(1 + index % 31),
            .source = @truncate(index *% 0x9e37_79b9),
            .immediate = @as(i32, @intCast(index & 0xfff)) - 2048,
            .clock = @intCast(1 + index % 100_000),
            .pc = @truncate(0x1000 +% index *% 4),
            .rd_previous = @truncate(index *% 0x0101_0101),
        });
    }
    var columns = try OwnedColumns.init(allocator, row_count, M31.zero());
    defer columns.deinit();

    for (rows, 0..) |row, index| witness.writeActiveRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);
    for (rows, 0..) |row, index| legacy_oracle.writeRow(&columns.views, index, row);
    consumeColumns(&columns.views, rows.len);

    var generated_medians: [log_rows.len]u64 = undefined;
    for (log_rows, 0..) |log_size, case_index| {
        const active = rows[0..(@as(usize, 1) << @intCast(log_size))];
        var generated_times: [nine_samples]u64 = undefined;
        var legacy_times: [nine_samples]u64 = undefined;
        for (0..nine_samples) |sample| {
            if ((sample & 1) == 0) {
                generated_times[sample] = try measureGenerated(&columns.views, active);
                legacy_times[sample] = try measureLegacy(&columns.views, active);
            } else {
                legacy_times[sample] = try measureLegacy(&columns.views, active);
                generated_times[sample] = try measureGenerated(&columns.views, active);
            }
        }
        std.mem.sort(u64, &generated_times, {}, std.sort.asc(u64));
        std.mem.sort(u64, &legacy_times, {}, std.sort.asc(u64));
        const generated_median = generated_times[nine_samples / 2];
        const legacy_median = legacy_times[nine_samples / 2];
        generated_medians[case_index] = generated_median;
        std.debug.print(
            "\n  typed LT_IMM authority log_rows={d}: generated={d} ns " ++
                "legacy={d} ns median_speed={d:.4}x\n",
            .{
                log_size,
                generated_median,
                legacy_median,
                @as(f64, @floatFromInt(legacy_median)) /
                    @as(f64, @floatFromInt(generated_median)),
            },
        );
        try std.testing.expect(generated_median * 97 <= legacy_median * 100);
    }
    for (1..generated_medians.len) |index| {
        try std.testing.expect(
            generated_medians[index] * 10 <= generated_medians[index - 1] * 176,
        );
    }
}

const RowConfig = struct {
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    source: u32,
    immediate: i32,
    clock: u32,
    pc: u32 = 0x1000,
    rd_previous: u32 = 0x1122_3344,
};

fn makeRow(config: RowConfig) witness.TraceRow {
    std.debug.assert(config.opcode == .SLTI or config.opcode == .SLTIU);
    std.debug.assert(config.immediate >= -2048 and config.immediate <= 2047);
    std.debug.assert(config.clock != 0);
    const source = if (config.rs1 == 0) 0 else config.source;
    const source_clock = (config.clock - 1) *% 4 +% 1;
    const immediate_bits: u32 = @bitCast(config.immediate);
    const comparison = if (config.opcode == .SLTI)
        @as(i32, @bitCast(source)) < config.immediate
    else
        source < immediate_bits;
    return .{
        .clk = config.clock,
        .pc = config.pc,
        .opcode = config.opcode,
        .rd = config.rd,
        .rs1 = config.rs1,
        .rs2 = 0,
        .imm = config.immediate,
        .rs1_val = source,
        .rs2_val = 0,
        .rs1_prev_clk = 0,
        .rs2_prev_clk = 0,
        .rd_prev_val = if (config.rd == 0)
            0
        else if (config.rd == config.rs1)
            source
        else
            config.rd_previous,
        .rd_prev_clk = if (config.rd == config.rs1) source_clock else 0,
        .rd_val = if (config.rd == 0) 0 else @intFromBool(comparison),
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = config.pc +% 4,
    };
}

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: [witness.MAIN_COLUMN_COUNT][]M31,
    views: [witness.MAIN_COLUMN_COUNT][]M31,

    fn init(
        allocator: std.mem.Allocator,
        row_count: usize,
        fill: M31,
    ) !OwnedColumns {
        var result = OwnedColumns{
            .allocator = allocator,
            .storage = undefined,
            .views = undefined,
        };
        var initialized: usize = 0;
        errdefer for (result.storage[0..initialized]) |column| allocator.free(column);
        for (&result.storage, &result.views) |*storage, *view| {
            storage.* = try allocator.alloc(M31, row_count);
            @memset(storage.*, fill);
            view.* = storage.*;
            initialized += 1;
        }
        return result;
    }

    fn deinit(self: *OwnedColumns) void {
        for (self.storage) |column| self.allocator.free(column);
        self.* = undefined;
    }

    fn expectStorageValue(self: *const OwnedColumns, expected: M31) !void {
        for (self.storage) |column| for (column) |value|
            try std.testing.expectEqual(expected, value);
    }
};

fn expectLegacyColumns(
    rows: []const witness.TraceRow,
    log_size: u32,
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
) !void {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    try std.testing.expect(rows.len <= domain_size);
    var expected = try OwnedColumns.init(std.testing.allocator, domain_size, M31.zero());
    defer expected.deinit();
    for (rows, 0..) |row, row_index|
        legacy_oracle.writeRow(&expected.views, row_index, row);
    for (actual, expected.views) |actual_column, expected_column| {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected_column),
            std.mem.sliceAsBytes(actual_column),
        );
    }
}

fn expectInvalidBinding(
    definition: *const typed.Definition,
    binding: *const witness.WitnessBinding,
) !void {
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(definition, binding),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
}

const nine_samples: usize = 9;

fn measureGenerated(
    columns: *[witness.MAIN_COLUMN_COUNT][]M31,
    rows: []const witness.TraceRow,
) !u64 {
    var timer = try std.time.Timer.start();
    for (rows, 0..) |row, index| witness.writeActiveRow(columns, index, row);
    const elapsed = timer.read();
    consumeColumns(columns, rows.len);
    return elapsed;
}

fn measureLegacy(
    columns: *[witness.MAIN_COLUMN_COUNT][]M31,
    rows: []const witness.TraceRow,
) !u64 {
    var timer = try std.time.Timer.start();
    for (rows, 0..) |row, index| legacy_oracle.writeRow(columns, index, row);
    const elapsed = timer.read();
    consumeColumns(columns, rows.len);
    return elapsed;
}

fn consumeColumns(
    columns: *const [witness.MAIN_COLUMN_COUNT][]M31,
    active_rows: usize,
) void {
    var checksum: u64 = 0;
    for (columns) |column| {
        for (column[0..active_rows]) |value| checksum +%= value.v;
    }
    std.mem.doNotOptimizeAway(&checksum);
}
