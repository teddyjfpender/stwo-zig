const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constraint_program = @import("../constraint_program.zig");
const symbolic = @import("../extract/symbolic.zig");
const lookup_entry = @import("../lookups/entry.zig");
const legacy_fence = @import("../semantics/fence_legacy_test_oracle.zig");
const legacy_witness = @import("../../runner/witness/fence_legacy_test_oracle.zig");
const support = @import("typed_fence_witness_test_support.zig");
const authority = @import("typed_fence_authority.zig");
const typed_fence = @import("typed_fence.zig");
const typed_fence_witness = @import("typed_fence_witness.zig");

test "E-019 typed FENCE fixed authority binding is exact source-independent and self-contained" {
    var generated = try typed_fence.build(std.testing.allocator, .generated);
    var generated_live = true;
    defer if (generated_live) generated.deinit();
    var moved = try typed_fence.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/fence.air",
        .start = .{ .byte_offset = 41, .line = 3, .column = 7 },
        .end = .{ .byte_offset = 46, .line = 3, .column = 12 },
    } });
    defer moved.deinit();

    const binding = try authority.Binding.canonical(&generated);
    const executor = try authority.Authority.init(&generated, &binding);
    const moved_binding = try authority.Binding.canonical(&moved);
    const moved_executor = try authority.Authority.init(&moved, &moved_binding);
    try std.testing.expectEqual(
        authority.AUTHORITY_BINDING_FORMAT_VERSION,
        binding.format_version,
    );
    try std.testing.expectEqual(typed_fence.SEMANTIC_DIGEST, binding.semantic_digest);
    try std.testing.expectEqual(
        typed_fence_witness.WITNESS_BINDING_DIGEST,
        binding.witness_binding_digest,
    );
    try std.testing.expectEqual(authority.AUTHORITY_BINDING_DIGEST, binding.identityDigest());
    try std.testing.expectEqual(binding.identityDigest(), executor.identityDigest());
    try std.testing.expectEqual(executor.identityDigest(), moved_executor.identityDigest());
    try std.testing.expect(std.meta.eql(binding, executor.identitySnapshot()));
    try std.testing.expect(std.meta.eql(binding, moved_binding));
    const pinned = authority.Authority.pinned();
    try std.testing.expectEqualDeep(executor, pinned);
    try std.testing.expectEqualDeep(
        authority.CANONICAL_BINDING,
        pinned.identitySnapshot(),
    );

    generated.deinit();
    generated_live = false;
    const instruction = try fenceInstruction(31, 17, 0xf53);
    const retired = try executor.retire(instruction, 0xffff_fffc);
    try std.testing.expectEqual(@as(u32, 0), retired.next_pc);

    var storage: [authority.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*column_storage, *column| column.* = column_storage;
    const row = makeRow(31, 17, 0xf53, 9);
    executor.writeActiveRow(&columns, 0, row);
    try std.testing.expectEqual(M31.fromCanonical(31), columns[3][0]);
    try std.testing.expectEqual(M31.fromCanonical(17), columns[4][0]);
    try std.testing.expectEqual(M31.fromCanonical(0xf53), columns[5][0]);
}

test "E-019 typed FENCE fixed authority rejects every malformed binding class" {
    var definition = try typed_fence.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try authority.Binding.canonical(&definition);

    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.opcode_id +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.witness_binding_digest[31] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.main_column_count +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(authority.DirectRecipe, &malformed.direct[0], &malformed.direct[1]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[0].domain = .memory_access;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[1].role = .request;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].arity = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].access_ordinal = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(
        authority.LookupDescriptor,
        &malformed.lookups[1],
        &malformed.lookups[2],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);

    definition.model.roots[0] = definition.model.roots[1];
    try std.testing.expectError(
        error.InvalidFenceDefinition,
        authority.Authority.init(&definition, &canonical),
    );
}

test "E-019 typed FENCE fixed direct and lookup programs are symbolically identical" {
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    for (&columns) |*column| column.* = arena.column("");
    const selector = arena.column("is_active");
    const Legacy = legacy_fence.Semantics(symbolic.Scalar);
    const legacy_row = try Legacy.Row.fromMainColumns(&columns);
    const legacy_direct = Legacy.evaluate(legacy_row);
    const legacy_placement = Legacy.placementConstraint(legacy_row, selector);
    const legacy_lookups = legacyLookupProgram(symbolic.Scalar, legacy_row);
    const node_count_before = arena.nodes.items.len;

    const executor = authority.Authority.pinned();
    const actual = try executor.buildProgram(symbolic.Scalar, &columns, selector);

    // This is an independent former-production oracle, not a typed-to-typed
    // comparison. Exact node reuse proves polynomial equality for all inputs.
    try std.testing.expectEqual(node_count_before, arena.nodes.items.len);
    try std.testing.expectEqual(legacy_row.enabler.id, actual.active_row.id);
    try std.testing.expectEqual(
        legacy_direct.values.len + 1,
        actual.direct_constraints.values.len,
    );
    for (
        legacy_direct.values,
        actual.direct_constraints.values[0..legacy_direct.values.len],
    ) |want, got| try std.testing.expectEqual(want.id, got.id);
    try std.testing.expectEqual(
        legacy_placement.id,
        actual.direct_constraints.values[legacy_direct.values.len].id,
    );
    try expectLookupListsEqual(symbolic.Scalar, legacy_lookups, actual.lookup_entries);
}

test "E-019 typed FENCE fixed execution covers all immediate encodings and reserved registers" {
    var definition = try typed_fence.build(std.testing.allocator, .generated);
    const binding = try authority.Binding.canonical(&definition);
    const executor = try authority.Authority.init(&definition, &binding);
    definition.deinit();

    for (0..1 << 12) |immediate_raw| {
        const rd: u5 = @intCast(immediate_raw & 31);
        const rs1: u5 = @intCast((immediate_raw * 13) & 31);
        const instruction = try fenceInstruction(rd, rs1, @intCast(immediate_raw));
        const pc: u32 = @truncate(immediate_raw *% 0x0101_0104);
        const retired = try executor.retire(instruction, pc);
        if (retired.next_pc != pc +% 4) return error.ExhaustiveFenceMismatch;
    }
    for (0..32) |rd_raw| for (0..32) |rs1_raw| {
        const instruction = try fenceInstruction(
            @intCast(rd_raw),
            @intCast(rs1_raw),
            0xf53,
        );
        _ = try executor.retire(instruction, 0xffff_fffc);
    };

    try std.testing.expectError(
        error.WrongFenceOpcode,
        executor.retire(
            .{ .opcode = .ADDI, .rd = 0, .rs1 = 0, .rs2 = 0, .imm = 0 },
            0x1000,
        ),
    );
    try std.testing.expectError(
        error.InvalidFenceImmediate,
        executor.retire(
            .{ .opcode = .FENCE, .rd = 0, .rs1 = 0, .rs2 = 0, .imm = 2048 },
            0x1000,
        ),
    );
}

test "E-019 typed FENCE fixed witness facade is exact and rejection atomic" {
    var definition = try typed_fence.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try authority.Binding.canonical(&definition);
    const executor = try authority.Authority.init(&definition, &binding);

    const immediates = [_]u12{ 0, 1, 0x7ff, 0x800, 0xf53, 0xfff };
    var rows: [32 * immediates.len]authority.TraceRow = undefined;
    var cursor: usize = 0;
    for (0..32) |rd| {
        for (immediates) |immediate| {
            rows[cursor] = makeRow(
                @intCast(rd),
                @intCast((rd * 13 + cursor) & 31),
                immediate,
                @intCast(cursor + 1),
            );
            cursor += 1;
        }
    }

    var actual = try OwnedColumns.init(std.testing.allocator, 256, M31.fromCanonical(0x5151));
    defer actual.deinit();
    var legacy = try OwnedColumns.init(std.testing.allocator, 256, M31.fromCanonical(0x6262));
    defer legacy.deinit();
    try executor.generateMainInto(&actual.views, &rows, 8);
    for (rows, 0..) |row, index| legacy_witness.writeRow(&legacy.views, index, row);
    for (legacy.views) |column| @memset(column[rows.len..], M31.zero());
    for (actual.views, legacy.views) |got, want|
        try std.testing.expectEqualSlices(M31, want, got);

    const sentinel = M31.fromCanonical(0x1ace);
    for (actual.views) |column| @memset(column, sentinel);
    var forged = rows;
    forged[forged.len - 1].rd_val ^= 1;
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&actual.views, &forged, 8),
    );
    try actual.expectAll(sentinel);
}

test "E-019 typed FENCE fixed direct and lookup hot paths retain production throughput" {
    if (builtin.mode != .ReleaseFast) return;

    const benchmark_row_count = 1 << 12;
    const rows = try std.testing.allocator.alloc(
        [authority.MAIN_COLUMN_COUNT]QM31,
        benchmark_row_count,
    );
    defer std.testing.allocator.free(rows);
    for (rows, 0..) |*row, row_index| {
        for (row, 0..) |*value, column_index| {
            const seed = @as(u64, row_index + 1) *% 0x9e37_79b1 +%
                @as(u64, column_index + 1) *% 0x85eb_ca77;
            value.* = QM31.fromM31(
                M31.fromU64(seed +% 0x243f_6a88),
                M31.fromU64(seed *% 3 +% 0x85a3_08d3),
                M31.fromU64(seed *% 5 +% 0x1319_8a2e),
                M31.fromU64(seed *% 7 +% 0x0370_7344),
            );
        }
    }
    const active = QM31.fromM31(
        M31.fromCanonical(7),
        M31.fromCanonical(11),
        M31.fromCanonical(13),
        M31.fromCanonical(17),
    );
    const samples = 11;
    const iterations = 1 << 16;
    var fixed_direct: [samples]u64 = undefined;
    var production_direct: [samples]u64 = undefined;
    var fixed_lookups: [samples]u64 = undefined;
    var production_lookups: [samples]u64 = undefined;
    for (0..samples) |sample| {
        if ((sample & 1) == 0) {
            fixed_direct[sample] = try measureFixedDirect(rows, active, iterations);
            production_direct[sample] = try measureProductionDirect(rows, active, iterations);
            fixed_lookups[sample] = try measureFixedLookups(rows, iterations);
            production_lookups[sample] = try measureProductionLookups(rows, iterations);
        } else {
            production_lookups[sample] = try measureProductionLookups(rows, iterations);
            fixed_lookups[sample] = try measureFixedLookups(rows, iterations);
            production_direct[sample] = try measureProductionDirect(rows, active, iterations);
            fixed_direct[sample] = try measureFixedDirect(rows, active, iterations);
        }
    }
    const fixed_direct_median = median(&fixed_direct);
    const production_direct_median = median(&production_direct);
    const fixed_lookup_median = median(&fixed_lookups);
    const production_lookup_median = median(&production_lookups);
    std.debug.print(
        "\n  E-019 FENCE fixed authority: direct={d} ns production={d} ns " ++
            "speed={d:.4}x; lookups={d} ns production={d} ns speed={d:.4}x\n",
        .{
            fixed_direct_median,
            production_direct_median,
            @as(f64, @floatFromInt(production_direct_median)) /
                @as(f64, @floatFromInt(fixed_direct_median)),
            fixed_lookup_median,
            production_lookup_median,
            @as(f64, @floatFromInt(production_lookup_median)) /
                @as(f64, @floatFromInt(fixed_lookup_median)),
        },
    );
    try std.testing.expect(fixed_direct_median * 97 <= production_direct_median * 100);
    try std.testing.expect(fixed_lookup_median * 97 <= production_lookup_median * 100);
}

fn expectInvalidBinding(
    definition: *const typed_fence.Definition,
    malformed: authority.Binding,
) !void {
    try std.testing.expectError(
        error.InvalidAuthorityBinding,
        authority.Authority.init(definition, &malformed),
    );
}

fn expectLookupListsEqual(
    comptime S: type,
    expected: @import("../lookups/entry.zig").Builder(S).List,
    actual: @import("../lookups/entry.zig").Builder(S).List,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected.batch_size, actual.batch_size);
    for (expected.entries[0..expected.len], actual.entries[0..actual.len]) |want, got| {
        try std.testing.expectEqual(want.domain, got.domain);
        try std.testing.expectEqual(want.role, got.role);
        try std.testing.expectEqual(want.arity, got.arity);
        try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
        try std.testing.expectEqual(want.numerator.id, got.numerator.id);
        for (want.values[0..want.arity], got.values[0..got.arity]) |want_value, got_value|
            try std.testing.expectEqual(want_value.id, got_value.id);
    }
}

fn legacyLookupProgram(
    comptime S: type,
    row: legacy_fence.Semantics(S).Row,
) lookup_entry.Builder(S).List {
    const e = lookup_entry.Builder(S);
    const requests = legacy_fence.Semantics(S).lookups(row);
    var result = e.List{};
    e.program(&result, requests.program.numerator, requests.program.tuple);
    e.stateRequests(&result, requests.state);
    return result;
}

fn fenceInstruction(rd: u5, rs1: u5, immediate: u12) !authority.DecodedInst {
    return authority.DecodedInst.decode(encodeFence(rd, rs1, immediate));
}

fn encodeFence(rd: u5, rs1: u5, immediate: u12) u32 {
    return (@as(u32, immediate) << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, rd) << 7) |
        0b0001111;
}

fn makeRow(rd: u5, rs1: u5, immediate: u12, clock: u32) authority.TraceRow {
    return support.makeRow(
        rd,
        rs1,
        signExtend12(immediate),
        clock,
        0x1000 +% (clock -% 1) *% 4,
        clock *% 0x0102_0304,
    );
}

fn signExtend12(value: u12) i32 {
    const shifted: i32 = @bitCast(@as(u32, value) << 20);
    return shifted >> 20;
}

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: [authority.MAIN_COLUMN_COUNT][]M31,
    views: [authority.MAIN_COLUMN_COUNT][]M31,

    fn init(allocator: std.mem.Allocator, rows: usize, fill: M31) !OwnedColumns {
        var result = OwnedColumns{
            .allocator = allocator,
            .storage = undefined,
            .views = undefined,
        };
        var initialized: usize = 0;
        errdefer for (result.storage[0..initialized]) |column| allocator.free(column);
        for (&result.storage, &result.views) |*storage, *view| {
            storage.* = try allocator.alloc(M31, rows);
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

    fn expectAll(self: *const OwnedColumns, expected: M31) !void {
        for (self.views) |column| {
            for (column) |value| try std.testing.expectEqual(expected, value);
        }
    }
};

const ConcreteBuilder = constraint_program.Builder(QM31);
const FixedEvaluator = authority.Evaluator(QM31);

fn measureFixedDirect(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |iteration| {
        const result = try FixedEvaluator.direct(&rows[iteration & (rows.len - 1)], active);
        for (result.values) |value| absorbScalar(&checksum, value);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureProductionDirect(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |iteration| {
        var direct: ConcreteBuilder.DirectConstraints = undefined;
        try ConcreteBuilder.buildDirectInto(
            .fence,
            &rows[iteration & (rows.len - 1)],
            active,
            &direct,
        );
        std.debug.assert(direct.len == authority.DIRECT_CONSTRAINT_COUNT);
        for (direct.values[0..direct.len]) |value|
            absorbScalar(&checksum, value);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureFixedLookups(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0xbb67_ae85_84ca_a73b;
    for (0..iterations) |iteration| {
        var result: @import("../lookups/entry.zig").List = undefined;
        try FixedEvaluator.lookupsInto(&rows[iteration & (rows.len - 1)], &result);
        absorbLookups(&checksum, &result);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureProductionLookups(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0xbb67_ae85_84ca_a73b;
    for (0..iterations) |iteration| {
        var result: @import("../lookups/entry.zig").List = undefined;
        try ConcreteBuilder.buildLookupsInto(
            .fence,
            &rows[iteration & (rows.len - 1)],
            &result,
        );
        absorbLookups(&checksum, &result);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

inline fn absorbScalar(checksum: *u64, value: QM31) void {
    const limbs = value.toM31Array();
    const low = @as(u64, limbs[0].v) | (@as(u64, limbs[1].v) << 32);
    const high = @as(u64, limbs[2].v) | (@as(u64, limbs[3].v) << 32);
    checksum.* = std.math.rotl(u64, checksum.* ^ low, 17) *%
        0x9e37_79b1_85eb_ca87 ^ high;
}

fn absorbLookups(
    checksum: *u64,
    result: *const @import("../lookups/entry.zig").List,
) void {
    std.debug.assert(result.len == authority.LOOKUP_COUNT);
    for (result.entries[0..result.len]) |lookup| {
        absorbScalar(checksum, lookup.numerator);
        for (lookup.values[0..lookup.arity]) |value| absorbScalar(checksum, value);
    }
}

fn median(samples: []u64) u64 {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return samples[samples.len / 2];
}
