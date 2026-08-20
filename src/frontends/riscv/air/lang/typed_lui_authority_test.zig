const std = @import("std");
const builtin = @import("builtin");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constraint_program = @import("../constraint_program.zig");
const formal_program = @import("../extract/program.zig");
const program_json = @import("../extract/program_json.zig");
const runtime_program = @import("../extract/runtime_program.zig");
const symbolic = @import("../extract/symbolic.zig");
const lookup_entry = @import("../lookups/entry.zig");
const legacy_lui = @import("../semantics/lui_legacy_test_oracle.zig");
const legacy_witness = @import("../../runner/witness/lui_legacy_test_oracle.zig");
const authority = @import("typed_lui_authority.zig");
const typed_lui = @import("typed_lui.zig");
const typed_lui_witness = @import("typed_lui_witness.zig");

test "E-018 typed LUI fixed authority binding is exact source-independent and self-contained" {
    var generated = try typed_lui.build(std.testing.allocator, .generated);
    var moved = try typed_lui.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/lui.air",
        .start = .{ .byte_offset = 91, .line = 7, .column = 3 },
        .end = .{ .byte_offset = 96, .line = 7, .column = 8 },
    } });
    defer moved.deinit();

    const binding = authority.Binding.canonical(&generated);
    const executor = try authority.Authority.init(&generated, &binding);
    const moved_binding = authority.Binding.canonical(&moved);
    const moved_executor = try authority.Authority.init(&moved, &moved_binding);
    try std.testing.expectEqual(
        authority.AUTHORITY_BINDING_FORMAT_VERSION,
        binding.format_version,
    );
    try std.testing.expectEqual(typed_lui.SEMANTIC_DIGEST, binding.semantic_digest);
    try std.testing.expectEqual(
        typed_lui_witness.WITNESS_BINDING_DIGEST,
        binding.witness_binding_digest,
    );
    try std.testing.expectEqual(
        authority.AUTHORITY_BINDING_DIGEST,
        binding.identityDigest(),
    );
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

    // The executable snapshot owns no arena pointer. Destroy the source and use
    // every forward/witness seam afterwards.
    generated.deinit();
    const instruction = luiInstruction(31, 0x8abcd);
    const retired = try executor.retire(instruction);
    try std.testing.expect(retired.write_enabled);
    try std.testing.expectEqual(@as(u32, 0x8abcd000), retired.attempted_value);
    try std.testing.expectEqual(retired.attempted_value, retired.visible_value);

    var storage: [authority.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*column_storage, *column| column.* = column_storage;
    const row = makeRow(31, 0x8abcd, 9);
    executor.writeActiveRow(&columns, 0, row);
    try std.testing.expectEqual(M31.fromCanonical(0xd0), columns[10][0]);
    try std.testing.expectEqual(M31.fromCanonical(0xbc), columns[11][0]);
    try std.testing.expectEqual(M31.fromCanonical(0x8a), columns[12][0]);
}

test "E-018 typed LUI fixed authority rejects every malformed binding class" {
    var definition = try typed_lui.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = authority.Binding.canonical(&definition);

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
    std.mem.swap(
        authority.DirectRecipe,
        &malformed.direct[0],
        &malformed.direct[1],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[0].domain = .memory_access;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[1].role = .request;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[3].arity = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[4].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(
        authority.LookupDescriptor,
        &malformed.lookups[5],
        &malformed.lookups[6],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);

    // Definition validation precedes binding trust.
    definition.constraint_roots[0] = definition.constraint_roots[1];
    try std.testing.expectError(
        error.InvalidLuiDefinition,
        authority.Authority.init(&definition, &canonical),
    );
}

test "E-018 typed LUI fixed direct and lookup programs are symbolically identical" {
    const executor = try authenticatedAuthority();
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    for (&columns) |*column| column.* = arena.column("");
    const selector = arena.column("is_active");
    const Legacy = legacy_lui.Semantics(symbolic.Scalar);
    const legacy_row = try Legacy.Row.fromMainColumns(&columns);
    const legacy_direct = Legacy.evaluate(legacy_row);
    const legacy_placement = Legacy.placementConstraint(legacy_row, selector);
    const legacy_lookups = legacyLookupProgram(symbolic.Scalar, legacy_row);
    const node_count_before = arena.nodes.items.len;

    const actual = try executor.buildProgram(symbolic.Scalar, &columns, selector);

    // The retired Stark-V-shaped evaluator above is intentionally not imported
    // by production. Exact node reuse therefore proves equality as polynomials
    // for every field input without comparing the typed path to itself.
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

test "E-020 one authenticated LUI program has byte-exact formal and runtime exports" {
    const allocator = std.testing.allocator;
    const executor = try authenticatedAuthority();

    // Exercise execution, physical witness, direct roots, and ordered lookup
    // relations through this exact capability before exporting it. This is the
    // SSOT convergence shape the later production switch will consume.
    const row = makeRow(29, 0x8cdef, 17);
    const retirement = try executor.retire(luiInstruction(29, 0x8cdef));
    try std.testing.expectEqual(row.rd_val, retirement.visible_value);
    var row_storage: [authority.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var row_columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    var scalar_columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
    for (&row_storage, &row_columns) |*storage, *column| column.* = storage;
    executor.writeActiveRow(&row_columns, 0, row);
    for (row_storage, &scalar_columns) |storage, *scalar|
        scalar.* = QM31.fromBase(storage[0]);
    const concrete = try executor.buildProgram(
        QM31,
        &scalar_columns,
        QM31.one(),
    );
    try std.testing.expect(concrete.direct_constraints.allZero());
    try std.testing.expect(concrete.active_row.eql(QM31.one()));
    try std.testing.expectEqual(authority.LOOKUP_COUNT, concrete.lookup_entries.len);
    try std.testing.expectEqual(authority.LOOKUP_BATCH_SIZE, concrete.lookup_entries.batch_size);

    var production_json = std.Io.Writer.Allocating.init(allocator);
    defer production_json.deinit();
    {
        var arena = symbolic.Arena.init(allocator);
        defer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();
        const production = try formal_program.buildLui(&arena);
        try program_json.writeLui(
            &production_json.writer,
            &arena,
            production,
        );
    }

    var authenticated_json = std.Io.Writer.Allocating.init(allocator);
    defer authenticated_json.deinit();
    {
        var arena = symbolic.Arena.init(allocator);
        defer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();
        const authenticated = try formal_program.buildLuiFromAuthority(
            &arena,
            &executor,
        );
        try program_json.writeLui(
            &authenticated_json.writer,
            &arena,
            authenticated,
        );
    }
    try std.testing.expectEqualSlices(
        u8,
        production_json.written(),
        authenticated_json.written(),
    );

    var production_direct = try runtime_program.build(allocator, .lui);
    defer production_direct.deinit();
    var authenticated_direct = try runtime_program.buildLuiFromAuthority(
        allocator,
        &executor,
    );
    defer authenticated_direct.deinit();
    try expectRuntimeNodesEqual(
        production_direct.nodes,
        authenticated_direct.nodes,
    );
    try std.testing.expectEqualSlices(
        u32,
        production_direct.roots,
        authenticated_direct.roots,
    );
    try std.testing.expectEqual(
        production_direct.column_count,
        authenticated_direct.column_count,
    );

    var production_lookups = try runtime_program.buildLookups(allocator, .lui);
    defer production_lookups.deinit();
    var authenticated_lookups = try runtime_program.buildLuiLookupsFromAuthority(
        allocator,
        &executor,
    );
    defer authenticated_lookups.deinit();
    try expectRuntimeNodesEqual(
        production_lookups.nodes,
        authenticated_lookups.nodes,
    );
    try std.testing.expectEqual(
        production_lookups.column_count,
        authenticated_lookups.column_count,
    );
    try std.testing.expectEqual(
        production_lookups.batch_size,
        authenticated_lookups.batch_size,
    );
    try std.testing.expectEqual(
        production_lookups.entries.len,
        authenticated_lookups.entries.len,
    );
    for (
        production_lookups.entries,
        authenticated_lookups.entries,
    ) |expected, actual| {
        try std.testing.expectEqual(expected.numerator, actual.numerator);
        try std.testing.expectEqual(expected.arity, actual.arity);
        try std.testing.expectEqualSlices(
            u32,
            expected.values[0..expected.arity],
            actual.values[0..actual.arity],
        );
    }
}

test "E-018 typed LUI fixed execution covers every upper immediate and destination" {
    var definition = try typed_lui.build(std.testing.allocator, .generated);
    const binding = authority.Binding.canonical(&definition);
    const executor = try authority.Authority.init(&definition, &binding);
    definition.deinit();

    var upper: u32 = 0;
    while (upper < (1 << 20)) : (upper += 1) {
        var rd_raw: u32 = 0;
        while (rd_raw < 32) : (rd_raw += 1) {
            const rd: u5 = @intCast(rd_raw);
            const actual = try executor.retire(luiInstruction(rd, upper));
            const attempted = upper << 12;
            if (actual.rd != rd or
                actual.write_enabled != (rd != 0) or
                actual.attempted_value != attempted or
                actual.visible_value != if (rd == 0) 0 else attempted)
            {
                return error.ExhaustiveLuiMismatch;
            }
        }
    }

    try std.testing.expectError(
        error.WrongLuiOpcode,
        executor.retire(.{ .opcode = .AUIPC, .rd = 1, .rs1 = 0, .rs2 = 0, .imm = 0 }),
    );
}

test "E-018 typed LUI fixed witness facade is exact and rejection atomic" {
    var definition = try typed_lui.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = authority.Binding.canonical(&definition);
    const executor = try authority.Authority.init(&definition, &binding);

    const uppers = [_]u32{ 0, 1, 0x7ff, 0x800, 0x7ffff, 0x80000, 0xffffe, 0xfffff };
    var rows: [32 * uppers.len]authority.TraceRow = undefined;
    var cursor: usize = 0;
    for (0..32) |rd| {
        for (uppers) |upper| {
            rows[cursor] = makeRow(@intCast(rd), upper, @intCast(cursor + 1));
            cursor += 1;
        }
    }

    var actual = try OwnedColumns.init(std.testing.allocator, 256, M31.fromCanonical(0x5151));
    defer actual.deinit();
    var legacy = try OwnedColumns.init(std.testing.allocator, 256, M31.fromCanonical(0x6262));
    defer legacy.deinit();
    try executor.generateMainInto(&actual.views, &rows, 8);
    for (rows, 0..) |row, index|
        legacy_witness.writeRow(&legacy.views, index, row);
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

test "E-018 typed LUI fixed direct and lookup hot paths retain production throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const executor = try authenticatedAuthority();

    // Heap-backed, full-extension inputs defeat loop-invariant folding while
    // keeping fixture construction outside the timed region. Each evaluator
    // sees the same cache-resident row stream in alternating sample order.
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
    const iterations = 1 << 15;
    var fixed_direct: [samples]u64 = undefined;
    var production_direct: [samples]u64 = undefined;
    var fixed_lookups: [samples]u64 = undefined;
    var production_lookups: [samples]u64 = undefined;
    for (0..samples) |sample| {
        if ((sample & 1) == 0) {
            fixed_direct[sample] = try measureFixedDirect(&executor, rows, active, iterations);
            production_direct[sample] = try measureProductionDirect(rows, active, iterations);
            fixed_lookups[sample] = try measureFixedLookups(&executor, rows, iterations);
            production_lookups[sample] = try measureProductionLookups(rows, iterations);
        } else {
            production_lookups[sample] = try measureProductionLookups(rows, iterations);
            fixed_lookups[sample] = try measureFixedLookups(&executor, rows, iterations);
            production_direct[sample] = try measureProductionDirect(rows, active, iterations);
            fixed_direct[sample] = try measureFixedDirect(&executor, rows, active, iterations);
        }
    }
    const fixed_direct_median = median(&fixed_direct);
    const production_direct_median = median(&production_direct);
    const fixed_lookup_median = median(&fixed_lookups);
    const production_lookup_median = median(&production_lookups);
    std.debug.print(
        "\n  E-018 LUI fixed authority: direct={d} ns production={d} ns " ++
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

    // Paired median non-inferiority: candidate must retain at least 97% of
    // the current direct and lookup throughput.
    try std.testing.expect(fixed_direct_median * 97 <= production_direct_median * 100);
    try std.testing.expect(fixed_lookup_median * 97 <= production_lookup_median * 100);
}

fn expectInvalidBinding(
    definition: *const typed_lui.Definition,
    malformed: authority.Binding,
) !void {
    try std.testing.expectError(
        error.InvalidAuthorityBinding,
        authority.Authority.init(definition, &malformed),
    );
}

fn authenticatedAuthority() !authority.Authority {
    var definition = try typed_lui.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = authority.Binding.canonical(&definition);
    return authority.Authority.init(&definition, &binding);
}

fn expectRuntimeNodesEqual(
    expected: []const prover_component.BasePolynomialNode,
    actual: []const prover_component.BasePolynomialNode,
) !void {
    try std.testing.expectEqualSlices(
        prover_component.BasePolynomialNode,
        expected,
        actual,
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

/// Test-only reconstruction of the retired relation adapter. Keeping this
/// outside `constraint_program.zig` prevents the legacy evaluator from
/// re-entering production while preserving an independent exact oracle for
/// transcript order, roles, access ordinals, and polynomial expressions.
fn legacyLookupProgram(
    comptime S: type,
    row: legacy_lui.Semantics(S).Row,
) lookup_entry.Builder(S).List {
    const e = lookup_entry.Builder(S);
    const requests = legacy_lui.Semantics(S).lookups(row);
    var result = e.List{};
    e.program(&result, requests.program.numerator, requests.program.tuple);
    e.stateRequests(&result, requests.state);
    e.range884(
        &result,
        requests.immediate_range.numerator,
        requests.immediate_range.tuple.values(),
    );
    e.memoryEventAt(
        &result,
        .consume,
        1,
        requests.rd.consume.numerator,
        requests.rd.consume.tuple,
    );
    e.memoryEventAt(
        &result,
        .emit,
        1,
        requests.rd.emit.numerator,
        requests.rd.emit.tuple,
    );
    e.range20At(
        &result,
        1,
        requests.rd.clock_gap.numerator,
        requests.rd.clock_gap.tuple.value,
    );
    return result;
}

fn luiInstruction(rd: u5, upper: u32) authority.DecodedInst {
    return .{
        .opcode = .LUI,
        .rd = rd,
        .rs1 = 0,
        .rs2 = 0,
        .imm = @bitCast(upper << 12),
    };
}

fn makeRow(rd: u5, upper: u32, clock: u32) authority.TraceRow {
    const result = upper << 12;
    return .{
        .clk = clock,
        .pc = 0x1000 +% (clock -% 1) *% 4,
        .opcode = .LUI,
        .rd = rd,
        .rs1 = 0,
        .rs2 = 0,
        .imm = @bitCast(result),
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_prev_val = clock *% 0x0102_0304,
        .rd_prev_clk = clock -% 1,
        .rd_val = if (rd == 0) 0 else result,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004 +% (clock -% 1) *% 4,
    };
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

fn measureFixedDirect(
    compiled: *const authority.Authority,
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |iteration| {
        const result = try compiled.evaluateDirect(
            QM31,
            &rows[iteration & (rows.len - 1)],
            active,
        );
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
            .lui,
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
    compiled: *const authority.Authority,
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0xbb67_ae85_84ca_a73b;
    for (0..iterations) |iteration| {
        var result: @import("../lookups/entry.zig").List = undefined;
        const columns = &rows[iteration & (rows.len - 1)];
        try compiled.buildLookupsInto(QM31, columns, &result);
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
        const columns = &rows[iteration & (rows.len - 1)];
        try ConcreteBuilder.buildLookupsInto(.lui, columns, &result);
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
    for (result.entries[0..result.len]) |entry| {
        absorbScalar(checksum, entry.numerator);
        for (entry.values[0..entry.arity]) |value| absorbScalar(checksum, value);
    }
}

fn median(samples: []u64) u64 {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return samples[samples.len / 2];
}
