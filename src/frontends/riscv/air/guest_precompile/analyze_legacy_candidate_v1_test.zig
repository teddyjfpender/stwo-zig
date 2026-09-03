const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const candidate = @import("analyze_legacy_candidate_v1.zig");
const scan = @import("analyze_legacy_scan_candidate_v1.zig");
const bitmap = @import("analyze_legacy_bitmap_candidate_v1.zig");
const relations = @import("analyze_legacy_relations_candidate_v1.zig");
const reference = @import("../../../../tools/riscv/analyze_legacy_semantics/semantics.zig");

const sample_source = [_]u8{
    0x60, 0x5b, // PUSH1 0x5b: the immediate must not become a bitmap bit.
    0x5b, // The scanned JUMPDEST must become a bitmap bit.
    0xe6, // DUPN affects EOF-immediate padding when followed by STOP.
    0x00,
};

test "descriptor parity binds exact Revm42 semantics and excludes fallbacks" {
    const descriptor = try candidate.DescriptorV1.init(7, 0x2000, &sample_source);
    var expected = try reference.analyze(std.testing.allocator, &sample_source);
    defer expected.deinit(std.testing.allocator);
    try std.testing.expectEqual(expected.bitmap_bytes, descriptor.summary.bitmap_bytes);
    try std.testing.expectEqual(expected.scanIterations(), descriptor.summary.scan_iterations);
    try std.testing.expectEqual(expected.push_count, descriptor.summary.push_count);
    try std.testing.expectEqual(expected.jumpdest_count, descriptor.summary.jumpdest_count);
    try std.testing.expectEqual(expected.push_overflow, descriptor.summary.push_overflow);
    try std.testing.expectEqual(
        expected.eof_immediate_padding,
        descriptor.summary.eof_immediate_padding,
    );
    try std.testing.expectEqual(expected.total_padding, descriptor.summary.total_padding);
    try descriptor.validate(&sample_source);

    const caller = candidate.CallerV1{
        .entry_clock = 9,
        .entry_pc = candidate.function_entry_pc,
        .bytes_struct_pointer = 0x1800,
        .descriptor = descriptor,
    };
    try caller.validate(&sample_source);
    try std.testing.expectError(
        error.EmptyBytecodeUsesNewRaw,
        candidate.DescriptorV1.init(0, 0x2000, &.{}),
    );
    try std.testing.expectError(
        error.Eip7702BytecodeUsesNewRaw,
        candidate.DescriptorV1.init(0, 0x2000, &.{ 0xef, 0x01, 0x44 }),
    );
    var wrong_source = sample_source;
    wrong_source[2] = 0x5c;
    try std.testing.expectError(
        error.InvalidCallDescriptor,
        descriptor.validate(&wrong_source),
    );
    var wrong_caller = caller;
    wrong_caller.entry_pc += 4;
    try std.testing.expectError(
        error.InvalidCallDescriptor,
        wrong_caller.validate(&sample_source),
    );
    try std.testing.expectEqualStrings(
        "45f05bd88fd09e32ea43cf5e94190759ea6ace7c",
        candidate.revm_git_revision,
    );
    try std.testing.expectEqualStrings(
        "cf26e05a027549b772a04ff4f2ad7bcd03eaaa5dbd42d53f03830050504671d4",
        candidate.revm_source_sha256_hex,
    );
}

test "scan AIR closes in M31 and QM31 with identical constraint inventory" {
    const descriptor = try candidate.DescriptorV1.init(3, 0x4000, &sample_source);
    const rows = try scan.materialize(std.testing.allocator, descriptor, &sample_source);
    defer std.testing.allocator.free(rows);
    try std.testing.expectEqual(@as(usize, 4), rows.len);
    for (rows, 0..) |row, index| {
        const next = if (index + 1 < rows.len) rows[index + 1] else scan.zeroRow(M31);
        var base_sink = Sink(M31){};
        scan.evaluateGeneric(
            M31,
            &row,
            &next,
            M31.one(),
            feltBool(index + 1 < rows.len),
            feltBool(index == 0),
            &base_sink,
        );
        try std.testing.expectEqual(@as(usize, 0), base_sink.nonzero);

        const secure_row = scan.liftRow(QM31, &row);
        const secure_next = scan.liftRow(QM31, &next);
        var secure_sink = Sink(QM31){};
        scan.evaluateGeneric(
            QM31,
            &secure_row,
            &secure_next,
            QM31.one(),
            secureBool(index + 1 < rows.len),
            secureBool(index == 0),
            &secure_sink,
        );
        try std.testing.expectEqual(base_sink.count, secure_sink.count);
        try std.testing.expectEqual(@as(usize, 0), secure_sink.nonzero);
    }
    const source_tuple = scan.sourceByteTuple(M31, &rows[1]);
    try std.testing.expectEqual(@as(u32, 0x4002), source_tuple[1].toU32());
    try std.testing.expectEqual(@as(u32, 2), source_tuple[2].toU32());
    try std.testing.expectEqual(@as(u32, candidate.jumpdest_opcode), source_tuple[3].toU32());
}

test "scan AIR rejects cursor byte history count overflow and EOF mutations" {
    const truncated = [_]u8{ 0x5b, 0x7f, 0xaa };
    const descriptor = try candidate.DescriptorV1.init(1, 0x3000, &truncated);
    const rows = try scan.materialize(std.testing.allocator, descriptor, &truncated);
    defer std.testing.allocator.free(rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(@as(u32, 31), rows[1].push_overflow.toU32());
    try expectScanMutation(rows, 0, struct {
        fn mutate(row: *scan.Row(M31), _: *scan.Row(M31)) void {
            row.source_byte_bits[0] = toggle(row.source_byte_bits[0]);
        }
    }.mutate);
    try expectScanMutation(rows, 0, struct {
        fn mutate(_: *scan.Row(M31), next: *scan.Row(M31)) void {
            next.previous_opcode = next.previous_opcode.add(M31.one());
        }
    }.mutate);
    try expectScanMutation(rows, 0, struct {
        fn mutate(row: *scan.Row(M31), _: *scan.Row(M31)) void {
            row.next_cursor = row.next_cursor.add(M31.one());
        }
    }.mutate);
    try expectScanMutation(rows, 1, struct {
        fn mutate(row: *scan.Row(M31), _: *scan.Row(M31)) void {
            row.push_overflow = row.push_overflow.add(M31.one());
        }
    }.mutate);
    try expectScanMutation(rows, 1, struct {
        fn mutate(row: *scan.Row(M31), _: *scan.Row(M31)) void {
            row.eof_immediate_padding = row.eof_immediate_padding.add(M31.one());
        }
    }.mutate);
}

test "bitmap AIR proves valid prefix and zero unused bits in both fields" {
    const descriptor = try candidate.DescriptorV1.init(3, 0x4000, &sample_source);
    const rows = try bitmap.materialize(std.testing.allocator, descriptor, &sample_source);
    defer std.testing.allocator.free(rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    const zero = bitmap.zeroRow(M31);
    var base_sink = Sink(M31){};
    bitmap.evaluateGeneric(
        M31,
        &rows[0],
        &zero,
        M31.one(),
        M31.zero(),
        M31.one(),
        &base_sink,
    );
    try std.testing.expectEqual(@as(usize, 0), base_sink.nonzero);
    const secure_row = bitmap.liftRow(QM31, &rows[0]);
    const secure_zero = bitmap.zeroRow(QM31);
    var secure_sink = Sink(QM31){};
    bitmap.evaluateGeneric(
        QM31,
        &secure_row,
        &secure_zero,
        QM31.one(),
        QM31.zero(),
        QM31.one(),
        &secure_sink,
    );
    try std.testing.expectEqual(base_sink.count, secure_sink.count);
    try std.testing.expectEqual(@as(usize, 0), secure_sink.nonzero);

    var malformed = rows[0];
    malformed.bitmap_bits[31] = M31.one();
    try expectBitmapNonzero(malformed);
    malformed = rows[0];
    malformed.valid_bits[3] = M31.zero();
    try expectBitmapNonzero(malformed);
    malformed = rows[0];
    malformed.bitmap_tail_padding_bits[0] = toggle(
        malformed.bitmap_tail_padding_bits[0],
    );
    try expectBitmapNonzero(malformed);
}

test "bitmap set bits cancel exactly against semantic JUMPDEST requests" {
    const descriptor = try candidate.DescriptorV1.init(11, 0x5000, &sample_source);
    const scan_rows = try scan.materialize(
        std.testing.allocator,
        descriptor,
        &sample_source,
    );
    defer std.testing.allocator.free(scan_rows);
    const bitmap_rows = try bitmap.materialize(
        std.testing.allocator,
        descriptor,
        &sample_source,
    );
    defer std.testing.allocator.free(bitmap_rows);
    try relations.validateStatement(descriptor, scan_rows, bitmap_rows);
    try std.testing.expectEqual(@as(u32, 0), bitmap_rows[0].bitmap_bits[1].toU32());
    try std.testing.expectEqual(@as(u32, 1), bitmap_rows[0].bitmap_bits[2].toU32());

    const elements = relations.Elements(M31){
        .z = M31.fromCanonical(91),
        .alpha = M31.fromCanonical(17),
    };
    const request = relations.scanInteraction(M31, &scan_rows[1], elements);
    const supply = relations.bitmapInteraction(M31, &bitmap_rows[0], 2, elements);
    try std.testing.expect(request.denominator.eql(supply.denominator));
    try std.testing.expect(request.numerator.add(supply.numerator).isZero());

    var malformed = try std.testing.allocator.dupe(bitmap.Row(M31), bitmap_rows);
    defer std.testing.allocator.free(malformed);
    malformed[0].bitmap_bits[2] = M31.zero();
    try std.testing.expectError(
        error.JumpdestMultiplicityMismatch,
        relations.validateExactJumpdestClosure(scan_rows, malformed),
    );
    malformed[0] = bitmap_rows[0];
    malformed[0].bitmap_bits[3] = M31.one();
    try std.testing.expectError(
        error.JumpdestMultiplicityMismatch,
        relations.validateExactJumpdestClosure(scan_rows, malformed),
    );
    var wrong_descriptor = descriptor;
    wrong_descriptor.summary.scan_iterations += 1;
    try std.testing.expectError(
        error.DescriptorMismatch,
        relations.validateStatement(wrong_descriptor, scan_rows, bitmap_rows),
    );
}

test "retained projection is exact diagnostic custody and never a proof claim" {
    try candidate.retained_projection.validate();
    try std.testing.expectEqual(@as(u32, 115), candidate.retained_projection.call_count);
    try std.testing.expectEqual(@as(u64, 796_670), candidate.retained_projection.scan_rows);
    try std.testing.expectEqual(@as(u64, 166_105), candidate.retained_projection.bitmap_bytes);
    try std.testing.expectEqual(
        @as(u64, 41_558),
        candidate.retained_projection.bitmap_word_rows,
    );
    try std.testing.expect(!candidate.production_active);
    try std.testing.expect(!candidate.opcode_allocated);
    try std.testing.expect(!candidate.proof_opcode_allocated);
    try std.testing.expect(!candidate.stark_component_ready);
    try std.testing.expect(!scan.memory_relation_ready);
    try std.testing.expect(!bitmap.interaction_component_ready);
    try std.testing.expect(!relations.relation_registered);
    try std.testing.expect(candidate.retained_projection.proof_claim == null);
    try std.testing.expect(candidate.retained_projection.end_to_end_claim == null);

    var malformed = candidate.retained_projection;
    malformed.scan_rows += 1;
    try std.testing.expectError(error.InvalidCallDescriptor, malformed.validate());
    malformed = candidate.retained_projection;
    malformed.production = true;
    try std.testing.expectError(error.InvalidCallDescriptor, malformed.validate());
}

fn expectScanMutation(
    clean: []const scan.Row(M31),
    index: usize,
    mutate: *const fn (*scan.Row(M31), *scan.Row(M31)) void,
) !void {
    var row = clean[index];
    var next = if (index + 1 < clean.len) clean[index + 1] else scan.zeroRow(M31);
    mutate(&row, &next);
    var sink = Sink(M31){};
    scan.evaluateGeneric(
        M31,
        &row,
        &next,
        M31.one(),
        feltBool(index + 1 < clean.len),
        feltBool(index == 0),
        &sink,
    );
    try std.testing.expect(sink.nonzero != 0);
}

fn expectBitmapNonzero(row: bitmap.Row(M31)) !void {
    const zero = bitmap.zeroRow(M31);
    var sink = Sink(M31){};
    bitmap.evaluateGeneric(
        M31,
        &row,
        &zero,
        M31.one(),
        M31.zero(),
        M31.one(),
        &sink,
    );
    try std.testing.expect(sink.nonzero != 0);
}

fn Sink(comptime S: type) type {
    return struct {
        count: usize = 0,
        nonzero: usize = 0,

        pub fn add(self: *@This(), value: S, degree: u8) void {
            std.debug.assert(degree <= scan.maximum_constraint_degree);
            self.count += 1;
            self.nonzero += @intFromBool(!value.isZero());
        }
    };
}

fn toggle(value: M31) M31 {
    return M31.one().sub(value);
}

fn feltBool(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

fn secureBool(value: bool) QM31 {
    return QM31.fromBase(feltBool(value));
}
