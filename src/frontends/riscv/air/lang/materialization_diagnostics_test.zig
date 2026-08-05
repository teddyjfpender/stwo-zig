const std = @import("std");
const compat = @import("typed_poseidon2_compat.zig");
const diagnostics = @import("materialization_diagnostics.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const golden_report_sha256 = [_]u8{
    0x33, 0xea, 0xdd, 0x08, 0x0a, 0x71, 0x5f, 0xe0,
    0x9d, 0x1b, 0x3e, 0xd3, 0xad, 0x8a, 0xbc, 0x18,
    0xcb, 0x35, 0xf7, 0x1e, 0x56, 0x89, 0x5e, 0x6a,
    0xc6, 0x28, 0x10, 0xa1, 0xdf, 0xeb, 0x0e, 0xf2,
};

test "materialization report covers all 426 source and physical identities exactly" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    var binding = try fixture.makeBinding(std.testing.allocator, &plan);
    defer binding.deinit(std.testing.allocator);
    const report = try renderMachine(std.testing.allocator, &fixture, &plan, &binding);
    defer std.testing.allocator.free(report);

    try std.testing.expect(std.mem.startsWith(
        u8,
        report,
        "schema=stwo.typed-air.poseidon2.materialization-report-v1\n" ++
            "format_version=1 record_count=426\n" ++
            "scope selection=root_closure identity=whole_program_digest " ++
            "plan_order=generic_dependency_topological " ++
            "placement_order=legacy_lane_major\n",
    ));
    try expectDeclaredRecordFields(report);
    var seen_ordinals = [_]bool{false} ** compat.N_MATERIALIZATIONS;
    var seen_plan_ids = [_]bool{false} ** compat.N_MATERIALIZATIONS;
    var seen_columns = [_]bool{false} ** compat.N_MAIN_COLUMNS;
    var record_count: usize = 0;
    var lines = std.mem.splitScalar(u8, report, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "record ")) continue;
        const ordinal = try decimalField(line, "legacy_ordinal=");
        const plan_id = try decimalField(line, "generic_plan_id=");
        const column_index = try decimalField(line, "column_index=");
        try std.testing.expect(ordinal < seen_ordinals.len and !seen_ordinals[ordinal]);
        try std.testing.expect(plan_id < seen_plan_ids.len and !seen_plan_ids[plan_id]);
        try std.testing.expect(column_index < seen_columns.len and !seen_columns[column_index]);
        seen_ordinals[ordinal] = true;
        seen_plan_ids[plan_id] = true;
        seen_columns[column_index] = true;
        try expectRecordFidelity(&fixture, &plan, binding.entries[ordinal], line);
        record_count += 1;
    }
    try std.testing.expectEqual(@as(usize, compat.N_MATERIALIZATIONS), record_count);
    for (seen_ordinals) |seen| try std.testing.expect(seen);
    for (seen_plan_ids) |seen| try std.testing.expect(seen);
    for (compat.TEMPORARY_START..compat.WIDE_COLUMN) |column_index| {
        try std.testing.expect(seen_columns[column_index]);
    }

    try expectRepresentative(
        report,
        0,
        "semantic_path=riscv.poseidon2_m31.external_round[0].lane[0].square",
        "phase=external_round round=0 lane=0 role=square " ++
            "constraint_ordinal=1 column_index=17 column_name=poseidon2.temporary[0]",
    );
    try expectRepresentative(
        report,
        32,
        "semantic_path=riscv.poseidon2_m31.external_round[1].lane[0].shifted",
        "phase=external_round round=1 lane=0 role=shifted " ++
            "constraint_ordinal=33 column_index=49 column_name=poseidon2.temporary[32]",
    );
    try expectRepresentative(
        report,
        176,
        "semantic_path=riscv.poseidon2_m31.internal_round[0].lane[0].shifted",
        "phase=internal_round round=0 lane=0 role=shifted " ++
            "constraint_ordinal=177 column_index=193 column_name=poseidon2.temporary[176]",
    );
    try expectRepresentative(
        report,
        410,
        "semantic_path=riscv.poseidon2_m31.output[0]",
        "phase=output round=none lane=0 role=output " ++
            "constraint_ordinal=411 column_index=427 column_name=poseidon2.temporary[410]",
    );

    var actual_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(report, &actual_digest, .{});
    if (!std.mem.eql(u8, &golden_report_sha256, &actual_digest)) {
        const hex = std.fmt.bytesToHex(actual_digest, .lower);
        std.debug.print("materialization report sha256={s}\n", .{&hex});
    }
    try std.testing.expectEqualSlices(u8, &golden_report_sha256, &actual_digest);
}

test "materialization report replay is byte stable and carries no allocation identity" {
    var first = try Fixture.init(std.testing.allocator);
    defer first.deinit();
    var first_plan = try first.makePlan(std.testing.allocator);
    defer first_plan.deinit();
    var first_binding = try first.makeBinding(std.testing.allocator, &first_plan);
    defer first_binding.deinit(std.testing.allocator);
    const first_report = try renderMachine(
        std.testing.allocator,
        &first,
        &first_plan,
        &first_binding,
    );
    defer std.testing.allocator.free(first_report);

    // Keep the first owner live so the replay necessarily occupies different
    // allocations. Only stable IDs and content may survive into the stream.
    var second = try Fixture.init(std.testing.allocator);
    defer second.deinit();
    var second_plan = try second.makePlan(std.testing.allocator);
    defer second_plan.deinit();
    var second_binding = try second.makeBinding(std.testing.allocator, &second_plan);
    defer second_binding.deinit(std.testing.allocator);
    const second_report = try renderMachine(
        std.testing.allocator,
        &second,
        &second_plan,
        &second_binding,
    );
    defer std.testing.allocator.free(second_report);

    try std.testing.expectEqualSlices(u8, first_report, second_report);
    try std.testing.expect(std.mem.indexOf(u8, first_report, "0x") == null);
    try std.testing.expect(std.mem.indexOf(u8, first_report, "pointer") == null);

    var human = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer human.deinit();
    try diagnostics.writeHuman(
        std.testing.allocator,
        &human.writer,
        &first.arena,
        first.definition,
        first.spans,
        &first_plan,
        &first_binding,
    );
    try std.testing.expect(std.mem.startsWith(
        u8,
        human.written(),
        "Poseidon2 materializations (426 slots; generic_dependency_topological " ++
            "plan -> legacy_lane_major placement)\n",
    ));
    try std.testing.expect(std.mem.indexOf(
        u8,
        human.written(),
        "legacy[410] column[427] poseidon2.temporary[410]",
    ) != null);
}

test "materialization report rejects corruption before emitting any byte" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    var binding = try fixture.makeBinding(std.testing.allocator, &plan);
    defer binding.deinit(std.testing.allocator);

    var storage: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const saved_value = binding.entries[0].value;
    binding.entries[0].value = binding.entries[1].value;
    try std.testing.expectError(
        error.PlanBindingMismatch,
        diagnostics.writeMachine(
            std.testing.allocator,
            &writer,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            &plan,
            &binding,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
    binding.entries[0].value = saved_value;

    const saved_digest_byte = plan.program_digest[0];
    plan.program_digest[0] ^= 1;
    try std.testing.expectError(
        error.ProgramDigestMismatch,
        diagnostics.writeMachine(
            std.testing.allocator,
            &writer,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            &plan,
            &binding,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
    plan.program_digest[0] = saved_digest_byte;
}

test "materialization report handles writer and validation allocation failures" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    var binding = try fixture.makeBinding(std.testing.allocator, &plan);
    defer binding.deinit(std.testing.allocator);

    var failing: std.Io.Writer = .failing;
    try std.testing.expectError(
        error.WriteFailed,
        diagnostics.writeMachine(
            std.testing.allocator,
            &failing,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            &plan,
            &binding,
        ),
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{ &fixture, &plan, &binding },
    );
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    plan: *const materializer.Plan,
    binding: *const compat.OwnedBinding,
) !void {
    var storage: [256]u8 = undefined;
    var discarding = std.Io.Writer.Discarding.init(&storage);
    try diagnostics.writeMachine(
        allocator,
        &discarding.writer,
        &fixture.arena,
        fixture.definition,
        fixture.spans,
        plan,
        binding,
    );
    try std.testing.expect(discarding.fullCount() > 200_000);
}

fn renderMachine(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    plan: *const materializer.Plan,
    binding: *const compat.OwnedBinding,
) ![]u8 {
    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    try diagnostics.writeMachine(
        allocator,
        &output.writer,
        &fixture.arena,
        fixture.definition,
        fixture.spans,
        plan,
        binding,
    );
    return output.toOwnedSlice();
}

fn expectRecordFidelity(
    fixture: *const Fixture,
    plan: *const materializer.Plan,
    entry: compat.Binding,
    line: []const u8,
) !void {
    const plan_index = types.idIndex(entry.plan_materialization);
    const planned = plan.materializations[plan_index];
    try std.testing.expectEqual(
        @as(usize, @intFromEnum(entry.value)),
        try decimalField(line, "value_id="),
    );
    try std.testing.expectEqualStrings(
        compat.POLICY_NAME,
        try field(line, "compatibility_policy="),
    );
    try std.testing.expectEqualStrings(
        materializer.policy_id,
        try field(line, "materializer_policy="),
    );
    try std.testing.expectEqualStrings(
        diagnostics.SELECTION_SCOPE,
        try field(line, "selection_scope="),
    );
    try std.testing.expectEqualStrings(
        diagnostics.IDENTITY_SCOPE,
        try field(line, "identity_scope="),
    );
    try std.testing.expectEqualStrings(
        planned.stable_name.slice(),
        try field(line, "stable_name="),
    );
    try std.testing.expectEqual(
        @as(usize, entry.source_span.start.byte_offset),
        try decimalField(line, "span_start_byte="),
    );
    try std.testing.expectEqual(
        @as(usize, entry.source_span.start.line),
        try decimalField(line, "span_start_line="),
    );
    try std.testing.expectEqual(
        @as(usize, entry.source_span.end.byte_offset),
        try decimalField(line, "span_end_byte="),
    );
    try std.testing.expectEqual(
        @as(usize, planned.constraint_degree),
        try decimalField(line, "constraint_degree="),
    );
    try std.testing.expectEqual(
        @as(usize, entry.materialization.constraint),
        try decimalField(line, "constraint_ordinal="),
    );

    var semantic_storage: [128]u8 = undefined;
    var semantic_writer = std.Io.Writer.fixed(&semantic_storage);
    try compat.writeSemanticPath(&semantic_writer, entry.materialization);
    try std.testing.expectEqualStrings(
        semantic_writer.buffered(),
        try field(line, "semantic_path="),
    );
    var column_storage: [64]u8 = undefined;
    var column_writer = std.Io.Writer.fixed(&column_storage);
    try compat.writeColumnName(&column_writer, entry.materialization.column);
    try std.testing.expectEqualStrings(
        column_writer.buffered(),
        try field(line, "column_name="),
    );
    const dependencies = plan.dependenciesFor(entry.plan_materialization).?;
    try expectDependencies(
        dependencies,
        try field(line, "generic_dependency_plan_ids="),
    );

    const source_id = entry.source_span.source.?;
    try std.testing.expectEqual(
        @as(usize, @intFromEnum(source_id)),
        try decimalField(line, "source_id="),
    );
    const path = fixture.arena.sourcePath(source_id).?;
    var path_hex_storage: [256]u8 = undefined;
    const path_hex = try hexInto(&path_hex_storage, path);
    try std.testing.expectEqualStrings(path_hex, try field(line, "source_path_hex="));
}

fn expectDependencies(
    expected: []const materializer.MaterializationId,
    encoded: []const u8,
) !void {
    if (expected.len == 0) {
        try std.testing.expectEqualStrings("none", encoded);
        return;
    }
    var actual = std.mem.splitScalar(u8, encoded, ',');
    for (expected) |dependency| {
        const item = actual.next() orelse return error.MissingDependency;
        try std.testing.expectEqual(
            @as(usize, @intFromEnum(dependency)),
            try std.fmt.parseInt(usize, item, 10),
        );
    }
    try std.testing.expect(actual.next() == null);
}

fn expectRepresentative(
    report: []const u8,
    ordinal: usize,
    semantic: []const u8,
    placement: []const u8,
) !void {
    const line = record(report, ordinal) orelse return error.MissingRecord;
    try std.testing.expect(std.mem.indexOf(u8, line, semantic) != null);
    try std.testing.expect(std.mem.indexOf(u8, line, placement) != null);
}

fn expectDeclaredRecordFields(report: []const u8) !void {
    const declaration_prefix = "fields=";
    var declared: ?[]const u8 = null;
    var first_record: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, report, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, declaration_prefix)) {
            declared = line[declaration_prefix.len..];
        } else if (first_record == null and std.mem.startsWith(u8, line, "record ")) {
            first_record = line;
        }
    }
    try std.testing.expectEqualStrings(diagnostics.RECORD_FIELDS, declared orelse
        return error.MissingFieldDeclaration);

    var names = std.mem.splitScalar(u8, declared.?, ',');
    var tokens = std.mem.splitScalar(u8, first_record orelse
        return error.MissingRecord, ' ');
    try std.testing.expectEqualStrings("record", tokens.next().?);
    while (names.next()) |name| {
        const token = tokens.next() orelse return error.MissingRecordField;
        const equals = std.mem.indexOfScalar(u8, token, '=') orelse
            return error.MalformedRecordField;
        try std.testing.expectEqualStrings(name, token[0..equals]);
    }
    try std.testing.expect(tokens.next() == null);
}

fn record(report: []const u8, ordinal: usize) ?[]const u8 {
    var prefix_storage: [48]u8 = undefined;
    const prefix = std.fmt.bufPrint(
        &prefix_storage,
        "record legacy_ordinal={d} ",
        .{ordinal},
    ) catch return null;
    var lines = std.mem.splitScalar(u8, report, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, prefix)) return line;
    }
    return null;
}

fn decimalField(line: []const u8, key: []const u8) !usize {
    return std.fmt.parseInt(usize, try field(line, key), 10);
}

fn field(line: []const u8, key: []const u8) ![]const u8 {
    const key_start = std.mem.indexOf(u8, line, key) orelse return error.MissingField;
    const start = key_start + key.len;
    const tail = line[start..];
    const end = std.mem.indexOfScalar(u8, tail, ' ') orelse tail.len;
    return tail[0..end];
}

fn hexInto(storage: []u8, bytes: []const u8) ![]const u8 {
    if (storage.len < bytes.len * 2) return error.HexBufferTooSmall;
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        storage[2 * index] = alphabet[byte >> 4];
        storage[2 * index + 1] = alphabet[byte & 0x0f];
    }
    return storage[0 .. bytes.len * 2];
}

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
        return .{ .arena = arena, .gate = gate, .spans = spans, .definition = definition };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn makePlan(self: *const Fixture, allocator: std.mem.Allocator) !materializer.Plan {
        const roots = poseidon.values(self.definition.outputs);
        return materializer.plan(allocator, &self.arena, .{
            .roots = &roots,
            .gate = self.gate,
        });
    }

    fn makeBinding(
        self: *const Fixture,
        allocator: std.mem.Allocator,
        plan: *const materializer.Plan,
    ) !compat.OwnedBinding {
        var schedule = try compat.generate(allocator);
        defer schedule.deinit(allocator);
        return compat.bindPlan(
            allocator,
            &self.arena,
            self.definition,
            self.spans,
            schedule,
            plan,
        );
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
