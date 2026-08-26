const std = @import("std");
const symbolic = @import("../extract/symbolic.zig");
const lookup_entry = @import("../lookups/entry.zig");
const legacy_auipc = @import("../semantics/auipc_legacy_test_oracle.zig");
const authority = @import("typed_auipc_authority.zig");
const typed_auipc = @import("typed_auipc.zig");
const typed_auipc_witness = @import("typed_auipc_witness.zig");

test "E-020 AUIPC fixed authority is source-independent self-contained and pinned" {
    var generated = try typed_auipc.build(std.testing.allocator, .generated);
    var generated_live = true;
    defer if (generated_live) generated.deinit();
    var moved = try typed_auipc.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/auipc.air",
        .start = .{ .byte_offset = 117, .line = 11, .column = 3 },
        .end = .{ .byte_offset = 123, .line = 11, .column = 9 },
    } });
    defer moved.deinit();

    const binding = try authority.Binding.canonical(&generated);
    const admitted = try authority.Authority.init(&generated, &binding);
    const moved_binding = try authority.Binding.canonical(&moved);
    const moved_admitted = try authority.Authority.init(&moved, &moved_binding);
    try std.testing.expectEqual(typed_auipc.SEMANTIC_DIGEST, binding.semantic_digest);
    try std.testing.expectEqual(
        typed_auipc_witness.WITNESS_BINDING_DIGEST,
        binding.witness_binding_digest,
    );
    try std.testing.expectEqual(authority.AUTHORITY_BINDING_DIGEST, binding.identityDigest());
    try std.testing.expectEqual(binding.identityDigest(), admitted.identityDigest());
    try std.testing.expectEqual(admitted.identityDigest(), moved_admitted.identityDigest());
    try std.testing.expectEqualDeep(binding, moved_binding);
    try std.testing.expectEqualDeep(admitted, authority.Authority.pinned());

    generated.deinit();
    generated_live = false;
    const instruction = try auipcInstruction(31, 0x8abcd);
    const retired = try admitted.retire(instruction, 0x3fff_fffc);
    try std.testing.expect(retired.write_enabled);
    try std.testing.expectEqual(@as(u32, 0xcabc_cffc), retired.attempted_value);
    try std.testing.expectEqual(retired.attempted_value, retired.visible_value);
    try std.testing.expectEqual(@as(u32, 0x4000_0000), retired.next_pc);

    const x0 = try admitted.retire(try auipcInstruction(0, 0xfffff), 0x1000);
    try std.testing.expect(!x0.write_enabled);
    try std.testing.expectEqual(@as(u32, 0), x0.visible_value);
    try std.testing.expectEqual(@as(u32, 0), x0.attempted_value);
}

test "E-020 AUIPC fixed authority rejects every malformed binding class" {
    var definition = try typed_auipc.build(std.testing.allocator, .generated);
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
    malformed.lookups[6].arity = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(
        authority.LookupDescriptor,
        &malformed.lookups[10],
        &malformed.lookups[11],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);

    definition.model.roots[0] = definition.model.roots[1];
    try std.testing.expectError(
        error.InvalidAuipcDefinition,
        authority.Authority.init(&definition, &canonical),
    );
}

test "E-020 AUIPC fixed direct and relation programs are symbolically identical" {
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    for (&columns) |*column| column.* = arena.column("");
    const selector = arena.column("is_active");
    const Legacy = legacy_auipc.Semantics(symbolic.Scalar);
    const legacy_row = try Legacy.Row.fromMainColumns(&columns);
    const legacy_direct = Legacy.evaluate(legacy_row);
    const legacy_placement = Legacy.placementConstraint(legacy_row, selector);
    const legacy_lookups = legacyLookupProgram(symbolic.Scalar, legacy_row);
    const node_count_before = arena.nodes.items.len;

    const actual = try authority.Authority.pinned().buildProgram(
        symbolic.Scalar,
        &columns,
        selector,
    );
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
    try expectLookupListsEqual(
        symbolic.Scalar,
        legacy_lookups,
        actual.lookup_entries,
    );
}

test "E-020 AUIPC execution exhausts U-immediate signs destinations and PC boundaries" {
    const admitted = authority.Authority.pinned();
    const pcs = [_]u32{ 0, 4, 0x1000, (@as(u32, 1) << 30) - 4 };
    const uppers = [_]u32{ 0, 1, 0x7ffff, 0x80000, 0xfffff };
    for (pcs) |pc| for (uppers) |upper| for (0..32) |rd_raw| {
        const rd: u5 = @intCast(rd_raw);
        const instruction = try auipcInstruction(rd, upper);
        const retired = try admitted.retire(instruction, pc);
        const expected = pc +% (upper << 12);
        try std.testing.expectEqual(expected, retired.attempted_value);
        try std.testing.expectEqual(if (rd == 0) 0 else expected, retired.visible_value);
        try std.testing.expectEqual(pc +% 4, retired.next_pc);
    };
    try std.testing.expectError(
        error.WrongAuipcOpcode,
        admitted.retire(.{
            .opcode = .LUI,
            .rd = 1,
            .rs1 = 0,
            .rs2 = 0,
            .imm = 0,
        }, 0),
    );
    try std.testing.expectError(
        error.ProgramCounterOutOfRange,
        admitted.retire(try auipcInstruction(1, 0), @as(u32, 1) << 30),
    );
}

fn expectInvalidBinding(
    definition: *const typed_auipc.Definition,
    malformed: authority.Binding,
) !void {
    try std.testing.expectError(
        error.InvalidAuthorityBinding,
        authority.Authority.init(definition, &malformed),
    );
}

fn expectLookupListsEqual(
    comptime S: type,
    expected: lookup_entry.Builder(S).List,
    actual: lookup_entry.Builder(S).List,
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

/// Independent reconstruction of the retired Stark-V-shaped relation adapter.
fn legacyLookupProgram(
    comptime S: type,
    row: legacy_auipc.Semantics(S).Row,
) lookup_entry.Builder(S).List {
    const e = lookup_entry.Builder(S);
    const requests = legacy_auipc.Semantics(S).lookups(row);
    var result = e.List{};
    e.program(&result, requests.program.numerator, requests.program.tuple);
    e.stateRequests(&result, requests.state);
    for (requests.ranges.result) |request|
        e.range88(&result, request.numerator, request.tuple.values());
    e.range88(
        &result,
        requests.ranges.pc[0].numerator,
        requests.ranges.pc[0].tuple.values(),
    );
    e.rangeM31(
        &result,
        requests.ranges.pc[1].numerator,
        requests.ranges.pc[1].tuple.values(),
    );
    e.range88(
        &result,
        requests.ranges.immediate[0].numerator,
        requests.ranges.immediate[0].tuple.values(),
    );
    e.rangeM31(
        &result,
        requests.ranges.immediate[1].numerator,
        requests.ranges.immediate[1].tuple.values(),
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

fn auipcInstruction(rd: u5, upper: u32) !authority.DecodedInst {
    std.debug.assert(upper < (@as(u32, 1) << 20));
    return authority.DecodedInst.decode(
        (upper << 12) | (@as(u32, rd) << 7) | 0b0010111,
    );
}
