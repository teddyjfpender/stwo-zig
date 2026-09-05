const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const candidate = @import("typed_load_store_selector_alias_candidate_v1.zig");
const decode = @import("../../runner/decode.zig");
const degree = @import("degree.zig");
const typed = @import("typed_load_store.zig");
const types = @import("types.zig");

test "selector-alias candidate authors 48 columns with unchanged roots relations and degree" {
    var compact = try candidate.build(std.testing.allocator);
    defer compact.deinit();
    var canonical = try typed.build(std.testing.allocator, .generated);
    defer canonical.deinit();

    try compact.validate();
    try std.testing.expect(!candidate.production_active);
    try std.testing.expectEqual(@as(usize, 48), compact.physical.len);
    try std.testing.expectEqual(compact.columns.src.addr, compact.columns.src_addr_selector);
    try std.testing.expectEqual(compact.columns.dst.addr, compact.columns.dst_addr_selector);
    try std.testing.expectEqual(
        canonical.arena.constraintsView().len,
        compact.arena.constraintsView().len,
    );
    try std.testing.expectEqual(
        canonical.arena.effectsView().len,
        compact.arena.effectsView().len,
    );

    var compact_degrees = try degree.analyze(std.testing.allocator, &compact.arena);
    defer compact_degrees.deinit();
    var canonical_degrees = try degree.analyze(std.testing.allocator, &canonical.arena);
    defer canonical_degrees.deinit();
    try std.testing.expectEqual(
        canonical_degrees.maximumConstraintDegree(),
        compact_degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqual(@as(degree.Degree, 3), compact_degrees.maximumConstraintDegree());
    for (compact.model.constraints, canonical.model.constraints) |compact_id, canonical_id| {
        try std.testing.expectEqual(
            canonical_degrees.constraint(canonical_id),
            compact_degrees.constraint(compact_id),
        );
    }
    for (compact.arena.effectsView(), canonical.arena.effectsView(), 0..) |
        compact_effect,
        canonical_effect,
        index,
    | {
        const effect_id = try types.idFromIndex(types.EffectId, index);
        try std.testing.expectEqual(canonical_effect.kind, compact_effect.kind);
        try std.testing.expect(std.meta.eql(canonical_effect.binding, compact_effect.binding));
        try std.testing.expectEqual(canonical_effect.access_ordinal, compact_effect.access_ordinal);
        try std.testing.expectEqual(
            canonical.arena.effectValues(effect_id).?.len,
            compact.arena.effectValues(effect_id).?.len,
        );
    }
    try std.testing.expect(!std.mem.eql(
        u8,
        &compact.verifier_program_identity,
        &typed.SEMANTIC_DIGEST,
    ));

    const saved_identity = compact.verifier_program_identity;
    compact.verifier_program_identity[0] ^= 1;
    try std.testing.expectError(error.InvalidSelectorAliasProgram, compact.validate());
    compact.verifier_program_identity = saved_identity;

    const saved_source_alias = compact.columns.src_addr_selector;
    compact.columns.src_addr_selector = compact.columns.clock;
    try std.testing.expectError(error.InvalidSelectorAliasProgram, compact.validate());
    compact.columns.src_addr_selector = saved_source_alias;

    const first = compact.physical[0];
    compact.physical[0] = compact.physical[1];
    compact.physical[1] = first;
    try std.testing.expectError(error.InvalidSelectorAliasProgram, compact.validate());
    compact.physical[1] = compact.physical[0];
    compact.physical[0] = first;
    try compact.validate();
}

test "selector-alias projection expands exactly for all eight RV32 opcode paths" {
    const opcodes = [_]decode.Opcode{ .LB, .LH, .LBU, .LHU, .LW, .SB, .SH, .SW };
    for (opcodes, 0..) |opcode, index| {
        const offset: u2 = switch (opcode) {
            .LB, .LBU, .SB => 3,
            .LH, .LHU, .SH => 2,
            .LW, .SW => 0,
            else => unreachable,
        };
        const canonical = try candidate.canonicalTraceRow(makeRow(
            opcode,
            offset,
            0x80ff_7e01 +% @as(u32, @intCast(index)),
            index,
        ));
        try std.testing.expectEqual(
            canonical[candidate.source_address_column].toU32(),
            canonical[candidate.source_selector_column].toU32(),
        );
        try std.testing.expectEqual(
            canonical[candidate.destination_address_column].toU32(),
            canonical[candidate.destination_selector_column].toU32(),
        );
        const compact = try candidate.project(canonical);
        const expanded = candidate.expand(compact);
        try expectM31SliceEqual(&canonical, &expanded);
        const reprojected = try candidate.project(expanded);
        try expectM31SliceEqual(&compact, &reprojected);
    }

    var forged_source = try candidate.canonicalTraceRow(makeRow(.LB, 1, 0x80, 9));
    forged_source[candidate.source_selector_column] =
        forged_source[candidate.source_selector_column].add(M31.one());
    try std.testing.expectError(error.SelectorAliasMismatch, candidate.project(forged_source));

    var forged_destination = try candidate.canonicalTraceRow(makeRow(.SW, 0, 0x1234, 10));
    forged_destination[candidate.destination_selector_column] =
        forged_destination[candidate.destination_selector_column].add(M31.one());
    try std.testing.expectError(
        error.SelectorAliasMismatch,
        candidate.project(forged_destination),
    );
}

test "selector-alias geometry projects exact retained 210-leaf load-store savings" {
    const retained_rows = [_]u32{
        1069449, 915263,  802705,  762738,  823800,  1504170, 1735630, 1733646,
        1501886, 1338350, 1338159, 1338716, 1338352, 1338837, 1340373, 1340094,
        1339275, 1338644, 1340226, 1343637, 1341155, 1343140, 1343756, 1345276,
        1341413, 1342302, 1593596, 1773407, 1620116, 1340268, 1340296, 1339308,
        1339769, 1338787, 1341905, 1337583, 1341100, 1337169, 1338444, 1338952,
        1335689, 1349851, 1343085, 1341576, 1339058, 1341260, 1346248, 1340976,
        1339337, 1338473, 1343900, 1359754, 1339925, 1335530, 1334655, 1337273,
        1333501, 1338417, 1566487, 1592572, 1685017, 1509958, 1595000, 1634812,
        1301641, 1308816, 1338050, 1481409, 1340482, 1456047, 1359058, 1335643,
        1337823, 1350263, 1334964, 1343186, 1437098, 1598983, 1347417, 1442222,
        1362433, 1434007, 1345789, 1330772, 1365007, 1327868, 1307917, 1507499,
        1399953, 1359031, 1299601, 1329398, 1328466, 1543610, 1533616, 1414946,
        1534331, 1595846, 1576401, 1330730, 1355377, 1319805, 1449715, 1392799,
        1371502, 1333431, 1487679, 1304052, 1437753, 1297925, 1394028, 1432671,
        1446262, 1386424, 1587003, 1520987, 1471887, 1305019, 1322468, 1556708,
        1531138, 1596102, 1601261, 1327359, 1325769, 1681656, 1594429, 1460280,
        1455722, 1564050, 1592894, 1681972, 1525054, 1593379, 1645689, 1572593,
        1594760, 1632655, 1565403, 1595305, 1603098, 1427621, 1303546, 1385959,
        1328758, 1342879, 1547110, 1299424, 1389337, 1330192, 1370327, 1599175,
        1676761, 1519277, 1597541, 1634263, 1510745, 1595931, 1626209, 1357545,
        1404737, 1343630, 1424918, 1296833, 1413487, 1325144, 1422662, 1304301,
        1384187, 1323236, 1345562, 1415667, 1431505, 1303368, 1367078, 1337164,
        1326528, 1308526, 1308752, 1291719, 1273405, 1272764, 1273688, 893728,
        866672,  858040,  855714,  855388,  855427,  855252,  855241,  853400,
        852000,  851914,  851894,  851793,  851678,  851889,  852244,  852990,
        852224,  852501,  852008,  852466,  852007,  851355,  852691,  853700,
        853778,  907262,
    };
    const projection = try candidate.projectGeometry(&retained_rows);
    try std.testing.expectEqual(@as(u32, 210), projection.leaf_count);
    try std.testing.expectEqual(@as(u64, 280_225_149), projection.active_rows);
    try std.testing.expectEqual(@as(u64, 4_386), projection.shard_count);
    try std.testing.expectEqual(@as(u64, 282_025_120), projection.padded_domain_rows);
    try std.testing.expectEqual(@as(u64, 14_101_256_000), projection.canonical_main_cells);
    try std.testing.expectEqual(@as(u64, 13_537_205_760), projection.candidate_main_cells);
    try std.testing.expectEqual(@as(u64, 564_050_240), projection.saved_main_cells);
    try std.testing.expectEqual(@as(u64, 2_256_200_960), projection.saved_raw_bytes);

    const boundary = try candidate.projectGeometry(&.{ 0, 1, 17, 65_536, 65_537 });
    try std.testing.expectEqual(@as(u64, 5), boundary.shard_count);
    try std.testing.expectEqual(@as(u64, 131_136), boundary.padded_domain_rows);
}

fn makeRow(opcode: decode.Opcode, offset: u2, value: u32, index: usize) candidate.TraceRow {
    const is_load = switch (opcode) {
        .LB, .LH, .LBU, .LHU, .LW => true,
        else => false,
    };
    const rd: u5 = if (index == 4) 0 else 10;
    return .{
        .clk = @intCast(index + 9),
        .pc = @intCast(0x1000 + index * 4),
        .opcode = opcode,
        .rd = rd,
        .rs1 = 5,
        .rs2 = 6,
        .imm = 0,
        .rs1_val = 0x3000,
        .rs2_val = value,
        .rs1_prev_clk = 2,
        .rs2_prev_clk = 3,
        .rd_prev_val = 0x5566_7788,
        .rd_prev_clk = 4,
        .rd_val = if (is_load and rd != 0) value else 0,
        .mem_addr = 0x3000 + @as(u32, offset),
        .mem_val = value,
        .mem_prev_word = 0xa1b2_c3d4,
        .mem_next_word = if (is_load) 0xa1b2_c3d4 else value,
        .mem_prev_clk = 5,
        .is_load = is_load,
        .is_store = !is_load,
        .branch_taken = false,
        .next_pc = @intCast(0x1004 + index * 4),
    };
}

fn expectM31SliceEqual(expected: []const M31, actual: []const M31) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |lhs, rhs|
        try std.testing.expectEqual(lhs.toU32(), rhs.toU32());
}
