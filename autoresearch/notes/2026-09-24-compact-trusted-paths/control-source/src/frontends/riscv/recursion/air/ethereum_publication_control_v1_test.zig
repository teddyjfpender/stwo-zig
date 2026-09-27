const std = @import("std");
const Air = @import("ethereum_publication_control_v1.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const legacy = @import("vm_public_logup_control.zig").Air;
const binding = @import("universal_relation_binding.zig");
const direct = @import("direct_constraint_program.zig");
test "Ethereum publication control preserves schedule tuples and rejects inactive values" {
    const allocator = std.testing.allocator;
    const identity = try Air.semanticIdentity(allocator);
    std.debug.print("ETHEREUM_PUBLICATION_CONTROL_SEAL={s}\n", .{std.fmt.bytesToHex(identity.bytes, .lower)});
    try std.testing.expectEqualStrings(Air.SEMANTIC_DIGEST_HEX, &std.fmt.bytesToHex(identity.bytes, .lower));
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    var old = try legacy.build(allocator);
    defer old.deinit();
    const old_plan = try binding.Binding(legacy).authenticate(&old);
    const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var constraints: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for ([_]u32{ 0, 1 }) |segment| for ([_]u32{ 0, 1 }) |binary| for ([_]u32{ 0, 1 }) |lane| {
        const row: [11]M31 = .{ M31.one(), M31.fromCanonical(lane), M31.one(), M31.fromCanonical(7), M31.fromCanonical(5), M31.zero(), M31.zero(), M31.zero(), M31.zero(), M31.fromCanonical(segment), M31.fromCanonical(binary) };
        var converted = Air.controlRow(row);
        const entries = plan.preparedEntries(converted);
        const original = old_plan.preparedEntries(row);
        try std.testing.expectEqual(original[0].domain, entries[0].domain);
        try std.testing.expect(original[0].numerator.eql(entries[0].numerator));
        try std.testing.expectEqualSlices(@TypeOf(entries[0].values[0]), original[0].values[0..original[0].arity], entries[0].values[0..entries[0].arity]);
        for (entries[1..]) |entry| try std.testing.expect(entry.numerator.isZero());
        try program.evaluateBaseInto(&converted, &scratch, &constraints);
        for (constraints) |constraint| try std.testing.expect(constraint.isZero());
        converted[0] = M31.one();
        try program.evaluateBaseInto(&converted, &scratch, &constraints);
        try std.testing.expect(!constraints[1].isZero());
    };
}

test "Ethereum publication control joins canonical fields and rejects modulus aliases" {
    const allocator = std.testing.allocator;
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const plan = try Air.Relation.authenticate(&definition);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var constraints: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    var pp = [_]u32{0} ** Air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    pp[13] = 1;
    pp[14] = 1102;
    pp[15] = 16;
    for ([_]u32{ 0, 1, 65535, 65536, 2147483646 }) |word| {
        var row = try Air.rawWordRow(M31.fromCanonical(word), M31.fromCanonical(word & 65535), M31.fromCanonical(word >> 16), true, 32, pp);
        try program.evaluateBaseInto(&row, &scratch, &constraints);
        for (constraints) |constraint| try std.testing.expect(constraint.isZero());
        const entries = plan.preparedEntries(row);
        for (entries[9..12]) |entry| for (entry.values[0..entry.arity]) |value|
            try std.testing.expect(value.toM31Array()[0].toU32() < 256);
        row[1] = row[1].add(M31.one());
        try program.evaluateBaseInto(&row, &scratch, &constraints);
        var rejected = false;
        for (constraints) |constraint| rejected = rejected or !constraint.isZero();
        try std.testing.expect(rejected);
    }
    try std.testing.expectError(error.NoncanonicalPublicationWord, Air.rawWordRow(M31.zero(), M31.fromCanonical(65535), M31.fromCanonical(32767), true, 32, pp));
    try std.testing.expectError(error.NoncanonicalPublicationWord, Air.rawWordRow(M31.zero(), M31.zero(), M31.fromCanonical(32768), true, 32, pp));
    var alias = try Air.rawWordRow(M31.zero(), M31.zero(), M31.zero(), true, 32, pp);
    alias[1] = M31.fromCanonical(65535);
    alias[2] = M31.fromCanonical(32767);
    alias[3] = M31.fromCanonical(255);
    alias[4] = M31.fromCanonical(255);
    alias[5] = M31.fromCanonical(255);
    alias[6] = M31.fromCanonical(127);
    alias[7] = M31.zero();
    alias[8] = M31.zero();
    alias[9] = M31.fromCanonical(254);
    try program.evaluateBaseInto(&alias, &scratch, &constraints);
    try std.testing.expect(!constraints[15].isZero());
    const single = try Air.rawWordRow(M31.fromCanonical(2147483646), M31.fromCanonical(2147483646), M31.zero(), false, 124, pp);
    try program.evaluateBaseInto(&single, &scratch, &constraints);
    for (constraints) |constraint| try std.testing.expect(constraint.isZero());
    const entries = plan.preparedEntries(single);
    for (entries[8..]) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "Ethereum publication control authenticates claim sources against raw frame words" {
    const interaction = @import("relation_interaction.zig");
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    var pp = [_]u32{0} ** Air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    pp[11] = 0;
    pp[12] = 73;
    pp[32] = 1;
    const row = try Air.rawWordRow(M31.fromCanonical(19), M31.fromCanonical(19), M31.zero(), false, 268435456, pp);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var constraints: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try program.evaluateBaseInto(&row, &scratch, &constraints);
    for (constraints) |constraint| try std.testing.expect(constraint.isZero());
    const original = plan.preparedEntries(row);
    const domain = original[12].domain;
    const domain_mask = @as(u64, 1) << @as(u6, @intCast(@intFromEnum(domain)));
    // Both source tuples stand for independently authenticated providers.
    // Changing preprocessing represents a different admitted circuit root;
    // changing a witness must satisfy both the join and these same tuples.
    for (0..5) |mutation| {
        var changed = row;
        switch (mutation) {
            0 => {},
            1 => changed[Air.PHYSICAL_MAIN_COLUMN_COUNT + 11] = M31.one(),
            2 => changed[Air.PHYSICAL_MAIN_COLUMN_COUNT + 12] = M31.fromCanonical(74),
            3 => {
                changed[0] = M31.fromCanonical(20);
                changed[1] = changed[0];
            },
            4 => changed[Air.PHYSICAL_MAIN_COLUMN_COUNT + 32] = M31.zero(),
            else => unreachable,
        }
        var ledger = interaction.TupleLedger.init(std.testing.allocator);
        defer ledger.deinit();
        try plan.appendPreparedTupleContributions(&ledger, 17, &.{changed}, domain_mask);
        for ([_]usize{ 7, 12 }) |event| {
            const entry = original[event];
            try ledger.append(domain, 5, @intCast(event), .emit, QM31.one(), entry.values[0..entry.arity]);
        }
        try std.testing.expectEqual(mutation == 0, ledger.classify().isClosed());
    }
    var changed_limb = row;
    changed_limb[1] = M31.fromCanonical(20);
    try program.evaluateBaseInto(&changed_limb, &scratch, &constraints);
    var failed = false;
    for (constraints) |constraint| failed = failed or !constraint.isZero();
    try std.testing.expect(failed);
}
