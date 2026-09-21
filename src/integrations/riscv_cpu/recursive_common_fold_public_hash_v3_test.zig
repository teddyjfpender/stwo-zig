const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const subject = @import("recursive_common_fold_public_hash_v3.zig");
const WordAir = air.field_public_word_v3;
const HashAir = air.vm_public_claim_hash;
const Ledger = air.relation_interaction.TupleLedger;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

/// Checks internal hash routing and exact provider requests. Statement/public
/// boundary integration is a separate gate; this test grants no proof capability.
pub fn exercise(left: anytype, right: anytype, schedule: anytype) !void {
    const digest = try WordAir.computeSemanticDigest(std.testing.allocator);
    std.debug.print("FIELD_PUBLIC_WORD_DIGEST={s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    try std.testing.expectEqualDeep(WordAir.SEMANTIC_DIGEST, digest);
    var prepared = try subject.Prepared.init(std.testing.allocator, left, right, schedule);
    defer prepared.deinit();
    try check(&prepared);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const boundary_mod = @import("recursive_common_fold_public_output_v3.zig");
    const boundary = try boundary_mod.derive(&schedule.parent, &relations);
    var definition = try WordAir.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try air.universal_relation_binding.Binding(WordAir).authenticate(&definition);
    var public_sum = QM31.zero();
    for (prepared.words) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.domain == .recursion_statement_word and entry.ordinal == 2 and !entry.numerator.isZero())
            public_sum = public_sum.add(entry.numerator.mul(try (try entry.denominator(&relations)).inv()));
    };
    try std.testing.expect(public_sum.add(boundary.claimed_sum).isZero());
    var changed_boundary = boundary;
    changed_boundary.claimed_sum = changed_boundary.claimed_sum.add(QM31.one());
    try std.testing.expectError(error.InvalidPublicOutputBoundary, changed_boundary.validate());

    const original = prepared.words[0][1];
    prepared.words[0][1] = original.add(M31.one());
    try std.testing.expectError(error.FieldPublicHashJoinMismatch, check(&prepared));
    prepared.words[0][1] = original;
}

fn check(prepared: *const subject.Prepared) !void {
    var ledger = Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    for (prepared.hashes, 0..) |rows, phase| try append(HashAir, &ledger, @intCast(13 + phase), rows);
    try append(WordAir, &ledger, 17, prepared.words);
    for (prepared.calls) |call| {
        var state: [16]M31 = undefined;
        for (&state, call.input) |*value, word| value.* = M31.fromCanonical(word);
        frontend.air.memory_commitment.poseidon2.permute(&state);
        var tuple: [32]QM31 = undefined;
        for (tuple[0..16], call.input) |*value, word| value.* = QM31.fromBase(M31.fromCanonical(word));
        for (tuple[16..], state) |*value, word| value.* = QM31.fromBase(word);
        try ledger.append(.poseidon2_io, 34, 0, .emit, QM31.one(), &tuple);
    }
    const report = ledger.classify();
    std.debug.print("FIELD_PUBLIC_HASH_INTERNAL_JOIN calls={d} contributions={d} unmatched={d}\n", .{ prepared.calls.len, report.contribution_count, report.unmatched_tuple_count });
    if (!report.isClosed()) return error.FieldPublicHashJoinMismatch;
}

fn append(comptime Air: type, ledger: *Ledger, component: u8, rows: []const [Air.LOGICAL_INPUT_COUNT]M31) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const compiled = try air.direct_constraint_program.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const plan = try air.universal_relation_binding.Binding(Air).authenticate(&definition);
    var scratch: [air.direct_constraint_program.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        try compiled.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.eql(M31.zero())) return error.FieldPublicHashConstraintMismatch;
        for (plan.preparedEntries(row)) |entry| {
            if (entry.domain == .recursion_statement_word) continue;
            try ledger.append(entry.domain, component, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
        }
    }
}
