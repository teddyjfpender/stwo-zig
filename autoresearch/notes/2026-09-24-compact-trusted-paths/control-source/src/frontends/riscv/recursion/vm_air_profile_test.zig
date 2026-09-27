const std = @import("std");
const stwo_core = @import("stwo_core");
const QM31 = stwo_core.fields.qm31.QM31;
const statement_mod = @import("../air/statement.zig");
const subject = @import("vm_air_profile.zig");

test "R-012 row18 profile derives exact dynamic VM schedule and detailed claim order" {
    const allocator = std.testing.allocator;
    const statement = try allocator.create(statement_mod.RiscVStatement);
    defer allocator.destroy(statement);
    initFixture(statement);

    const component_count = 2 * @as(usize, statement.n_components) + statement.n_infra;
    const facts = try allocator.alloc(subject.testing.Facts, component_count);
    defer allocator.free(facts);
    try subject.testing.expectedFacts(statement, facts);

    const profile = try subject.testing.deriveFromFacts(statement, facts);
    try profile.validate();
    try std.testing.expectEqual(@as(u32, @intCast(component_count)), profile.component_count);
    try std.testing.expectEqual(@as(u32, 12), profile.relation_challenge_count);
    try std.testing.expectEqual(try subject.claimedSumCount(statement), profile.claimed_sum_count);
    try std.testing.expect(profile.air_instruction_count > profile.component_count);

    const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    defer allocator.destroy(claim);
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    var next: u32 = 1;
    for (statement.component_descs[0..statement.n_components], 0..) |descriptor, index| {
        for (claim.opcode_claims[index][0..@import("../air/lookups/opcode_entries.zig").batchCount(descriptor.family)]) |*slot| {
            slot.* = QM31.fromU32Unchecked(next, next + 1, next + 2, next + 3);
            next += 4;
        }
    }
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, index| {
        for (0..statement_mod.nClaimedSumsForInfra(descriptor.kind)) |sum| {
            try claim.setInfraClaim(
                descriptor.kind,
                index,
                sum,
                QM31.fromU32Unchecked(next, next + 1, next + 2, next + 3),
            );
            next += 4;
        }
    }
    const detailed = try allocator.alloc(QM31, profile.claimed_sum_count);
    defer allocator.free(detailed);
    try subject.writeDetailedClaims(statement, claim, detailed);
    var expected_limb: u32 = 1;
    for (detailed) |value| {
        const limbs = value.toM31Array();
        try std.testing.expectEqual(expected_limb, limbs[0].toU32());
        expected_limb += 4;
    }
}

test "R-012 row18 profile rejects count, order-shape, split, and claim mutations" {
    const allocator = std.testing.allocator;
    const statement = try allocator.create(statement_mod.RiscVStatement);
    defer allocator.destroy(statement);
    initFixture(statement);

    const component_count = 2 * @as(usize, statement.n_components) + statement.n_infra;
    const facts = try allocator.alloc(subject.testing.Facts, component_count);
    defer allocator.free(facts);
    try subject.testing.expectedFacts(statement, facts);
    const honest = try subject.testing.deriveFromFacts(statement, facts);

    facts[1].n_constraints += 1;
    try std.testing.expectError(
        error.ConstraintCountMismatch,
        subject.testing.deriveFromFacts(statement, facts),
    );
    facts[1].n_constraints -= 1;

    facts[component_count - 1].composition_log_split += 1;
    try std.testing.expectError(
        error.InconsistentCompositionLogSplit,
        subject.testing.deriveFromFacts(statement, facts),
    );
    facts[component_count - 1].composition_log_split -= 1;

    var changed = statement.infra_descs[0];
    statement.infra_descs[0] = statement.infra_descs[1];
    statement.infra_descs[1] = changed;
    try std.testing.expectError(
        error.ConstraintCountMismatch,
        subject.testing.deriveFromFacts(statement, facts),
    );
    changed = statement.infra_descs[0];
    statement.infra_descs[0] = statement.infra_descs[1];
    statement.infra_descs[1] = changed;
    const restored = try subject.testing.deriveFromFacts(statement, facts);
    try std.testing.expectEqual(honest.manifest_digest, restored.manifest_digest);

    try std.testing.expectError(
        error.ComponentCountMismatch,
        subject.testing.deriveFromFacts(statement, facts[0 .. facts.len - 1]),
    );
}

fn initFixture(statement: *statement_mod.RiscVStatement) void {
    statement.n_components = 2;
    statement.component_descs[0] = .{
        .family = .base_alu_imm,
        .log_size = 6,
        .n_rows = 40,
        .n_columns = 17,
    };
    statement.component_descs[1] = .{
        .family = .mul,
        .log_size = 5,
        .n_rows = 24,
        .n_columns = 15,
    };
    statement.n_infra = 5;
    statement.infra_descs[0] = .{
        .kind = .program,
        .log_size = 5,
        .n_rows = 20,
        .n_columns = 10,
    };
    statement.infra_descs[1] = .{
        .kind = .memory,
        .log_size = 6,
        .n_rows = 48,
        .n_columns = 8,
    };
    statement.infra_descs[2] = .{
        .kind = .merkle,
        .log_size = 6,
        .n_rows = 48,
        .n_columns = 10,
    };
    statement.infra_descs[3] = .{
        .kind = .poseidon2,
        .log_size = 6,
        .n_rows = 48,
        .n_columns = 786,
    };
    statement.infra_descs[4] = .{
        .kind = .range_check_20,
        .log_size = 20,
        .n_rows = 1 << 20,
        .n_columns = 1,
    };
}
