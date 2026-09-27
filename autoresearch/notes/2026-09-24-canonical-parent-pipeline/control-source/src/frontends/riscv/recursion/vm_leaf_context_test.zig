const std = @import("std");
const stwo_core = @import("stwo_core");
const QM31 = stwo_core.fields.qm31.QM31;
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");
const trace_mod = @import("../runner/trace.zig");
const vm_air_profile = @import("vm_air_profile.zig");
const subject = @import("vm_leaf_context.zig");

test "R-012 verified VM leaf context owns exact detailed authority" {
    const allocator = std.testing.allocator;
    const statement = try allocator.create(statement_mod.RiscVStatement);
    defer allocator.destroy(statement);
    initFixture(statement);
    const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    defer allocator.destroy(claim);
    initClaim(statement, claim);

    const component_count = 2 * @as(usize, statement.n_components) + statement.n_infra;
    const facts = try allocator.alloc(vm_air_profile.testing.Facts, component_count);
    defer allocator.free(facts);
    try vm_air_profile.testing.expectedFacts(statement, facts);
    const profile = try vm_air_profile.testing.deriveFromFacts(statement, facts);
    const relations = relation_challenges.Relations.dummy();

    var context = try subject.testing.initFromProfile(
        allocator,
        statement,
        claim,
        &relations,
        profile,
    );
    defer context.deinit();
    try context.validate();
    try std.testing.expectEqual(
        @as(usize, profile.claimed_sum_count),
        context.detailed_claims.len,
    );
    try std.testing.expectEqual(statement.n_components, context.component_descs.len);
    try std.testing.expectEqual(statement.n_infra, context.infra_descs.len);

    // Caller mutation cannot rewrite recursive inputs after verification.
    statement.component_descs[0].n_rows -= 1;
    claim.opcode_claims[0][0] = QM31.zero();
    try context.validate();
    try std.testing.expect(context.detailed_claims[0].eql(q(1)));
}

test "R-012 VM leaf context rejects every authenticated storage class mutation" {
    const allocator = std.testing.allocator;
    const statement = try allocator.create(statement_mod.RiscVStatement);
    defer allocator.destroy(statement);
    initFixture(statement);
    const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    defer allocator.destroy(claim);
    initClaim(statement, claim);
    const component_count = 2 * @as(usize, statement.n_components) + statement.n_infra;
    const facts = try allocator.alloc(vm_air_profile.testing.Facts, component_count);
    defer allocator.free(facts);
    try vm_air_profile.testing.expectedFacts(statement, facts);
    const profile = try vm_air_profile.testing.deriveFromFacts(statement, facts);
    const relations = relation_challenges.Relations.dummy();
    var context = try subject.testing.initFromProfile(
        allocator,
        statement,
        claim,
        &relations,
        profile,
    );
    defer context.deinit();

    context.detailed_claims[0] = context.detailed_claims[0].add(QM31.one());
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.detailed_claims[0] = context.detailed_claims[0].sub(QM31.one());
    try context.validate();

    context.canonical_claims[0] = context.canonical_claims[0].add(QM31.one());
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.canonical_claims[0] = context.canonical_claims[0].sub(QM31.one());
    try context.validate();

    context.relation_draws[3] = context.relation_draws[3].add(QM31.one());
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.relation_draws[3] = context.relation_draws[3].sub(QM31.one());
    try context.validate();

    context.component_descs[0].n_rows -= 1;
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
    context.component_descs[0].n_rows += 1;
    try context.validate();

    context.identity_digest[0] ^= 1;
    try std.testing.expectError(error.ContextDigestMismatch, context.validate());
}

fn initClaim(
    statement: *const statement_mod.RiscVStatement,
    claim: *statement_mod.RiscVInteractionClaim,
) void {
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    var next: u32 = 1;
    for (statement.component_descs[0..statement.n_components], 0..) |descriptor, index| {
        for (claim.opcode_claims[index][0..opcode_entries.batchCount(descriptor.family)]) |*slot| {
            slot.* = q(next);
            next += 1;
        }
    }
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, index| {
        for (0..statement_mod.nClaimedSumsForInfra(descriptor.kind)) |sum| {
            claim.setInfraClaim(descriptor.kind, index, sum, q(next)) catch unreachable;
            next += 1;
        }
    }
}

fn initFixture(statement: *statement_mod.RiscVStatement) void {
    statement.n_components = 2;
    statement.component_descs[0] = .{
        .family = .base_alu_imm,
        .log_size = 6,
        .n_rows = 40,
        .n_columns = trace_mod.nColumnsForFamily(.base_alu_imm),
    };
    statement.component_descs[1] = .{
        .family = .mul,
        .log_size = 5,
        .n_rows = 24,
        .n_columns = trace_mod.nColumnsForFamily(.mul),
    };
    statement.n_infra = 3;
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
        .kind = .range_check_20,
        .log_size = 20,
        .n_rows = 1 << 20,
        .n_columns = 1,
    };
}

fn q(value: u32) QM31 {
    return QM31.fromU32Unchecked(value, 0, 0, 0);
}
