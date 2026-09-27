const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const pair = @import("blake3_span_identity_pair.zig");
const graph = @import("../statement_semantics_circuit_blake3.zig");
const identity = @import("../span_identity_blake3.zig");
const binding = @import("universal_relation_binding.zig");
const direct = @import("direct_constraint_program.zig");
const lang = @import("../../air/lang/mod.zig");
const schema = @import("../../air/lookups/tables/schema.zig");

test "BLAKE3 Span identity paired witness satisfies direct constraints and lookup tables" {
    const a = std.testing.allocator;
    const fixture = @import("../span_statement_blake3_test_fixture.zig");
    var circuit = try graph.build(a);
    defer circuit.deinit();
    var plan = try pair.buildParent(a, &circuit, .{ .scalar = 21, .packing = 22, .bytes = 23, .hash = 24 }, 25);
    defer plan.deinit();
    const context = try fixture.job(1);
    const words = try (try fixture.leaf(context, 0, context.complete.initial_state, context.complete.final_state)).canonicalWords();
    var prepared = try plan.prepare(a, &words, .{ .statement = try identity.hash(&words, .statement), .job = try identity.hash(&words, .job) });
    defer prepared.deinit();
    try check(@import("qm31_pack_wire.zig"), &prepared.statement.inputs.packing);
    try check(@import("blake3_field_bytes.zig"), &prepared.statement.inputs.encoding);
    for ([_]*const @import("blake3_span_identity_hash.zig").Prepared{ &prepared.statement.hash, &prepared.job }) |hash| {
        try check(@import("blake3_byte_route.zig"), hash.route_rows);
        try check(@import("blake3_g_call.zig"), hash.hash_rows.g_rows);
        try check(@import("blake3_xor_call.zig"), hash.hash_rows.xor_rows);
        try check(@import("blake3_boundary.zig"), hash.hash_rows.boundary_rows);
    }
    // Forge witnesses after construction, bypassing native validity checks.
    const encoding = @import("blake3_field_bytes.zig");
    var forged = prepared.statement.inputs.encoding[0];
    forged[4] = forged[4].add(M.one());
    try std.testing.expectError(error.UnsatisfiedIdentityConstraint, check(encoding, &.{forged}));
    const xor = @import("blake3_xor_call.zig");
    var bad_xor = prepared.job.hash_rows.xor_rows[0];
    bad_xor[8] = bad_xor[8].add(M.one());
    try std.testing.expectError(error.InvalidTuple, check(xor, &.{bad_xor}));
}

fn check(comptime Air: type, rows: []const Air.Row) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const relations = try binding.Binding(Air).authenticate(&definition);
    var scratch: [direct.MAX_NODES]M = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M = undefined;
    for (rows) |row| {
        try program.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero()) return error.UnsatisfiedIdentityConstraint;
        for (relations.preparedEntries(row)) |entry| {
            if (entry.numerator.isZero()) continue;
            if (entry.schema == lang.relation.id(.recursion_wire)) continue;
            var checked = false;
            inline for (.{ schema.Kind.bitwise, schema.Kind.range_check_8_8 }) |kind| {
                if (entry.schema == lang.relation.id(@field(lang.relation.Domain, @tagName(kind)))) {
                    _ = try schema.indexSecure(kind, entry.values[0..schema.arity(kind)]);
                    checked = true;
                }
            }
            if (!checked) return error.UncheckedIdentityRelation;
        }
    }
}
