//! Differential lookup closure: the new hash consumers must exactly equal the
//! extra fanout added to existing statement inputs. Base graph obligations cancel.
const std = @import("std");
const core = @import("stwo_core");
const graph = @import("../statement_semantics_circuit_blake3.zig");
const authority = @import("blake3_span_identity_binding.zig");
const inputs = @import("blake3_span_identity_inputs.zig");
const hash = @import("blake3_span_identity_hash.zig");
const identity = @import("../span_identity_blake3.zig");
const row11 = @import("statement_semantics_input_witness_blake3.zig");
const statement_air = @import("statement_semantics_input.zig");
const binding = @import("universal_relation_binding.zig");
const lang = @import("../../air/lang/mod.zig");
const M = core.fields.m31.M31;
const circuits = inputs.Circuits{ .scalar = 21, .packing = 22, .bytes = 23, .hash = 24 };
const Ledger = std.AutoHashMap([6]u32, M);

test "BLAKE3 Span identity joins authenticated parent inputs through full hash" {
    const a = std.testing.allocator;
    const fixture = @import("../span_statement_blake3_test_fixture.zig");
    const span = @import("../span_statement_blake3.zig");
    const context = try fixture.job(2);
    const middle = try fixture.state(8, 0xa0);
    const left = try fixture.leaf(context, 0, context.complete.initial_state, middle);
    const right = try fixture.leaf(context, 1, middle, context.complete.final_state);
    const words = try (try span.SpanStatement.fold(left, right)).canonicalWords();
    var circuit = try graph.build(a);
    defer circuit.deinit();
    var base = try row11.Preprocessed.init(a, circuits.scalar, circuit.inputBindings());
    defer base.deinit();
    for ([_]identity.Purpose{ .statement, .job }) |purpose| {
        var plan = try authority.buildParent(a, &circuit, purpose, circuits);
        defer plan.deinit();
        var combined = try plan.prepare(a, &words, try identity.hash(&words, purpose));
        defer combined.deinit();
        var prepared_inputs = combined.inputs;
        const prepared_hash = &combined.hash;
        try std.testing.expect(try closes(&plan, &base, &prepared_inputs, prepared_hash, &words));
        // Substituting a packed statement coordinate breaks the scalar or packed
        // join even if a separate native serialization would still be valid.
        prepared_inputs.packing[0][0] = prepared_inputs.packing[0][0].add(M.one());
        try std.testing.expect(!try closes(&plan, &base, &prepared_inputs, prepared_hash, &words));
        prepared_inputs = try inputs.prepare(&plan.inputs, &words);
        var wrong_claim = try identity.hash(&words, purpose);
        wrong_claim.bytes[31] ^= 0x80;
        var wrong = try hash.prepare(a, purpose, .{ .circuit = circuits.bytes, .first_wire = 0 }, circuits.hash, &words, wrong_claim);
        defer wrong.deinit();
        try std.testing.expect(!try closes(&plan, &base, &prepared_inputs, &wrong, &words));
    }
}

fn closes(plan: *const authority.Plan, base: *const row11.Preprocessed, prepared: *const inputs.Rows, hashed: *const hash.Prepared, words: *const identity.StatementWords) !bool {
    return closesPair(plan, base, prepared, hashed, null, words);
}
fn closesPair(plan: *const authority.Plan, base: *const row11.Preprocessed, prepared: *const inputs.Rows, hashed: *const hash.Prepared, second: ?*const hash.Prepared, words: *const identity.StatementWords) !bool {
    const a = std.testing.allocator;
    var ledger = Ledger.init(a);
    defer ledger.deinit();
    var definition = try statement_air.build(a);
    defer definition.deinit();
    const authenticated = try binding.Binding(statement_air).authenticate(&definition);
    for (plan.statement_inputs.rows, base.rows) |after, before| {
        // Only parent rows change; unrelated graph inputs cancel identically.
        if (after.use_count == before.use_count) continue;
        const value = words[after.word_index];
        for (authenticated.preparedEntries(try row11.logicalRow(after, value, .binary_node))) |entry| try add(&ledger, entry, M.one());
        for (authenticated.preparedEntries(try row11.logicalRow(before, value, .binary_node))) |entry| try add(&ledger, entry, M.one().neg());
    }
    inline for (.{ @import("qm31_pack_wire.zig"), @import("blake3_field_bytes.zig"), @import("blake3_byte_route.zig"), @import("blake3_g_call.zig"), @import("blake3_xor_call.zig"), @import("blake3_boundary.zig") }, .{ prepared.packing, prepared.encoding, hashed.route_rows, hashed.hash_rows.g_rows, hashed.hash_rows.xor_rows, hashed.hash_rows.boundary_rows }) |Air, rows| {
        var d = try Air.build(a);
        defer d.deinit();
        const authenticated_rows = try binding.Binding(Air).authenticate(&d);
        for (rows) |row| for (authenticated_rows.preparedEntries(row)) |entry| try add(&ledger, entry, M.one());
    }
    if (second) |extra| {
        inline for (.{ @import("blake3_byte_route.zig"), @import("blake3_g_call.zig"), @import("blake3_xor_call.zig"), @import("blake3_boundary.zig") }, .{ extra.route_rows, extra.hash_rows.g_rows, extra.hash_rows.xor_rows, extra.hash_rows.boundary_rows }) |Air, rows| {
            var d = try Air.build(a);
            defer d.deinit();
            const authenticated_rows = try binding.Binding(Air).authenticate(&d);
            for (rows) |row| for (authenticated_rows.preparedEntries(row)) |entry| try add(&ledger, entry, M.one());
        }
    }
    var values = ledger.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}
fn add(ledger: *Ledger, entry: anytype, scale: M) !void {
    if (entry.schema != lang.relation.id(.recursion_wire)) return;
    var key: [6]u32 = undefined;
    for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
    const slot = try ledger.getOrPut(key);
    if (!slot.found_existing) slot.value_ptr.* = M.zero();
    slot.value_ptr.* = slot.value_ptr.*.add((try entry.numerator.tryIntoM31()).mul(scale));
}


test "BLAKE3 Span identity pair shares canonical producers and closes both hashes" {
    const pair = @import("blake3_span_identity_pair.zig");
    const fixture = @import("../span_statement_blake3_test_fixture.zig");
    const a = std.testing.allocator;
    var circuit = try graph.build(a);
    defer circuit.deinit();
    const context = try fixture.job(1);
    const words = try (try fixture.leaf(context, 0, context.complete.initial_state, context.complete.final_state)).canonicalWords();
    var base = try row11.Preprocessed.init(a, circuits.scalar, circuit.inputBindings());
    defer base.deinit();
    var plan = try pair.buildParent(a, &circuit, circuits, 25);
    defer plan.deinit();
    const claims = pair.Claims{ .statement = try identity.hash(&words, .statement), .job = try identity.hash(&words, .job) };
    var prepared = try plan.prepare(a, &words, claims);
    defer prepared.deinit();
    try std.testing.expect(try closesPair(&plan.statement, &base, &prepared.statement.inputs, &prepared.statement.hash, &prepared.job, &words));
    // Removing the job consumer must expose its unmatched byte fanout.
    try std.testing.expect(!try closes(&plan.statement, &base, &prepared.statement.inputs, &prepared.statement.hash, &words));
    for ([_]u32{ circuits.scalar, circuits.packing, circuits.bytes, circuits.hash }) |id| try std.testing.expectError(error.InvalidSpanIdentityCircuits, pair.buildParent(a, &circuit, circuits, id));
}
