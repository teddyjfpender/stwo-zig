//! Real native-capture differential gate for statement-dependent bridge roots.
//! This proves graph replay/admission, not closure of the outer provider cohort.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const M31 = @import("stwo_core").fields.m31.M31;
const preparation = frontend.recursion.vm_composition_preparation;
const compiler = frontend.recursion.incremental_ethereum_vm_composition_program_v4;
const span = frontend.recursion.span_statement;

pub fn audit(allocator: std.mem.Allocator, prepared: anytype) !void {
    const capture = &prepared.input.stage101;
    const current = prepared.composition.source().view();
    try std.testing.expectEqual(@as(u32, 2), prepared.composition.program().input_profile.vm_statement_root_count);
    const shape = compiler.StatementRootCompilerInput{
        .core_statement = &capture.statement.core,
        .extension_statement = &capture.extension,
        .lookup_manifest = &capture.manifest,
        .authenticated_lookup = &capture.authenticated,
        .base_profile = &prepared.base_profile,
        .bridge_geometry = capture.profile.bridge_geometry,
    };
    const roots = frontend.recursion.air.vm_statement_roots.word_indices;
    const expected_roots = [2]u32{ capture.profile.continuation_roots.entry, capture.profile.continuation_roots.exit };
    const inputs = try allocator.alloc(M31, current.circuit.bindings.len);
    defer allocator.free(inputs);
    for (current.circuit.bindings, inputs[0..current.circuit.bindings.len]) |binding, *value|
        value.* = try current.evaluation.values[binding.node_id].tryIntoM31();
    for (roots, expected_roots, inputs[current.circuit.bindings.len - roots.len ..]) |word, expected, *value| {
        try std.testing.expectEqual(expected, prepared.input.statement_words[word]);
        try std.testing.expectEqual(expected, value.toU32());
    }

    var compiled = try preparation.Compiled.initEthereumWithStatementRoots(allocator, shape);
    var compiled_pending = true;
    defer if (compiled_pending) compiled.deinit();
    const program = compiled.program();
    try std.testing.expectEqual(@as(u32, 2), program.input_profile.vm_statement_root_count);
    try std.testing.expectEqual(inputs.len, program.bindings.len);
    const graph_identity = program.graph_sha256;
    try std.testing.expectEqualSlices(u8, &graph_identity, &current.circuit.graph_digest);
    compiled_pending = false; // Finalization consumes on both success and failure.
    var owned = try compiled.finalize(inputs, 1);
    defer owned.deinit();
    try owned.source().audit();
    const view = owned.source().view();
    var root_rows: usize = 0;
    var routed_rows: [2]frontend.recursion.air.vm_air_composition_input_witness.Row = undefined;
    var routed_values: [2]M31 = undefined;
    for (view.preprocessing.rows, view.schedule_values) |row, value| {
        switch (row.classification) {
            .vm_input => |source| switch (source) {
                .statement_word => |word| {
                    try std.testing.expect(root_rows < roots.len);
                    try std.testing.expectEqual(roots[root_rows], word);
                    try std.testing.expectEqual(expected_roots[root_rows], value.toU32());
                    routed_rows[root_rows] = row;
                    routed_values[root_rows] = value;
                    root_rows += 1;
                },
                else => {},
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 2), root_rows);
    var statement_words: span.StatementWords = undefined;
    for (&statement_words, prepared.input.statement_words) |*word, value|
        word.* = M31.fromCanonical(value);
    const audit_routing = frontend.recursion.statement_root_routing_audit.audit;
    try audit_routing(allocator, &statement_words, &routed_rows, &routed_values);
    try frontend.recursion.air.statement_root_physical_audit.audit(allocator, &statement_words);
    try std.testing.expectError(error.StatementRootRoutingNotClosed, audit_routing(allocator, &statement_words, routed_rows[0..1], routed_values[0..1]));
    const duplicate_rows = routed_rows ++ .{routed_rows[0]};
    const duplicate_values = routed_values ++ .{routed_values[0]};
    try std.testing.expectError(error.StatementRootRoutingNotClosed, audit_routing(allocator, &statement_words, &duplicate_rows, &duplicate_values));

    // The same graph admits the authentic values and rejects either changed
    // root. Root values cannot select a different graph during compilation.
    for (0..2) |root| {
        const at = current.circuit.bindings.len - roots.len + root;
        const saved = inputs[at];
        inputs[at] = saved.add(M31.one());
        routed_values[root] = inputs[at];
        try std.testing.expectError(error.StatementRootRoutingNotClosed, audit_routing(allocator, &statement_words, &routed_rows, &routed_values));
        routed_values[root] = saved;
        var altered = try preparation.Compiled.initEthereumWithStatementRoots(allocator, shape);
        var altered_pending = true;
        defer if (altered_pending) altered.deinit();
        try std.testing.expectEqualSlices(u8, &graph_identity, &altered.program().graph_sha256);
        altered_pending = false;
        try std.testing.expectError(error.UnsatisfiedCircuit, altered.finalize(inputs, 1));
        inputs[at] = saved;
    }
    std.debug.print("ETHEREUM_STATEMENT_ROOT_REPLAY roots=2 entry={d} exit={d} graph={s} native_capture_valid=true graph_stable=true changed_roots_rejected=2 segment_statement_routing_closed=true routing_negative_cases_rejected=4 physical_native_recursive_parity=true outer_provider_closure=false\n", .{ expected_roots[0], expected_roots[1], std.fmt.bytesToHex(graph_identity, .lower) });
}
