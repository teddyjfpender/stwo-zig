//! Exact segment-scope closure from the actual row-10, row-11 and row-18 AIRs.
//! Diagnostic gate only: the outer proof must still commit the V3 schedule.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("air/mod.zig");
const provider = @import("air/statement_input_roots_v3.zig");
const semantics = @import("statement_semantics_circuit.zig");
const StatementWords = @import("span_statement.zig").StatementWords;

pub fn audit(
    allocator: std.mem.Allocator,
    words: *const StatementWords,
    vm_rows: []const air.vm_air_composition_input_witness.Row,
    vm_values: []const M31,
) !void {
    return auditWithRouting(allocator, words, vm_rows, vm_values, null);
}

/// The integration's admitted plan supplies both provider fan-out and any
/// additional statement consumers; legacy diagnostics retain root-only routing.
pub fn auditWithRouting(
    allocator: std.mem.Allocator,
    words: *const StatementWords,
    vm_rows: []const air.vm_air_composition_input_witness.Row,
    vm_values: []const M31,
    routing: anytype,
) !void {
    if (vm_rows.len != vm_values.len) return error.StatementRootRoutingShapeMismatch;
    var ledger = air.relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    var definition = try provider.build(allocator);
    defer definition.deinit();
    const plan = try provider.Relation.authenticate(&definition);
    var preprocessing = try air.statement_input_witness.Preprocessed.init(allocator);
    defer preprocessing.deinit();
    _ = try provider.Routing.identity(&preprocessing);
    for (preprocessing.rows) |row| {
        const logical = if (@TypeOf(routing) == @TypeOf(null))
            try provider.Routing.logicalRow(row, .{ .segment_leaf = words })
        else
            try routing.providerRow(row, .{ .segment_leaf = words });
        try appendSegmentEntries(&ledger, 10, &plan.preparedEntries(logical));
    }

    // Derive the consumers from the real admitted statement circuit, rather
    // than fabricating one opposing lookup term for each provider word.
    var circuit = try semantics.build(allocator);
    defer circuit.deinit();
    var semantics_pp = try air.statement_semantics_input_witness.Preprocessed.init(allocator, 1, circuit.inputBindings());
    defer semantics_pp.deinit();
    const ConsumerAir = if (@TypeOf(routing) == @TypeOf(null)) air.statement_semantics_input else @TypeOf(routing.*).ConsumerAir;
    var semantics_air = try ConsumerAir.build(allocator);
    defer semantics_air.deinit();
    const semantics_plan = try air.universal_relation_binding.Binding(ConsumerAir).authenticate(&semantics_air);
    for (semantics_pp.rows) |row| {
        if (row.source != .statement or !row.active_kinds.segment or
            row.statement_scope != air.statement_input.SEGMENT_STATEMENT_SCOPE) continue;
        const logical = if (@TypeOf(routing) == @TypeOf(null))
            try air.statement_semantics_input_witness.logicalRow(row, words[row.word_index], .segment_leaf)
        else
            try routing.logicalConsumerRow(row, words[row.word_index]);
        try appendSegmentEntries(&ledger, 11, &semantics_plan.preparedEntries(logical));
    }

    if (@TypeOf(routing) != @TypeOf(null)) {
        for (0..words.len) |word| {
            const row = routing.consumerRow(word) orelse continue;
            const logical = try routing.logicalConsumerRow(row, words[row.word_index]);
            try appendSegmentEntries(&ledger, 11, &semantics_plan.preparedEntries(logical));
        }
    }

    if (@TypeOf(routing) != @TypeOf(null)) {
        if (@hasDecl(@TypeOf(routing.*), "PublicationConsumerAir")) {
            const PublicationAir = @TypeOf(routing.*).PublicationConsumerAir;
            var publication_air = try PublicationAir.build(allocator);
            defer publication_air.deinit();
            const publication_plan = try PublicationAir.Relation.authenticate(&publication_air);
            for (words, 0..) |value, word| {
                const row = routing.publicationConsumerRow(word, value);
                try appendSegmentEntries(&ledger, 17, &publication_plan.preparedEntries(row));
            }
        }
    }

    var vm_air = try air.vm_air_composition_input.build(allocator);
    defer vm_air.deinit();
    const vm_plan = try air.vm_air_composition_input_relation.authenticate(&vm_air);
    for (vm_rows, vm_values) |row, value| {
        const logical = try air.vm_air_composition_input_witness.logicalRow(row, value, .segment_leaf);
        try appendSegmentEntries(&ledger, 18, &vm_plan.preparedEntries(logical));
    }
    if (!ledger.classify().isClosed()) return error.StatementRootRoutingNotClosed;
}

fn appendSegmentEntries(ledger: *air.relation_interaction.TupleLedger, component: u8, entries: []const air.relation_interaction.Entry) !void {
    for (entries) |entry| {
        if (entry.domain != .recursion_statement_word or !entry.values[0].isZero()) continue;
        try ledger.append(entry.domain, component, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    }
}
