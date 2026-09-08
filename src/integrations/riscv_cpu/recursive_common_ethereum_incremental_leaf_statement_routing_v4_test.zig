const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const air = frontend.recursion.air;
const subject = @import("recursive_common_ethereum_incremental_leaf_statement_routing_v4.zig");
const sums = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");

test "Ethereum statement routing closes admitted graph sources and rejects missing duplicate shifted routes" {
    const allocator = std.testing.allocator;
    const plan = blk: {
        var program = try sums.build(allocator, 1);
        defer program.deinit(allocator);
        const graph_nodes = try allocator.alloc(air.composition_circuit.Node, program.circuit.nodes().len);
        defer allocator.free(graph_nodes);
        for (graph_nodes, program.circuit.nodes()) |*out, node| out.* = sums.graphNode(node);
        const graph_identity = air.composition_circuit.computeGraphDigest(graph_nodes, program.circuit.outputs());
        const uses = program.circuit.useCounts()[0..program.bindings.len];
        const admitted = try subject.Plan.init(program.bindings, uses, graph_identity);
        try std.testing.expect(admitted.rowCount() > 0);
        for (0..subject.WORD_COUNT) |word| {
            if (admitted.consumerRow(word)) |row| {
                try std.testing.expectEqual(uses[1 + word], row.use_count);
                try std.testing.expectEqual(1 + word, row.node_id);
            } else try std.testing.expectEqual(@as(u32, 0), uses[1 + word]);
        }
        const byte_start = 1 + subject.WORD_COUNT + sums.CLOCK_LIMB_COUNT;
        const original_byte = program.bindings[byte_start];
        program.bindings[byte_start] = program.bindings[byte_start + 1];
        try std.testing.expectError(error.InvalidEthereumStatementRouting, subject.Plan.init(program.bindings, uses, graph_identity));
        program.bindings[byte_start] = original_byte;
        program.bindings[1] = .{ .statement_word = 1 };
        try std.testing.expectError(error.InvalidEthereumStatementRouting, subject.Plan.init(program.bindings, uses, graph_identity));
        break :blk admitted;
    };
    // The graph and bindings are destroyed. The admitted schedule owns its
    // counts, while proof values enter separately through actual AIR tuples.
    const identity = plan.identity();
    var words: frontend.recursion.span_statement.StatementWords = .{M31.zero()} ** subject.WORD_COUNT;
    const roots = air.vm_statement_roots;
    const vm = air.vm_air_composition_input_witness;
    var vm_rows: [2]vm.Row = undefined;
    var vm_values: [2]M31 = undefined;
    for (roots.word_indices, 0..) |word, index| {
        vm_rows[index] = .{ .classification = .{ .vm_input = .{ .statement_word = word } }, .circuit_id = 7, .node_id = @intCast(index), .use_count = 1 };
        vm_values[index] = words[word];
    }
    const audit = frontend.recursion.statement_root_routing_audit.auditWithRouting;
    try audit(allocator, &words, &vm_rows, &vm_values, &plan);
    // Changing statement values must not change circuit/profile admission.
    words[roots.word_indices[0]] = M31.one();
    vm_values[0] = M31.one();
    try audit(allocator, &words, &vm_rows, &vm_values, &plan);
    try std.testing.expectEqual(identity, plan.identity());
    for (std.enums.values(Broken.Mode)) |mode| {
        const broken: Broken = .{ .plan = &plan, .mode = mode };
        try std.testing.expectError(error.StatementRootRoutingNotClosed, audit(allocator, &words, &vm_rows, &vm_values, &broken));
    }
}

/// Negative fixtures corrupt only one end of an otherwise real AIR route.
const Broken = struct {
    pub const PublicationConsumerAir = subject.Plan.PublicationConsumerAir;
    pub fn publicationConsumerRow(self: *const Broken, word: usize, value: M31) PublicationConsumerAir.Relation.Row {
        return self.plan.publicationConsumerRow(word, value);
    }
    pub const ConsumerAir = subject.Plan.ConsumerAir;
    const Mode = enum { missing, duplicate, shifted };
    plan: *const subject.Plan,
    mode: Mode,

    pub fn providerRow(self: *const Broken, row: air.statement_input_witness.Row, words: air.statement_input_witness.StatementWitness) !air.statement_input_roots_v3.Relation.Row {
        if (self.mode == .missing)
            return air.statement_input_roots_v3.Routing.logicalRow(row, words);
        return air.statement_input_roots_v3.Routing.logicalRowForPlan(row, words, self);
    }

    pub fn extraUses(self: *const Broken, row: air.statement_input_witness.Row) u32 {
        return self.plan.extraUses(row) + @as(u32, @intFromBool(self.mode == .duplicate and row.segment_mask == 1));
    }

    pub fn logicalConsumerRow(self: *const Broken, row: air.statement_semantics_input_witness.Row, value: M31) !ConsumerAir.Relation.Row {
        return self.plan.logicalConsumerRow(row, value);
    }

    pub fn consumerRow(self: *const Broken, word: usize) ?air.statement_semantics_input_witness.Row {
        var row = self.plan.consumerRow(word) orelse return null;
        if (self.mode == .shifted) {
            row.word_index = 0;
            row.integer = air.statement_semantics_input_witness.isIntegerWord(0);
        }
        return row;
    }
};

test "Ethereum statement byte routing pins shared AIR" {
    const byte_air = air.statement_semantics_bytes_v2;
    const identity = try byte_air.semanticIdentity(std.testing.allocator);
    if (!std.meta.eql(identity.bytes, byte_air.SEMANTIC_DIGEST))
        std.debug.print("STATEMENT_BYTE_AIR_SEAL={x}\n", .{identity.bytes});
    var definition = try byte_air.build(std.testing.allocator);
    defer definition.deinit();
    var legacy = try air.statement_semantics_input.build(std.testing.allocator);
    defer legacy.deinit();
    try legacy.validate();
    const relation = try byte_air.Relation.authenticate(&definition);
    const row: air.statement_semantics_input_witness.Row = .{
        .source = .statement,
        .integer = true,
        .active_kinds = .SEGMENT,
        .circuit_id = 42,
        .node_id = 1,
        .use_count = 2,
        .statement_scope = air.statement_input.SEGMENT_STATEMENT_SCOPE,
        .word_index = frontend.recursion.span_statement.canonical_layout.entry_state_start + frontend.recursion.span_statement.canonical_layout.machine_state_registers_start_offset,
    };
    var logical = try byte_air.logicalRow(row, M31.fromCanonical(0x1234), .segment_leaf, .{ M31.fromCanonical(541), M31.fromCanonical(3), M31.fromCanonical(542), M31.fromCanonical(2) });
    const entries = relation.preparedEntries(logical);
    try std.testing.expectEqual(@as(u32, 541), entries[3].values[1].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0x34), entries[3].values[2].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 3), entries[3].numerator.toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 542), entries[4].values[1].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0x12), entries[4].values[2].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 2), entries[4].numerator.toM31Array()[0].toU32());
    const direct = air.direct_constraint_program;
    const program = try direct.authenticate(&definition.arena, byte_air.SEMANTIC_DIGEST, byte_air.LOGICAL_INPUT_COUNT);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var constraints: [byte_air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try program.evaluateBaseInto(&logical, &scratch, &constraints);
    for (constraints) |constraint| try std.testing.expect(constraint.isZero());
    logical[2] = logical[2].add(M31.one());
    try program.evaluateBaseInto(&logical, &scratch, &constraints);
    try std.testing.expect(!constraints[3].isZero());
    definition.arena.effects.items[3].liveness = definition.arena.effects.items[4].liveness;
    try std.testing.expectError(error.InvalidStatementByteRoutingDefinition, definition.validate());
}

test "Ethereum clock routing pins shared AIR and preserves legacy namespaces" {
    const clock_air = air.transcript_payload_clocks_v2;
    const identity = try clock_air.semanticIdentity(std.testing.allocator);
    if (!std.meta.eql(identity.bytes, clock_air.SEMANTIC_DIGEST))
        std.debug.print("TRANSCRIPT_CLOCK_AIR_SEAL={x}\n", .{identity.bytes});
    var definition = try clock_air.build(std.testing.allocator);
    defer definition.deinit();
    const relation = try clock_air.Relation.authenticate(&definition);
    const row = clockPayloadRow(0);
    const logical = try clock_air.logicalRow(row, M31.fromCanonical(0xffff));
    const entries = relation.preparedEntries(logical);
    try std.testing.expectEqual(@as(u32, 5), entries[2].values[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), entries[2].values[1].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0xffff), entries[2].values[2].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 1), entries[2].numerator.toM31Array()[0].toU32());
    // Clock sources do not manufacture a row-10 verifier-input lookup.
    try std.testing.expect(entries[1].numerator.isZero());
    const direct = air.direct_constraint_program;
    const program = try direct.authenticate(&definition.arena, clock_air.SEMANTIC_DIGEST, clock_air.LOGICAL_INPUT_COUNT);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var constraints: [clock_air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try program.evaluateBaseInto(&logical, &scratch, &constraints);
    for (constraints) |constraint| try std.testing.expect(constraint.isZero());
    try std.testing.expectError(error.InvalidTraceRow, air.transcript_payload_witness.logicalRowForRecordedFrame(row, M31.one(), .segment_leaf));
    var legacy_row = row;
    legacy_row.source_word_index = air.transcript_payload_witness.PAYLOAD_WORD_OFFSET + row.payload_index;
    try std.testing.expectError(error.InvalidTraceRow, air.transcript_payload_witness.logicalRow(legacy_row, M31.one(), .segment_leaf));
    var legacy_definition = try air.transcript_payload.build(std.testing.allocator);
    defer legacy_definition.deinit();
    try legacy_definition.validate();
    definition.arena.effects.items[2].liveness = definition.arena.effects.items[1].liveness;
    try std.testing.expectError(error.InvalidTranscriptClockRoutingDefinition, definition.validate());
}

test "Ethereum clock routing closes native sources and matches admitted graph wires" {
    try std.testing.expectEqual(@as(usize, 128), subject.CLOCK_WORD_COUNT);
    const allocator = std.testing.allocator;
    const plan = blk: {
        var program = try sums.build(allocator, 1);
        defer program.deinit(allocator);
        const graph_nodes = try allocator.alloc(air.composition_circuit.Node, program.circuit.nodes().len);
        defer allocator.free(graph_nodes);
        for (graph_nodes, program.circuit.nodes()) |*out, node| out.* = sums.graphNode(node);
        const graph_identity = air.composition_circuit.computeGraphDigest(graph_nodes, program.circuit.outputs());
        const uses = program.circuit.useCounts()[0..program.bindings.len];
        const admitted = try subject.Plan.init(program.bindings, uses, graph_identity);
        var consumer_definition = try subject.Plan.ConsumerAir.build(allocator);
        defer consumer_definition.deinit();
        const consumer = try subject.Plan.ConsumerAir.Relation.authenticate(&consumer_definition);
        for (0..subject.CLOCK_WORD_COUNT) |index| {
            const row = admitted.clockConsumerRow(index);
            const node = 1 + subject.WORD_COUNT + index;
            try std.testing.expectEqual(@as(u32, @intCast(node)), row.node_id);
            try std.testing.expectEqual(uses[node], row.use_count);
            try std.testing.expectEqual(@as(u32, 1), admitted.clockProviderUses(index));
            try std.testing.expectEqual(@as(u32, 5), row.statement_scope);
            try std.testing.expectEqual(@as(u32, @intCast(index)), row.word_index);
            try std.testing.expect(row.integer);
            try std.testing.expectEqualDeep([_]M31{M31.zero()} ** 4, admitted.byteColumns(row));
            const value = M31.fromU64(1000 + index);
            const entries = consumer.preparedEntries(try admitted.logicalConsumerRow(row, value));
            try std.testing.expectEqual(row.circuit_id, entries[1].values[0].toM31Array()[0].toU32());
            try std.testing.expectEqual(row.node_id, entries[1].values[1].toM31Array()[0].toU32());
            try std.testing.expectEqual(value.toU32(), entries[1].values[2].toM31Array()[0].toU32());
            try std.testing.expectEqual(uses[node], entries[1].numerator.toM31Array()[0].toU32());
            try std.testing.expect(entries[3].numerator.isZero());
            try std.testing.expect(entries[4].numerator.isZero());
        }
        try std.testing.expectEqual(@as(u32, 0), admitted.clockProviderUses(subject.CLOCK_WORD_COUNT));
        const clock_start = 1 + subject.WORD_COUNT;
        const original = program.bindings[clock_start];
        program.bindings[clock_start] = program.bindings[clock_start + 1];
        try std.testing.expectError(error.InvalidEthereumStatementRouting, subject.Plan.init(program.bindings, uses, graph_identity));
        program.bindings[clock_start] = original;
        break :blk admitted;
    };
    // The source graph is destroyed. Both endpoints consume the admitted
    // immutable plan; proof values remain independently supplied inputs.
    try auditClockRoutes(&plan, .valid);
    for ([_]ClockCorruption{ .missing, .duplicate, .wrong, .swapped, .changed_value }) |mode|
        try std.testing.expectError(error.EthereumClockRoutingNotClosed, auditClockRoutes(&plan, mode));
    const row = plan.clockConsumerRow(0);
    _ = try plan.logicalConsumerRow(row, M31.fromCanonical(0xffff));
    try std.testing.expectError(error.IntegerWordOutOfRange, plan.logicalConsumerRow(row, M31.fromCanonical(0x10000)));
    try std.testing.expectError(error.InvalidInputBinding, air.statement_semantics_input_witness.logicalRow(row, M31.one(), .segment_leaf));
}

const ClockCorruption = enum { valid, missing, duplicate, wrong, swapped, changed_value };

fn clockPayloadRow(index: usize) air.transcript_payload_witness.Row {
    const clocks = frontend.recursion.ethereum_clock_routing_v1;
    return .{
        .row_mask = 1,
        .segment_mask = 1,
        .binary_mask = 0,
        .verifier_id = 0,
        .sequence = 3,
        .tag = 0,
        .args = .{ 0, 0, 0, 0 },
        .payload_index = @intCast(clocks.WIRE_START + index),
        .source_kind = .statement,
        .item_index = clocks.STATEMENT_SCOPE,
        .limb_index = @intCast(index),
        .constant_mask = 0,
        .input_use_count = 0,
        .constant_value = 0,
        .source_hash_id = 0,
        .source_word_index = @intCast(frontend.recursion.recording_poseidon_channel_v4.RATE + clocks.WIRE_START + index),
    };
}

fn auditClockRoutes(plan: *const subject.Plan, mode: ClockCorruption) !void {
    const allocator = std.testing.allocator;
    const clock_air = air.transcript_payload_clocks_v2;
    var provider_definition = try clock_air.build(allocator);
    defer provider_definition.deinit();
    const provider = try clock_air.Relation.authenticate(&provider_definition);
    var consumer_definition = try subject.Plan.ConsumerAir.build(allocator);
    defer consumer_definition.deinit();
    const consumer = try subject.Plan.ConsumerAir.Relation.authenticate(&consumer_definition);
    var ledger = air.relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    for (0..subject.CLOCK_WORD_COUNT) |index| {
        const value = M31.fromU64(1000 + index);
        const provided = provider.preparedEntries(try clock_air.logicalRow(clockPayloadRow(index), value));
        try std.testing.expectEqual(plan.clockProviderUses(index), provided[2].numerator.toM31Array()[0].toU32());
        if (!(mode == .missing and index == 0)) try appendClockStatements(&ledger, 5, &provided);
        if (mode == .duplicate and index == 0) try appendClockStatements(&ledger, 5, &provided);
        var row = plan.clockConsumerRow(index);
        if (mode == .wrong and index == 0) row.word_index = 1;
        if (mode == .swapped and index < 2) row.word_index = @intCast(1 - index);
        const consumed_value = if (mode == .changed_value and index == 0) value.add(M31.one()) else value;
        const consumed = consumer.preparedEntries(try plan.logicalConsumerRow(row, consumed_value));
        try appendClockStatements(&ledger, 11, &consumed);
    }
    if (!ledger.classify().isClosed()) return error.EthereumClockRoutingNotClosed;
}

fn appendClockStatements(ledger: *air.relation_interaction.TupleLedger, component: u8, entries: []const air.relation_interaction.Entry) !void {
    for (entries) |entry| {
        if (entry.domain != .recursion_statement_word) continue;
        try ledger.append(entry.domain, component, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    }
}

test "Ethereum native continuation routing separates snapshot words and authenticates exact graph uses" {
    const allocator = std.testing.allocator;
    var program = try sums.buildWithNativeRoots(allocator, 1, null, false, .legacy_v4, .nonfinal_program_v1);
    defer program.deinit(allocator);
    const uses = program.circuit.useCounts()[0..program.bindings.len];
    const plan = try subject.Plan.init(program.bindings, uses, .{0} ** 32);
    try std.testing.expect(plan.usesNativeRoots());
    var legacy = try sums.build(allocator, 1);
    defer legacy.deinit(allocator);
    const legacy_plan = try subject.Plan.init(legacy.bindings, legacy.circuit.useCounts()[0..legacy.bindings.len], .{0} ** 32);
    try std.testing.expect(!legacy_plan.usesNativeRoots());
    try std.testing.expect(!std.meta.eql(plan.identity(), legacy_plan.identity()));
    var definition = try subject.Plan.ConsumerAir.build(allocator);
    defer definition.deinit();
    const consumer = try subject.Plan.ConsumerAir.Relation.authenticate(&definition);
    var vm_definition = try air.vm_air_composition_input.build(allocator);
    defer vm_definition.deinit();
    const vm_relation = try air.vm_air_composition_input_relation.authenticate(&vm_definition);
    for (0..2) |index| {
        const side: u1 = @intCast(index);
        const row = plan.nativeRootConsumerRow(side).?;
        try std.testing.expectEqual(@as(u32, 6), row.statement_scope);
        try std.testing.expectEqual(index, row.word_index);
        try std.testing.expect(!row.integer);
        try std.testing.expectEqual(@as(u32, 1), plan.nativeRootSourceUses(side));
        try std.testing.expectEqual(@as(u32, 0), legacy_plan.nativeRootSourceUses(side));
        try std.testing.expect(legacy_plan.nativeRootConsumerRow(side) == null);
        try std.testing.expectEqualDeep([_]M31{M31.zero()} ** 4, plan.byteColumns(row));
        const value = M31.fromCanonical(12345 + @as(u32, side));
        const entries = consumer.preparedEntries(try plan.logicalConsumerRow(row, value));
        try std.testing.expectEqual(row.node_id, entries[1].values[1].toM31Array()[0].toU32());
        try std.testing.expectEqual(value.toU32(), entries[1].values[2].toM31Array()[0].toU32());
        try std.testing.expectEqual(uses[row.node_id], entries[1].numerator.toM31Array()[0].toU32());
        try std.testing.expect(entries[3].numerator.isZero() and entries[4].numerator.isZero());
        try std.testing.expectError(error.InvalidInputBinding, air.statement_semantics_input_witness.logicalRow(row, value, .segment_leaf));
        const vm_row: air.vm_air_composition_input_witness.Row = .{ .classification = .{ .vm_input = .{ .native_continuation_root = side } }, .circuit_id = 7, .node_id = 9, .use_count = 3 };
        const vm_entries = try vm_relation.entries(&vm_definition.arena, air.vm_air_composition_input.SEMANTIC_DIGEST, vm_definition.events, try air.vm_air_composition_input_witness.logicalRow(vm_row, value, .segment_leaf));
        try std.testing.expectEqual(@as(u32, 6), vm_entries[6].values[0].toM31Array()[0].toU32());
        try std.testing.expectEqual(@as(u32, side), vm_entries[6].values[1].toM31Array()[0].toU32());
        try std.testing.expectEqual(value.toU32(), vm_entries[6].values[2].toM31Array()[0].toU32());
        // These graph inputs cannot be silently sourced from the snapshot digest.
        const original = program.bindings[row.node_id];
        program.bindings[row.node_id] = .{ .statement_word = @intCast(air.vm_statement_roots.word_indices[index]) };
        try std.testing.expectError(error.InvalidEthereumStatementRouting, subject.Plan.init(program.bindings, uses, .{0} ** 32));
        program.bindings[row.node_id] = .{ .native_continuation_root = side ^ 1 };
        try std.testing.expectError(error.InvalidEthereumStatementRouting, subject.Plan.init(program.bindings, uses, .{0} ** 32));
        program.bindings[row.node_id] = original;
    }
    const first = plan.nativeRootConsumerRow(0).?.node_id;
    const original = program.bindings[first];
    program.bindings[first] = .segment_selector;
    try std.testing.expectError(error.InvalidEthereumStatementRouting, subject.Plan.init(program.bindings, uses, .{0} ** 32));
    program.bindings[first] = original;
    var changed_uses = try allocator.dupe(u32, uses);
    defer allocator.free(changed_uses);
    changed_uses[first] = 0;
    try std.testing.expectError(error.InvalidEthereumStatementRouting, subject.Plan.init(program.bindings, changed_uses, .{0} ** 32));
}
