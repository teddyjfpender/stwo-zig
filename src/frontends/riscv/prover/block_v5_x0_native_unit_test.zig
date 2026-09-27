//! Nonproving local-zero native migration qualification. No STARK, device or
//! block execution entrypoint is invoked by these fixtures.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const envelope = @import("../air/x0_native_envelope_v1.zig");
const zero = @import("../air/x0_local_custody_v1.zig");
const trace = @import("../runner/trace.zig");
const semantic = @import("../air/semantic_component.zig");
const lookup = @import("../air/lookups/opcode_component.zig");

test "block-v5 x0 native symbolic degree and authenticated masks cover every family" {
    const a = std.testing.allocator;
    var relations_channel = core.proof_suites.Blake3.Channel{};
    const relations = try @import("../air/relation_challenges.zig").Relations.draw(a, &relations_channel);
    for (0..trace.N_FAMILIES) |i| {
        const family: trace.OpcodeFamily = @enumFromInt(i);
        var program = try envelope.directProgram(a, family);
        defer program.deinit();
        const degrees = try a.alloc(u32, program.nodes.len);
        defer a.free(degrees);
        for (program.nodes, degrees, 0..) |node, *degree, index| {
            switch (node.op) {
                .constant => degree.* = 0,
                .column => degree.* = 1,
                .neg => {
                    try std.testing.expect(node.lhs < index);
                    degree.* = degrees[node.lhs];
                },
                .add, .sub => {
                    try std.testing.expect(node.lhs < index and node.rhs < index);
                    degree.* = @max(degrees[node.lhs], degrees[node.rhs]);
                },
                .mul => {
                    try std.testing.expect(node.lhs < index and node.rhs < index);
                    degree.* = degrees[node.lhs] + degrees[node.rhs];
                },
            }
        }
        for (program.roots) |root| try std.testing.expect(degrees[root] <= zero.MAX_DEGREE);
        const component = try semantic.SemanticComponent.initLocalZero(family, 2, 1, 0);
        const old_component = try semantic.SemanticComponent.init(family, 2, 1, 0);
        try std.testing.expectEqual(try envelope.mainColumnCount(family), component.mainColumnCount());
        try std.testing.expect(!std.meta.eql(component.mask_binding.binding_digest, old_component.mask_binding.binding_digest));
        var logs = try component.traceLogDegreeBounds(a);
        defer logs.deinit(a);
        try std.testing.expectEqual(try envelope.mainColumnCount(family), logs.items[1].len);
        const claims = [_]Q{Q.zero()} ** @import("../air/lookups/entry.zig").MAX_BATCHES;
        const placement = try lookup.OpcodeLookupComponent.initLocalZero(family, 2, 0, 0, 0, &relations, claims[0..@import("../air/lookups/opcode_entries.zig").batchCount(family)]);
        try placement.mask_binding.validate();
        var forged = placement.mask_binding;
        forged.local_zero = false;
        forged.borrowed_main_current_columns = @intCast(trace.nColumnsForFamily(family));
        // Independently recomputing the legacy width does not make the new
        // binding digest a valid legacy recipe.
        try std.testing.expectError(error.InvalidWindowDigest, forged.validate());
    }
}

test "block-v5 x0 native real instruction cells and signed table census preserve all ordinals" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00700093, 0x00308013, 0x00504113, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try @import("../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var captured = try session.startSegment(3);
    defer captured.deinit();
    var io = try @import("blake3_segment_public.zig").Owned.init(a, &captured);
    defer io.deinit();
    var rom = try @import("../air/program/blake3_commitment.zig").buildDeclared(a, @as(@import("../air/program/commitment.zig").DeclaredDecodeAuthority, .base), .{captured.execution_trace.rows.items}, captured.rw_memory.program_words, @import("commitment_program_witness.zig").completionFetch(io.data.completion));
    defer rom.deinit();
    // Derive the complete declaration and boundary fetch from the actual ELF
    // words before either recipe may admit public execution data.
    io.data.program_root = rom.root;
    const owner_mod = @import("blake3_execution_trace.zig");
    const old = try owner_mod.Owner.init(a, &captured.execution_trace, io.data, &captured.state_chain_tracker);
    defer old.deinit();
    const current = try owner_mod.Owner.initLocalZeroWithExternal(a, &captured.execution_trace, io.data, &captured.state_chain_tracker, 0);
    defer current.deinit();
    try std.testing.expect(current.statement.localZeroCustody() and !old.statement.localZeroCustody());
    try std.testing.expectEqual(@as(u32, 3), current.statement.total_steps);
    try std.testing.expectEqual(old.statement.n_components, current.statement.n_components);
    try std.testing.expectEqual(@as(u32, 0), current.statement.public_data.reg_last_clock[0]);
    try current.statement.validateBlake3Execution();
    const old_total = old.opcode_columns.lookup_counters.?.get(.range_check_20).signedTotal();
    const new_total = current.opcode_columns.lookup_counters.?.get(.range_check_20).signedTotal();
    // Three actual x0 accesses disappear from custody, while all three real
    // instruction rows and their six access ordinals remain authenticated.
    try std.testing.expect(new_total.sub(old_total).eql(M.fromCanonical(3)));
    var ordinal_count: usize = 0;
    var authenticated_zero_read_mutations: usize = 0;
    for (current.statement.component_descs[0..current.statement.n_components], 0..) |desc, index| {
        const columns = &current.opcode_columns.components[index];
        const physical_size = @as(usize, 1) << @intCast(desc.log_size);
        const layout = try envelope.schedule(desc.family);
        try std.testing.expectEqual(trace.OpcodeFamily.base_alu_imm, desc.family);
        var definition = try @import("../air/lang/typed_addi.zig").build(a, .generated);
        defer definition.deinit();
        const source_ordinal: u8 = @intFromEnum(definition.events.source.ordinal);
        var old_source = try @import("../air/extract/runtime_program.zig").buildLookups(a, desc.family);
        defer old_source.deinit();
        for (0..physical_size) |physical| {
            var row: [trace.MAX_FAMILY_COLUMNS]Q = undefined;
            for (columns.columns[0..desc.n_columns], row[0..desc.n_columns]) |column, *value| value.* = Q.fromBase(column[physical]);
            const selector = if (physical == core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(3, desc.log_size), desc.log_size)) Q.zero() else Q.one();
            const equations = try envelope.Builder(Q).direct(desc.family, row[0..desc.n_columns], selector);
            for (equations.values[0..equations.len]) |equation| try std.testing.expect(equation.isZero());
            const typed = try envelope.Builder(Q).lookups(desc.family, row[0..desc.n_columns]);
            for (layout.groups[0..layout.len]) |group| {
                try std.testing.expectEqual(@as(?u8, group.ordinal), typed.entries[group.consume].access_ordinal);
                try std.testing.expectEqual(@as(?u8, group.ordinal), typed.entries[group.emit].access_ordinal);
                try std.testing.expectEqual(@as(?u8, group.ordinal), typed.entries[group.gap].access_ordinal);
                ordinal_count += @intFromBool(selector.eql(Q.one()));
                if (selector.isZero()) continue;
                // This fixture contains ADDI/XORI only. Its authentic typed
                // read schedule identifies the source; a destination write
                // may also expose raw columns and must not count as a read.
                if (group.ordinal != source_ordinal) continue;
                const old_width = trace.nColumnsForFamily(desc.family);
                const original = try @import("../air/lookups/opcode_entries.zig").fromMain(desc.family, row[0..old_width]);
                const before = original.entries[group.consume];
                const after = original.entries[group.emit];
                if (!before.values[0].isZero() or !before.values[1].isZero() or after.numerator.isZero()) continue;
                // Read-transition before and after are distinct physical
                // cells. Resolve BOTH through the authoritative source DAG;
                // changing a single cell would merely violate read equality.
                const before_node = old_source.nodes[old_source.entries[group.consume].values[3]];
                const after_node = old_source.nodes[old_source.entries[group.emit].values[3]];
                if (before_node.op != .column or after_node.op != .column) continue;
                try std.testing.expect(before_node.value < old_width and after_node.value < old_width);
                var changed = row;
                changed[before_node.value] = changed[before_node.value].add(Q.one());
                if (after_node.value != before_node.value) changed[after_node.value] = changed[after_node.value].add(Q.one());
                const forged_source = try @import("../air/lookups/opcode_entries.zig").fromMain(desc.family, changed[0..old_width]);
                const first = forged_source.entries[group.consume];
                const last = forged_source.entries[group.emit];
                try std.testing.expect(first.values[0].isZero() and first.values[1].isZero() and last.numerator.eql(after.numerator));
                try std.testing.expect(!first.values[3].isZero());
                for (first.values[3..7], last.values[3..7]) |read, write| try std.testing.expect(read.eql(write));
                const access = try envelope.Builder(Q).access(&forged_source, group, changed[old_width + 2 * (@as(usize, group.ordinal) - 1) ..][0..2]);
                const local_terms = zero.Algebra(Q).constraints(access);
                try std.testing.expect(!local_terms[7].isZero() and !local_terms[11].isZero());
                authenticated_zero_read_mutations += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 6), ordinal_count);
    try std.testing.expectEqual(@as(usize, 2), authenticated_zero_read_mutations);
    var stale = current.statement;
    stale.x0_local_custody_version = 0;
    try std.testing.expectError(error.InvalidStatement, stale.validateBlake3Execution());
    stale = current.statement;
    stale.public_data.reg_last_clock[0] = 1;
    try std.testing.expectError(error.UntrustedX0LocalPublicBoundary, stale.validateBlake3Execution());
    try current.sealNativeOnly();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const template = @import("block_v5_native_template_protocol_v3.zig");
    try std.testing.expectEqual(current.statement.component_descs[0].log_size + 1, try template.maximumProofColumnLog(&current.statement, 0));
    try std.testing.expectEqual(old.statement.component_descs[0].log_size, try template.maximumProofColumnLog(&old.statement, 0));
    const first = try template.geometryDigest(&current.statement, 0);
    const legacy = try template.geometryDigest(&old.statement, 0);
    try std.testing.expect(!std.meta.eql(first, legacy));
    const pinned = try template.Template.fromShape(&current.statement, config, .rv32im_zkvm_v1, 0, @splat(9));
    try std.testing.expectError(error.UntrustedNativeV5Template, pinned.admit(&old.statement, try pinned.identity()));
}

test "block-v5 x0 native quotient recovery preserves discarded LDE degree and source ownership" {
    const a = std.testing.allocator;
    const engine = @import("stwo_prover_engine");
    const poly = engine.poly.circle.poly;
    const twiddle = engine.poly.twiddles;
    const owner_mod = @import("../air/prepared_evaluation_owner.zig");
    for ([_]u32{ 1, 3 }) |trace_log| {
        const coefficients = try a.alloc(M, @as(usize, 1) << @intCast(trace_log));
        defer a.free(coefficients);
        for (coefficients, 0..) |*value, i| value.* = M.fromCanonical(@intCast(13 + 7 * i));
        const polynomial = try poly.CircleCoefficients.initBorrowed(coefficients);
        const target = core.poly.circle.canonic.CanonicCoset.new(trace_log + 2).circleDomain();
        const committed = try polynomial.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(trace_log + 1).circleDomain());
        defer a.free(committed.values);
        const original = try a.dupe(M, committed.values);
        defer a.free(original);
        const reference = try polynomial.evaluate(a, target);
        defer a.free(reference.values);
        var tower = try twiddle.precomputeM31(a, target.half_coset);
        defer twiddle.deinitM31(a, &tower);
        const shared = twiddle.TwiddleTree([]const M).init(tower.root_coset, tower.twiddles, tower.itwiddles);
        var prepared = try owner_mod.Owner.init(a, 2);
        defer prepared.deinit();
        const recovered = try prepared.valueRecovering(.{ .log_size = trace_log + 1, .values = committed.values }, trace_log, trace_log + 2, target.size(), shared);
        const retained = try prepared.valueRecovering(.{ .log_size = trace_log + 1, .values = committed.values, .coefficients = polynomial }, trace_log, trace_log + 2, target.size(), shared);
        try prepared.finishWithTwiddles(target, shared);
        try std.testing.expectEqualSlices(M, reference.values, recovered);
        try std.testing.expectEqualSlices(M, reference.values, retained);
        try std.testing.expectEqualSlices(M, original, committed.values);
    }
    var high: [8]M = @splat(M.zero());
    high[4] = M.one();
    const high_polynomial = try poly.CircleCoefficients.initBorrowed(&high);
    const committed = try high_polynomial.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(3).circleDomain());
    defer a.free(committed.values);
    const target = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    var tower = try twiddle.precomputeM31(a, target.half_coset);
    defer twiddle.deinitM31(a, &tower);
    const shared = twiddle.TwiddleTree([]const M).init(tower.root_coset, tower.twiddles, tower.itwiddles);
    var prepared = try owner_mod.Owner.init(a, 1);
    defer prepared.deinit();
    try std.testing.expectError(error.InvalidProofShape, prepared.valueRecovering(.{ .log_size = 3, .values = committed.values }, 2, 4, target.size(), shared));
    try std.testing.expectEqual(@as(usize, 0), prepared.initialized);
}
