//! Complete native child verifier row assembly. No implicit public input fallback.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const HashColumns = @import("../blake3_native_hash_columns.zig").Owner;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const lower = @import("verifier_arithmetic_lowering.zig");
const Graph = @import("composition_circuit.zig").CircuitGraph;
const vm = @import("../vm_air_composition_circuit.zig");
const scalar = @import("scalar_wire_source.zig");
const boundary = @import("blake3_boundary.zig");
const storage = @import("blake3_parent_row_storage.zig");
pub const selectors = storage.selectors;
pub const Airs = storage.Airs;
const FixedTuple = storage.FixedTuple;
const Builder = storage.Builder;
pub const Prepared = storage.Prepared;
const directCohort = storage.directCohort;
const inventory = @import("blake3_parent_input_inventory.zig").check;
pub const Sources = struct {
    composition: *const vm.Prepared,
    transcript: *const @import("blake3_native_transcript.zig").Prepared,
    deep: *const @import("blake3_native_deep.zig").Prepared,
    fri: *const @import("blake3_native_fri.zig").Prepared,
    payloads: *const @import("blake3_native_payload_links.zig").Prepared,
    samples: *const @import("blake3_native_sample_links.zig").Prepared,
    challenges: *const @import("blake3_native_pcs_challenges.zig").Prepared,
    terminal: *const @import("blake3_native_terminal_encoding.zig").Prepared,
    queries: *const @import("blake3_native_queries.zig").Prepared,
    openings: *const @import("blake3_native_openings.zig").Prepared,
    roots: *const @import("blake3_native_root_nonce.zig").Prepared,
    public_boundary: *const @import("blake3_native_public_boundary.zig").Prepared,
    public_join: *const @import("blake3_native_public_links.zig").Prepared,
    public_inputs: *const @import("blake3_native_public_sources.zig").Prepared,
    paths: *const @import("blake3_stark_paths.zig").Prepared,
    pub fn graphs(self: Sources) [5]Graph {
        return .{ self.composition.circuit.graph(), self.deep.graph.graph(), self.fri.graph.graph(), self.public_boundary.graph.graph, self.public_join.graph.graph };
    }
    pub fn evaluations(self: Sources) [5][]const Q {
        return .{ self.composition.evaluation.values, self.deep.evaluation.values, self.fri.evaluation.values, self.public_boundary.evaluation.values, self.public_join.evaluation.values };
    }
};
/// Read-only census of the exact graph lanes used by this assembler.
pub fn fusionCensus(a: std.mem.Allocator, sources: anytype) !void {
    const graphs = sources.graphs();
    return fusionCensusGraphs(a, &graphs, sources.deep);
}
/// Read-only planning diagnostic: no transcript/path witness columns required.
pub fn fusionCensusGraphs(a: std.mem.Allocator, graphs: []const Graph, deep: anytype) !void {
    var removed: usize = 0;
    var original: usize = 0;
    for (graphs, 0..) |graph, i| {
        const lane = lower.Lane{ .circuit_id = @intCast(1500 + 2 * i), .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
        const census = try @import("arithmetic_fusion_census.zig").inspect(a, lane);
        std.debug.print("BLAKE3_RESIDUAL_FUSION_CENSUS lane={d} multiply={d} linear={d} inverse={d} quotient_accumulations={d} prelinear_products={d} prelinear_hidden_rows={d} prelinear_add={d} prelinear_sub={d} prelinear_neg={d} prelinear_both={d} candidate_only=true\n", .{ lane.circuit_id, census.remaining_multiply, census.remaining_linear, census.remaining_inverse, census.quotient_accumulations, census.prelinear_products, census.prelinear_hidden_rows, census.prelinear_add, census.prelinear_sub, census.prelinear_neg, census.prelinear_both_operands });
        original += census.multiply + census.linear + census.inverse;
        removed += census.removedRows();
        std.debug.print("BLAKE3_ARITHMETIC_CENSUS lane={d} nodes={d} multiply={d} linear={d} inverse={d} dot4={d} fma={d} removable_rows={d}\n", .{ lane.circuit_id, census.nodes, census.multiply, census.linear, census.inverse, census.dot4_matches, census.fma_matches, census.removedRows() });
    }
    const pcs_census = try @import("detached_pcs_opening_plan.zig").censusGraph(a, deep.graph.graph(), deep.graph.bindings, &.{});
    std.debug.print("BLAKE3_PCS_QUERY_FUSION_CENSUS nodes={d} query_inputs={d} single_use={d} shared={d} dot4={d} eligible={d} scope=pre_lowering_graph_candidates\n", .{ pcs_census.graph_nodes, pcs_census.queried_inputs, pcs_census.single_use_queried_inputs, pcs_census.shared_queried_inputs, pcs_census.opening4_groups, pcs_census.eligible_groups });
    std.debug.print("BLAKE3_ARITHMETIC_CENSUS total_rows={d} removable_rows={d} removed_relation_events={d} scope=graph_match_census\n", .{ original, removed, 2 * removed });
}

pub fn prepare(a: std.mem.Allocator, source: anytype) !Prepared {
    return prepareMode(false, false, a, source, null, null);
}
pub fn prepareCensus(a: std.mem.Allocator, source: anytype) !Prepared {
    return prepareMode(true, false, a, source, null, null);
}
/// Transfers main-column ownership only after every fallible assembly step.
/// Transferred columns and the returned rows retain one allocation authority.
/// Stateless allocators may have an undefined context pointer: never compare it.
pub fn prepareWithHashColumns(source: anytype, columns: *HashColumns) !Prepared {
    if (!columns.owns_backing) return error.InvalidNativeHashColumns;
    return prepareMode(false, false, columns.allocator, source, columns, null);
}
pub fn preparePartition(source: anytype, columns: *HashColumns) !storage.Partition {
    if (columns.owns_backing) return error.InvalidNativeHashColumns;
    return prepareMode(false, true, columns.allocator, source, columns, null);
}
/// Called once after direct columns and copied rows no longer borrow the
/// transcript/path sources. Arithmetic graphs must remain alive until return.
/// The callback is irreversible; callers must also clean up on later failure.
pub const ReleaseRows = struct {
    context: *anyopaque,
    call: *const fn (*anyopaque) void,
};
pub fn prepareReleasingRows(source: anytype, columns: *HashColumns, release: ReleaseRows) !Prepared {
    if (!columns.owns_backing) return error.InvalidNativeHashColumns;
    return prepareMode(false, false, columns.allocator, source, columns, release);
}
pub fn preparePartitionReleasingRows(source: anytype, columns: *HashColumns, release: ReleaseRows) !storage.Partition {
    if (columns.owns_backing) return error.InvalidNativeHashColumns;
    return prepareMode(false, true, columns.allocator, source, columns, release);
}
fn prepareMode(comptime audit: bool, comptime shared: bool, a: std.mem.Allocator, source: anytype, hash_columns: ?*HashColumns, release_rows: ?ReleaseRows) !(if (shared) storage.Partition else Prepared) {
    if (hash_columns) |owner| {
        if (source.transcript.live.hash_metadata == null or source.paths.hash_metadata == null) return error.InvalidNativeHashColumns;
        const transcript = try owner.transcript();
        const paths = try owner.paths();
        const transcript_metadata = source.transcript.live.hash_metadata orelse return error.InvalidNativeHashColumns;
        const path_metadata = source.paths.hash_metadata orelse return error.InvalidNativeHashColumns;
        if (source.transcript.live.g_rows.len != 0 or source.transcript.live.xor_rows.len != 0 or source.paths.live.g_rows.len != 0 or source.paths.live.xor_rows.len != 0) return error.InvalidNativeHashColumns;
        if (transcript_metadata.g_rows.ptr != transcript.g_rows.metadata.ptr or transcript_metadata.g_rows.len != transcript.g_rows.metadata.len or
            transcript_metadata.xor_rows.ptr != transcript.xor_rows.metadata.ptr or transcript_metadata.xor_rows.len != transcript.xor_rows.metadata.len or
            path_metadata.g_rows.ptr != paths.g_rows.metadata.ptr or path_metadata.g_rows.len != paths.g_rows.metadata.len or
            path_metadata.xor_rows.ptr != paths.xor_rows.metadata.ptr or path_metadata.xor_rows.len != paths.xor_rows.metadata.len) return error.InvalidNativeHashColumns;
    } else if (source.transcript.live.hash_metadata != null or source.paths.hash_metadata != null) return error.InvalidNativeHashColumns;
    if (comptime @hasDecl(@TypeOf(source), "execution")) {
        try source.validate(a);
    } else {
        try source.composition.validate();
        try source.deep.graph.validateEvaluation(&source.deep.evaluation);
        try source.fri.evaluation.validateAgainst(&source.fri.graph);
        try source.public_boundary.validate(a);
        try source.public_join.graph.validate();
        var aggregate = try source.public_join.evaluate(a, &source.public_join.inputs);
        defer aggregate.deinit();
        if (aggregate.values.len != source.public_join.evaluation.values.len) return error.InvalidNativeParentRows;
        for (aggregate.values, source.public_join.evaluation.values) |actual, expected| if (!actual.eql(expected)) return error.InvalidNativeParentRows;
    }
    if (source.paths.fixed_hash_metadata != null and (source.paths.fixed.g_rows.len != 0 or source.paths.fixed.xor_rows.len != 0)) return error.InvalidNativeParentRows;
    try source.transcript.plan.validate();
    var b = Builder.init(a);
    defer b.deinit();
    var main: [Airs.len][]Column = @splat(&.{});
    var fixed: FixedTuple(false) = undefined;
    inline for (0..Airs.len) |i| fixed[i] = &.{};
    errdefer inline for (0..Airs.len) |i| {
        if (hash_columns == null or i >= 2) {
            for (main[i]) |column| a.free(column.values);
            a.free(main[i]);
        }
        a.free(fixed[i]);
    };
    try b.reserve(0, try std.math.add(usize, source.transcript.plan.fixed.hashCounts().g, if (source.paths.fixed_hash_metadata) |m| m.g_rows.len else source.paths.fixed.g_rows.len));
    try b.reserve(1, try std.math.add(usize, source.transcript.plan.fixed.hashCounts().xor, if (source.paths.fixed_hash_metadata) |m| m.xor_rows.len else source.paths.fixed.xor_rows.len));
    const graphs = source.graphs();
    const values = source.evaluations();
    // Replacements are selected once, before constructing any row roster.
    const source_direct = @import("blake3_direct_source_columns_v1.zig");
    var source_counts = source_direct.Counts{};
    try appendSources(source, &source_counts);
    try appendSelectorInputs(a, source, graphs, values, &source_counts);
    var source_columns = try source_direct.Builder.init(a, &b, source_counts.counts);
    defer source_columns.deinit();
    try appendSources(source, &source_columns);
    // Claimed-sum sources belong to the same frozen scalar column inventory.
    // Selector public boundary terms share the frozen direct cohort2 inventory.
    try appendSelectorInputs(a, source, graphs, values, &source_columns);
    try source_columns.takeInto(&main, &fixed);
    // Finish every cohort that still reads borrowed source rows before
    // lowering allocates its arithmetic scratch. Other cohorts are copied.
    inline for (.{ 0, 1 }) |i| try projectCohort(i, shared, a, source, hash_columns, &b, &main, &fixed);
    if (release_rows) |release| release.call(release.context);
    @import("stwo_prover_engine").measurement.process_usage.reportStage("assembly.row_sources_released");
    // Selector-use scratch was released before the separate input audit.
    const packed_rows = try @import("blake3_recursive_column_rows_v1.zig").ForAir(Airs[11]).init(main[11], fixed[11]);
    const scalar_rows = try @import("blake3_recursive_column_rows_v1.zig").ForAir(Airs[12]).init(main[12], fixed[12]);
    const boundary_rows = try @import("blake3_recursive_column_rows_v1.zig").ForAir(Airs[2]).init(main[2], fixed[2]);
    const input_count = if (comptime @hasDecl(@TypeOf(source), "externalInputs")) blk: {
        const external = try source.externalInputs(a);
        defer a.free(external);
        break :blk try @import("blake3_parent_input_inventory.zig").checkExternal(a, graphs, values, scalar_rows, boundary_rows, packed_rows, external);
    } else try inventory(a, graphs, values, scalar_rows, boundary_rows, packed_rows);
    @import("stwo_prover_engine").measurement.process_usage.reportStage("assembly.input_inventory_released");
    {
        // Scratch belongs to this phase, not the final column projection.
        // Use the backing allocator so nested owners actually release their buffers.
        // Reuse the canonical lowering plan, including constant and output terms.
        var lanes: [2 * graphs.len]lower.Lane = undefined;
        var evaluations: [2 * graphs.len]lower.Evaluation = undefined;
        for (graphs, values, 0..) |graph, evaluated, i| {
            lanes[2 * i] = .{ .circuit_id = @intCast(1500 + 2 * i), .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
            lanes[2 * i + 1] = lanes[2 * i];
            lanes[2 * i + 1].circuit_id += 1;
            lanes[2 * i + 1].active_in = .binary;
            evaluations[2 * i] = .{ .circuit_identity = graph.identity_digest, .values = evaluated };
            evaluations[2 * i + 1] = evaluations[2 * i];
        }
        const reference = try lower.Reference.seal(&lanes);
        var plan = try lower.Plan.init(a, reference);
        defer plan.deinit();
        // Inventory is complete. Expand its admitted boundary columns before the
        // arithmetic matcher allocates its scratch, and emit later public terms
        // into the same final columns. No second transpose is required.
        var public_count: usize = 0;
        for (plan.public_terms) |term| if (term.active_in == .segment) {
            public_count = try std.math.add(usize, public_count, 1);
        };
        var boundaries = try @import("blake3_direct_cohort_columns_v1.zig").ForAir(Airs[2]).init(a, try std.math.add(usize, boundary_rows.rowCount(), public_count));
        defer boundaries.deinit();
        for (0..boundary_rows.rowCount()) |index| try boundaries.append(boundary_rows.rowAt(index));
        // Inventory no longer owns a dense boundary roster. Release the
        // admitted initial physical domain before allocating fusion scratch.
        for (main[2]) |column| a.free(column.values);
        a.free(main[2]);
        a.free(fixed[2]);
        main[2] = &.{};
        fixed[2] = &.{};
        // Emit arithmetic cohorts directly into their final committed layout.
        // Dot4 opening rows remain exact sources for the native PCS matcher.
        var fused = try @import("arithmetic_fusion_rows.zig").materializeColumns(a, &plan, reference, .{ .lanes = &evaluations }, .segment_leaf);
        defer fused.deinit();
        var query_fused = try @import("native_pcs_fusion_rows.zig").materializeColumns(a, source.deep, fused.opening, scalar_rows);
        defer query_fused.deinit();
        // Inventory and both matcher passes have consumed this borrowed view.
        // Release the original scalar columns before adopting the filtered
        // committed columns; there is no full scalar row/fixed-row copy.
        if (b.rows[12].items.len != 0 or b.fixed[12].items.len != 0) return error.InvalidNativeParentRows;
        for (main[12]) |column| a.free(column.values);
        a.free(main[12]);
        main[12] = &.{};
        a.free(fixed[12]);
        fixed[12] = &.{};
        const native_opening_count = query_fused.native.fixed.len;
        std.debug.print("BLAKE3_NATIVE_QUERY_FUSION groups={d} removed_scalars={d} direct_columns=true\n", .{ native_opening_count, 4 * native_opening_count });
        inline for (.{ 3, 4, 5 }, .{ &fused.multiply, &fused.inverse, &fused.linear }) |i, cohort| {
            if (b.rows[i].items.len != 0 or b.fixed[i].items.len != 0 or main[i].len != 0 or fixed[i].len != 0) return error.InvalidNativeParentRows;
            const committed = try cohort.take();
            main[i] = committed.main;
            fixed[i] = committed.fixed;
        }
        inline for (.{ 12, 18, 19 }, .{ &query_fused.scalars, &query_fused.opening, &query_fused.native }) |i, cohort| {
            if (b.rows[i].items.len != 0 or b.fixed[i].items.len != 0 or main[i].len != 0 or fixed[i].len != 0) return error.InvalidNativeParentRows;
            const committed = try cohort.take();
            main[i] = committed.main;
            fixed[i] = committed.fixed;
        }
        std.debug.print("BLAKE3_NATIVE_FUSION dot4={d} fma={d} arithmetic_rows={d} direct_columns=true\n", .{ fused.dot4_matches, fused.fma_matches, fixed[3].len + fixed[4].len + fixed[5].len + fused.opening.len });
        for (plan.public_terms) |term| if (term.active_in == .segment) {
            const weight = M.fromCanonical(term.multiplicity);
            const row = try boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array());
            try boundaries.append(row);
        };
        if (main[2].len != 0 or fixed[2].len != 0) return error.InvalidNativeParentRows;
        const committed_boundaries = try boundaries.take();
        main[2] = committed_boundaries.main;
        fixed[2] = committed_boundaries.fixed;
    }
    if (audit) {
        var live: usize = 0;
        var capacity: usize = 0;
        inline for (Airs, 0..) |Air, i| {
            const direct_fixed_bytes = fixed[i].len * @sizeOf(storage.FixedRow(Air));
            const used = b.rows[i].items.len * @sizeOf(Air.Row) + b.fixed[i].items.len * @sizeOf(storage.FixedRow(Air)) + direct_fixed_bytes;
            const allocated = b.rows[i].capacity * @sizeOf(Air.Row) + b.fixed[i].capacity * @sizeOf(storage.FixedRow(Air)) + direct_fixed_bytes;
            live += used;
            capacity += allocated;
            std.debug.print("NATIVE_ROW_CAPACITY air={d} rows={d} row_bytes={d} live_bytes={d} capacity_bytes={d}\n", .{ i, @max(b.rows[i].items.len, fixed[i].len), @sizeOf(Air.Row), used, allocated });
        }
        std.debug.print("NATIVE_ROW_CAPACITY total_live={d} current_buffers={d} scratch_before_finalize={d}\n", .{ live, capacity, @as(usize, 0) });
    }
    @import("stwo_prover_engine").measurement.process_usage.reportStage("assembly.scratch_released");
    inline for (0..Airs.len) |i| {
        if (comptime !directCohort(i)) {
            if (main[i].len == 0) try projectCohort(i, shared, a, source, hash_columns, &b, &main, &fixed);
        }
    }
    if (audit) std.debug.print("NATIVE_ROW_CAPACITY scratch_released_at_return={d}\n", .{@as(usize, 0)});
    if (shared) return .{ .allocator = a, .main = main, .fixed = fixed, .input_count = input_count, .first = hash_columns.?.first, .capacity = hash_columns.?.capacity };
    if (hash_columns) |owner| owner.main = @splat(&.{});
    return .{ .allocator = a, .main = main, .fixed = fixed, .input_count = input_count };
}

/// Reuse one graph-sized counter vector, then release it before inventory and
/// arithmetic lowering. An arena here used to retain every vector throughout
/// the largest assembly phases even when individual consumers were finished.
fn appendSelectorInputs(a: std.mem.Allocator, source: anytype, graphs: anytype, values: anytype, b: anytype) !void {
    var max_nodes = @max(graphs[1].nodes.len, graphs[2].nodes.len);
    if (comptime !@hasDecl(@TypeOf(source), "execution")) max_nodes = @max(max_nodes, graphs[0].nodes.len);
    const scratch = try a.alloc(u32, max_nodes);
    defer a.free(scratch);
    // Only these two VM source roles were not already supplied by joins.
    if (comptime !@hasDecl(@TypeOf(source), "execution")) {
        const vm_uses = try lower.computeUseCountsInto(graphs[0], scratch);
        var selector_count: usize = 0;
        for (source.composition.circuit.bindings) |binding| switch (binding.source) {
            .segment_selector => {
                if (!values[0][binding.node_id].eql(Q.one())) return error.InvalidNativeParentRows;
                const row = try boundary.logicalCoordinates(1500, binding.node_id, M.fromCanonical(vm_uses[binding.node_id]), Q.one().toM31Array());
                try b.append(2, &.{row}, &.{row});
                selector_count += 1;
            },
            .claimed_sum => {
                const value = values[0][binding.node_id].tryIntoM31() catch return error.InvalidNativeParentRows;
                try b.append(12, &.{try scalar.logicalRow(1500, binding.node_id, vm_uses[binding.node_id], value)}, &.{try scalar.logicalRow(1500, binding.node_id, vm_uses[binding.node_id], M.zero())});
            },
            else => {},
        };
        if (selector_count != 1) return error.InvalidNativeParentRows;
    }
    inline for (.{ source.deep.graph.bindings, source.fri.graph.bindings }, 1..) |bindings, lane| {
        const uses = try lower.computeUseCountsInto(graphs[lane], scratch);
        var active_count: usize = 0;
        for (bindings) |binding| if (binding.source == .active_selector) {
            if (!values[lane][binding.node_id].eql(Q.one())) return error.InvalidNativeParentRows;
            const row = try boundary.logicalCoordinates(1500 + 2 * lane, binding.node_id, M.fromCanonical(uses[binding.node_id]), Q.one().toM31Array());
            try b.append(2, &.{row}, &.{row});
            active_count += 1;
        };
        if (active_count != 1) return error.InvalidNativeParentRows;
    }
}

/// One source append recipe for count admission and final column emission.
fn appendSources(source: anytype, b: anytype) !void {
    if (comptime @hasDecl(@TypeOf(source), "execution")) {
        try source.appendInputs(b);
    } else {
        const claim_words = @import("blake3_native_public_links.zig").CLAIM_WORDS;
        if (source.samples.sourceCount() < claim_words) return error.InvalidNativeParentRows;
        try source.public_join.appendPart(.composition, b);
        try source.challenges.appendInputs(b);
        try source.public_join.appendPart(.challenges, b);
        try source.public_join.appendPart(.claims, b);
        try source.samples.appendInputs(claim_words, b);
        try source.fri.appendInputs(b);
        try source.queries.appendInputs(b);
        try source.openings.appendInputs(b);
        try source.public_join.appendPart(.totals, b);
        try source.public_join.appendPart(.destinations, b);
        try source.public_inputs.appendSums(b);
        try source.public_inputs.appendCoordinates(b);
        try source.roots.appendKey(b);
        try source.roots.appendMain(b);
        try source.roots.appendWords(b);
        try source.payloads.appendPacking(b);
    }
    try source.payloads.appendEncoded(b);
    try source.queries.appendEncoded(b);
    try source.paths.inputs.appendCohort(11, b);
    try source.paths.inputs.appendCohort(10, b);
    try source.paths.inputs.appendCohort(16, b);
    try source.paths.inputs.appendCohort(17, b);
    try source.terminal.appendInputs(b);
    if (source.transcript.plan.fixed.hash_metadata) |trusted| {
        if (source.transcript.live.hash_metadata) |compact| try b.appendMetadata(0, compact.g_rows, trusted.g_rows) else try b.appendCompact(0, source.transcript.live.g_rows, trusted.g_rows);
    } else {
        if (source.transcript.live.hash_metadata) |compact| try b.appendMetadata(0, compact.g_rows, source.transcript.plan.fixed.g_rows) else try b.append(0, source.transcript.live.g_rows, source.transcript.plan.fixed.g_rows);
    }
    if (source.transcript.plan.fixed.hash_metadata) |trusted| {
        if (source.transcript.live.hash_metadata) |compact| try b.appendMetadata(1, compact.xor_rows, trusted.xor_rows) else try b.appendCompact(1, source.transcript.live.xor_rows, trusted.xor_rows);
    } else {
        if (source.transcript.live.hash_metadata) |compact| try b.appendMetadata(1, compact.xor_rows, source.transcript.plan.fixed.xor_rows) else try b.append(1, source.transcript.live.xor_rows, source.transcript.plan.fixed.xor_rows);
    }
    try source.transcript.live.appendCohort(2, &source.transcript.plan.fixed, b);
    try source.transcript.live.appendCohort(6, &source.transcript.plan.fixed, b);
    try source.transcript.live.appendCohort(7, &source.transcript.plan.fixed, b);
    try source.transcript.live.appendCohort(8, &source.transcript.plan.fixed, b);
    try source.transcript.live.appendCohort(14, &source.transcript.plan.fixed, b);
    try source.transcript.live.appendCohort(15, &source.transcript.plan.fixed, b);
    if (source.paths.hash_metadata) |compact| {
        if (source.paths.fixed_hash_metadata) |trusted| try b.appendMetadata(0, compact.g_rows, trusted.g_rows) else try b.appendMetadata(0, compact.g_rows, source.paths.fixed.g_rows);
    } else {
        if (source.paths.fixed_hash_metadata != null) return error.InvalidNativeParentRows;
        try b.append(0, source.paths.live.g_rows, source.paths.fixed.g_rows);
    }
    if (source.paths.hash_metadata) |compact| {
        if (source.paths.fixed_hash_metadata) |trusted| try b.appendMetadata(1, compact.xor_rows, trusted.xor_rows) else try b.appendMetadata(1, compact.xor_rows, source.paths.fixed.xor_rows);
    } else {
        if (source.paths.fixed_hash_metadata != null) return error.InvalidNativeParentRows;
        try b.append(1, source.paths.live.xor_rows, source.paths.fixed.xor_rows);
    }
    try source.paths.appendCohort(2, b);
    if (source.paths.inputs.columns != null) try source.paths.inputs.appendCohort(2, b);
    try source.paths.appendCohort(7, b);
    if (source.paths.inputs.columns != null) try source.paths.inputs.projection.appendRoutes(b);
    try source.paths.appendCohort(9, b);
    try source.paths.appendCohort(13, b);
}

fn directChunks(comptime i: usize, source: anytype) [2][]const Airs[i].Row {
    return switch (i) {
        0 => .{ source.transcript.live.g_rows, source.paths.live.g_rows },
        1 => .{ source.transcript.live.xor_rows, source.paths.live.xor_rows },
        7 => .{ source.transcript.live.route_rows, source.paths.live.route_rows },
        else => @compileError("cohort does not have an admitted direct source pair"),
    };
}

fn projectCohort(comptime i: usize, comptime shared: bool, a: std.mem.Allocator, source: anytype, hash_columns: ?*HashColumns, b: *Builder, main: *[Airs.len][]Column, fixed: *FixedTuple(false)) !void {
    const Air = Airs[i];
    const log: u32 = if (b.fixed[i].items.len <= 1) 1 else std.math.log2_int_ceil(usize, b.fixed[i].items.len);
    const adopted: ?[]Column = if (comptime i < 2) if (hash_columns) |owner| blk: {
        if (!shared and log != owner.layout.logs[i]) return error.InvalidNativeHashColumns;
        break :blk owner.main[i];
    } else null else null;
    if (adopted) |columns| {
        main[i] = columns;
    } else {
        var columns: std.ArrayList(Column) = .empty;
        defer columns.deinit(a);
        errdefer for (columns.items) |column| a.free(column.values);
        if (comptime directCohort(i)) {
            const chunks = directChunks(i, source);
            if (try std.math.add(usize, chunks[0].len, chunks[1].len) != b.fixed[i].items.len) return error.InvalidNativeParentRows;
            try @import("blake3_row_columns.zig").projectChunks(Air, a, &chunks, log, 1, &columns);
        } else {
            try @import("blake3_row_columns.zig").project(Air, a, b.rows[i].items, log, 1, &columns);
        }
        main[i] = try columns.toOwnedSlice(a);
    }
    b.rows[i].deinit(a);
    b.rows[i] = .empty;
    fixed[i] = try b.fixed[i].toOwnedSlice(a);
}
