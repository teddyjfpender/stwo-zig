//! Development-only Cairo emission into the backend-neutral ProofProgram IR.
//!
//! The currently loadable Cairo semantic pack is selected from a Rust proof.
//! It is useful for parity and backend development, but is not production AIR
//! authority. This module deliberately exposes no CUDA schedule or executor.

const std = @import("std");
const backend = @import("stwo_backend_contracts");
const core = @import("stwo_core");
const adapter = @import("../../frontends/cairo/adapter/mod.zig");
const compact = @import("../../frontends/cairo/compact_verifier_interchange.zig");
const proof_plan = @import("../../frontends/cairo/proof_plan.zig");
const staged = @import("../../frontends/cairo/staged_arena_planner.zig");
const statement = @import("../../frontends/cairo/statement_bootstrap.zig");
const composition = @import("../../frontends/cairo/witness/composition_bundle.zig");
const semantic_pack = @import("../../frontends/cairo/witness/semantic_pack.zig");
const source_semantic_pack = @import("../../frontends/cairo/witness/source_semantic_pack.zig");
const identities = @import("identity.zig");

const ir = backend.proof_program;

pub const production_ready = false;

pub const BufferDescription = struct {
    staged: staged.BufferSpec,
    storage: ir.StorageClass = .request_local,
    immutable: bool = false,
};

pub const Inputs = struct {
    proof: *const proof_plan.CairoProofPlan,
    semantics: *const semantic_pack.Loaded,
    compact_statement: []const u8,
    protocol: compact.CompactProtocolV1,
    buffers: []const BufferDescription,
};

pub const Error = error{
    DevelopmentSemanticsRequired,
    GeometryOverflow,
    InvalidBufferGeometry,
    InvalidCompositionGeometry,
    InvalidPreprocessedGeometry,
    InvalidProofPlan,
    InvalidStatementEncoding,
};

/// Authenticates a proof-independent source registry against the runtime
/// component plan. This is necessary but not sufficient for production: AIR
/// composition and fixed/preprocessed authority remain incomplete.
pub fn authenticateSourceComponentPlan(
    pack: *const source_semantic_pack.Loaded,
    proof: *const proof_plan.CairoProofPlan,
) !void {
    try pack.admitProofPlan(proof);
}

/// Emits a generic program for parity and backend-development work only.
/// The authenticated pack is checked before and after reading coefficient
/// metadata so mutable artifact paths cannot change the emitted identity.
pub fn emitDevelopmentOnly(
    allocator: std.mem.Allocator,
    input: Inputs,
) !ir.ProofProgram {
    if (input.semantics.provenance != .proof_derived)
        return Error.DevelopmentSemanticsRequired;
    try input.semantics.assertUnchanged();
    const preprocessed_logs = try readPreprocessedLogs(
        allocator,
        input.semantics.files.preprocessed_coefficients,
        input.semantics.fixed_tables.preprocessed_identities,
    );
    defer allocator.free(preprocessed_logs);
    try input.semantics.assertUnchanged();
    return emitAuthenticated(allocator, .{
        .proof = input.proof,
        .pack = identities.PackIdentity.fromLoaded(input.semantics),
        .composition = &input.semantics.composition,
        .preprocessed_logs = preprocessed_logs,
        .compact_statement = input.compact_statement,
        .protocol = input.protocol,
        .buffers = input.buffers,
    });
}

const Authority = struct {
    proof: *const proof_plan.CairoProofPlan,
    pack: identities.PackIdentity,
    composition: *const composition.Bundle,
    preprocessed_logs: []const u32,
    compact_statement: []const u8,
    protocol: compact.CompactProtocolV1,
    buffers: []const BufferDescription,
};

fn emitAuthenticated(allocator: std.mem.Allocator, authority: Authority) !ir.ProofProgram {
    try validateAuthority(allocator, authority);
    const pack_digest = authority.pack.digest();
    const trace_columns = try traceColumns(allocator, authority);
    defer allocator.free(trace_columns);
    const constraints = try constraintsFor(allocator, authority.composition, pack_digest);
    defer allocator.free(constraints);
    const commitments = try commitmentTrees(trace_columns, authority.protocol);
    const fri_layers = try friLayers(allocator, authority.protocol);
    defer allocator.free(fri_layers);
    const composition_degree_log = try maxConstraintDegreeLog(authority.composition);
    const buffers = try proofBuffers(allocator, authority.proof, authority.buffers);
    defer allocator.free(buffers);
    var graph = try Graph.init(allocator, authority);
    defer graph.deinit();

    return ir.ProofProgram.init(allocator, .{
        .identity = .{
            .frontend = .cairo,
            .air = pack_digest,
            .statement = identities.statementDigest(authority.compact_statement),
            .protocol = try identities.protocolDigest(authority.protocol),
        },
        .trace_columns = trace_columns,
        .constraints = constraints,
        .commitments = &commitments,
        .transcript = graph.barriers.items,
        .quotient = .{
            .term_count = std.math.cast(u32, authority.composition.total_constraints) orelse
                return Error.GeometryOverflow,
            .group_count = std.math.cast(u32, authority.composition.components.len) orelse
                return Error.GeometryOverflow,
            .evaluation_log_rows = authority.protocol.max_log_degree_bound,
            .composition_degree_log = composition_degree_log,
        },
        .fri_layers = fri_layers,
        .buffers = buffers,
        .nodes = graph.nodes.items,
        .dependency_ids = graph.dependencies.items,
    });
}

fn validateAuthority(allocator: std.mem.Allocator, authority: Authority) !void {
    if (authority.pack.provenance != .proof_derived)
        return Error.DevelopmentSemanticsRequired;
    try authority.protocol.validate();
    try validateStatementForComposition(
        allocator,
        authority.compact_statement,
        authority.composition,
    );
    const bundle = authority.composition;
    if (bundle.plan_hash == 0 or
        bundle.plan_hash != authority.pack.composition_plan_hash or
        authority.pack.verifier_max_log_degree_bound != authority.protocol.max_log_degree_bound or
        (bundle.verifierMaxLogDegreeBound() catch
            return Error.InvalidCompositionGeometry) != authority.pack.verifier_max_log_degree_bound or
        bundle.components.len != authority.proof.components.len or
        authority.preprocessed_logs.len != authority.protocol.trace_columns[0])
    {
        return Error.InvalidCompositionGeometry;
    }

    var constraints: u64 = 0;
    var max_evaluation_log: u32 = 0;
    var cursors = [3]u32{ 0, 0, 0 };
    for (bundle.components) |component| {
        const planned = authority.proof.find(component.label) orelse return Error.InvalidProofPlan;
        if (!componentMatchesPlan(component, planned)) return Error.InvalidProofPlan;
        const degree_log = std.math.sub(
            u32,
            component.evaluation_log_size,
            component.trace_log_size,
        ) catch return Error.InvalidCompositionGeometry;
        if (degree_log == 0 or
            component.denominator_inverses.len != try pow2(degree_log))
        {
            return Error.InvalidCompositionGeometry;
        }
        for (component.preprocessed_indices) |index| {
            if (index >= authority.preprocessed_logs.len)
                return Error.InvalidPreprocessedGeometry;
        }
        if (component.random_coefficient_offset != constraints) return Error.InvalidCompositionGeometry;
        constraints = std.math.add(u64, constraints, component.n_constraints) catch
            return Error.GeometryOverflow;
        max_evaluation_log = @max(max_evaluation_log, component.evaluation_log_size);
        var seen = [3]bool{ false, false, false };
        for (component.trace_spans) |span| {
            if (span.tree >= 3 or seen[span.tree] or span.start != cursors[span.tree] or
                span.end < span.start or span.end > authority.protocol.trace_columns[span.tree])
                return Error.InvalidCompositionGeometry;
            seen[span.tree] = true;
            cursors[span.tree] = span.end;
        }
        if (!seen[0] or !seen[1] or !seen[2] or cursors[0] != 0)
            return Error.InvalidCompositionGeometry;
        var next_root: u32 = 0;
        for (component.parts) |part| {
            if (part.rc_base != next_root or part.semantic_hash != part.program.header.semantic_hash or
                part.program.header.domain_log_size != component.trace_log_size or
                part.program.header.n_interactions != 3 or
                part.program.header.n_ext_params != component.ext_sources.len)
                return Error.InvalidCompositionGeometry;
            try part.program.validate();
            next_root = std.math.add(u32, next_root, part.program.header.n_constraints) catch
                return Error.GeometryOverflow;
        }
        if (next_root != component.n_constraints) return Error.InvalidCompositionGeometry;
    }
    if (constraints != bundle.total_constraints or max_evaluation_log != bundle.max_evaluation_log_size or
        cursors[1] != authority.protocol.trace_columns[1] or
        cursors[2] != authority.protocol.trace_columns[2])
        return Error.InvalidCompositionGeometry;
    for (authority.preprocessed_logs) |log_rows| {
        if (log_rows == 0 or log_rows > authority.protocol.max_log_degree_bound)
            return Error.InvalidPreprocessedGeometry;
    }
}

fn componentMatchesPlan(
    component: composition.Component,
    planned: *const proof_plan.Component,
) bool {
    for (planned.trace_parts) |part| {
        if (part.rows.padded_rows == @as(u32, 1) << @intCast(component.trace_log_size))
            return true;
    }
    return false;
}

fn traceColumns(allocator: std.mem.Allocator, authority: Authority) ![]ir.TraceColumn {
    var total: usize = 0;
    for (authority.protocol.trace_columns) |count|
        total = std.math.add(usize, total, count) catch return Error.GeometryOverflow;
    const columns = try allocator.alloc(ir.TraceColumn, total);
    var cursor: usize = 0;
    for (authority.preprocessed_logs) |log_rows| {
        columns[cursor] = columnAt(cursor, std.math.maxInt(u32), log_rows, .preprocessed);
        cursor += 1;
    }
    inline for ([_]u32{ 1, 2 }) |tree| {
        const role: ir.ColumnRole = if (tree == 1) .main else .interaction;
        for (authority.composition.components, 0..) |component, component_index| {
            const span = findSpan(component, tree) orelse return Error.InvalidCompositionGeometry;
            for (span.start..span.end) |_| {
                columns[cursor] = columnAt(cursor, @intCast(component_index), component.trace_log_size, role);
                cursor += 1;
            }
        }
    }
    const composition_log = std.math.sub(
        u32,
        authority.protocol.max_log_degree_bound,
        1,
    ) catch return Error.InvalidCompositionGeometry;
    for (0..authority.protocol.trace_columns[3]) |_| {
        columns[cursor] = columnAt(cursor, std.math.maxInt(u32) - 1, composition_log, .composition);
        cursor += 1;
    }
    std.debug.assert(cursor == columns.len);
    return columns;
}

fn constraintsFor(
    allocator: std.mem.Allocator,
    bundle: *const composition.Bundle,
    pack_digest: ir.Digest,
) ![]ir.ConstraintProgram {
    const constraints = try allocator.alloc(ir.ConstraintProgram, bundle.components.len);
    for (bundle.components, constraints, 0..) |component, *constraint, index| {
        constraint.* = .{
            .id = @intCast(index),
            .component = @intCast(index),
            .expression = identities.componentProgramDigest(pack_digest, component),
            .constraint_count = component.n_constraints,
            .max_degree_log = std.math.sub(
                u32,
                component.evaluation_log_size,
                component.trace_log_size,
            ) catch return Error.InvalidCompositionGeometry,
        };
    }
    return constraints;
}

fn maxConstraintDegreeLog(bundle: *const composition.Bundle) Error!u32 {
    var maximum: u32 = 0;
    for (bundle.components) |component| {
        maximum = @max(
            maximum,
            std.math.sub(
                u32,
                component.evaluation_log_size,
                component.trace_log_size,
            ) catch return Error.InvalidCompositionGeometry,
        );
    }
    if (maximum == 0) return Error.InvalidCompositionGeometry;
    return maximum;
}

fn commitmentTrees(columns: []const ir.TraceColumn, protocol: compact.CompactProtocolV1) ![4]ir.CommitmentTree {
    var trees: [4]ir.CommitmentTree = undefined;
    var first: u32 = 0;
    inline for (0..4) |tree_index| {
        const count = protocol.trace_columns[tree_index];
        var evaluation_log: u32 = 0;
        for (columns[first .. first + count]) |column| {
            evaluation_log = @max(
                evaluation_log,
                std.math.add(u32, column.log_rows, protocol.log_blowup_factor) catch
                    return Error.GeometryOverflow,
            );
        }
        trees[tree_index] = .{
            .id = tree_index,
            .role = @enumFromInt(tree_index),
            .first_column = first,
            .column_count = count,
            .evaluation_log_rows = evaluation_log,
            .log_rows_per_leaf = evaluation_log,
            .retain_openings = true,
        };
        first = std.math.add(u32, first, count) catch return Error.GeometryOverflow;
    }
    return trees;
}

fn friLayers(allocator: std.mem.Allocator, protocol: compact.CompactProtocolV1) ![]ir.FriLayer {
    const final_log = std.math.add(u32, protocol.log_last_layer_degree_bound, 1) catch
        return Error.InvalidCompositionGeometry;
    const geometry = core.fri.geometry.FriGeometry.initRuntime(protocol.max_log_degree_bound, .{
        .round_count = protocol.fri_tree_count,
        .fold_step = protocol.fri_fold_step,
        .final_log = final_log,
        .packed_log = core.fri.geometry.FriGeometry.packed_log,
    }) catch return Error.InvalidCompositionGeometry;
    const layers = try allocator.alloc(ir.FriLayer, geometry.roundCount());
    for (layers, 0..) |*layer, index| layer.* = .{
        .tree_id = @intCast(index),
        .evaluation_log_rows = try geometry.evaluationLog(index),
        .fold_step = try geometry.roundFold(index),
        .cumulative_fold = try geometry.cumulativeFold(index),
        .log_rows_per_leaf = try geometry.leafLog(index),
    };
    return layers;
}

fn proofBuffers(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    descriptions: []const BufferDescription,
) ![]ir.Buffer {
    const specs = try allocator.alloc(staged.BufferSpec, descriptions.len);
    defer allocator.free(specs);
    for (descriptions, specs) |description, *spec| spec.* = description.staged;
    var planner = try staged.StagedArenaPlanner.init(allocator, proof);
    defer planner.deinit();
    var lifetimes = try planner.derive(allocator, specs);
    defer lifetimes.deinit();
    const buffers = try allocator.alloc(ir.Buffer, descriptions.len);
    for (descriptions, lifetimes.logical, buffers) |description, logical, *buffer| {
        if (logical.size_bytes == 0 or logical.size_bytes % 4 != 0 or
            logical.alignment < 4 or logical.alignment % 4 != 0)
            return Error.InvalidBufferGeometry;
        var first = logical.live_ranges[0].first;
        var last = logical.live_ranges[0].last;
        for (logical.live_ranges[1..]) |range| {
            first = @min(first, range.first);
            last = @max(last, range.last);
        }
        buffer.* = .{
            .id = logical.id,
            .words = logical.size_bytes / 4,
            .alignment_words = @intCast(logical.alignment / 4),
            .live_from = try planner.programStageForTick(first),
            .live_through = try planner.programStageForTick(last),
            .storage = description.storage,
            .immutable = description.immutable,
        };
    }
    return buffers;
}

const Graph = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(ir.Node) = .empty,
    dependencies: std.ArrayList(u32) = .empty,
    barriers: std.ArrayList(ir.TranscriptBarrier) = .empty,

    fn init(allocator: std.mem.Allocator, authority: Authority) !Graph {
        var graph = Graph{ .allocator = allocator };
        errdefer graph.deinit();
        const trace_nodes = try allocator.alloc(u32, authority.proof.components.len);
        defer allocator.free(trace_nodes);
        @memset(trace_nodes, std.math.maxInt(u32));
        for (authority.proof.levels) |level| for (level.component_indices) |component_index| {
            var dependencies: [64]u32 = undefined;
            var dependency_count: usize = 0;
            const component = authority.proof.components[component_index];
            for (component.producer_edges) |edge| try addPlanDependency(
                authority.proof,
                trace_nodes,
                edge.producer,
                &dependencies,
                &dependency_count,
            );
            for (component.capacity_feeds) |feed| try addPlanDependency(
                authority.proof,
                trace_nodes,
                feed.producer,
                &dependencies,
                &dependency_count,
            );
            const captured = findComponent(authority.composition, component.name) orelse
                return Error.InvalidProofPlan;
            trace_nodes[component_index] = try graph.addNode(
                .trace_generation,
                .trace_generation,
                dependencies[0..dependency_count],
                .component,
                try componentWork(captured, 1),
            );
        };
        const preprocessed_commit = try graph.addNode(
            .commitment,
            .trace_commit,
            &.{},
            .merkle_subtree,
            try roleWork(authority, 0),
        );
        const main_dependencies = try allocator.alloc(u32, trace_nodes.len + 1);
        defer allocator.free(main_dependencies);
        @memcpy(main_dependencies[0..trace_nodes.len], trace_nodes);
        main_dependencies[trace_nodes.len] = preprocessed_commit;
        const main_commit = try graph.addNode(
            .commitment,
            .trace_commit,
            main_dependencies,
            .merkle_subtree,
            try roleWork(authority, 1),
        );
        const interaction_pow = try graph.chainNode(.pow, .trace_commit, main_commit, .coordination);
        const interaction_eval = try graph.chainNode(
            .constraint_evaluation,
            .trace_commit,
            interaction_pow,
            .component,
        );
        const interaction_commit = try graph.chainNode(.commitment, .trace_commit, interaction_eval, .merkle_subtree);
        const composition_eval = try graph.chainNode(
            .constraint_evaluation,
            .constraint_evaluation,
            interaction_commit,
            .component,
        );
        const composition_commit = try graph.chainNode(
            .commitment,
            .constraint_evaluation,
            composition_eval,
            .merkle_subtree,
        );
        const oods = try graph.chainNode(.oods, .oods, composition_commit, .coordination);
        const quotient = try graph.chainNode(.quotient, .quotient, oods, .quotient_chunk);
        const fri = try graph.chainNode(.fri_commit, .fri_commit, quotient, .fri_round);
        const query_pow = try graph.chainNode(.pow, .pow, fri, .coordination);
        const decommit = try graph.chainNode(.decommit, .decommit, query_pow, .merkle_subtree);
        _ = decommit;
        try graph.emitTranscript(authority, main_commit, interaction_pow, interaction_commit, composition_commit, oods, fri, query_pow);
        return graph;
    }

    fn deinit(self: *Graph) void {
        self.barriers.deinit(self.allocator);
        self.dependencies.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    fn addNode(
        self: *Graph,
        kind: ir.OperationKind,
        stage_value: ir.Stage,
        dependencies: []const u32,
        parallelism: ir.Parallelism,
        work: ir.WorkEstimate,
    ) !u32 {
        const id = std.math.cast(u32, self.nodes.items.len) orelse return Error.GeometryOverflow;
        const first = std.math.cast(u32, self.dependencies.items.len) orelse return Error.GeometryOverflow;
        try self.dependencies.appendSlice(self.allocator, dependencies);
        try self.nodes.append(self.allocator, .{
            .id = id,
            .kind = kind,
            .stage = stage_value,
            .dependencies = .{ .first = first, .count = @intCast(dependencies.len) },
            .parallelism = parallelism,
            .graph_candidate = false,
            .work = work,
        });
        return id;
    }

    fn chainNode(
        self: *Graph,
        kind: ir.OperationKind,
        stage_value: ir.Stage,
        dependency: u32,
        parallelism: ir.Parallelism,
    ) !u32 {
        return self.addNode(kind, stage_value, &.{dependency}, parallelism, .{
            .bytes_read = 1,
            .bytes_written = 1,
            .field_operations = 1,
            .hash_compressions = 0,
            .minimum_launches = 1,
        });
    }

    fn emitTranscript(
        self: *Graph,
        authority: Authority,
        main: u32,
        interaction_pow: u32,
        interaction: u32,
        composition_commit: u32,
        oods: u32,
        fri: u32,
        query_pow: u32,
    ) !void {
        try self.addBarrier(main, .mix, 1);
        try self.addBarrier(main, .mix, 1);
        try self.addBarrier(main, .mix, @intCast(authority.compact_statement.len / 4));
        try self.addBarrier(main, .mix, 1);
        try self.addBarrier(interaction_pow, .pow, 1);
        try self.addBarrier(interaction_pow, .challenge, 2);
        try self.addBarrier(interaction, .mix, @intCast(authority.composition.components.len));
        try self.addBarrier(interaction, .mix, 1);
        try self.addBarrier(interaction, .challenge, 1);
        try self.addBarrier(composition_commit, .mix, 1);
        try self.addBarrier(composition_commit, .challenge, 1);
        try self.addBarrier(oods, .mix, authority.protocol.sampled_value_words / 4);
        try self.addBarrier(oods, .challenge, 1);
        for (0..authority.protocol.fri_tree_count) |_| {
            try self.addBarrier(fri, .mix, 1);
            try self.addBarrier(fri, .challenge, 1);
        }
        try self.addBarrier(fri, .mix, authority.protocol.final_line_coefficient_count);
        try self.addBarrier(query_pow, .pow, 1);
        try self.addBarrier(query_pow, .queries, authority.protocol.query_count);
    }

    fn addBarrier(self: *Graph, node: u32, kind: ir.TranscriptKind, count: u32) !void {
        const ordinal = std.math.cast(u32, self.barriers.items.len) orelse return Error.GeometryOverflow;
        var phase: u32 = 0;
        if (self.barriers.getLastOrNull()) |previous| {
            if (previous.node == node) phase = std.math.add(u32, previous.phase, 1) catch
                return Error.GeometryOverflow;
        }
        try self.barriers.append(self.allocator, .{
            .ordinal = ordinal,
            .node = node,
            .phase = phase,
            .kind = kind,
            .value_count = count,
        });
    }
};

fn validateStatement(encoded: []const u8) Error!void {
    if (encoded.len < statement.compact_statement_header_bytes or
        !std.mem.eql(u8, encoded[0..8], &statement.compact_statement_magic) or
        std.mem.readInt(u16, encoded[8..10], .little) != statement.compact_statement_version or
        std.mem.readInt(u16, encoded[10..12], .little) != statement.compact_statement_header_bytes or
        !std.mem.allEqual(u8, encoded[12..16], 0) or !std.mem.allEqual(u8, encoded[72..80], 0))
        return Error.InvalidStatementEncoding;
    const program_count = std.mem.readInt(u32, encoded[48..52], .little);
    const output_count = std.mem.readInt(u32, encoded[52..56], .little);
    const enable_count = std.mem.readInt(u32, encoded[56..60], .little);
    const log_count = std.mem.readInt(u32, encoded[60..64], .little);
    const segment_count = std.mem.readInt(u32, encoded[64..68], .little);
    if (segment_count != adapter.N_PUBLIC_SEGMENTS or
        std.mem.readInt(u32, encoded[68..72], .little) != statement.compact_statement_memory_entry_words)
        return Error.InvalidStatementEncoding;
    var expected: u64 = statement.compact_statement_header_bytes;
    expected = addMul(expected, segment_count, 20) catch return Error.InvalidStatementEncoding;
    expected = addMul(
        expected,
        @as(u64, program_count) + @as(u64, output_count),
        36,
    ) catch return Error.InvalidStatementEncoding;
    expected = addMul(
        expected,
        @as(u64, enable_count) + @as(u64, log_count),
        4,
    ) catch return Error.InvalidStatementEncoding;
    if (expected != encoded.len) return Error.InvalidStatementEncoding;
}

fn validateStatementForComposition(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    bundle: *const composition.Bundle,
) !void {
    try validateStatement(encoded);
    var flat = statement.deriveFlatClaimGeometry(allocator, bundle) catch
        return Error.InvalidStatementEncoding;
    defer flat.deinit();
    const enable_count = std.mem.readInt(u32, encoded[56..60], .little);
    const log_count = std.mem.readInt(u32, encoded[60..64], .little);
    if (enable_count != flat.component_enable_bits.len or
        log_count != flat.component_log_sizes.len)
        return Error.InvalidStatementEncoding;
    const memory_count = @as(u64, std.mem.readInt(u32, encoded[48..52], .little)) +
        @as(u64, std.mem.readInt(u32, encoded[52..56], .little));
    var cursor = std.math.cast(
        usize,
        addMul(
            statement.compact_statement_header_bytes + adapter.N_PUBLIC_SEGMENTS * 20,
            memory_count,
            36,
        ) catch return Error.InvalidStatementEncoding,
    ) orelse return Error.InvalidStatementEncoding;
    for (flat.component_enable_bits) |enabled| {
        if (std.mem.readInt(u32, encoded[cursor..][0..4], .little) != @intFromBool(enabled))
            return Error.InvalidStatementEncoding;
        cursor += 4;
    }
    for (flat.component_log_sizes) |log_size| {
        if (std.mem.readInt(u32, encoded[cursor..][0..4], .little) != log_size)
            return Error.InvalidStatementEncoding;
        cursor += 4;
    }
}

fn readPreprocessedLogs(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected_identities: []const []u8,
) ![]u32 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    var header: [16]u8 = undefined;
    try readExact(file, &header);
    if (!std.mem.eql(u8, header[0..8], "STWZPPC\x00") or
        std.mem.readInt(u32, header[8..12], .little) != 1 or
        std.mem.readInt(u32, header[12..16], .little) != expected_identities.len)
        return Error.InvalidPreprocessedGeometry;
    const logs = try allocator.alloc(u32, expected_identities.len);
    errdefer allocator.free(logs);
    var identity_buffer: [semantic_pack.max_identity_bytes]u8 = undefined;
    for (expected_identities, logs) |expected, *log| {
        var record: [16]u8 = undefined;
        try readExact(file, &record);
        const name_len = std.mem.readInt(u16, record[0..2], .little);
        log.* = std.mem.readInt(u32, record[4..8], .little);
        const value_count = std.mem.readInt(u64, record[8..16], .little);
        if (name_len != expected.len or name_len > identity_buffer.len or
            std.mem.readInt(u16, record[2..4], .little) != 0 or log.* > 31 or
            value_count != @as(u64, 1) << @intCast(log.*))
            return Error.InvalidPreprocessedGeometry;
        try readExact(file, identity_buffer[0..name_len]);
        if (!std.mem.eql(u8, identity_buffer[0..name_len], expected))
            return Error.InvalidPreprocessedGeometry;
        const payload_bytes = std.math.mul(u64, value_count, 4) catch
            return Error.InvalidPreprocessedGeometry;
        file.seekBy(std.math.cast(i64, payload_bytes) orelse
            return Error.InvalidPreprocessedGeometry) catch return Error.InvalidPreprocessedGeometry;
    }
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return Error.InvalidPreprocessedGeometry;
    return logs;
}

fn readExact(file: std.fs.File, destination: []u8) !void {
    if (try file.readAll(destination) != destination.len) return error.EndOfStream;
}

fn addPlanDependency(
    proof: *const proof_plan.CairoProofPlan,
    trace_nodes: []const u32,
    producer: []const u8,
    output: *[64]u32,
    count: *usize,
) !void {
    const component = proof.componentIndex(producer) orelse return Error.InvalidProofPlan;
    const node = trace_nodes[component];
    if (node == std.math.maxInt(u32)) return Error.InvalidProofPlan;
    for (output[0..count.*]) |existing| if (existing == node) return;
    if (count.* == output.len) return Error.InvalidProofPlan;
    output[count.*] = node;
    count.* += 1;
}

fn roleWork(authority: Authority, tree: u32) !ir.WorkEstimate {
    var cells: u64 = 0;
    if (tree == 0) {
        for (authority.preprocessed_logs) |log_rows|
            cells = std.math.add(u64, cells, try pow2(log_rows)) catch return Error.GeometryOverflow;
    } else {
        for (authority.composition.components) |component|
            cells = std.math.add(u64, cells, try componentCells(component, tree)) catch
                return Error.GeometryOverflow;
    }
    const bytes = std.math.mul(u64, cells, 4) catch return Error.GeometryOverflow;
    return .{
        .bytes_read = bytes,
        .bytes_written = bytes,
        .field_operations = cells,
        .hash_compressions = cells,
        .minimum_launches = 1,
    };
}

fn componentWork(component: *const composition.Component, tree: u32) !ir.WorkEstimate {
    const cells = try componentCells(component.*, tree);
    const bytes = std.math.mul(u64, cells, 4) catch return Error.GeometryOverflow;
    return .{
        .bytes_read = 0,
        .bytes_written = bytes,
        .field_operations = cells,
        .hash_compressions = 0,
        .minimum_launches = 1,
    };
}

fn componentCells(component: composition.Component, tree: u32) !u64 {
    const span = findSpan(component, tree) orelse return Error.InvalidCompositionGeometry;
    const width = std.math.sub(u32, span.end, span.start) catch return Error.InvalidCompositionGeometry;
    return std.math.mul(u64, width, try pow2(component.trace_log_size)) catch Error.GeometryOverflow;
}

fn findComponent(bundle: *const composition.Bundle, label: []const u8) ?*const composition.Component {
    for (bundle.components) |*component| if (std.mem.eql(u8, component.label, label)) return component;
    return null;
}

fn findSpan(component: composition.Component, tree: u32) ?composition.TraceSpan {
    for (component.trace_spans) |span| if (span.tree == tree) return span;
    return null;
}

fn columnAt(id: usize, component: u32, log_rows: u32, role: ir.ColumnRole) ir.TraceColumn {
    return .{ .id = @intCast(id), .component = component, .ordinal = @intCast(id), .log_rows = log_rows, .role = role };
}

fn pow2(log: u32) Error!u64 {
    if (log >= 63) return Error.GeometryOverflow;
    return @as(u64, 1) << @intCast(log);
}

fn addMul(total: u64, count: u64, width: u64) !u64 {
    return std.math.add(u64, total, try std.math.mul(u64, count, width));
}

pub const testing = if (@import("builtin").is_test) struct {
    pub const TestAuthority = Authority;

    pub fn emit(allocator: std.mem.Allocator, authority: Authority) !ir.ProofProgram {
        return emitAuthenticated(allocator, authority);
    }
} else struct {};
