//! Authenticated Cairo PCS quotient topology for resident CUDA ingress.
//!
//! Proof samples, periodicity terms, point groups, and compact source geometry
//! are distinct shapes. This compiler derives each shape from authenticated AIR
//! and protocol inputs instead of reusing the AIR constraint schedule counts.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const circle = @import("stwo_core").circle;
const canonic = @import("stwo_core").poly.circle.canonic;
const compact = @import(
    "../../../../frontends/cairo/compact_verifier_interchange.zig",
);
const composition = @import(
    "../../../../frontends/cairo/witness/composition_bundle.zig",
);
const geometry = @import(
    "../../../../frontends/cairo/witness/quotient_geometry.zig",
);
const cairo_identity = @import("../../identity.zig");
const quotient_abi = @import(
    "../../../../backends/cuda/abi/stages/quotient.zig",
);
const types = @import("types.zig");

pub const Topology = types.Topology;
pub const TreeSpan = types.TreeSpan;
pub const SourceDescriptor = types.SourceDescriptor;

pub const Error = error{
    GeometryOverflow,
    InvalidBundleGeometry,
    InvalidCompactSourceGeometry,
    InvalidGroupGeometry,
    InvalidProgramGeometry,
    InvalidProtocolIdentity,
    InvalidSampleGeometry,
    UnsupportedProtocol,
};

const Source = struct {
    index: u32,
    log_size: u32,
};

const Term = struct {
    descriptor: quotient_abi.PreparedTermDescriptor,
    source: Source,
    point_shift: circle.CirclePointM31,
};

const Group = struct {
    point_shift: circle.CirclePointM31,
    log_size: u32,
    terms: std.ArrayList(u32) = .empty,

    fn deinit(self: *Group, allocator: std.mem.Allocator) void {
        self.terms.deinit(allocator);
        self.* = undefined;
    }
};

const Builder = struct {
    allocator: std.mem.Allocator,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    bundle: composition.Bundle,
    lifting_log_size: u32,
    trace_step: circle.CirclePointM31,
    lifting_generator: circle.CirclePointM31,
    sources: []SourceDescriptor,
    source_trees: []TreeSpan,
    terms: std.ArrayList(Term) = .empty,
    groups: std.ArrayList(Group) = .empty,
    sampled_value_count: usize = 0,
    source_evaluation_word_count: u64 = 0,

    fn deinit(self: *Builder) void {
        for (self.groups.items) |*group| group.deinit(self.allocator);
        self.groups.deinit(self.allocator);
        self.terms.deinit(self.allocator);
        if (self.source_trees.len != 0)
            self.allocator.free(self.source_trees);
        if (self.sources.len != 0)
            self.allocator.free(self.sources);
        self.* = undefined;
    }

    fn compile(self: *Builder) !void {
        var masks = geometry.deriveMasks(
            self.allocator,
            self.bundle,
            self.protocol.trace_columns[0],
            self.protocol.trace_columns[1],
            self.protocol.trace_columns[2],
        ) catch return Error.InvalidBundleGeometry;
        defer masks.deinit();

        const trees = try locateTrees(self.program, self.protocol);
        for (masks.preprocessed_used, 0..) |used, local| {
            if (!used) continue;
            const source = try self.sourceAt(trees[0], local);
            try self.appendColumn(source, &.{0});
        }
        for (masks.base_offsets, 0..) |offsets, local| {
            if (offsets.items.len == 0 or offsets.items.len > 2)
                return Error.InvalidSampleGeometry;
            const source = try self.sourceAt(trees[1], local);
            try self.appendColumn(source, offsets.items);
        }
        for (masks.interaction_offsets, 0..) |offsets, local| {
            if (offsets.items.len == 0 or offsets.items.len > 2)
                return Error.InvalidSampleGeometry;
            const source = try self.sourceAt(trees[2], local);
            try self.appendColumn(source, offsets.items);
        }
        for (0..trees[3].column_count) |local| {
            const source = try self.sourceAt(trees[3], local);
            try self.appendColumn(source, &.{0});
        }
    }

    fn sourceAt(
        self: Builder,
        tree: proof_ir.CommitmentTree,
        local: usize,
    ) !Source {
        if (local >= tree.column_count) return Error.InvalidProgramGeometry;
        const global = std.math.add(
            usize,
            tree.first_column,
            local,
        ) catch return Error.GeometryOverflow;
        if (global >= self.sources.len) return Error.InvalidProgramGeometry;
        return .{
            .index = try u32Count(global),
            .log_size = self.sources[global].compact.log_size,
        };
    }

    fn appendColumn(
        self: *Builder,
        source: Source,
        offsets: []const i32,
    ) !void {
        if (offsets.len == 0 or offsets.len > 2 or
            source.log_size >= self.lifting_log_size)
        {
            return Error.InvalidSampleGeometry;
        }
        const first_sample = self.sampled_value_count;
        if (offsets.len == 2) {
            const period = self.lifting_generator.repeatedDouble(
                source.log_size + 1,
            );
            const shift = self.trace_step.mulSigned(offsets[1]).add(period);
            try self.appendTerm(
                source,
                try u32Count(first_sample + 1),
                shift,
                period,
            );
        }
        for (offsets, 0..) |offset, ordinal| {
            try self.appendTerm(
                source,
                try u32Count(first_sample + ordinal),
                self.trace_step.mulSigned(offset),
                null,
            );
        }
        self.sampled_value_count = std.math.add(
            usize,
            self.sampled_value_count,
            offsets.len,
        ) catch return Error.GeometryOverflow;
    }

    fn appendTerm(
        self: *Builder,
        source: Source,
        sample_index: u32,
        shift: circle.CirclePointM31,
        period: ?circle.CirclePointM31,
    ) !void {
        const term_index = try u32Count(self.terms.items.len);
        const descriptor = quotient_abi.PreparedTermDescriptor{
            .sample_index = sample_index,
            .exponent = term_index,
            .periodic = @intFromBool(period != null),
            .period_x = if (period) |point| point.x.v else 0,
            .period_y = if (period) |point| point.y.v else 0,
        };
        try self.terms.append(self.allocator, .{
            .descriptor = descriptor,
            .source = source,
            .point_shift = shift,
        });
        const group_index = try self.groupFor(shift);
        const group = &self.groups.items[group_index];
        group.log_size = @max(group.log_size, source.log_size);
        try group.terms.append(self.allocator, term_index);
    }

    fn groupFor(
        self: *Builder,
        shift: circle.CirclePointM31,
    ) !usize {
        for (self.groups.items, 0..) |group, index| {
            if (group.point_shift.eql(shift)) return index;
        }
        try self.groups.append(self.allocator, .{
            .point_shift = shift,
            .log_size = 0,
        });
        return self.groups.items.len - 1;
    }
};

pub fn derive(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !Topology {
    try validateInputs(bundle, program, protocol);
    const source_geometry = try compileSources(
        allocator,
        program,
        protocol,
    );
    errdefer allocator.free(source_geometry.trees);
    errdefer allocator.free(source_geometry.sources);
    const lifting_log_size = try geometry.validatedLiftingLogSize(
        bundle.max_evaluation_log_size,
    );
    var builder = Builder{
        .allocator = allocator,
        .program = program,
        .protocol = protocol,
        .bundle = bundle,
        .lifting_log_size = lifting_log_size,
        .trace_step = canonic.CanonicCoset.new(
            lifting_log_size - 1,
        ).step(),
        .lifting_generator = canonic.CanonicCoset.new(
            lifting_log_size,
        ).step(),
        .sources = source_geometry.sources,
        .source_trees = source_geometry.trees,
        .source_evaluation_word_count = source_geometry.word_count,
    };
    defer builder.deinit();
    try builder.compile();
    try validateDerived(builder, program, protocol);
    return finish(&builder);
}

fn finish(builder: *Builder) !Topology {
    const allocator = builder.allocator;
    const prepared = try allocator.alloc(
        quotient_abi.PreparedTermDescriptor,
        builder.terms.items.len,
    );
    errdefer allocator.free(prepared);
    for (builder.terms.items, prepared) |term, *descriptor| {
        descriptor.* = term.descriptor;
    }
    const offsets = try allocator.alloc(u32, builder.groups.items.len + 1);
    errdefer allocator.free(offsets);
    const indices = try allocator.alloc(u32, builder.terms.items.len);
    errdefer allocator.free(indices);
    const batch = try allocator.alloc(
        quotient_abi.BatchTermDescriptor,
        builder.terms.items.len,
    );
    errdefer allocator.free(batch);
    const group_logs = try allocator.alloc(u32, builder.groups.items.len);
    errdefer allocator.free(group_logs);
    const partial_logs = try allocator.alloc(u32, builder.groups.items.len);
    errdefer allocator.free(partial_logs);
    const partial_offsets = try allocator.alloc(
        u64,
        builder.groups.items.len + 1,
    );
    errdefer allocator.free(partial_offsets);

    offsets[0] = 0;
    partial_offsets[0] = 0;
    var cursor: usize = 0;
    var maximum_partial_log: u32 = 0;
    for (builder.groups.items, 0..) |group, group_index| {
        if (group.log_size == 0 or group.terms.items.len == 0)
            return Error.InvalidGroupGeometry;
        group_logs[group_index] = group.log_size;
        maximum_partial_log = @max(maximum_partial_log, group.log_size);
        partial_logs[group_index] = group.log_size;
        partial_offsets[group_index + 1] = std.math.add(
            u64,
            partial_offsets[group_index],
            @as(u64, 1) << @intCast(group.log_size),
        ) catch return Error.GeometryOverflow;
        for (group.terms.items) |term_index| {
            if (term_index >= builder.terms.items.len)
                return Error.InvalidGroupGeometry;
            const term = builder.terms.items[term_index];
            indices[cursor] = term_index;
            batch[cursor] = .{
                .source_index = term.source.index,
                .term_index = term_index,
                .source_log_size = term.source.log_size,
            };
            cursor += 1;
        }
        offsets[group_index + 1] = try u32Count(cursor);
    }
    if (cursor != builder.terms.items.len)
        return Error.InvalidGroupGeometry;

    const identity = topologyIdentity(
        builder.program,
        builder.protocol,
        builder.bundle,
        prepared,
        offsets,
        indices,
        batch,
        builder.sources,
        builder.source_trees,
        group_logs,
        partial_offsets,
    );
    const sources = builder.sources;
    const source_trees = builder.source_trees;
    builder.sources = &.{};
    builder.source_trees = &.{};
    return .{
        .allocator = allocator,
        .prepared_terms = prepared,
        .group_offsets = offsets,
        .group_term_indices = indices,
        .batch_terms = batch,
        .sources = sources,
        .source_trees = source_trees,
        .group_log_sizes = group_logs,
        .partial_log_sizes = partial_logs,
        .partial_offsets = partial_offsets,
        .sampled_value_count = try u32Count(builder.sampled_value_count),
        .source_evaluation_word_count = builder.source_evaluation_word_count,
        .maximum_partial_rows = @as(u32, 1) <<
            @intCast(maximum_partial_log),
        .identity = identity,
    };
}

const SourceGeometry = struct {
    sources: []SourceDescriptor,
    trees: []TreeSpan,
    word_count: u64,
};

fn compileSources(
    allocator: std.mem.Allocator,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !SourceGeometry {
    const trees = try locateTrees(program, protocol);
    const sources = try allocator.alloc(
        SourceDescriptor,
        program.trace_columns.len,
    );
    errdefer allocator.free(sources);
    const spans = try allocator.alloc(TreeSpan, trees.len);
    errdefer allocator.free(spans);
    var total_words: u64 = 0;
    for (trees, spans, 0..) |tree, *span, ordinal| {
        var tree_offset: u64 = 0;
        for (
            program.trace_columns[tree.first_column .. tree.first_column + tree.column_count],
            tree.first_column..,
        ) |column, source_index| {
            const physical_log = std.math.add(
                u32,
                column.log_rows,
                protocol.log_blowup_factor,
            ) catch return Error.GeometryOverflow;
            if (column.log_rows == 0 or column.log_rows > 30 or
                physical_log > 30)
            {
                return Error.InvalidCompactSourceGeometry;
            }
            const stride: u32 = @as(u32, 1) <<
                @intCast(physical_log);
            sources[source_index] = .{
                .tree_ordinal = @intCast(ordinal),
                .local_column = @intCast(
                    source_index - tree.first_column,
                ),
                .global_column = @intCast(source_index),
                .compact = .{
                    .offset_words = tree_offset,
                    .stride_words = stride,
                    .log_size = column.log_rows,
                },
            };
            tree_offset = std.math.add(u64, tree_offset, stride) catch
                return Error.GeometryOverflow;
        }
        span.* = .{
            .tree_ordinal = @intCast(ordinal),
            .role = tree.role,
            .first_source = tree.first_column,
            .source_count = tree.column_count,
            .evaluation_words = tree_offset,
        };
        total_words = std.math.add(u64, total_words, tree_offset) catch
            return Error.GeometryOverflow;
    }
    return .{
        .sources = sources,
        .trees = spans,
        .word_count = total_words,
    };
}

fn locateTrees(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) ![4]proof_ir.CommitmentTree {
    if (program.commitments.len != 4)
        return Error.InvalidProgramGeometry;
    var trees: [4]proof_ir.CommitmentTree = undefined;
    var first: u32 = 0;
    inline for (0..4) |ordinal| {
        const tree = program.commitments[ordinal];
        const role: proof_ir.CommitmentRole = @enumFromInt(ordinal);
        if (tree.id != ordinal or tree.role != role or
            tree.first_column != first or
            tree.column_count != protocol.trace_columns[ordinal])
        {
            return Error.InvalidProgramGeometry;
        }
        var maximum_log: u32 = 0;
        const end = std.math.add(
            usize,
            tree.first_column,
            tree.column_count,
        ) catch return Error.GeometryOverflow;
        if (end > program.trace_columns.len)
            return Error.InvalidProgramGeometry;
        for (program.trace_columns[tree.first_column..end]) |column| {
            if (column.role != @as(proof_ir.ColumnRole, @enumFromInt(ordinal)))
                return Error.InvalidProgramGeometry;
            maximum_log = @max(maximum_log, column.log_rows);
        }
        if (tree.evaluation_log_rows !=
            maximum_log + protocol.log_blowup_factor)
        {
            return Error.InvalidProgramGeometry;
        }
        trees[ordinal] = tree;
        first = std.math.add(u32, first, tree.column_count) catch
            return Error.GeometryOverflow;
    }
    if (first != program.trace_columns.len)
        return Error.InvalidProgramGeometry;
    return trees;
}

fn validateInputs(
    bundle: composition.Bundle,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !void {
    protocol.validate() catch return Error.UnsupportedProtocol;
    program.validate() catch return Error.InvalidProgramGeometry;
    if (program.identity.frontend != .cairo or
        !std.mem.eql(
            u8,
            &program.identity.protocol,
            &(try cairo_identity.protocolDigest(protocol)),
        ))
    {
        return Error.InvalidProtocolIdentity;
    }
    const verifier_log = bundle.verifierMaxLogDegreeBound() catch
        return Error.InvalidBundleGeometry;
    if (verifier_log != protocol.max_log_degree_bound or
        program.quotient.evaluation_log_rows != verifier_log or
        program.quotient.evaluation_log_rows > 30 or
        program.quotient.term_count != bundle.total_constraints or
        program.quotient.group_count != bundle.components.len or
        program.constraints.len != bundle.components.len or
        protocol.sampled_tree_count != 4 or
        protocol.sampled_value_words % 4 != 0)
    {
        return Error.InvalidProgramGeometry;
    }
    for (
        bundle.components,
        program.constraints,
        0..,
    ) |component, constraint, index| {
        const degree = std.math.sub(
            u32,
            component.evaluation_log_size,
            component.trace_log_size,
        ) catch return Error.InvalidBundleGeometry;
        if (constraint.id != index or
            constraint.component != index or
            constraint.constraint_count != component.n_constraints or
            constraint.max_degree_log != degree or
            !std.mem.eql(
                u8,
                &constraint.expression,
                &cairo_identity.componentProgramDigest(
                    program.identity.air,
                    component,
                ),
            ))
        {
            return Error.InvalidProgramGeometry;
        }
    }
    const trees = try locateTrees(program, protocol);
    inline for ([_]u32{ 1, 2 }) |tree_index| {
        const tree = trees[tree_index];
        var covered: u32 = 0;
        for (bundle.components, 0..) |component, component_index| {
            const span = componentSpan(component, tree_index) orelse
                return Error.InvalidBundleGeometry;
            if (span.start != covered or span.end < span.start or
                span.end > tree.column_count)
            {
                return Error.InvalidBundleGeometry;
            }
            for (
                program.trace_columns[tree.first_column + span.start .. tree.first_column + span.end],
            ) |column| {
                if (column.component != component_index or
                    column.log_rows != component.trace_log_size)
                {
                    return Error.InvalidBundleGeometry;
                }
            }
            covered = span.end;
        }
        if (covered != tree.column_count)
            return Error.InvalidBundleGeometry;
    }
}

fn validateDerived(
    builder: Builder,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !void {
    const protocol_samples = protocol.sampled_value_words / 4;
    if (builder.sampled_value_count != protocol_samples or
        builder.groups.items.len == 0 or
        builder.groups.items.len > 65_535 or
        builder.terms.items.len < builder.sampled_value_count or
        builder.sources.len != program.trace_columns.len)
    {
        return Error.InvalidSampleGeometry;
    }
    for (builder.terms.items, 0..) |term, index| {
        if (term.descriptor.exponent != index or
            term.descriptor.sample_index >= protocol_samples or
            term.source.index >= builder.sources.len)
        {
            return Error.InvalidSampleGeometry;
        }
        const source = builder.sources[term.source.index];
        if (source.global_column != term.source.index or
            source.compact.log_size != term.source.log_size)
            return Error.InvalidCompactSourceGeometry;
    }
}

fn componentSpan(
    component: composition.Component,
    tree: u32,
) ?composition.TraceSpan {
    var found: ?composition.TraceSpan = null;
    for (component.trace_spans) |span| {
        if (span.tree != tree) continue;
        if (found != null) return null;
        found = span;
    }
    return found;
}

fn topologyIdentity(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    bundle: composition.Bundle,
    prepared: []const quotient_abi.PreparedTermDescriptor,
    offsets: []const u32,
    indices: []const u32,
    batch: []const quotient_abi.BatchTermDescriptor,
    sources: []const SourceDescriptor,
    trees: []const TreeSpan,
    logs: []const u32,
    partial_offsets: []const u64,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/quotient-topology/v1\x00");
    hash.update(&program.semantic_digest);
    hash.update(&program.program_digest);
    const encoded = protocol.encode() catch unreachable;
    hash.update(&encoded);
    hashInt(&hash, u32, bundle.format_version);
    hashInt(&hash, u32, bundle.max_kernel_instructions);
    hashInt(&hash, u64, bundle.total_constraints);
    hashInt(&hash, u32, bundle.max_evaluation_log_size);
    hashInt(&hash, u64, bundle.plan_hash);
    hashInt(&hash, u64, bundle.components.len);
    for (bundle.components) |component| {
        hashBytes(&hash, component.label);
        hashInt(&hash, u32, component.instance);
        hashInt(&hash, u32, component.trace_log_size);
        hashInt(&hash, u32, component.evaluation_log_size);
        hashInt(&hash, u32, component.n_constraints);
        for (component.parts) |part| {
            hashInt(&hash, u32, part.rc_base);
            hashInt(&hash, u64, part.semantic_hash);
        }
    }
    hashInt(&hash, u64, prepared.len);
    for (prepared) |descriptor| {
        hashInt(&hash, u32, descriptor.sample_index);
        hashInt(&hash, u32, descriptor.exponent);
        hashInt(&hash, u32, descriptor.periodic);
        hashInt(&hash, u32, descriptor.period_x);
        hashInt(&hash, u32, descriptor.period_y);
    }
    hashIntSlice(&hash, u32, offsets);
    hashIntSlice(&hash, u32, indices);
    hashInt(&hash, u64, batch.len);
    for (batch) |descriptor| {
        hashInt(&hash, u32, descriptor.source_index);
        hashInt(&hash, u32, descriptor.term_index);
        hashInt(&hash, u32, descriptor.source_log_size);
    }
    hashInt(&hash, u64, sources.len);
    for (sources) |source| {
        hashInt(&hash, u32, source.tree_ordinal);
        hashInt(&hash, u32, source.local_column);
        hashInt(&hash, u32, source.global_column);
        hashInt(&hash, u64, source.compact.offset_words);
        hashInt(&hash, u32, source.compact.stride_words);
        hashInt(&hash, u32, source.compact.log_size);
    }
    hashInt(&hash, u64, trees.len);
    for (trees) |tree| {
        hashInt(&hash, u32, tree.tree_ordinal);
        hashInt(&hash, u8, @intFromEnum(tree.role));
        hashInt(&hash, u32, tree.first_source);
        hashInt(&hash, u32, tree.source_count);
        hashInt(&hash, u64, tree.evaluation_words);
    }
    hashIntSlice(&hash, u32, logs);
    hashIntSlice(&hash, u64, partial_offsets);
    return hash.finalResult();
}

fn hashIntSlice(
    hash: anytype,
    comptime F: type,
    values: []const F,
) void {
    hashInt(hash, u64, values.len);
    for (values) |value| hashInt(hash, F, value);
}

fn hashBytes(hash: anytype, bytes: []const u8) void {
    hashInt(hash, u64, bytes.len);
    hash.update(bytes);
}

fn hashInt(hash: anytype, comptime F: type, value: anytype) void {
    var bytes: [@sizeOf(F)]u8 = undefined;
    std.mem.writeInt(F, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn u32Count(value: anytype) !u32 {
    return std.math.cast(u32, value) orelse Error.GeometryOverflow;
}
