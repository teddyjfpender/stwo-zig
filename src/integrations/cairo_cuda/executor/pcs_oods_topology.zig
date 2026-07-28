//! Authenticated mixed-height OODS schedule for resident Cairo CUDA proofs.
//!
//! The common CUDA OODS kernels already accept heterogeneous coefficient
//! batches. This compiler preserves the canonical Cairo sample order while
//! lowering those samples to copy-free subviews of four compact trace trees.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const canonic = @import("stwo_core").poly.circle.canonic;
const field = @import("stwo_cuda_backend").abi.field;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const oods_stage = @import("stwo_cuda_backend").runtime.stages.oods;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const geometry = @import("stwo_cairo_frontend").witness.quotient_geometry;
const batches = @import("../../native_cuda/common/oods_batches.zig");
const shared_views = @import(
    "../../native_cuda/common/resident_views.zig",
);
const pcs_types = @import("pcs_hooks_types.zig");
const quotient_types = @import("quotient/types.zig");

pub const Cohort = struct {
    tree_ordinal: u32,
    source_offset_words: u64,
    source_stride_words: u32,
    coefficient_log_size: u32,
    first_sample: u32,
    sample_count: u32,
    factor_first: u64,
    scratch_first: u64,
};

pub const Topology = struct {
    allocator: std.mem.Allocator,
    offset_points: []field.CirclePointBaseField,
    fold_counts: []u32,
    output_indices: []u32,
    source_indices: []u32,
    cohorts: []Cohort,
    factor_count: usize,
    scratch_count: usize,
    blowup_log_size: u32,
    quotient_identity: proof_ir.Digest,
    identity: proof_ir.Digest,

    pub fn deinit(self: *Topology) void {
        self.allocator.free(self.cohorts);
        self.allocator.free(self.source_indices);
        self.allocator.free(self.output_indices);
        self.allocator.free(self.fold_counts);
        self.allocator.free(self.offset_points);
        self.* = undefined;
    }

    pub fn upload(
        self: Topology,
        session: anytype,
        oods: shared_views.Oods,
    ) !void {
        if (oods.offset_points.len != self.offset_points.len or
            oods.fold_counts.len != self.fold_counts.len or
            oods.output_indices.len != self.output_indices.len)
        {
            return error.InvalidKernelDescriptor;
        }
        try session.context.uploadSlice(
            field.CirclePointBaseField,
            oods.offset_points,
            self.offset_points,
        );
        try session.context.uploadSlice(
            u32,
            oods.fold_counts,
            self.fold_counts,
        );
        try session.context.uploadSlice(
            u32,
            oods.output_indices,
            self.output_indices,
        );
    }
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    topology_identity: proof_ir.Digest,
    oods: shared_views.Oods,
    batches: []batches.Batch,

    pub fn init(
        allocator: std.mem.Allocator,
        topology: Topology,
        quotient: quotient_types.Topology,
        trees: pcs_types.TraceTrees,
        oods: shared_views.Oods,
    ) !Bound {
        if (std.mem.allEqual(u8, &topology.identity, 0) or
            !std.mem.eql(
                u8,
                &topology.quotient_identity,
                &quotient.identity,
            ) or
            topology.cohorts.len == 0 or
            oods.sampled_values.len != topology.source_indices.len or
            oods.folding_factors.len < topology.factor_count or
            oods.reduce_a.len < topology.scratch_count or
            oods.reduce_b.len < topology.scratch_count)
        {
            return error.InvalidKernelDescriptor;
        }
        try validateTreeInventory(topology, quotient, trees);
        const output = try allocator.alloc(
            batches.Batch,
            topology.cohorts.len,
        );
        errdefer allocator.free(output);
        for (topology.cohorts, output) |cohort, *batch| {
            const tree = try treeAt(trees, cohort.tree_ordinal);
            const first = std.math.cast(
                usize,
                cohort.source_offset_words,
            ) orelse return error.SizeOverflow;
            const words = try mul(
                cohort.sample_count,
                cohort.source_stride_words,
            );
            const source = try tree.coefficients.sub(first, words);
            batch.* = .{
                .coefficients = .{
                    .storage = source,
                    .column_stride_words = cohort.source_stride_words,
                },
                .coefficient_rows = try pow2u32(
                    cohort.coefficient_log_size,
                ),
                .coefficient_log_size = cohort.coefficient_log_size,
                .first_sample = cohort.first_sample,
                .sample_count = cohort.sample_count,
                .factor_first = std.math.cast(
                    usize,
                    cohort.factor_first,
                ) orelse return error.SizeOverflow,
                .scratch_first = std.math.cast(
                    usize,
                    cohort.scratch_first,
                ) orelse return error.SizeOverflow,
            };
        }
        var exact = oods;
        exact.folding_factors = try oods.folding_factors.sub(
            0,
            topology.factor_count,
        );
        exact.reduce_a = try oods.reduce_a.sub(0, topology.scratch_count);
        exact.reduce_b = try oods.reduce_b.sub(0, topology.scratch_count);
        return .{
            .allocator = allocator,
            .topology_identity = topology.identity,
            .oods = exact,
            .batches = output,
        };
    }

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.batches);
        self.* = undefined;
    }
};

pub fn derive(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    quotient: quotient_types.Topology,
) !Topology {
    try validateInputs(program, protocol, quotient);
    var masks = try geometry.deriveMasks(
        allocator,
        bundle,
        protocol.trace_columns[0],
        protocol.trace_columns[1],
        protocol.trace_columns[2],
    );
    defer masks.deinit();

    const sample_count: usize = quotient.sampled_value_count;
    const offsets = try allocator.alloc(
        field.CirclePointBaseField,
        sample_count,
    );
    errdefer allocator.free(offsets);
    const folds = try allocator.alloc(u32, sample_count);
    errdefer allocator.free(folds);
    const indices = try allocator.alloc(u32, sample_count);
    errdefer allocator.free(indices);
    const sources = try allocator.alloc(u32, sample_count);
    errdefer allocator.free(sources);

    const lifting_log = bundle.max_evaluation_log_size;
    const trace_step = canonic.CanonicCoset.new(lifting_log - 1).step();
    var cursor: usize = 0;
    for (masks.preprocessed_used, 0..) |used, local| {
        if (used) try appendSample(
            quotient,
            0,
            local,
            trace_step.mulSigned(0),
            lifting_log,
            offsets,
            folds,
            indices,
            sources,
            &cursor,
        );
    }
    for (masks.base_offsets, 0..) |mask_offsets, local| {
        for (mask_offsets.items) |offset| try appendSample(
            quotient,
            1,
            local,
            trace_step.mulSigned(offset),
            lifting_log,
            offsets,
            folds,
            indices,
            sources,
            &cursor,
        );
    }
    for (masks.interaction_offsets, 0..) |mask_offsets, local| {
        for (mask_offsets.items) |offset| try appendSample(
            quotient,
            2,
            local,
            trace_step.mulSigned(offset),
            lifting_log,
            offsets,
            folds,
            indices,
            sources,
            &cursor,
        );
    }
    const composition_span = quotient.source_trees[3];
    for (0..composition_span.source_count) |local| try appendSample(
        quotient,
        3,
        local,
        trace_step.mulSigned(0),
        lifting_log,
        offsets,
        folds,
        indices,
        sources,
        &cursor,
    );
    if (cursor != sample_count)
        return error.InvalidKernelDescriptor;
    try validateTermSources(allocator, quotient, sources);

    const cohort_storage = try allocator.alloc(Cohort, sample_count);
    errdefer allocator.free(cohort_storage);
    const compiled = try compileCohorts(
        quotient,
        sources,
        protocol.log_blowup_factor,
        cohort_storage,
    );
    const cohorts = try allocator.dupe(Cohort, compiled.cohorts);
    errdefer allocator.free(cohorts);
    allocator.free(cohort_storage);
    const identity = topologyIdentity(
        quotient.identity,
        protocol.log_blowup_factor,
        offsets,
        folds,
        indices,
        sources,
        cohorts,
        compiled.factor_count,
        compiled.scratch_count,
    );
    return .{
        .allocator = allocator,
        .offset_points = offsets,
        .fold_counts = folds,
        .output_indices = indices,
        .source_indices = sources,
        .cohorts = cohorts,
        .factor_count = compiled.factor_count,
        .scratch_count = compiled.scratch_count,
        .blowup_log_size = protocol.log_blowup_factor,
        .quotient_identity = quotient.identity,
        .identity = identity,
    };
}

const Compiled = struct {
    cohorts: []const Cohort,
    factor_count: usize,
    scratch_count: usize,
};

fn compileCohorts(
    quotient: quotient_types.Topology,
    sample_sources: []const u32,
    blowup_log: u32,
    storage: []Cohort,
) !Compiled {
    var count: usize = 0;
    var factors: u64 = 0;
    var scratch: u64 = 0;
    for (sample_sources, 0..) |source_index, sample_index| {
        if (source_index >= quotient.sources.len)
            return error.InvalidKernelDescriptor;
        const source = quotient.sources[source_index];
        if (source.compact.log_size == 0 or
            source.compact.log_size >= bundleCircleLimit() or
            source.compact.stride_words !=
                try pow2u32(source.compact.log_size + blowup_log))
        {
            return error.InvalidKernelDescriptor;
        }
        const divisor = try pow2u64(blowup_log);
        if (source.compact.offset_words % divisor != 0)
            return error.InvalidKernelDescriptor;
        const coefficient_offset = source.compact.offset_words / divisor;
        const coefficient_stride = try pow2u32(source.compact.log_size);
        var coalesced = false;
        if (count != 0) {
            const previous = &storage[count - 1];
            const expected = std.math.add(
                u64,
                previous.source_offset_words,
                try mulU64(
                    previous.sample_count,
                    previous.source_stride_words,
                ),
            ) catch return error.SizeOverflow;
            if (previous.tree_ordinal == source.tree_ordinal and
                previous.source_stride_words == coefficient_stride and
                previous.coefficient_log_size == source.compact.log_size and
                expected == coefficient_offset)
            {
                previous.sample_count += 1;
                coalesced = true;
            }
        }
        if (!coalesced) {
            storage[count] = .{
                .tree_ordinal = source.tree_ordinal,
                .source_offset_words = coefficient_offset,
                .source_stride_words = coefficient_stride,
                .coefficient_log_size = source.compact.log_size,
                .first_sample = @intCast(sample_index),
                .sample_count = 1,
                .factor_first = factors,
                .scratch_first = scratch,
            };
            count += 1;
        }
        factors = std.math.add(
            u64,
            factors,
            source.compact.log_size,
        ) catch return error.SizeOverflow;
        scratch = std.math.add(
            u64,
            scratch,
            std.math.divCeil(
                u64,
                try pow2u64(source.compact.log_size),
                oods_stage.first_coefficients_per_block,
            ) catch return error.SizeOverflow,
        ) catch return error.SizeOverflow;
    }
    return .{
        .cohorts = storage[0..count],
        .factor_count = std.math.cast(usize, factors) orelse
            return error.SizeOverflow,
        .scratch_count = std.math.cast(usize, scratch) orelse
            return error.SizeOverflow,
    };
}

fn appendSample(
    quotient: quotient_types.Topology,
    tree_ordinal: u32,
    local_column: usize,
    offset: anytype,
    lifting_log: u32,
    offsets: []field.CirclePointBaseField,
    folds: []u32,
    indices: []u32,
    sources: []u32,
    cursor: *usize,
) !void {
    if (tree_ordinal >= quotient.source_trees.len)
        return error.InvalidKernelDescriptor;
    const span = quotient.source_trees[tree_ordinal];
    if (span.tree_ordinal != tree_ordinal or
        local_column >= span.source_count or cursor.* >= offsets.len)
    {
        return error.InvalidKernelDescriptor;
    }
    const source_index = std.math.add(
        u32,
        span.first_source,
        @intCast(local_column),
    ) catch return error.SizeOverflow;
    const source = quotient.sources[source_index];
    if (source.tree_ordinal != tree_ordinal or
        source.local_column != local_column or
        lifting_log < source.compact.log_size)
    {
        return error.InvalidKernelDescriptor;
    }
    offsets[cursor.*] = .{ .x = offset.x.v, .y = offset.y.v };
    folds[cursor.*] = lifting_log - source.compact.log_size;
    indices[cursor.*] = @intCast(cursor.*);
    sources[cursor.*] = source_index;
    cursor.* += 1;
}

fn validateTermSources(
    allocator: std.mem.Allocator,
    quotient: quotient_types.Topology,
    sample_sources: []const u32,
) !void {
    const sentinel = std.math.maxInt(u32);
    const term_sources = try allocator.alloc(
        u32,
        quotient.prepared_terms.len,
    );
    defer allocator.free(term_sources);
    @memset(term_sources, sentinel);
    const seen_samples = try allocator.alloc(bool, sample_sources.len);
    defer allocator.free(seen_samples);
    @memset(seen_samples, false);
    for (quotient.batch_terms) |term| {
        if (term.term_index >= term_sources.len or
            term.source_index >= quotient.sources.len or
            term_sources[term.term_index] != sentinel)
        {
            return error.InvalidKernelDescriptor;
        }
        term_sources[term.term_index] = term.source_index;
    }
    for (
        quotient.prepared_terms,
        term_sources,
    ) |term, source_index| {
        if (source_index == sentinel or
            term.sample_index >= sample_sources.len or
            sample_sources[term.sample_index] != source_index)
        {
            return error.InvalidKernelDescriptor;
        }
        if (term.periodic == 0) {
            if (seen_samples[term.sample_index])
                return error.InvalidKernelDescriptor;
            seen_samples[term.sample_index] = true;
        }
    }
    for (seen_samples) |seen| {
        if (!seen) return error.InvalidKernelDescriptor;
    }
}

fn validateInputs(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    quotient: quotient_types.Topology,
) !void {
    try program.validate();
    try protocol.validate();
    if (program.identity.frontend != .cairo or
        std.mem.allEqual(u8, &quotient.identity, 0) or
        quotient.source_trees.len != 4 or
        quotient.sources.len != program.trace_columns.len or
        quotient.sampled_value_count != protocol.sampled_value_words / 4)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn treeAt(
    trees: pcs_types.TraceTrees,
    ordinal: u32,
) !pcs_types.CompactTree {
    for (trees.active()) |tree| {
        if (tree.ordinal == ordinal) return tree;
    }
    return error.InvalidKernelDescriptor;
}

fn validateTreeInventory(
    topology: Topology,
    quotient: quotient_types.Topology,
    trees: pcs_types.TraceTrees,
) !void {
    if (trees.len != quotient.source_trees.len)
        return error.InvalidKernelDescriptor;
    for (quotient.source_trees) |span| {
        const tree = try treeAt(trees, span.tree_ordinal);
        if (tree.role != span.role or
            tree.first_column != span.first_source or
            tree.column_count != span.source_count)
        {
            return error.InvalidKernelDescriptor;
        }
        var coefficient_words: u64 = 0;
        for (
            quotient.sources[span.first_source .. span.first_source + span.source_count],
        ) |source| {
            coefficient_words = std.math.add(
                u64,
                coefficient_words,
                try pow2u64(source.compact.log_size),
            ) catch return error.SizeOverflow;
        }
        const tree_words = std.math.cast(
            u64,
            tree.coefficients.len,
        ) orelse return error.SizeOverflow;
        const evaluation_words = std.math.mul(
            u64,
            coefficient_words,
            try pow2u64(topology.blowup_log_size),
        ) catch return error.SizeOverflow;
        if (tree_words != coefficient_words or
            span.evaluation_words != evaluation_words)
        {
            return error.InvalidKernelDescriptor;
        }
    }
}

fn topologyIdentity(
    quotient_identity: proof_ir.Digest,
    blowup_log_size: u32,
    offsets: []const field.CirclePointBaseField,
    folds: []const u32,
    indices: []const u32,
    sources: []const u32,
    cohorts: []const Cohort,
    factor_count: usize,
    scratch_count: usize,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/oods-topology/v1\x00");
    hash.update(&quotient_identity);
    hashInt(&hash, u32, blowup_log_size);
    hashInt(&hash, u64, offsets.len);
    for (offsets) |offset| {
        hashInt(&hash, u32, offset.x);
        hashInt(&hash, u32, offset.y);
    }
    hashSlice(&hash, u32, folds);
    hashSlice(&hash, u32, indices);
    hashSlice(&hash, u32, sources);
    hashInt(&hash, u64, cohorts.len);
    for (cohorts) |cohort| {
        hashInt(&hash, u32, cohort.tree_ordinal);
        hashInt(&hash, u64, cohort.source_offset_words);
        hashInt(&hash, u32, cohort.source_stride_words);
        hashInt(&hash, u32, cohort.coefficient_log_size);
        hashInt(&hash, u32, cohort.first_sample);
        hashInt(&hash, u32, cohort.sample_count);
        hashInt(&hash, u64, cohort.factor_first);
        hashInt(&hash, u64, cohort.scratch_first);
    }
    hashInt(&hash, u64, factor_count);
    hashInt(&hash, u64, scratch_count);
    return hash.finalResult();
}

fn hashSlice(
    hash: anytype,
    comptime T: type,
    values: []const T,
) void {
    hashInt(hash, u64, values.len);
    for (values) |value| hashInt(hash, T, value);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn bundleCircleLimit() u32 {
    return 31;
}

fn pow2u32(log_size: u32) !u32 {
    if (log_size >= 32) return error.SizeOverflow;
    return @as(u32, 1) << @intCast(log_size);
}

fn pow2u64(log_size: u32) !u64 {
    if (log_size >= 64) return error.SizeOverflow;
    return @as(u64, 1) << @intCast(log_size);
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}

fn mulU64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.SizeOverflow;
    return std.math.mul(u64, lhs, rhs) catch error.SizeOverflow;
}
