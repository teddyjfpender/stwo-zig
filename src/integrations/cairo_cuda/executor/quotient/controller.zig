//! Authenticated resident execution of the complete Cairo quotient stage.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const canonic = @import("stwo_core").poly.circle.canonic;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const quotient_stage = @import("stwo_cuda_backend").runtime.stages.quotient;
const transform = @import("stwo_cuda_backend").runtime.stages.transform;
const slot_binding = @import("../pcs_slot_binding.zig");
const pcs_types = @import("../pcs_hooks_types.zig");
const resident_plan = @import("../resident_plan.zig");
const resident_sources = @import("resident_sources.zig");
const buckets_module = @import("buckets.zig");
const topology_module = @import("topology.zig");

const NativeOps = struct {
    pub const prepareTerms = quotient_stage.Native.prepareTerms;
    pub const finalizeGroups = quotient_stage.Native.finalizeGroups;
    pub const accumulate = quotient_stage.addressed.Native.accumulateBucketedFinalized;
    pub const combine = quotient_stage.Native.combineCompact;
    pub const inverse = transform.Native.inverseCompact;
    pub const extend = transform.Native.extend;
};

pub const Circle = struct {
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
};

const Views = struct {
    sample_points: common.SecureCirclePoints,
    sampled_values: common.SecureFields,
    challenge: common.SecureFields,
    term_points: common.SecureCirclePoints,
    line_coefficients: common.SecureFields,
    group_points: common.SecureCirclePoints,
    first_linear_terms: common.SecureFields,
    partial_coordinates: [4]common.Words,
    result_coordinates: quotient_stage.CoordinateColumns,
    subdomain_coordinates: common.Words,
    subdomain_inverse_twiddles: common.Words,
    coefficient_logs: common.Words,
    forward_twiddles: common.Words,
};

pub const Prepared = struct {
    topology: topology_module.Topology,
    buckets: buckets_module.Plan,
    sources: resident_sources.Bound,
    groups: quotient_stage.PreparedGroups,
    numerator: quotient_stage.AddressedNumeratorTopology,
    combine: quotient_stage.CompactCombineTopology,
    circle: Circle,
    views: Views,
    plan_identity: proof_ir.Digest,
    identity: proof_ir.Digest,

    pub fn deinit(self: *Prepared) void {
        self.sources.deinit();
        self.buckets.deinit();
        self.topology.deinit();
        self.* = undefined;
    }

    pub fn execute(self: Prepared, session: anytype) !void {
        return self.executeWith(NativeOps, session);
    }

    /// Called after the canonical twiddle upload, before ingress is sealed.
    pub fn initializeTransform(self: Prepared, session: anytype, inverse_twiddles: common.Words) !void {
        const coefficient_log = self.combine.domain_log_size;
        try prepareSubdomainTwiddles(session, inverse_twiddles, self.views.subdomain_inverse_twiddles, coefficient_log + 1);
        try session.context.uploadSlice(u32, self.views.coefficient_logs, &.{ coefficient_log, coefficient_log, coefficient_log, coefficient_log });
    }

    pub fn executeWith(
        self: Prepared,
        comptime Ops: type,
        session: anytype,
    ) !void {
        if (std.mem.allEqual(u8, &self.identity, 0))
            return error.InvalidKernelDescriptor;
        try Ops.prepareTerms(
            session,
            self.groups,
            self.views.sample_points,
            self.views.sampled_values,
            self.views.challenge,
            self.views.term_points,
            self.views.line_coefficients,
        );
        try Ops.finalizeGroups(
            session,
            self.groups,
            self.views.term_points,
            self.views.line_coefficients,
            self.views.group_points,
            self.views.first_linear_terms,
        );
        try Ops.accumulate(
            session,
            self.numerator,
            quotient_stage.addressed.BucketExecution{
                .buckets = self.buckets.descriptors,
                .group_bucket_offsets = self.buckets.group_bucket_offsets,
                .group_log_sizes = self.topology.group_log_sizes,
                .output_offsets = self.topology.partial_offsets,
                .group_term_offsets = self.topology.group_offsets,
                .group_term_indices = self.topology.group_term_indices,
                .maximum_scratch_rows = self.buckets.maximum_scratch_rows,
            },
            self.views.line_coefficients,
            .{
                .c0 = self.views.result_coordinates.c0,
                .c1 = self.views.result_coordinates.c1,
                .c2 = self.views.result_coordinates.c2,
                .c3 = self.views.result_coordinates.c3,
            },
            .{
                .c0 = self.views.partial_coordinates[0],
                .c1 = self.views.partial_coordinates[1],
                .c2 = self.views.partial_coordinates[2],
                .c3 = self.views.partial_coordinates[3],
            },
        );
        try Ops.combine(
            session,
            self.circle.half_coset_initial_index,
            self.circle.half_coset_step_size,
            self.combine,
            self.views.group_points,
            self.views.first_linear_terms,
            .{
                .c0 = self.views.partial_coordinates[0],
                .c1 = self.views.partial_coordinates[1],
                .c2 = self.views.partial_coordinates[2],
                .c3 = self.views.partial_coordinates[3],
            },
            try coordinateColumns(self.views.subdomain_coordinates),
        );
        // Quotients are defined on the first bit-reversed subdomain, as in
        // pinned Stwo. Repeating its numerator rows on the full coset changes
        // the rational function and violates the FRI degree bound.
        const log_size = self.combine.domain_log_size;
        const rows = @as(usize, 1) << @intCast(log_size);
        const coefficients = common.WordMatrix{
            .storage = self.views.subdomain_coordinates,
            .column_stride_words = rows,
        };
        try Ops.inverse(session, .quotient, coefficients, coefficients, log_size, self.views.subdomain_inverse_twiddles);
        try Ops.extend(
            session,
            .quotient,
            coefficients,
            self.views.coefficient_logs,
            .{ .storage = try slot_binding.coordinateStorage(self.views.result_coordinates), .column_stride_words = rows * 2 },
            log_size + 1,
            self.views.forward_twiddles,
            false,
        );
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    session: anytype,
    plan: *const resident_plan.Plan,
    bundle: composition.Bundle,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    bindings: pcs_types.Bindings,
) !Prepared {
    if (!std.mem.eql(u8, &bindings.identity, &plan.identity) or
        !std.mem.eql(
            u8,
            &program.program_digest,
            &plan.program_identity,
        ))
    {
        return error.InvalidKernelDescriptor;
    }
    var topology = try topology_module.derive(
        allocator,
        bundle,
        program,
        protocol,
    );
    errdefer topology.deinit();
    try validatePlan(plan, topology);
    var buckets = try buckets_module.build(allocator, topology);
    errdefer buckets.deinit();
    if (buckets.descriptors.len == 0 or
        buckets.maximum_scratch_rows > bindings.quotient.result_coordinates.c0.len)
    {
        return error.InvalidKernelDescriptor;
    }
    var sources = try resident_sources.Bound.init(
        allocator,
        topology,
        bindings.trees,
    );
    errdefer sources.deinit();

    const quotient = bindings.quotient;
    const groups = try quotient_stage.prepareGroups(
        allocator,
        session,
        topology.prepared_terms,
        topology.group_offsets,
        topology.group_term_indices,
        quotient.prepared_terms,
        quotient.group_offsets,
        quotient.group_term_indices,
        topology.sampled_value_count,
    );
    const numerator = try sources.prepareNumerator(
        session,
        topology,
        buckets.terms,
        quotient,
    );
    const combine = try quotient_stage.prepareCompactCombineTopology(
        session,
        topology.partial_log_sizes,
        topology.partial_offsets,
        quotient.partial_log_sizes,
        quotient.partial_offsets,
        program.quotient.evaluation_log_rows - 1,
        topology.partial_offsets[topology.partial_offsets.len - 1],
    );
    const circle = try deriveCircle(program.quotient.evaluation_log_rows);
    const coefficient_log = program.quotient.evaluation_log_rows - 1;
    const views = Views{
        .sample_points = bindings.oods.sample_points,
        .sampled_values = bindings.oods.sampled_values,
        .challenge = quotient.challenge,
        .term_points = quotient.term_points,
        .line_coefficients = quotient.line_coefficients,
        .group_points = quotient.group_points,
        .first_linear_terms = quotient.first_linear_terms,
        .partial_coordinates = quotient.partial_coordinates,
        .result_coordinates = quotient.result_coordinates,
        .subdomain_coordinates = quotient.subdomain_coordinates,
        .subdomain_inverse_twiddles = quotient.subdomain_inverse_twiddles,
        .coefficient_logs = quotient.coefficient_logs,
        .forward_twiddles = try bindings.twiddles_forward.sub(bindings.twiddles_forward.len - (@as(usize, 1) << @intCast(coefficient_log)), @as(usize, 1) << @intCast(coefficient_log)),
    };
    try validateViews(
        topology,
        program.quotient.evaluation_log_rows,
        views,
    );
    return .{
        .topology = topology,
        .buckets = buckets,
        .sources = sources,
        .groups = groups,
        .numerator = numerator,
        .combine = combine,
        .circle = circle,
        .views = views,
        .plan_identity = plan.identity,
        .identity = preparedIdentity(
            plan.identity,
            topology.identity,
            sources.identity,
            views,
        ),
    };
}

fn validatePlan(
    plan: *const resident_plan.Plan,
    topology: topology_module.Topology,
) !void {
    const geometry = plan.quotient_geometry;
    const partial_words = std.math.cast(
        usize,
        topology.partial_offsets[topology.partial_offsets.len - 1],
    ) orelse return error.SizeOverflow;
    if (geometry.term_count != topology.prepared_terms.len or
        geometry.group_count != topology.group_log_sizes.len or
        geometry.source_count != topology.sources.len or
        geometry.partial_word_count != partial_words or
        geometry.maximum_partial_rows != topology.maximum_partial_rows or
        !std.mem.eql(u8, &geometry.identity, &topology.identity))
    {
        return error.InvalidKernelDescriptor;
    }
}

fn validateViews(
    topology: topology_module.Topology,
    result_log_rows: u32,
    views: Views,
) !void {
    const terms = topology.prepared_terms.len;
    const groups = topology.group_log_sizes.len;
    const partial_words = std.math.cast(
        usize,
        topology.partial_offsets[topology.partial_offsets.len - 1],
    ) orelse return error.SizeOverflow;
    if (views.sample_points.len != topology.sampled_value_count or
        views.sampled_values.len != topology.sampled_value_count or
        views.challenge.len != 1 or
        views.term_points.len != terms or
        views.line_coefficients.len != try mul(terms, 3) or
        views.group_points.len != groups or
        views.first_linear_terms.len != groups)
    {
        return error.InvalidKernelDescriptor;
    }
    for (views.partial_coordinates) |coordinate| {
        if (coordinate.len != partial_words)
            return error.InvalidKernelDescriptor;
    }
    if (result_log_rows == 0 or result_log_rows > 30)
        return error.InvalidKernelDescriptor;
    const result_rows = @as(usize, 1) << @intCast(result_log_rows);
    if (views.subdomain_coordinates.len != result_rows * 2 or
        views.subdomain_inverse_twiddles.len != result_rows / 4 or
        views.coefficient_logs.len != 4 or views.forward_twiddles.len != result_rows / 2)
        return error.InvalidKernelDescriptor;
    const result = views.result_coordinates;
    if (result.c0.len != result_rows or
        result.c1.len != result_rows or
        result.c2.len != result_rows or
        result.c3.len != result_rows)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn deriveCircle(domain_log_size: u32) !Circle {
    if (domain_log_size == 0 or domain_log_size > 30)
        return error.InvalidKernelDescriptor;
    const domain = canonic.CanonicCoset.new(domain_log_size).circleDomain();
    return .{
        .half_coset_initial_index = try u32Count(
            domain.half_coset.initial_index.v,
        ),
        .half_coset_step_size = try u32Count(
            domain.half_coset.step_size.mul(2).v,
        ),
    };
}

fn coordinateColumns(storage: common.Words) !quotient_stage.CoordinateColumns {
    if (storage.len == 0 or storage.len % 4 != 0) return error.InvalidKernelDescriptor;
    const rows = storage.len / 4;
    return .{ .c0 = try storage.sub(0, rows), .c1 = try storage.sub(rows, rows), .c2 = try storage.sub(rows * 2, rows), .c3 = try storage.sub(rows * 3, rows) };
}

/// Each layer contributes its prefix, not the suffix used for a smaller
/// canonical coset. The initial point stays fixed when splitting a domain.
fn prepareSubdomainTwiddles(session: anytype, source: common.Words, destination: common.Words, domain_log: u32) !void {
    if (domain_log < 4 or domain_log > 30 or !std.math.isPowerOfTwo(source.len) or destination.len != (@as(usize, 1) << @intCast(domain_log - 2)) or source.len < destination.len * 2) return error.InvalidKernelDescriptor;
    const full_half = destination.len * 2;
    var source_start = source.len - full_half;
    var layer_size = destination.len / 2;
    var cursor: usize = 0;
    while (layer_size != 0) : (layer_size /= 2) {
        try session.context.copyDeviceSlice(u32, try destination.sub(cursor, layer_size), try source.sub(source_start, layer_size));
        cursor += layer_size;
        source_start += layer_size * 2;
    }
    try session.context.copyDeviceSlice(u32, try destination.sub(cursor, 1), try source.sub(source.len - 1, 1));
}

fn preparedIdentity(
    plan_identity: proof_ir.Digest,
    topology_identity: proof_ir.Digest,
    source_identity: proof_ir.Digest,
    views: Views,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/quotient-controller/v1\x00");
    hash.update(&plan_identity);
    hash.update(&topology_identity);
    hash.update(&source_identity);
    hashView(&hash, views.sample_points);
    hashView(&hash, views.sampled_values);
    hashView(&hash, views.challenge);
    hashView(&hash, views.term_points);
    hashView(&hash, views.line_coefficients);
    hashView(&hash, views.group_points);
    hashView(&hash, views.first_linear_terms);
    hashView(&hash, views.subdomain_coordinates);
    hashView(&hash, views.subdomain_inverse_twiddles);
    hashView(&hash, views.coefficient_logs);
    hashView(&hash, views.forward_twiddles);
    for (views.partial_coordinates) |value| hashView(&hash, value);
    hashView(&hash, views.result_coordinates.c0);
    hashView(&hash, views.result_coordinates.c1);
    hashView(&hash, views.result_coordinates.c2);
    hashView(&hash, views.result_coordinates.c3);
    return hash.finalResult();
}

fn hashView(hash: *std.crypto.hash.sha2.Sha256, view: anytype) void {
    hashInt(hash, u64, view.address);
    hashInt(hash, u64, view.len);
    hashInt(hash, u64, view.owner);
    hashInt(hash, u64, view.generation);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn u32Count(value: anytype) !u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

fn mul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.SizeOverflow;
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
