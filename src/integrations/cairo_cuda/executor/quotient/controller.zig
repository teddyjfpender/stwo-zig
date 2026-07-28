//! Authenticated resident execution of the complete Cairo quotient stage.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const canonic = @import("stwo_core").poly.circle.canonic;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const quotient_stage = @import("stwo_cuda_backend").runtime.stages.quotient;
const pcs_types = @import("../pcs_hooks_types.zig");
const resident_plan = @import("../resident_plan.zig");
const resident_sources = @import("resident_sources.zig");
const topology_module = @import("topology.zig");

const NativeOps = struct {
    pub const prepareTerms = quotient_stage.Native.prepareTerms;
    pub const finalizeGroups = quotient_stage.Native.finalizeGroups;
    pub const accumulate = quotient_stage.addressed.Native.accumulate;
    pub const combine = quotient_stage.Native.combineCompact;
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
};

pub const Prepared = struct {
    topology: topology_module.Topology,
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
        self.topology.deinit();
        self.* = undefined;
    }

    pub fn execute(self: Prepared, session: anytype) !void {
        return self.executeWith(NativeOps, session);
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
            self.views.line_coefficients,
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
            self.views.result_coordinates,
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
        quotient,
    );
    const combine = try quotient_stage.prepareCompactCombineTopology(
        session,
        topology.partial_log_sizes,
        topology.partial_offsets,
        quotient.partial_log_sizes,
        quotient.partial_offsets,
        program.quotient.evaluation_log_rows,
        topology.partial_offsets[topology.partial_offsets.len - 1],
    );
    const circle = try deriveCircle(program.quotient.evaluation_log_rows);
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
    };
    try validateViews(
        topology,
        program.quotient.evaluation_log_rows,
        views,
    );
    return .{
        .topology = topology,
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
            domain.half_coset.step_size.v,
        ),
    };
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
