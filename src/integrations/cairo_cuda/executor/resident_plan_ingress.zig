//! Authenticated non-PCS geometry required by one Cairo CUDA proof arena.
//!
//! The AIR and compact protocol cannot reveal adapted-input, writer, relation,
//! or generated-evaluator storage. Production callers must compile these exact
//! counts from the admitted products and provide their source identities.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const composition = @import(
    "../../../frontends/cairo/witness/composition_bundle.zig",
);

pub const Writer = struct {
    launch_count: u32,
    input_words: u64,
    pointer_words: u64,
    descriptor_words: u64,
    lookup_words: u64,
    scratch_words: u64,
    fixed_table_words: u64,
    memory_table_words: u64,
    identity: proof_ir.Digest,
};

pub const Relation = struct {
    instance_count: u32,
    top_level_pointer_words: u64,
    source_pointer_words: u64,
    descriptor_words: u64,
    geometry_words: u64,
    challenge_words: u64,
    alpha_power_words: u64,
    denominator_words: u64,
    claimed_sum_words: u64,
    output_pointer_words: u64,
    output_coordinate_words: u64,
    reduction_scratch_words: u64,
    scan_scratch_words: u64,
    identity: proof_ir.Digest,
};

pub const Evaluation = struct {
    placement_count: u32,
    argument_words: u64,
    trace_offset_words: u64,
    interaction_offset_words: u64,
    lde_descriptor_words: u64,
    lde_tile_words: u64,
    base_parameter_words: u64,
    extended_parameter_descriptor_words: u64,
    extended_parameter_words: u64,
    composition_log_count: u32,
    composition_offset_words: u64,
    composition_accumulator_words: u64,
    identity: proof_ir.Digest,
};

pub const Geometry = struct {
    adapted_input_words: u64,
    adapted_input_identity: proof_ir.Digest,
    statement_bootstrap_words: u64,
    statement_bootstrap_identity: proof_ir.Digest,
    writer: Writer,
    relation: Relation,
    evaluation: Evaluation,

    pub fn validate(self: Geometry) !void {
        if (self.adapted_input_words == 0 or
            self.statement_bootstrap_words == 0 or
            self.writer.launch_count == 0 or
            self.writer.input_words == 0 or
            self.writer.pointer_words == 0 or
            self.writer.descriptor_words == 0 or
            self.writer.lookup_words == 0 or
            self.writer.scratch_words == 0 or
            self.writer.fixed_table_words == 0 or
            self.writer.memory_table_words == 0 or
            self.relation.instance_count == 0 or
            self.relation.top_level_pointer_words == 0 or
            self.relation.source_pointer_words == 0 or
            self.relation.descriptor_words == 0 or
            self.relation.geometry_words == 0 or
            self.relation.challenge_words == 0 or
            self.relation.alpha_power_words == 0 or
            self.relation.denominator_words == 0 or
            self.relation.claimed_sum_words == 0 or
            self.relation.output_pointer_words == 0 or
            self.relation.output_coordinate_words == 0 or
            self.relation.reduction_scratch_words == 0 or
            self.relation.scan_scratch_words == 0 or
            self.evaluation.placement_count == 0 or
            self.evaluation.argument_words == 0 or
            self.evaluation.trace_offset_words == 0 or
            self.evaluation.interaction_offset_words == 0 or
            self.evaluation.lde_descriptor_words == 0 or
            self.evaluation.lde_tile_words == 0 or
            self.evaluation.extended_parameter_descriptor_words == 0 or
            self.evaluation.extended_parameter_words == 0 or
            self.evaluation.extended_parameter_words % 4 != 0 or
            self.evaluation.extended_parameter_descriptor_words !=
                (self.evaluation.extended_parameter_words / 4) * 8 or
            self.evaluation.composition_log_count == 0 or
            self.evaluation.composition_offset_words !=
                (@as(u64, self.evaluation.composition_log_count) + 1) * 2 or
            self.evaluation.composition_accumulator_words == 0 or
            digestEmpty(self.adapted_input_identity) or
            digestEmpty(self.statement_bootstrap_identity) or
            digestEmpty(self.writer.identity) or
            digestEmpty(self.relation.identity) or
            digestEmpty(self.evaluation.identity))
        {
            return error.InvalidIngressGeometry;
        }
        if (self.relation.challenge_words != 8 or
            self.relation.reduction_scratch_words !=
                self.relation.scan_scratch_words)
        {
            return error.InvalidIngressGeometry;
        }
        _ = try self.identity();
    }

    pub fn identity(self: Geometry) !proof_ir.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/cairo/cuda/resident-ingress/v1\x00");
        hashInt(&hash, self.adapted_input_words);
        hash.update(&self.adapted_input_identity);
        hashInt(&hash, self.statement_bootstrap_words);
        hash.update(&self.statement_bootstrap_identity);
        inline for (std.meta.fields(Writer)) |field| {
            if (field.type == proof_ir.Digest) {
                hash.update(&@field(self.writer, field.name));
            } else {
                hashInt(&hash, @field(self.writer, field.name));
            }
        }
        inline for (std.meta.fields(Relation)) |field| {
            if (field.type == proof_ir.Digest) {
                hash.update(&@field(self.relation, field.name));
            } else {
                hashInt(&hash, @field(self.relation, field.name));
            }
        }
        inline for (std.meta.fields(Evaluation)) |field| {
            if (field.type == proof_ir.Digest) {
                hash.update(&@field(self.evaluation, field.name));
            } else {
                hashInt(&hash, @field(self.evaluation, field.name));
            }
        }
        return hash.finalResult();
    }
};

pub fn validateEvaluation(
    bundle: composition.Bundle,
    evaluation: Evaluation,
) !void {
    const expected = try deriveEvaluation(bundle, evaluation.identity);
    if (!std.meta.eql(expected, evaluation))
        return error.InvalidIngressGeometry;
}

pub fn deriveEvaluation(
    bundle: composition.Bundle,
    identity: proof_ir.Digest,
) !Evaluation {
    var placements: u64 = 0;
    var trace_offsets: u64 = 0;
    var interaction_offsets: u64 = 0;
    var base_parameters: u64 = 0;
    var extended_parameters: u64 = 0;
    var lde_tile_words: u64 = 0;
    var logs = [_]bool{false} ** 63;
    for (bundle.components) |component| {
        placements = try add(placements, component.parts.len);
        var base_columns: u64 = 0;
        var interaction_columns: u64 = 0;
        for (component.trace_spans) |span| {
            const width = std.math.sub(u32, span.end, span.start) catch
                return error.InvalidIngressGeometry;
            switch (span.tree) {
                1 => base_columns = width,
                2 => interaction_columns = width,
                else => {},
            }
        }
        const sources = try add(
            component.preprocessed_indices.len,
            try add(base_columns, interaction_columns),
        );
        trace_offsets = try add(trace_offsets, sources);
        interaction_offsets = try add(interaction_offsets, 3);
        lde_tile_words = @max(
            lde_tile_words,
            try mul(sources, try pow2(component.evaluation_log_size)),
        );
        if (component.evaluation_log_size >= logs.len)
            return error.InvalidIngressGeometry;
        logs[component.evaluation_log_size] = true;
        var component_base: u32 = 0;
        for (component.parts) |part| {
            component_base = @max(
                component_base,
                part.program.header.n_base_params,
            );
        }
        base_parameters = try add(base_parameters, component_base);
        extended_parameters = try add(
            extended_parameters,
            try mul(component.ext_sources.len, 4),
        );
    }
    var log_count: u32 = 0;
    var accumulator_words: u64 = 0;
    for (logs, 0..) |active, log| {
        if (!active) continue;
        log_count += 1;
        accumulator_words = try add(
            accumulator_words,
            try mul(try pow2(@intCast(log)), 4),
        );
    }
    return .{
        .placement_count = std.math.cast(u32, placements) orelse
            return error.InvalidIngressGeometry,
        .argument_words = try mul(placements, 24),
        .trace_offset_words = trace_offsets,
        .interaction_offset_words = interaction_offsets,
        .lde_descriptor_words = try mul(trace_offsets, 6),
        .lde_tile_words = lde_tile_words,
        .base_parameter_words = base_parameters,
        .extended_parameter_descriptor_words = try mul(extended_parameters / 4, 8),
        .extended_parameter_words = extended_parameters,
        .composition_log_count = log_count,
        .composition_offset_words = try mul(@as(u64, log_count) + 1, 2),
        .composition_accumulator_words = accumulator_words,
        .identity = identity,
    };
}

fn digestEmpty(digest: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &digest, 0);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    value: anytype,
) void {
    const T = @TypeOf(value);
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn pow2(log: u32) !u64 {
    if (log >= 63) return error.InvalidIngressGeometry;
    return @as(u64, 1) << @intCast(log);
}

fn add(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse
        return error.InvalidIngressGeometry;
    const rhs = std.math.cast(u64, right) orelse
        return error.InvalidIngressGeometry;
    return std.math.add(u64, lhs, rhs) catch
        error.InvalidIngressGeometry;
}

fn mul(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse
        return error.InvalidIngressGeometry;
    const rhs = std.math.cast(u64, right) orelse
        return error.InvalidIngressGeometry;
    return std.math.mul(u64, lhs, rhs) catch
        error.InvalidIngressGeometry;
}

test "ingress identity covers every arena cardinality" {
    var geometry = Geometry{
        .adapted_input_words = 1,
        .adapted_input_identity = [_]u8{1} ** 32,
        .statement_bootstrap_words = 1,
        .statement_bootstrap_identity = [_]u8{5} ** 32,
        .writer = .{
            .launch_count = 1,
            .input_words = 1,
            .pointer_words = 1,
            .descriptor_words = 1,
            .lookup_words = 1,
            .scratch_words = 1,
            .fixed_table_words = 1,
            .memory_table_words = 1,
            .identity = [_]u8{2} ** 32,
        },
        .relation = .{
            .instance_count = 1,
            .top_level_pointer_words = 1,
            .source_pointer_words = 1,
            .descriptor_words = 1,
            .geometry_words = 1,
            .challenge_words = 8,
            .alpha_power_words = 1,
            .denominator_words = 1,
            .claimed_sum_words = 1,
            .output_pointer_words = 1,
            .output_coordinate_words = 1,
            .reduction_scratch_words = 1,
            .scan_scratch_words = 1,
            .identity = [_]u8{3} ** 32,
        },
        .evaluation = .{
            .placement_count = 1,
            .argument_words = 1,
            .trace_offset_words = 1,
            .interaction_offset_words = 1,
            .lde_descriptor_words = 6,
            .lde_tile_words = 1,
            .base_parameter_words = 0,
            .extended_parameter_descriptor_words = 8,
            .extended_parameter_words = 4,
            .composition_log_count = 1,
            .composition_offset_words = 4,
            .composition_accumulator_words = 1,
            .identity = [_]u8{4} ** 32,
        },
    };
    try geometry.validate();
    const before = try geometry.identity();
    geometry.relation.output_coordinate_words += 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &before,
        &(try geometry.identity()),
    ));
}
