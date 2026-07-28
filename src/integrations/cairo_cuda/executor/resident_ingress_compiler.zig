//! Exact ingress-region sizing from admitted Cairo products.

const std = @import("std");
const adapter = @import("stwo_cairo_frontend").adapter;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const witness = @import("stwo_cairo_frontend").witness.bundle;
const direct_inputs = @import("stwo_cairo_frontend").witness.direct_inputs;
const fixed = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const fixed_plan = @import("../base_writer_plan/fixed_tables.zig");
const memory_plan = @import("../base_writer_plan/memory.zig");
const relation_adapter = @import("../relation_adapter.zig");
const recorded = @import("../recorded_witness.zig");
const ec_contract = @import("stwo_cuda_backend").runtime.stages.cairo_ec_op_contract;
const witness_abi = @import("stwo_cuda_backend").abi.stages.cairo_witness;
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const ingress = @import("resident_plan_ingress.zig");

const pointer_words: u64 = @sizeOf(usize) / @sizeOf(u32);

pub const Input = struct {
    adapted_input_bytes: u64,
    adapted_input_identity: [32]u8,
    statement_bootstrap_words: u64,
    statement_bootstrap_identity: [32]u8,
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    witnesses: witness.Bundle,
    fixed_tables: fixed.Bundle,
    feeds: feed_bundle.Bundle,
    prover_input: *const adapter.ProverInput,
    relations: *const relation_adapter.Plan,
    writer_identity: [32]u8,
    evaluation_identity: [32]u8,
};

pub fn compile(
    allocator: std.mem.Allocator,
    input: Input,
) !ingress.Geometry {
    if (input.adapted_input_bytes == 0 or
        input.statement_bootstrap_words == 0 or
        input.proof.components.len != input.components.components.len)
    {
        return error.InvalidIngressGeometry;
    }
    var fixed_tables = try fixed_plan.compile(
        allocator,
        input.components,
        input.fixed_tables,
    );
    defer fixed_tables.deinit();
    var memory_tables = try memory_plan.compile(
        allocator,
        input.components,
        input.prover_input,
    );
    defer memory_tables.deinit();

    const writer = try writerGeometry(
        input.proof,
        input.components,
        input.witnesses,
        input.feeds,
        fixed_tables,
        memory_tables,
        input.prover_input,
        input.writer_identity,
    );
    const relation_shape = try input.relations.preparedInputShape();
    const relation = try relationGeometry(
        relation_shape,
        input.relations.topology_identity,
    );
    const evaluation = try ingress.deriveEvaluation(
        input.components,
        input.evaluation_identity,
    );
    const output = ingress.Geometry{
        .adapted_input_words = divCeil(input.adapted_input_bytes, 4),
        .adapted_input_identity = input.adapted_input_identity,
        .statement_bootstrap_words = input.statement_bootstrap_words,
        .statement_bootstrap_identity = input.statement_bootstrap_identity,
        .writer = writer,
        .relation = relation,
        .evaluation = evaluation,
    };
    try output.validate();
    return output;
}

fn writerGeometry(
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    witnesses: witness.Bundle,
    feeds: feed_bundle.Bundle,
    fixed_tables: fixed_plan.Plan,
    memory_tables: memory_plan.Plan,
    prover_input: *const adapter.ProverInput,
    identity: [32]u8,
) !ingress.Writer {
    var pointers: u64 = 0;
    var descriptors: u64 = 0;
    var lookup: u64 = 0;
    var scratch: u64 = 0;
    var input_words: u64 = 0;
    for (proof.components, components.components) |planned, component| {
        const rows = try pow2(component.trace_log_size);
        switch (planned.writer) {
            .recorded_aot => {
                const program = (witnesses.find(planned.name) orelse
                    return error.MissingRecordedWitnessLowering).program;
                if (try direct_inputs.resolve(
                    prover_input,
                    planned.name,
                )) |direct| {
                    if (direct.columnCount() != program.n_inputs)
                        return error.InvalidIngressGeometry;
                } else if (planned.producer_edges.len == 0) {
                    return error.MissingRecordedWitnessInput;
                }
                input_words = try add(
                    input_words,
                    try mul(rows, program.n_inputs),
                );
                pointers = try add(
                    pointers,
                    try mul(
                        try add(
                            try add(
                                @max(program.n_inputs, 1),
                                @max(program.n_cols, 1),
                            ),
                            try add(
                                @max(program.n_mult_tables, 1),
                                recorded.execution_table_count,
                            ),
                        ),
                        pointer_words,
                    ),
                );
                descriptors = try add(
                    descriptors,
                    recorded.execution_stride_count,
                );
                lookup = try add(
                    lookup,
                    try mul(rows, program.n_lookup_words),
                );
                scratch = try add(
                    scratch,
                    try mul(rows, program.n_sub_words),
                );
            },
            .native_backend => if (std.mem.eql(
                u8,
                planned.name,
                "ec_op_builtin",
            )) {
                pointers = try add(
                    pointers,
                    ec_contract.execution_table_count * pointer_words,
                );
                const partial_rows = try mul(
                    rows,
                    ec_contract.partial_padded_rounds,
                );
                lookup = try add(
                    lookup,
                    try mul(rows, ec_contract.lookup_words_per_row),
                );
                scratch = try add(
                    scratch,
                    try mul(
                        partial_rows,
                        ec_contract.partial_input_column_count,
                    ),
                );
            } else {
                const program = (witnesses.find(planned.name) orelse
                    return error.MissingRecordedWitnessLowering).program;
                pointers = try add(
                    pointers,
                    try mul(
                        try add(
                            try add(
                                @max(program.n_inputs, 1),
                                @max(program.n_cols, 1),
                            ),
                            try add(
                                @max(program.n_mult_tables, 1),
                                recorded.execution_table_count,
                            ),
                        ),
                        pointer_words,
                    ),
                );
                descriptors = try add(
                    descriptors,
                    recorded.execution_stride_count,
                );
                lookup = try add(
                    lookup,
                    try mul(rows, program.n_lookup_words),
                );
                scratch = try add(
                    scratch,
                    try mul(rows, program.n_sub_words),
                );
            },
            .fixed_table => {
                const entry = fixed_tables.find(
                    planned.name,
                    planned.instance,
                ) orelse return error.MissingFixedTable;
                lookup = try add(
                    lookup,
                    try mul(rows, entry.lookup_output_count),
                );
            },
            .memory_trace => {},
        }
    }
    const input_actions = try inputActionGeometry(
        proof,
        witnesses,
        descriptors,
    );
    pointers = try add(pointers, input_actions.pointer_words);
    descriptors = try add(
        descriptors,
        input_actions.descriptor_words,
    );
    scratch = try add(scratch, input_actions.scratch_words);
    input_words = try add(
        input_words,
        try memoryInputWords(memory_tables),
    );
    const feed = try feedGeometry(feeds, fixed_tables);
    pointers = try add(pointers, feed.pointer_words);
    descriptors = try add(descriptors, feed.metadata_words);
    scratch = try add(scratch, feed.multiplicity_words);
    return .{
        .launch_count = @intCast(proof.components.len - 1),
        .input_words = input_words,
        .pointer_words = pointers,
        .descriptor_words = descriptors,
        .lookup_words = lookup,
        .scratch_words = scratch,
        .fixed_table_words = try fixedWords(fixed_tables),
        .memory_table_words = try memoryWords(memory_tables),
        .identity = identity,
    };
}

const InputActionGeometry = struct {
    pointer_words: u64 = 0,
    descriptor_words: u64 = 0,
    scratch_words: u64 = 0,
};

fn inputActionGeometry(
    proof: *const proof_plan.CairoProofPlan,
    witnesses: witness.Bundle,
    descriptor_base_words: u64,
) !InputActionGeometry {
    var output = InputActionGeometry{};
    const gather_descriptor_words =
        @sizeOf(witness_abi.MultiEdgeDescriptor) / @sizeOf(u32);
    for (proof.components) |component| {
        if (component.writer != .recorded_aot or
            component.producer_edges.len == 0)
        {
            continue;
        }
        const program = (witnesses.find(component.name) orelse
            return error.MissingRecordedWitnessLowering).program;
        if (proof_plan.compactGeometry(component.name)) |compact| {
            if (program.n_inputs != compact.multiplicity_slot + 1)
                return error.InvalidIngressGeometry;
            output.pointer_words = try add(
                output.pointer_words,
                try mul(
                    try add(
                        component.producer_edges.len,
                        program.n_inputs,
                    ),
                    pointer_words,
                ),
            );
            output.descriptor_words = try add(
                output.descriptor_words,
                try mul(component.producer_edges.len, 6),
            );
            var total_rows: u64 = 0;
            for (component.producer_edges) |edge| {
                const producer = uniqueComponent(
                    proof,
                    edge.producer,
                ) orelse return error.InvalidIngressGeometry;
                const rows = componentRealRows(proof, producer) orelse
                    return error.InvalidIngressGeometry;
                total_rows = try add(
                    total_rows,
                    try mul(rows, edge.instances),
                );
            }
            const sort_rows = try ceilPowerOfTwo(total_rows);
            const workspace = try add(
                try mul(
                    sort_rows,
                    try add(compact.tuple_words, 16),
                ),
                5_121,
            );
            output.scratch_words = @max(
                output.scratch_words,
                workspace,
            );
        } else {
            const absolute_cursor = try add(
                descriptor_base_words,
                output.descriptor_words,
            );
            const aligned_cursor = std.mem.alignForward(
                u64,
                absolute_cursor,
                @alignOf(witness_abi.MultiEdgeDescriptor) /
                    @sizeOf(u32),
            );
            output.descriptor_words = try add(
                output.descriptor_words,
                aligned_cursor - absolute_cursor,
            );
            output.descriptor_words = try add(
                output.descriptor_words,
                try mul(
                    component.producer_edges.len,
                    gather_descriptor_words,
                ),
            );
        }
    }
    return output;
}

fn uniqueComponent(
    proof: *const proof_plan.CairoProofPlan,
    name: []const u8,
) ?u32 {
    var found: ?u32 = null;
    for (proof.components, 0..) |component, index| {
        if (!std.mem.eql(u8, component.name, name)) continue;
        if (found != null) return null;
        found = @intCast(index);
    }
    return found;
}

fn componentRealRows(
    proof: *const proof_plan.CairoProofPlan,
    index: u32,
) ?u64 {
    if (index >= proof.components.len) return null;
    for (proof.components[index].trace_parts) |part| {
        if (part.id == .main) {
            const rows = part.rows.real_rows orelse return null;
            return @intCast(rows);
        }
    }
    return null;
}

fn ceilPowerOfTwo(value: u64) !u64 {
    if (value == 0) return error.InvalidIngressGeometry;
    return std.math.ceilPowerOfTwo(u64, value) catch
        error.InvalidIngressGeometry;
}

fn memoryInputWords(plan: memory_plan.Plan) !u64 {
    var total: u64 = 0;
    for (plan.entries) |entry| {
        const columns: u64 = switch (entry.kind) {
            .address_to_id => 1,
            .id_to_big, .id_to_small => entry.limb_count,
        };
        const source_rows = switch (entry.kind) {
            // EC-op indexes this execution table by the original Cairo
            // address, so retain the canonical zero-address sentinel. The
            // memory base writer consumes the suffix beginning at offset one.
            .address_to_id => try add(
                entry.source_value_count,
                entry.source_value_offset,
            ),
            .id_to_big, .id_to_small => entry.source_value_count,
        };
        total = try add(
            total,
            try mul(source_rows, columns),
        );
    }
    return total;
}

const FeedGeometry = struct {
    pointer_words: u64,
    metadata_words: u64,
    multiplicity_words: u64,
};

fn feedGeometry(
    feeds: feed_bundle.Bundle,
    fixed_tables: fixed_plan.Plan,
) !FeedGeometry {
    var pointer_words_total: u64 = 0;
    var metadata_words: u64 = 0;
    var multiplicity_words: u64 = 0;
    var unique_destinations: u64 = 0;
    for (feeds.feeds) |feed| {
        if (feed.descriptors.len == 0 or
            feed.descriptors.len % 14 != 0 or
            feed.destinations.len == 0)
        {
            return error.InvalidIngressGeometry;
        }
        pointer_words_total = try add(
            pointer_words_total,
            try mul(@max(feed.luts.len, 1), pointer_words),
        );
        pointer_words_total = try add(
            pointer_words_total,
            try mul(feed.destinations.len, pointer_words),
        );
        metadata_words = try add(
            metadata_words,
            feed.descriptors.len,
        );
        for (feed.luts) |lut|
            metadata_words = try add(metadata_words, lut.len);
        for (feed.destinations) |destination| {
            if (destination.words == 0)
                return error.InvalidIngressGeometry;
            if (firstDestination(feeds, destination.name, destination.words)) {
                unique_destinations = try add(unique_destinations, 1);
                multiplicity_words = try add(
                    multiplicity_words,
                    destination.words,
                );
            }
        }
    }
    for (fixed_tables.entries) |entry| {
        const required_words = try mul(
            entry.row_count,
            entry.multiplicity_column_count,
        );
        if (feedDestinationWords(feeds, entry.name)) |words| {
            if (words != required_words)
                return error.InvalidIngressGeometry;
            continue;
        }
        unique_destinations = try add(unique_destinations, 1);
        multiplicity_words = try add(
            multiplicity_words,
            required_words,
        );
    }
    // One pointer and one u32 length per unique destination for the single
    // request clear launch.
    pointer_words_total = try add(
        pointer_words_total,
        try mul(unique_destinations, pointer_words),
    );
    metadata_words = try add(metadata_words, unique_destinations);
    return .{
        .pointer_words = pointer_words_total,
        .metadata_words = metadata_words,
        .multiplicity_words = multiplicity_words,
    };
}

fn feedDestinationWords(
    feeds: feed_bundle.Bundle,
    name: []const u8,
) ?u64 {
    var result: ?u64 = null;
    for (feeds.feeds) |feed| {
        for (feed.destinations) |destination| {
            if (!std.mem.eql(u8, destination.name, name)) continue;
            if (result) |words| {
                if (words != destination.words) return null;
            } else {
                result = destination.words;
            }
        }
    }
    return result;
}

fn firstDestination(
    feeds: feed_bundle.Bundle,
    name: []const u8,
    words_expected: u64,
) bool {
    for (feeds.feeds) |feed| {
        for (feed.destinations) |destination| {
            if (!std.mem.eql(u8, destination.name, name)) continue;
            std.debug.assert(destination.words == words_expected);
            return destination.name.ptr == name.ptr;
        }
    }
    unreachable;
}

fn fixedWords(plan: fixed_plan.Plan) !u64 {
    var total: u64 = 0;
    for (plan.entries) |entry| {
        if (entry.source_column_count != 0) {
            total = try alignPointerWords(total);
            total = try add(
                total,
                try mul(entry.source_column_count, pointer_words),
            );
        }
        total = try alignPointerWords(total);
        total = try add(
            total,
            try mul(entry.multiplicity_column_count, pointer_words),
        );
        total = try add(total, entry.trace_output_count);
        total = try alignPointerWords(total);
        total = try add(
            total,
            try mul(entry.trace_output_count, pointer_words),
        );
        total = try add(total, try mul(entry.lookup_output_count, 4));
        total = try alignPointerWords(total);
        total = try add(
            total,
            try mul(entry.lookup_output_count, pointer_words),
        );
    }
    return total;
}

fn alignPointerWords(value: u64) !u64 {
    const remainder = value % pointer_words;
    return if (remainder == 0)
        value
    else
        add(value, pointer_words - remainder);
}

test "fixed ingress sizing includes pointer alignment after odd metadata" {
    var entries = [_]fixed_plan.Entry{.{
        .component_index = 0,
        .fixed_ordinal = 0,
        .graph_hash = 0,
        .name = "odd_trace_outputs",
        .instance = 0,
        .log_size = 4,
        .row_count = 16,
        .source_column_count = 0,
        .multiplicity_column_count = 1,
        .trace_output_count = 1,
        .lookup_output_count = 1,
        .preprocessed_sources = &.{},
        .trace_multiplicity_columns = &.{0},
        .lookup_descriptors = &.{ 0, 0, 0, 0 },
        .identity = [_]u8{0} ** 32,
    }};
    const plan = fixed_plan.Plan{
        .allocator = std.testing.allocator,
        .entries = &entries,
        .identity = [_]u8{0} ** 32,
    };
    try std.testing.expectEqual(@as(u64, 12), try fixedWords(plan));
}

fn memoryWords(plan: memory_plan.Plan) !u64 {
    var total: u64 = 0;
    for (plan.entries) |entry| {
        // Eight scalar geometry words plus the explicit pointer body.
        total = try add(total, 8);
        total = try add(
            total,
            try mul(
                try add(entry.output_column_count, entry.limb_count),
                pointer_words,
            ),
        );
    }
    return total;
}

fn relationGeometry(
    shape: relation_adapter.PreparedInputShape,
    identity: [32]u8,
) !ingress.Relation {
    const table_words = try mul(shape.instance_count, pointer_words);
    const geometry_words = try mul(
        shape.geometry_records,
        @sizeOf(relation_abi.Geometry) / @sizeOf(u32),
    );
    const denominator_words = try mul(
        shape.denominator_secure_fields,
        4,
    );
    return .{
        .instance_count = shape.instance_count,
        .top_level_pointer_words = try mul(table_words, 5),
        .source_pointer_words = shape.source_pointer_words,
        .descriptor_words = shape.descriptor_words,
        .geometry_words = geometry_words,
        .challenge_words = 8,
        .alpha_power_words = try mul(shape.max_alpha_powers, 4),
        .denominator_words = denominator_words,
        .claimed_sum_words = try mul(shape.instance_count, 4),
        .output_pointer_words = shape.output_pointer_words,
        .output_coordinate_words = shape.interaction_coordinate_cells,
        .reduction_scratch_words = shape.scratch_words,
        .scan_scratch_words = shape.scratch_words,
        .identity = identity,
    };
}

fn divCeil(value: u64, divisor: u64) u64 {
    return value / divisor + @intFromBool(value % divisor != 0);
}

fn pow2(log: u32) !u64 {
    if (log >= 63) return error.GeometryOverflow;
    return @as(u64, 1) << @intCast(log);
}

fn add(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.GeometryOverflow;
    return std.math.add(u64, lhs, rhs) catch error.GeometryOverflow;
}

fn mul(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.GeometryOverflow;
    return std.math.mul(u64, lhs, rhs) catch error.GeometryOverflow;
}
