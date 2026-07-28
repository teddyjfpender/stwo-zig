//! Gather and compact input-action ingress mapper boundary.

const std = @import("std");
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
const witness_abi = @import(
    "../../../../backends/cuda/abi/stages/cairo_witness.zig",
);
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const cairo_witness = @import(
    "../../../../backends/cuda/runtime/stages/cairo_witness.zig",
);
const witness_plan = @import(
    "../../../../backends/cuda/runtime/stages/cairo_witness_plan.zig",
);
const ec_contract = @import(
    "../../../../backends/cuda/runtime/stages/cairo_ec_op_contract.zig",
);
const recorded_witness = @import("../../recorded_witness.zig");
const recorded_binding = @import("../../recorded_binding.zig");
const request_compiler = @import("../../request_compiler.zig");
const resident_plan = @import("../resident_plan.zig");
const trace_writer = @import("../trace_writer_controller.zig");
const writer_inputs = @import("writer_inputs.zig");
const preaction_geometry = @import("writer_preaction_geometry.zig");
const writer_views = @import("writer_views.zig");

const expected_gather_actions = 8;
const expected_compact_actions = 3;
const pointer_words = @sizeOf(u64) / @sizeOf(u32);
const compact_descriptor_words = 6;

comptime {
    std.debug.assert(pointer_words == 2);
    std.debug.assert(
        @sizeOf(witness_abi.MultiEdgeDescriptor) % @sizeOf(u32) == 0,
    );
}

pub const Action = struct {
    component_index: u32,
    gather: ?trace_writer.GatherBinding = null,
    compact: ?@import(
        "../../../../backends/cuda/runtime/stages/cairo_witness.zig",
    ).Compact = null,
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    actions: []Action,

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.actions);
        self.* = undefined;
    }

    pub fn find(self: Bound, component_index: u32) ?Action {
        for (self.actions) |action| {
            if (action.component_index == component_index) return action;
        }
        return null;
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    session: anytype,
    uploader: anytype,
    provider: anytype,
    request: *const request_compiler.PreparedRequest,
    proof: *const proof_plan.CairoProofPlan,
    witnesses: witness_bundle.Bundle,
    inputs: *const writer_inputs.Bound,
    views: writer_views.Registry,
) !Bound {
    try validateAuthority(request, proof);

    const pointer_storage = try exactSlot(
        provider,
        &request.resident,
        .writer_pointer_tables,
    );
    const descriptor_storage = try exactSlot(
        provider,
        &request.resident,
        .writer_descriptors,
    );
    const scratch_storage = try exactSlot(
        provider,
        &request.resident,
        .writer_scratch,
    );
    var pointer_cursor = try recordedPointerWords(proof, witnesses);
    var descriptor_cursor = try recordedDescriptorWords(proof);
    const scratch_first = try recordedScratchWords(proof, witnesses);
    if (pointer_cursor > pointer_storage.len or
        descriptor_cursor > descriptor_storage.len or
        scratch_first > scratch_storage.len)
    {
        return error.InvalidWriterPreactionLayout;
    }

    var action_count: usize = 0;
    var gather_count: usize = 0;
    var compact_count: usize = 0;
    for (proof.components) |component| {
        if (component.writer != .recorded_aot or
            component.producer_edges.len == 0)
        {
            continue;
        }
        action_count = try add(action_count, 1);
        if (proof_plan.compactGeometry(component.name) == null) {
            gather_count = try add(gather_count, 1);
        } else {
            compact_count = try add(compact_count, 1);
        }
    }
    if (gather_count != expected_gather_actions or
        compact_count != expected_compact_actions or
        action_count != expected_gather_actions + expected_compact_actions)
    {
        return error.InvalidWriterPreactionInventory;
    }

    const actions = try allocator.alloc(Action, action_count);
    errdefer allocator.free(actions);
    var action_cursor: usize = 0;
    var maximum_compact_words: usize = 0;
    for (proof.components, 0..) |component, component_index| {
        if (component.writer != .recorded_aot or
            component.producer_edges.len == 0)
        {
            continue;
        }
        const output_columns = inputs.component(@intCast(component_index)) orelse
            return error.MissingWriterPreactionInputs;
        const consumer_rows = try componentRows(component);
        const program = (witnesses.find(component.name) orelse
            return error.MissingRecordedWitnessLowering).program;
        if (output_columns.len != program.n_inputs)
            return error.InvalidWriterPreactionLayout;

        if (proof_plan.compactGeometry(component.name)) |geometry| {
            const prepared = prepareCompact(
                allocator,
                session,
                uploader,
                pointer_storage,
                &pointer_cursor,
                descriptor_storage,
                &descriptor_cursor,
                scratch_storage,
                scratch_first,
                proof,
                witnesses,
                views,
                component,
                geometry,
                output_columns,
                consumer_rows,
            ) catch |err| {
                std.debug.print(
                    "cairo-cuda compact preaction {s} failed: {s}\n",
                    .{ component.name, @errorName(err) },
                );
                return err;
            };
            maximum_compact_words = @max(
                maximum_compact_words,
                prepared.workspace_words,
            );
            actions[action_cursor] = .{
                .component_index = @intCast(component_index),
                .compact = prepared.binding,
            };
        } else {
            const gather = prepareGather(
                allocator,
                session,
                descriptor_storage,
                &descriptor_cursor,
                scratch_storage,
                proof,
                witnesses,
                views,
                component,
                output_columns,
                consumer_rows,
            ) catch |err| {
                std.debug.print(
                    "cairo-cuda gather preaction {s} failed: {s}\n",
                    .{ component.name, @errorName(err) },
                );
                return err;
            };
            actions[action_cursor] = .{
                .component_index = @intCast(component_index),
                .gather = gather,
            };
        }
        action_cursor += 1;
    }
    std.debug.assert(action_cursor == actions.len);

    const compact_end = try add(scratch_first, maximum_compact_words);
    if (compact_end > scratch_storage.len)
        return error.InvalidWriterPreactionLayout;
    if (pointer_cursor > pointer_storage.len or
        descriptor_cursor > descriptor_storage.len)
    {
        return error.InvalidWriterPreactionLayout;
    }
    return .{ .allocator = allocator, .actions = actions };
}

const CompactPrepared = struct {
    binding: cairo_witness.Compact,
    workspace_words: usize,
};

fn prepareGather(
    allocator: std.mem.Allocator,
    session: anytype,
    descriptor_storage: common.Words,
    descriptor_cursor: *usize,
    scratch_storage: common.Words,
    proof: *const proof_plan.CairoProofPlan,
    witnesses: witness_bundle.Bundle,
    views: writer_views.Registry,
    component: proof_plan.Component,
    outputs: []const common.Words,
    consumer_rows: u32,
) !trace_writer.GatherBinding {
    _ = proof_plan.gatheredProducerEdges(component.name) orelse
        return error.InvalidWriterPreactionLayout;
    const edges = component.producer_edges;
    if (edges.len == 0)
        return error.InvalidWriterPreactionLayout;
    const input_width = edges[0].words_per_instance;
    if (outputs.len != try add(@intCast(input_width), 1))
        return error.InvalidWriterPreactionLayout;
    const output_matrix = try columnMatrix(outputs, consumer_rows);

    const descriptors = try allocator.alloc(
        witness_abi.MultiEdgeDescriptor,
        edges.len,
    );
    defer allocator.free(descriptors);
    var destination_row: u32 = 0;
    for (edges, descriptors) |edge, *descriptor| {
        const source = try producerSource(
            scratch_storage,
            proof,
            witnesses,
            views,
            edge,
        );
        if (edge.words_per_instance != input_width)
            return error.InvalidWriterPreactionLayout;
        descriptor.* = .{
            .source_offset_words = source.offset_words,
            .producer_rows = source.padded_rows,
            .word_base = edge.word_base,
            .words_per_instance = edge.words_per_instance,
            .instance_count = edge.instances,
            .destination_row_offset = destination_row,
        };
        destination_row = try preaction_geometry.addU32(
            destination_row,
            try preaction_geometry.mulU32(source.padded_rows, edge.instances),
        );
    }
    if (destination_row > consumer_rows or
        try preaction_geometry.canonicalRows(destination_row) != consumer_rows)
    {
        return error.InvalidWriterPreactionLayout;
    }

    const descriptor_words =
        @sizeOf(witness_abi.MultiEdgeDescriptor) / @sizeOf(u32);
    const word_count = try mul(edges.len, descriptor_words);
    descriptor_cursor.* = std.mem.alignForward(
        usize,
        descriptor_cursor.*,
        @alignOf(witness_abi.MultiEdgeDescriptor) / @sizeOf(u32),
    );
    const device_words = try take(
        descriptor_storage,
        descriptor_cursor,
        word_count,
    );
    const device_descriptors = try device_words.cast(
        witness_abi.MultiEdgeDescriptor,
    );
    const topology = try witness_plan.prepareMultiEdgeTopology(
        session,
        descriptors,
        device_descriptors,
        scratch_storage.len,
        true,
        false,
    );
    return .{
        .topology = topology,
        .producer_arena = scratch_storage,
        .outputs = output_matrix,
    };
}

fn prepareCompact(
    allocator: std.mem.Allocator,
    session: anytype,
    uploader: anytype,
    pointer_storage: common.Words,
    pointer_cursor: *usize,
    descriptor_storage: common.Words,
    descriptor_cursor: *usize,
    scratch_storage: common.Words,
    scratch_first: usize,
    proof: *const proof_plan.CairoProofPlan,
    witnesses: witness_bundle.Bundle,
    views: writer_views.Registry,
    component: proof_plan.Component,
    geometry: proof_plan.CompactGeometry,
    outputs: []const common.Words,
    consumer_rows: u32,
) !CompactPrepared {
    _ = session;
    if (outputs.len != geometry.multiplicity_slot + 1 or
        component.producer_edges.len == 0)
    {
        return error.InvalidWriterPreactionLayout;
    }
    const edges = component.producer_edges;
    for (outputs) |output| try requireExactColumn(output, consumer_rows);

    const producer_table = try take(
        pointer_storage,
        pointer_cursor,
        try mul(edges.len, pointer_words),
    );
    const consumer_table = try take(
        pointer_storage,
        pointer_cursor,
        try mul(outputs.len, pointer_words),
    );
    const descriptor_words = try mul(
        edges.len,
        compact_descriptor_words,
    );
    const device_descriptors = try take(
        descriptor_storage,
        descriptor_cursor,
        descriptor_words,
    );
    const host_sources = try allocator.alloc(common.Words, edges.len);
    defer allocator.free(host_sources);
    const host_descriptors = try allocator.alloc(u32, descriptor_words);
    defer allocator.free(host_descriptors);
    var total_rows: u32 = 0;
    for (edges, host_sources, 0..) |
        edge,
        *host_source,
        edge_index,
    | {
        const source = try producerSource(
            scratch_storage,
            proof,
            witnesses,
            views,
            edge,
        );
        host_source.* = source.words;
        const real_rows = source.real_rows orelse
            return error.InvalidWriterPreactionProducer;
        const first = edge_index * compact_descriptor_words;
        const descriptor = [compact_descriptor_words]u32{
            source.padded_rows,
            real_rows,
            edge.word_base,
            edge.words_per_instance,
            edge.instances,
            total_rows,
        };
        @memcpy(
            host_descriptors[first..][0..compact_descriptor_words],
            &descriptor,
        );
        total_rows = try preaction_geometry.addU32(
            total_rows,
            try preaction_geometry.mulU32(real_rows, edge.instances),
        );
    }
    const sort_rows = try preaction_geometry.nextPowerOfTwo(total_rows);
    if (total_rows == 0 or consumer_rows < 16 or
        !std.math.isPowerOfTwo(consumer_rows))
    {
        return error.InvalidWriterPreactionLayout;
    }
    const temp = try cairo_witness.Native.compactTempBytes(sort_rows);
    var workspace_cursor = scratch_first;
    const tuples = try takeAt(
        scratch_storage,
        &workspace_cursor,
        try mul(sort_rows, geometry.tuple_words),
    );
    const keys_a = try takeAt(
        scratch_storage,
        &workspace_cursor,
        sort_rows,
    );
    const keys_b = try takeAt(
        scratch_storage,
        &workspace_cursor,
        sort_rows,
    );
    const indices_a = try takeAt(
        scratch_storage,
        &workspace_cursor,
        sort_rows,
    );
    const indices_b = try takeAt(
        scratch_storage,
        &workspace_cursor,
        sort_rows,
    );
    const heads = try takeAt(
        scratch_storage,
        &workspace_cursor,
        sort_rows,
    );
    const positions = try takeAt(
        scratch_storage,
        &workspace_cursor,
        sort_rows,
    );
    const unique_count = try takeAt(
        scratch_storage,
        &workspace_cursor,
        1,
    );
    const sort_temp = try takeAt(
        scratch_storage,
        &workspace_cursor,
        try temp.sortWords(),
    );
    const scan_temp = try takeAt(
        scratch_storage,
        &workspace_cursor,
        try temp.scanWords(),
    );

    const producer_pointers = try allocator.alloc(
        u32,
        producer_table.len,
    );
    defer allocator.free(producer_pointers);
    try recorded_binding.encodePointerTable(
        producer_pointers,
        host_sources,
    );
    const consumer_pointers = try allocator.alloc(
        u32,
        consumer_table.len,
    );
    defer allocator.free(consumer_pointers);
    try recorded_binding.encodePointerTable(
        consumer_pointers,
        outputs,
    );
    try uploader.uploadSlice(u32, producer_table, producer_pointers);
    try uploader.uploadSlice(u32, device_descriptors, host_descriptors);
    try uploader.uploadSlice(u32, consumer_table, consumer_pointers);

    return .{
        .binding = .{
            .producer_pointer_table = producer_table,
            .edge_descriptors = device_descriptors,
            .edge_count = @intCast(edges.len),
            .tuple_words = geometry.tuple_words,
            .key_words = geometry.key_words,
            .total_rows = total_rows,
            .sort_rows = sort_rows,
            .consumer_rows = consumer_rows,
            .input_count = @intCast(outputs.len),
            .consumer_pointer_table = consumer_table,
            .enabler_slot = geometry.enabler_slot,
            .iota_slot = geometry.iota_slot,
            .multiplicity_slot = geometry.multiplicity_slot,
            .tuples = tuples,
            .keys_a = keys_a,
            .keys_b = keys_b,
            .indices_a = indices_a,
            .indices_b = indices_b,
            .heads = heads,
            .positions = positions,
            .unique_count = unique_count,
            .sort_temp = sort_temp,
            .sort_temp_bytes = temp.sort,
            .scan_temp = scan_temp,
            .scan_temp_bytes = temp.scan,
        },
        .workspace_words = workspace_cursor - scratch_first,
    };
}

const ProducerSource = struct {
    words: common.Words,
    offset_words: u64,
    padded_rows: u32,
    real_rows: ?u32,
};

fn producerSource(
    scratch: common.Words,
    proof: *const proof_plan.CairoProofPlan,
    witnesses: witness_bundle.Bundle,
    views: writer_views.Registry,
    edge: proof_plan.ProducerEdge,
) !ProducerSource {
    const index = uniqueComponent(proof, edge.producer) orelse
        return error.MissingWriterPreactionProducer;
    const view = views.find(index) orelse
        return error.MissingWriterPreactionProducer;
    const program = (witnesses.find(edge.producer) orelse
        return error.MissingRecordedWitnessLowering).program;
    if (program.n_sub_words == 0 or view.sub_words.len == 0 or
        view.sub_words.len % program.n_sub_words != 0 or
        !preaction_geometry.contains(scratch, view.sub_words))
    {
        return error.InvalidWriterPreactionProducer;
    }
    const physical_rows = view.sub_words.len / program.n_sub_words;
    if (physical_rows == 0 or physical_rows > std.math.maxInt(u32))
        return error.InvalidWriterPreactionProducer;
    const logical_rows = componentMainRows(proof.components[index]) orelse
        return error.InvalidWriterPreactionProducer;
    if (logical_rows.padded_rows != physical_rows) {
        return error.InvalidWriterPreactionProducer;
    }
    const byte_offset = view.sub_words.address - scratch.address;
    if (byte_offset % @sizeOf(u32) != 0)
        return error.InvalidWriterPreactionProducer;
    return .{
        .words = view.sub_words,
        .offset_words = byte_offset / @sizeOf(u32),
        .padded_rows = logical_rows.padded_rows,
        .real_rows = logical_rows.real_rows,
    };
}

fn componentMainRows(
    component: proof_plan.Component,
) ?proof_plan.RowExtent {
    for (component.trace_parts) |part| {
        if (part.id == .main) return part.rows;
    }
    return null;
}

fn validateAuthority(
    request: *const request_compiler.PreparedRequest,
    proof: *const proof_plan.CairoProofPlan,
) !void {
    if (std.mem.allEqual(u8, &request.resident.identity, 0) or
        request.proof.components.len != proof.components.len)
    {
        std.debug.print(
            "cairo-cuda preaction authority resident_empty={} request_components={} proof_components={}\n",
            .{
                std.mem.allEqual(u8, &request.resident.identity, 0),
                request.proof.components.len,
                proof.components.len,
            },
        );
        return error.InvalidWriterPreactionAuthority;
    }
    for (request.proof.components, proof.components, 0..) |
        expected,
        actual,
        index,
    | {
        if (expected.instance != actual.instance or
            expected.canonical_ordinal != actual.canonical_ordinal or
            expected.writer != actual.writer or
            !std.mem.eql(u8, expected.name, actual.name))
        {
            std.debug.print(
                "cairo-cuda preaction authority mismatch index={} expected={s}/{} actual={s}/{}\n",
                .{
                    index,
                    expected.name,
                    expected.instance,
                    actual.name,
                    actual.instance,
                },
            );
            return error.InvalidWriterPreactionAuthority;
        }
    }
}

fn recordedPointerWords(
    proof: *const proof_plan.CairoProofPlan,
    witnesses: witness_bundle.Bundle,
) !usize {
    var total: usize = 0;
    for (proof.components) |component| {
        switch (component.writer) {
            .recorded_aot => total = try add(
                total,
                try recordedProgramPointerWords(
                    (witnesses.find(component.name) orelse
                        return error.MissingRecordedWitnessLowering).program,
                ),
            ),
            .native_backend => if (std.mem.eql(
                u8,
                component.name,
                "ec_op_builtin",
            )) {
                total = try add(
                    total,
                    try mul(ec_contract.execution_table_count, pointer_words),
                );
            } else {
                total = try add(
                    total,
                    try recordedProgramPointerWords(
                        (witnesses.find(component.name) orelse
                            return error.MissingRecordedWitnessLowering).program,
                    ),
                );
            },
            .fixed_table, .memory_trace => {},
        }
    }
    return total;
}

fn recordedProgramPointerWords(program: anytype) !usize {
    var count = try add(
        @max(@as(usize, program.n_inputs), 1),
        @max(@as(usize, program.n_cols), 1),
    );
    count = try add(
        count,
        try add(
            @max(@as(usize, program.n_mult_tables), 1),
            recorded_witness.execution_table_count,
        ),
    );
    return mul(count, pointer_words);
}

fn recordedDescriptorWords(
    proof: *const proof_plan.CairoProofPlan,
) !usize {
    var count: usize = 0;
    for (proof.components) |component| {
        const recorded = component.writer == .recorded_aot or
            (component.writer == .native_backend and
                !std.mem.eql(u8, component.name, "ec_op_builtin"));
        if (recorded) count = try add(
            count,
            recorded_witness.execution_stride_count,
        );
    }
    return count;
}

fn recordedScratchWords(
    proof: *const proof_plan.CairoProofPlan,
    witnesses: witness_bundle.Bundle,
) !usize {
    var total: usize = 0;
    for (proof.components) |component| {
        const rows: usize = try componentRows(component);
        switch (component.writer) {
            .recorded_aot => total = try add(
                total,
                try mul(
                    rows,
                    (witnesses.find(component.name) orelse
                        return error.MissingRecordedWitnessLowering)
                        .program.n_sub_words,
                ),
            ),
            .native_backend => if (std.mem.eql(
                u8,
                component.name,
                "ec_op_builtin",
            )) {
                total = try add(
                    total,
                    try mul(
                        try mul(rows, ec_contract.partial_padded_rounds),
                        ec_contract.partial_input_column_count,
                    ),
                );
            } else {
                total = try add(
                    total,
                    try mul(
                        rows,
                        (witnesses.find(component.name) orelse
                            return error.MissingRecordedWitnessLowering)
                            .program.n_sub_words,
                    ),
                );
            },
            .fixed_table, .memory_trace => {},
        }
    }
    return total;
}

fn componentRows(component: proof_plan.Component) !u32 {
    var rows: ?u32 = null;
    for (component.trace_parts) |part| {
        if (part.id != .main) continue;
        if (rows != null) return error.InvalidWriterPreactionLayout;
        rows = part.rows.padded_rows;
    }
    const result = rows orelse return error.InvalidWriterPreactionLayout;
    if (result < 16 or !std.math.isPowerOfTwo(result))
        return error.InvalidWriterPreactionLayout;
    return result;
}

fn columnMatrix(
    columns: []const common.Words,
    rows: u32,
) !common.WordMatrix {
    if (columns.len == 0) return error.InvalidWriterPreactionLayout;
    const row_count: usize = rows;
    for (columns, 0..) |column, index| {
        try requireExactColumn(column, rows);
        const byte_offset = try mul(
            try mul(index, row_count),
            @sizeOf(u32),
        );
        const expected = std.math.add(
            usize,
            columns[0].address,
            byte_offset,
        ) catch return error.InvalidWriterPreactionLayout;
        if (column.address != expected or
            column.owner != columns[0].owner or
            column.generation != columns[0].generation)
        {
            return error.InvalidWriterPreactionLayout;
        }
    }
    return .{
        .storage = .{
            .address = columns[0].address,
            .len = try mul(row_count, columns.len),
            .owner = columns[0].owner,
            .generation = columns[0].generation,
        },
        .column_stride_words = row_count,
    };
}

fn requireExactColumn(column: common.Words, rows: u32) !void {
    if (column.len != @as(usize, rows) or column.address == 0)
        return error.InvalidWriterPreactionLayout;
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

fn exactSlot(
    provider: anytype,
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
) !common.Words {
    const descriptor = plan.slot(kind, 0) orelse
        return error.MissingWriterPreactionSlot;
    const words = try provider.slot(descriptor.id);
    if (words.len != descriptor.words)
        return error.InvalidWriterPreactionLayout;
    return words;
}

fn take(
    storage: common.Words,
    cursor: *usize,
    count: usize,
) !common.Words {
    return takeAt(storage, cursor, count);
}

fn takeAt(
    storage: common.Words,
    cursor: *usize,
    count: usize,
) !common.Words {
    if (count == 0) return error.InvalidWriterPreactionLayout;
    const result = try storage.sub(cursor.*, count);
    cursor.* = try add(cursor.*, count);
    return result;
}

fn add(left: usize, right: anytype) !usize {
    const cast = std.math.cast(usize, right) orelse
        return error.InvalidWriterPreactionLayout;
    return std.math.add(usize, left, cast) catch
        error.InvalidWriterPreactionLayout;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.InvalidWriterPreactionLayout;
    const rhs = std.math.cast(usize, right) orelse
        return error.InvalidWriterPreactionLayout;
    return std.math.mul(usize, lhs, rhs) catch
        error.InvalidWriterPreactionLayout;
}
