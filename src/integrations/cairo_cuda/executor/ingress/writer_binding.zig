//! One owned Cairo CUDA writer/feed/relation ingress closure.

const std = @import("std");
const product_aot = @import("stwo_cuda_backend").aot.product_registry;
const module_globals = @import("stwo_cuda_backend").aot.module_globals;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const adapter = @import("stwo_cairo_frontend").adapter;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const fixed_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
const native_ec = @import("../../native_ec.zig");
const recorded_witness = @import("../../recorded_witness.zig");
const ec_contract = @import("stwo_cuda_backend").runtime.stages.cairo_ec_op_contract;
const cairo_ec_op = @import("stwo_cuda_backend").runtime.stages.cairo_ec_op;
const request_compiler = @import("../../request_compiler.zig");
const fixed_plan = @import("../../base_writer_plan/fixed_tables.zig");
const trace_writer = @import("../trace_writer_controller.zig");
const controller_bundle = @import("controller_bundle.zig");
const multiplicity_feeds = @import("multiplicity_feeds.zig");
const relation_binding = @import("relation_binding.zig");
const writer_base_tables = @import("writer_base_tables.zig");
const writer_inputs = @import("writer_inputs.zig");
const writer_preactions = @import("writer_preactions.zig");
const writer_views = @import("writer_views.zig");

pub const Bound = struct {
    parent_allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    inputs_prepared: writer_inputs.Prepared,
    inputs: writer_inputs.Bound,
    views: writer_views.Registry,
    feeds: multiplicity_feeds.Bound,
    base_tables: writer_base_tables.Bound,
    preactions: writer_preactions.Bound,
    recorded: []recorded_witness.PreparedLaunch,
    native: []native_ec.Prepared,
    writers_prepared: trace_writer.Prepared,
    relation_sources: relation_binding.SourceRegistry,
    relation_prepared: relation_binding.Bound,

    pub fn writers(self: *const Bound) *const trace_writer.Prepared {
        return &self.writers_prepared;
    }

    pub fn relation(
        self: *const Bound,
    ) *const relation_stage.PreparedPlan {
        return self.relation_prepared.runtime();
    }

    pub fn deinit(self: *Bound) void {
        self.relation_prepared.deinit();
        self.relation_sources.deinit();
        self.writers_prepared.deinit();
        for (self.native) |*prepared| prepared.deinit();
        for (self.recorded) |*prepared| prepared.deinit();
        self.preactions.deinit();
        self.base_tables.deinit();
        self.feeds.deinit();
        self.inputs.deinit();
        self.inputs_prepared.deinit();
        const arena = self.arena;
        const parent = self.parent_allocator;
        arena.deinit();
        parent.destroy(arena);
        self.* = undefined;
    }
};

pub fn prepare(
    parent_allocator: std.mem.Allocator,
    session: anytype,
    uploader: anytype,
    provider: anytype,
    registry: product_aot.Registry,
    request: *const request_compiler.PreparedRequest,
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    witnesses: witness_bundle.Bundle,
    feeds: feed_bundle.Bundle,
    fixed: fixed_bundle.Bundle,
    input: *const adapter.ProverInput,
    controllers: *controller_bundle.Bound,
) !Bound {
    const arena = try parent_allocator.create(std.heap.ArenaAllocator);
    errdefer parent_allocator.destroy(arena);
    arena.* = .init(parent_allocator);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    var inputs_prepared = try writer_inputs.Prepared.init(
        allocator,
        proof,
        components,
        witnesses,
        input,
        &request.resident,
    );
    const inputs = try inputs_prepared.uploadAndBind(
        session,
        provider,
        &request.resident,
        proof,
        input,
    );
    const views = try writer_views.build(
        allocator,
        provider,
        request,
        proof,
        components,
        witnesses,
        fixed,
        controllers,
    );
    const feed_sources = try allocator.alloc(
        multiplicity_feeds.ComponentSubwords,
        views.components.len,
    );
    for (views.components, feed_sources) |component, *source| {
        source.* = .{
            .component_index = component.component_index,
            .words = component.sub_words,
        };
    }
    var active_fixed = try fixed_plan.compile(
        allocator,
        components,
        fixed,
    );
    defer active_fixed.deinit();
    const feed_bound = try multiplicity_feeds.prepareAndUpload(
        allocator,
        uploader,
        provider,
        &request.resident,
        request.trace_dispatch,
        feeds,
        active_fixed,
        feed_sources,
    );
    const memory_sources = try inputs.storage.sub(
        inputs_prepared.word_count,
        inputs.storage.len - inputs_prepared.word_count,
    );
    const base_tables = try writer_base_tables.prepare(
        allocator,
        session,
        uploader,
        provider,
        request,
        proof,
        components,
        fixed,
        input,
        &controllers.preprocessed_commit,
        feed_bound,
        views,
        memory_sources,
    );
    const preactions = try writer_preactions.prepare(
        allocator,
        session,
        uploader,
        provider,
        request,
        proof,
        witnesses,
        &inputs,
        views,
    );
    const launches = try prepareLaunches(
        allocator,
        session,
        uploader,
        provider,
        registry,
        request,
        proof,
        components,
        witnesses,
        fixed,
        input,
        controllers,
        inputs,
        views,
        feed_bound,
        base_tables,
        preactions,
    );
    const writers_prepared = try trace_writer.Prepared.initWithFeeds(
        allocator,
        request.trace_dispatch,
        launches.bindings,
        feed_bound.graph(),
    );
    const relation_sources = try relation_binding.buildSourceRegistry(
        allocator,
        &request.relation_plan,
        request.trace_dispatch,
        views,
        controllers.main_commit,
    );
    const relation_prepared = try relation_binding.prepareAndUpload(
        allocator,
        uploader,
        provider,
        &request.resident,
        request.proof_program,
        &request.relation_plan,
        relation_sources.sources,
    );
    return .{
        .parent_allocator = parent_allocator,
        .arena = arena,
        .inputs_prepared = inputs_prepared,
        .inputs = inputs,
        .views = views,
        .feeds = feed_bound,
        .base_tables = base_tables,
        .preactions = preactions,
        .recorded = launches.recorded,
        .native = launches.native,
        .writers_prepared = writers_prepared,
        .relation_sources = relation_sources,
        .relation_prepared = relation_prepared,
    };
}

const Launches = struct {
    recorded: []recorded_witness.PreparedLaunch,
    native: []native_ec.Prepared,
    bindings: []trace_writer.Binding,
};

const PartialBuffers = struct {
    input_pointer_table: common.Words,
    execution_pointer_table: common.Words,
    output_pointer_table: common.Words,
    multiplicity_pointer_table: common.Words,
    execution_strides: common.Words,
};

const NativeBuffers = struct {
    execution_pointer_table: common.Words,
    partial: PartialBuffers,
};

fn prepareLaunches(
    allocator: std.mem.Allocator,
    session: anytype,
    uploader: anytype,
    provider: anytype,
    registry: product_aot.Registry,
    request: *const request_compiler.PreparedRequest,
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    witnesses: witness_bundle.Bundle,
    fixed: fixed_bundle.Bundle,
    input: *const adapter.ProverInput,
    controllers: *controller_bundle.Bound,
    inputs: writer_inputs.Bound,
    views: writer_views.Registry,
    feeds: multiplicity_feeds.Bound,
    base: writer_base_tables.Bound,
    preactions: writer_preactions.Bound,
) !Launches {
    const pointer_storage = try exactSlot(
        provider,
        request,
        .writer_pointer_tables,
    );
    const descriptor_storage = try exactSlot(
        provider,
        request,
        .writer_descriptors,
    );
    var pointer_cursor: usize = 0;
    var descriptor_cursor: usize = 0;
    const recorded = try allocator.alloc(
        recorded_witness.PreparedLaunch,
        32,
    );
    const native = try allocator.alloc(native_ec.Prepared, 1);
    const bindings = try allocator.alloc(
        trace_writer.Binding,
        request.trace_dispatch.launch_order.len,
    );
    var recorded_count: usize = 0;
    var binding_count: usize = 0;
    var native_buffers: ?NativeBuffers = null;
    var partial_component_index: ?u32 = null;
    var root_component_index: ?u32 = null;

    const pedersen = try pedersenTable(
        fixed,
        &controllers.preprocessed_commit,
    );
    for (
        request.trace_dispatch.entries,
    ) |entry| {
        const planned = proof.components[entry.component_index];
        const component = components.components[entry.component_index];
        const view = views.find(entry.component_index) orelse
            return error.MissingWriterView;
        switch (planned.writer) {
            .recorded_aot => {
                const witness = witnesses.find(planned.name) orelse
                    return error.MissingRecordedWitnessLowering;
                const pointer_tables = try takeRecordedPointers(
                    pointer_storage,
                    &pointer_cursor,
                    witness.program,
                );
                const strides = try take(
                    descriptor_storage,
                    &descriptor_cursor,
                    recorded_witness.execution_stride_count,
                );
                const input_columns = inputs.component(
                    entry.component_index,
                ) orelse return error.MissingWriterInput;
                const multiplicities = try allocator.alloc(
                    common.Words,
                    witness.program.n_mult_tables,
                );
                const action = preactions.find(entry.component_index);
                recorded[recorded_count] = recorded_witness.prepare(
                    allocator,
                    session,
                    registry,
                    witness.label,
                    witness.semantic_hash,
                    witness.program,
                    componentGeometry(planned, component),
                    @intCast(componentRows(component)),
                    .{
                        .input_pointer_table = pointer_tables.input,
                        .input_columns = input_columns,
                        .execution_pointer_table = pointer_tables.execution,
                        .execution_tables = &base.execution_tables,
                        .execution_strides = strides,
                        .output_pointer_table = pointer_tables.output,
                        .output_columns = view.trace_columns,
                        .multiplicity_pointer_table = pointer_tables.multiplicity,
                        .multiplicity_tables = multiplicities,
                        .lookup_words_word_major = view.lookup_words,
                        .sub_words_word_major = view.sub_words,
                        .pedersen_w18 = if (witness.program
                            .deductionRequirements().pedersen_table)
                            pedersen
                        else
                            null,
                    },
                ) catch |err| {
                    std.debug.print(
                        "cairo-cuda writer launch {s} failed: {s}\n",
                        .{ planned.name, @errorName(err) },
                    );
                    return err;
                };
                bindings[binding_count] = .{
                    .component_index = entry.component_index,
                    .catalog_identity = entry.catalog_identity,
                    .body = .{
                        .recorded = &recorded[recorded_count],
                    },
                    .gather = if (action) |value| value.gather else null,
                    .compact = if (action) |value| value.compact else null,
                };
                recorded_count += 1;
                binding_count += 1;
            },
            .native_backend => if (std.mem.eql(
                u8,
                planned.name,
                "ec_op_builtin",
            )) {
                root_component_index = entry.component_index;
                native_buffers = .{
                    .execution_pointer_table = try take(
                        pointer_storage,
                        &pointer_cursor,
                        ec_contract.execution_table_count * 2,
                    ),
                    .partial = undefined,
                };
            } else {
                const witness = witnesses.find(planned.name) orelse
                    return error.MissingRecordedWitnessLowering;
                const pointers = try takeRecordedPointers(
                    pointer_storage,
                    &pointer_cursor,
                    witness.program,
                );
                native_buffers.?.partial = .{
                    .input_pointer_table = pointers.input,
                    .execution_pointer_table = pointers.execution,
                    .output_pointer_table = pointers.output,
                    .multiplicity_pointer_table = pointers.multiplicity,
                    .execution_strides = try take(
                        descriptor_storage,
                        &descriptor_cursor,
                        recorded_witness.execution_stride_count,
                    ),
                };
                partial_component_index = entry.component_index;
            },
            .fixed_table, .memory_trace => {},
        }
    }
    if (recorded_count != recorded.len or
        native_buffers == null or
        root_component_index == null or
        partial_component_index == null)
    {
        return error.InvalidWriterLaunchInventory;
    }
    const root_index = root_component_index.?;
    const partial_index = partial_component_index.?;
    const root_planned = proof.components[root_index];
    const partial_planned = proof.components[partial_index];
    const root_component = components.components[root_index];
    const partial_component = components.components[partial_index];
    const root_view = views.find(root_index) orelse
        return error.MissingWriterView;
    const partial_view = views.find(partial_index) orelse
        return error.MissingWriterView;
    const partial_witness = witnesses.find(partial_planned.name) orelse
        return error.MissingRecordedWitnessLowering;
    const geometry = cairo_ec_op.Geometry{
        .row_count = @intCast(componentRows(root_component)),
        .n_addresses = try castU32(input.memory.address_to_id.len),
        .n_big = try castU32(input.memory.f252_values.len),
        .n_small = try castU32(input.memory.small_values.len),
        .address_count_words = try castU32(
            input.memory.address_to_id.len -| 1,
        ),
        .big_count_words = try castU32(input.memory.f252_values.len),
        .small_count_words = try castU32(input.memory.small_values.len),
        .range_check_8_count_words = 256,
    };
    const partial_rows = try geometry.partialRowCount();
    const partial_columns = try splitColumns(
        allocator,
        views.find(root_index).?.sub_words,
        partial_rows,
    );
    if (partial_columns.len != ec_contract.partial_input_column_count)
        return error.InvalidNativeEcWorkspace;
    const segment = input.builtin_segments.ec_op_builtin orelse
        return error.MissingNativeEcSegment;
    const adapted = try exactSlot(provider, request, .adapted_input);
    const segment_start = try adapted.sub(0, 1);
    const segment_word = [_]u32{try castU32(segment.begin_addr)};
    try uploader.uploadSlice(u32, segment_start, &segment_word);
    const address_counts_storage = feeds.destination(
        "memory_address_to_id",
    ) orelse return error.MissingMultiplicityDestination;
    const big_counts_storage = feeds.destination(
        "memory_id_to_big",
    ) orelse return error.MissingMultiplicityDestination;
    const small_counts_storage = feeds.destination(
        "memory_id_to_big#small",
    ) orelse return error.MissingMultiplicityDestination;
    const range_check_8_counts_storage = feeds.destination(
        "range_check_8",
    ) orelse return error.MissingMultiplicityDestination;
    const address_counts = try address_counts_storage.sub(
        0,
        geometry.address_count_words,
    );
    const big_counts = try big_counts_storage.sub(
        0,
        geometry.big_count_words,
    );
    const small_counts = try small_counts_storage.sub(
        0,
        geometry.small_count_words,
    );
    const range_check_8_counts = try range_check_8_counts_storage.sub(
        0,
        geometry.range_check_8_count_words,
    );
    const partial_inputs = partial_columns[0 .. ec_contract.partial_input_column_count - 1];
    const partial_multiplicities = try allocator.alloc(
        common.Words,
        partial_witness.program.n_mult_tables,
    );
    native[0] = native_ec.prepare(
        allocator,
        session,
        registry,
        componentGeometry(root_planned, root_component),
        componentGeometry(partial_planned, partial_component),
        geometry,
        .{
            .execution_pointer_table = native_buffers.?.execution_pointer_table,
            .execution_tables = &base.execution_tables,
            .segment_start = segment_start,
            .trace_columns = root_view.trace_columns,
            .lookup_words_word_major = root_view.lookup_words,
            .partial_input_columns = partial_columns,
            .address_counts = address_counts,
            .big_counts = big_counts,
            .small_counts = small_counts,
            .range_check_8_counts = range_check_8_counts,
        },
        partial_witness.semantic_hash,
        partial_witness.program,
        .{
            .input_pointer_table = native_buffers.?.partial.input_pointer_table,
            .input_columns = partial_inputs,
            .execution_pointer_table = native_buffers.?.partial.execution_pointer_table,
            .execution_tables = &base.execution_tables,
            .execution_strides = native_buffers.?.partial.execution_strides,
            .output_pointer_table = native_buffers.?.partial.output_pointer_table,
            .output_columns = partial_view.trace_columns,
            .multiplicity_pointer_table = native_buffers.?.partial.multiplicity_pointer_table,
            .multiplicity_tables = partial_multiplicities,
            .lookup_words_word_major = partial_view.lookup_words,
            .sub_words_word_major = partial_view.sub_words,
            .pedersen_w18 = if (partial_witness.program
                .deductionRequirements().pedersen_table)
                pedersen
            else
                null,
        },
    ) catch |err| {
        std.debug.print(
            "cairo-cuda writer launch {s} failed: {s}\n",
            .{ root_planned.name, @errorName(err) },
        );
        return err;
    };
    const root_entry = request.trace_dispatch.entries[
        root_planned.canonical_ordinal
    ];
    const partial_entry = request.trace_dispatch.entries[
        partial_planned.canonical_ordinal
    ];
    bindings[binding_count] = .{
        .component_index = root_index,
        .catalog_identity = root_entry.catalog_identity,
        .body = .{ .native_ec = .{
            .prepared = &native[0],
            .member_component_index = partial_index,
            .member_catalog_identity = partial_entry.catalog_identity,
        } },
    };
    binding_count += 1;
    if (base.bindings.len + binding_count != bindings.len)
        return error.InvalidWriterLaunchInventory;
    @memcpy(
        bindings[binding_count..],
        base.bindings,
    );
    if (pointer_cursor > pointer_storage.len or
        descriptor_cursor > descriptor_storage.len)
    {
        return error.InvalidWriterMetadataExtent;
    }
    return .{
        .recorded = recorded,
        .native = native,
        .bindings = bindings,
    };
}

const RecordedPointers = struct {
    input: common.Words,
    execution: common.Words,
    output: common.Words,
    multiplicity: common.Words,
};

fn takeRecordedPointers(
    storage: common.Words,
    cursor: *usize,
    program: anytype,
) !RecordedPointers {
    return .{
        .input = try take(
            storage,
            cursor,
            try pointerWords(@max(program.n_inputs, 1)),
        ),
        .output = try take(
            storage,
            cursor,
            try pointerWords(@max(program.n_cols, 1)),
        ),
        .multiplicity = try take(
            storage,
            cursor,
            try pointerWords(@max(program.n_mult_tables, 1)),
        ),
        .execution = try take(
            storage,
            cursor,
            try pointerWords(recorded_witness.execution_table_count),
        ),
    };
}

fn take(
    storage: common.Words,
    cursor: *usize,
    count: usize,
) !common.Words {
    const output = try storage.sub(cursor.*, count);
    cursor.* = try add(cursor.*, count);
    return output;
}

fn pointerWords(count: anytype) !usize {
    return mul(count, @sizeOf(u64) / @sizeOf(u32));
}

fn componentGeometry(
    planned: proof_plan.Component,
    component: composition.Component,
) recorded_witness.ComponentGeometry {
    return .{
        .canonical_ordinal = planned.canonical_ordinal,
        .instance = planned.instance,
        .trace_log_size = component.trace_log_size,
    };
}

fn splitColumns(
    allocator: std.mem.Allocator,
    storage: common.Words,
    row_count: usize,
) ![]common.Words {
    if (row_count == 0 or storage.len % row_count != 0)
        return error.InvalidWriterViewExtent;
    const columns = try allocator.alloc(
        common.Words,
        storage.len / row_count,
    );
    for (columns, 0..) |*column, index| {
        column.* = try storage.sub(
            try mul(index, row_count),
            row_count,
        );
    }
    return columns;
}

fn pedersenTable(
    fixed: fixed_bundle.Bundle,
    preprocessed: *const @import("../trace_commit.zig").Bound,
) !recorded_witness.PedersenW18Table {
    const entry = fixed.find(
        "pedersen_points_table_window_bits_18",
    ) orelse return error.MissingPedersenW18Table;
    if (entry.preprocessed_sources.len !=
        module_globals.pedersen_w18_column_count + 1 or
        !std.mem.eql(u8, entry.preprocessed_sources[0], "seq_23"))
    {
        return error.InvalidPedersenW18Table;
    }
    var output: recorded_witness.PedersenW18Table = .{
        .columns = undefined,
        .identity = undefined,
    };
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/pedersen-w18/v1\x00");
    for (entry.preprocessed_sources[1..], &output.columns) |
        identity,
        *column,
    | {
        const ordinal = fixed.identityOrdinal(identity) orelse
            return error.MissingPedersenW18Table;
        column.* = try preprocessed.preprocessedBaseEvaluation(ordinal);
        if (column.len != module_globals.pedersen_w18_row_count)
            return error.InvalidPedersenW18Table;
        hash.update(identity);
    }
    output.identity = hash.finalResult();
    return output;
}

fn castU32(value: usize) !u32 {
    return std.math.cast(u32, value) orelse
        error.InvalidWriterViewExtent;
}

fn exactSlot(
    provider: anytype,
    request: *const request_compiler.PreparedRequest,
    kind: @import("../resident_plan.zig").SlotKind,
) !common.Words {
    const descriptor = request.resident.slot(kind, 0) orelse
        return error.MissingWriterViewSlot;
    const storage = try provider.slot(descriptor.id);
    if (storage.len != descriptor.words)
        return error.InvalidWriterViewExtent;
    return storage;
}

fn componentRows(component: composition.Component) usize {
    return @as(usize, 1) << @intCast(component.trace_log_size);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch
        error.InvalidWriterViewExtent;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.InvalidWriterViewExtent;
    const rhs = std.math.cast(usize, right) orelse
        return error.InvalidWriterViewExtent;
    return std.math.mul(usize, lhs, rhs) catch
        error.InvalidWriterViewExtent;
}

pub fn relationElements(
    provider: anytype,
    request: *const request_compiler.PreparedRequest,
) !common.SecureFields {
    const descriptor = request.resident.slot(
        .relation_challenges,
        0,
    ) orelse return error.MissingRelationChallengeSlot;
    const words = try provider.slot(descriptor.id);
    if (words.len != descriptor.words)
        return error.InvalidRelationChallengeExtent;
    return (try words.cast(
        @import("stwo_cuda_backend").abi.field.SecureField,
    )).sub(0, 2);
}
