//! Backend-neutral assembly of the official Cairo interaction commitment tree.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const adapter = @import("../adapter/mod.zig");
const claim_generator = @import("../claim_generator.zig");
const fixed_trace = @import("../conformance/fixed_trace.zig");
const recorded_interaction = @import("../conformance/recorded_interaction.zig");
const pedersen_table = @import("../preprocessed/pedersen_table.zig");
const cpu_memory = @import("../witness/cpu_memory_multiplicity.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const fixed_lookup = @import("../witness/fixed_lookup_words.zig");
const fixed_tables = @import("../witness/fixed_table_bundle.zig");
const implicit = @import("../witness/implicit_interaction_sources.zig");
const interaction_topology = @import("../witness/interaction_topology.zig");
const interaction_trace = @import("../witness/interaction_trace.zig");
const interaction_executor = @import("../witness/interaction_executor.zig");
const memory_tables = @import("../witness/memory_tables.zig");
const relation_bundle = @import("../witness/relation_bundle.zig");
const base_trace = @import("base_trace.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;

pub const lookup_power_count = 128;

pub const InteractionTrace = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    claimed_sums: []QM31,
    component_sum: QM31,

    pub fn deinit(self: *InteractionTrace) void {
        deinitColumns(self.allocator, self.columns);
        if (self.claimed_sums.len != 0) self.allocator.free(self.claimed_sums);
        self.* = undefined;
    }

    pub fn takeColumns(self: *InteractionTrace) []ColumnEvaluation {
        const columns = self.columns;
        self.columns = &.{};
        return columns;
    }

    pub fn takeClaimedSums(self: *InteractionTrace) []QM31 {
        const claimed_sums = self.claimed_sums;
        self.claimed_sums = &.{};
        return claimed_sums;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    topology: feed_topology.Loaded,
    fixed: *const fixed_tables.Bundle,
    relations: *const relation_bundle.Bundle,
    base: *const base_trace.BaseTrace,
    lookup_z: QM31,
    lookup_alpha: QM31,
    pedersen: ?*const pedersen_table.Table,
    executor: ?interaction_executor.Executor,
    recorder: ?*prover.stage_profile.Recorder,
) !InteractionTrace {
    const alpha_powers = deriveAlphaPowers(lookup_alpha);
    var collector = try Collector.init(
        allocator,
        &base.geometry,
        executor,
        recorder,
    );
    defer collector.deinit();

    for (base.execution.producers) |producer| {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            producer.label,
            producer.label,
        );
        defer stage.end();
        const component = topology.find(producer.label) orelse
            return error.MissingInteractionTopology;
        var compiled = try interaction_topology.compile(
            allocator,
            component,
            producer.lookup_words,
            producer.row_count,
        );
        defer compiled.deinit();
        const source = (try interaction_trace.SourceView.lookupWords(
            try interaction_trace.LookupColumns.init(
                producer.lookup_words,
                producer.row_count,
            ),
            producer.active_rows,
        )).withResidency(producer.lookupResidency());
        try collector.capture(
            producer.label,
            compiled.descriptors,
            source,
            lookup_z,
            &alpha_powers,
        );
    }

    var multiplicities = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "interaction_fixed_multiplicities",
            "Fixed-table multiplicities",
        );
        defer stage.end();
        break :blk try fixed_trace.populateLiveTopology(
            allocator,
            input,
            topology,
            base.execution.producers,
            fixed,
        );
    };
    defer multiplicities.deinit();
    for (fixed.entries) |entry| {
        if (collector.componentIndex(entry.component) == null) continue;
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            entry.component,
            entry.component,
        );
        defer stage.end();
        const relation = relations.find(entry.component) orelse
            return error.MissingRelationTemplate;
        const trace = componentTrace(relation.traces) orelse
            return error.MissingRelationTrace;
        if (std.mem.eql(u8, entry.component, "verify_bitwise_xor_12")) {
            var columns = try implicit.fixedMultiplicities(
                allocator,
                entry,
                &multiplicities,
            );
            defer columns.deinit();
            const source = try columns.xor12View();
            try source.validateDeclaration(trace.layout, trace.layout_arg);
            try collector.capture(
                entry.component,
                trace.descriptors,
                source,
                lookup_z,
                &alpha_powers,
            );
        } else {
            var lookup = fixed_lookup.Source{
                .entry = entry,
                .tables = &multiplicities,
                .pedersen = pedersen,
            };
            const source = try interaction_trace.SourceView.lookupWords(
                try lookup.lookupColumns(),
                entry.row_count,
            );
            try source.validateDeclaration(trace.layout, trace.layout_arg);
            try collector.capture(
                entry.component,
                trace.descriptors,
                source,
                lookup_z,
                &alpha_powers,
            );
        }
    }

    var counts = blk: {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "interaction_memory_multiplicities",
            "Memory multiplicities",
        );
        defer stage.end();
        break :blk try cpu_memory.collectTopology(
            allocator,
            input,
            topology,
            base.execution.producers,
        );
    };
    defer counts.deinit();
    try captureMemoryAddress(
        allocator,
        input,
        &counts,
        relations,
        &collector,
        lookup_z,
        &alpha_powers,
        recorder,
    );
    try captureMemoryBig(
        allocator,
        input,
        &counts,
        relations,
        &collector,
        lookup_z,
        &alpha_powers,
        recorder,
    );
    try captureMemorySmall(
        allocator,
        input,
        &counts,
        relations,
        &collector,
        lookup_z,
        &alpha_powers,
        recorder,
    );
    return collector.finish();
}

fn captureMemoryAddress(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory.Counts,
    relations: *const relation_bundle.Bundle,
    collector: *Collector,
    lookup_z: QM31,
    alpha_powers: []const QM31,
    recorder: ?*prover.stage_profile.Recorder,
) !void {
    const label = "memory_address_to_id";
    if (collector.componentIndex(label) == null) return;
    var stage = try prover.stage_profile.StageScope.begin(recorder, label, label);
    defer stage.end();
    var columns = try implicit.memoryAddress(allocator, input, counts);
    defer columns.deinit();
    const trace = componentTrace((relations.find(label) orelse
        return error.MissingRelationTemplate).traces) orelse
        return error.MissingRelationTrace;
    const source = try columns.addressView();
    try source.validateDeclaration(trace.layout, trace.layout_arg);
    try collector.capture(label, trace.descriptors, source, lookup_z, alpha_powers);
}

fn captureMemoryBig(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory.Counts,
    relations: *const relation_bundle.Bundle,
    collector: *Collector,
    lookup_z: QM31,
    alpha_powers: []const QM31,
    recorder: ?*prover.stage_profile.Recorder,
) !void {
    const relation = relations.find("memory_id_to_big") orelse
        return error.MissingRelationTemplate;
    const trace = findTrace(relation.traces, .each_memory_big) orelse
        return error.MissingRelationTrace;
    for (collector.geometry.components) |component| {
        if (!std.mem.eql(u8, component.name, "memory_id_to_big")) continue;
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            component.name,
            component.name,
        );
        defer stage.end();
        const index: usize = component.instance;
        var columns = try implicit.memoryBig(allocator, input, counts, index);
        defer columns.deinit();
        const offset = std.math.mul(usize, index, memory_tables.max_big_rows) catch
            return error.AllocationSizeOverflow;
        const source = try columns.bigView(@intCast(offset));
        try source.validateDeclaration(trace.layout, trace.layout_arg);
        try collector.captureIdentity(
            component.name,
            component.instance,
            trace.descriptors,
            source,
            lookup_z,
            alpha_powers,
        );
    }
}

fn captureMemorySmall(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory.Counts,
    relations: *const relation_bundle.Bundle,
    collector: *Collector,
    lookup_z: QM31,
    alpha_powers: []const QM31,
    recorder: ?*prover.stage_profile.Recorder,
) !void {
    const label = "memory_id_to_small";
    if (collector.componentIndex(label) == null) return;
    var stage = try prover.stage_profile.StageScope.begin(recorder, label, label);
    defer stage.end();
    const relation = relations.find("memory_id_to_big") orelse
        return error.MissingRelationTemplate;
    const trace = findTrace(relation.traces, .memory_small) orelse
        return error.MissingRelationTrace;
    var columns = try implicit.memorySmall(allocator, input, counts);
    defer columns.deinit();
    const source = try columns.smallView();
    try source.validateDeclaration(trace.layout, trace.layout_arg);
    try collector.capture(label, trace.descriptors, source, lookup_z, alpha_powers);
}

const ComponentColumns = struct {
    columns: []ColumnEvaluation,
    claimed_sum: QM31,
};

const Collector = struct {
    allocator: std.mem.Allocator,
    geometry: *const claim_generator.OwnedClaimGeometry,
    components: []?ComponentColumns,
    executor: ?interaction_executor.Executor,
    recorder: ?*prover.stage_profile.Recorder,

    fn init(
        allocator: std.mem.Allocator,
        geometry: *const claim_generator.OwnedClaimGeometry,
        executor: ?interaction_executor.Executor,
        recorder: ?*prover.stage_profile.Recorder,
    ) !Collector {
        const components = try allocator.alloc(?ComponentColumns, geometry.components.len);
        @memset(components, null);
        return .{
            .allocator = allocator,
            .geometry = geometry,
            .components = components,
            .executor = executor,
            .recorder = recorder,
        };
    }

    fn deinit(self: *Collector) void {
        for (self.components) |maybe_component| {
            if (maybe_component) |component|
                deinitColumns(self.allocator, component.columns);
        }
        self.allocator.free(self.components);
        self.* = undefined;
    }

    fn componentIndex(self: Collector, label: []const u8) ?usize {
        for (self.geometry.components, 0..) |component, index| {
            if (component.instance == 0 and std.mem.eql(u8, component.name, label))
                return index;
        }
        return null;
    }

    fn componentIdentityIndex(
        self: Collector,
        name: []const u8,
        instance: u32,
    ) ?usize {
        for (self.geometry.components, 0..) |component, index| {
            if (component.instance == instance and std.mem.eql(u8, component.name, name))
                return index;
        }
        return null;
    }

    fn capture(
        self: *Collector,
        label: []const u8,
        descriptors: []const u32,
        source: interaction_trace.SourceView,
        lookup_z: QM31,
        alpha_powers: []const QM31,
    ) !void {
        const component_index = self.componentIndex(label) orelse
            return error.UnknownInteractionComponent;
        try self.captureAt(
            component_index,
            descriptors,
            source,
            lookup_z,
            alpha_powers,
        );
    }

    fn captureIdentity(
        self: *Collector,
        name: []const u8,
        instance: u32,
        descriptors: []const u32,
        source: interaction_trace.SourceView,
        lookup_z: QM31,
        alpha_powers: []const QM31,
    ) !void {
        const component_index = self.componentIdentityIndex(name, instance) orelse
            return error.UnknownInteractionComponent;
        try self.captureAt(
            component_index,
            descriptors,
            source,
            lookup_z,
            alpha_powers,
        );
    }

    fn captureAt(
        self: *Collector,
        component_index: usize,
        descriptors: []const u32,
        source: interaction_trace.SourceView,
        lookup_z: QM31,
        alpha_powers: []const QM31,
    ) !void {
        if (self.components[component_index] != null)
            return error.DuplicateInteractionComponent;
        const component = self.geometry.components[component_index];
        const log_size = switch (component.log_size) {
            .known => |value| value,
            .deferred => return error.InvalidInteractionGeometry,
        };
        const row_count = @as(usize, 1) << @intCast(log_size);
        if (source.rows() != row_count) return error.InvalidInteractionGeometry;

        const allocated = try allocateCoordinateColumns(
            self.allocator,
            recorded_interaction.columnCount(descriptors) * 4,
            row_count,
            log_size,
        );
        errdefer deinitColumns(self.allocator, allocated.columns);

        const claimed_sum = blk: {
            var stage = try prover.stage_profile.StageScope.begin(
                self.recorder,
                "interaction_fraction_materialize",
                "Interaction fraction materialization",
            );
            defer stage.end();
            // Default path, and the configuration both products ship: the
            // relation evaluator writes the committed base-field coordinate
            // planes directly, so no secure column-major intermediate is ever
            // materialized (campaign 1 increment 2).
            const executor = self.executor orelse break :blk try recorded_interaction.materializeCoordinates(
                self.allocator,
                descriptors,
                source,
                lookup_z,
                alpha_powers,
                allocated.planes,
            );
            // Opt-in backend executor. Its ABI returns a secure column-major
            // trace, so it is lowered into the same pre-allocated planes rather
            // than into a second column allocation. `lowerLastColumn` is the
            // generic secure-to-four-plane primitive, applied per column.
            var materialized = try executor.execute(self.allocator, .{
                .descriptors = descriptors,
                .source = source,
                .z = lookup_z,
                .alpha_powers = alpha_powers,
            });
            defer materialized.deinit();
            if (materialized.row_count != row_count or
                materialized.column_count * 4 != allocated.planes.len)
                return error.InvalidInteractionGeometry;
            for (0..materialized.column_count) |column| {
                interaction_trace.lowerLastColumn(
                    allocated.planes[column * 4 ..][0..4],
                    materialized.column(column),
                );
            }
            break :blk materialized.claimed_sum;
        };
        self.allocator.free(allocated.planes);
        self.components[component_index] = .{
            .columns = allocated.columns,
            .claimed_sum = claimed_sum,
        };
    }

    fn finish(self: *Collector) !InteractionTrace {
        var total_columns: usize = 0;
        var global_sum = QM31.zero();
        for (self.components) |maybe_component| {
            const component = maybe_component orelse
                return error.MissingInteractionComponent;
            total_columns = std.math.add(
                usize,
                total_columns,
                component.columns.len,
            ) catch return error.AllocationSizeOverflow;
            global_sum = global_sum.add(component.claimed_sum);
        }
        const columns = try self.allocator.alloc(ColumnEvaluation, total_columns);
        errdefer self.allocator.free(columns);
        const claimed_sums = try self.allocator.alloc(QM31, self.components.len);
        errdefer self.allocator.free(claimed_sums);
        var cursor: usize = 0;
        for (self.components, 0..) |*maybe_component, index| {
            const component = maybe_component.*.?;
            @memcpy(columns[cursor..][0..component.columns.len], component.columns);
            cursor += component.columns.len;
            claimed_sums[index] = component.claimed_sum;
            self.allocator.free(component.columns);
            maybe_component.* = null;
        }
        return .{
            .allocator = self.allocator,
            .columns = columns,
            .claimed_sums = claimed_sums,
            .component_sum = global_sum,
        };
    }
};

const AllocatedColumns = struct {
    columns: []ColumnEvaluation,
    /// Borrowed writable views of `columns`, in the order the relation
    /// evaluator emits them. Freed once materialization returns.
    planes: [][]M31,
};

/// Allocates the committed coordinate columns the relation evaluator writes
/// into directly.
///
/// The evaluator covers every destination row of every plane, so the
/// allocation is deliberately left uninitialized: zero-filling here would be a
/// second full pass over the interaction trace that nothing can observe.
fn allocateCoordinateColumns(
    allocator: std.mem.Allocator,
    column_count: usize,
    row_count: usize,
    log_size: u32,
) !AllocatedColumns {
    const columns = try allocator.alloc(ColumnEvaluation, column_count);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    const planes = try allocator.alloc([]M31, column_count);
    errdefer allocator.free(planes);
    while (initialized < column_count) : (initialized += 1) {
        const values = try allocator.alloc(M31, row_count);
        columns[initialized] = .{ .log_size = @intCast(log_size), .values = values };
        planes[initialized] = values;
    }
    return .{ .columns = columns, .planes = planes };
}

fn deriveAlphaPowers(alpha: QM31) [lookup_power_count]QM31 {
    var result: [lookup_power_count]QM31 = undefined;
    var power = QM31.one();
    for (&result) |*value| {
        value.* = power;
        power = power.mul(alpha);
    }
    return result;
}

fn componentTrace(
    traces: []const relation_bundle.Trace,
) ?relation_bundle.Trace {
    return findTrace(traces, .component);
}

fn findTrace(
    traces: []const relation_bundle.Trace,
    part: relation_bundle.TracePart,
) ?relation_bundle.Trace {
    for (traces) |trace| if (trace.part == part) return trace;
    return null;
}

fn deinitColumns(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
) void {
    if (columns.len == 0) return;
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}
