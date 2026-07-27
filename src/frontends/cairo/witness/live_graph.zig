//! Live, backend-neutral execution of the Cairo witness dependency graph.
//!
//! Component presence starts at the admitted `ProverInput`. Direct roots own
//! their domains, gathered consumers derive theirs from producer cardinality,
//! and compact consumers derive theirs from the actual unique tuple set.
//! Rust checkpoints are deliberately absent from this production boundary.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const claim_generator = @import("../claim_generator.zig");
const proof_plan = @import("../proof_plan.zig");
const compact_inputs = @import("compact_inputs.zig");
const component_executor = @import("component_executor.zig");
const component_layout = @import("component_layout.zig");
const deductions = @import("deductions/mod.zig");
const direct_inputs = @import("direct_inputs.zig");
const gathered_inputs = @import("gathered_inputs.zig");
const producer_output = @import("producer_output.zig");
const witness_bundle = @import("bundle.zig");
const stage_profile = @import("stwo_prover_impl").stage_profile;

pub const Error = error{
    AllocationSizeOverflow,
    ClaimGeometryMismatch,
    IncompleteWitnessGraph,
    MissingProducer,
    UnsupportedWitnessProgram,
};

pub const Component = struct {
    layout: component_layout.ComponentLayout,
    active_rows: u32,
};

pub const ProducerOutput = producer_output.ProducerOutput;

pub const Execution = struct {
    allocator: std.mem.Allocator,
    components: []Component,
    producers: []ProducerOutput,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.components);
        for (self.producers) |producer| producer.deinit(self.allocator);
        self.allocator.free(self.producers);
        self.* = undefined;
    }
};

/// Scoped access to one materialized generated component. The execution storage
/// is valid only for the duration of `visit`.
pub const ComponentObserver = struct {
    context: *anyopaque,
    visit: *const fn (
        context: *anyopaque,
        layout: component_layout.ComponentLayout,
        execution: *const component_executor.Execution,
    ) anyerror!void,
};

pub fn execute(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    programs: *const witness_bundle.Bundle,
    geometry: *claim_generator.OwnedClaimGeometry,
    observer: ?ComponentObserver,
    recorder: ?*stage_profile.Recorder,
) !Execution {
    var components = std.ArrayList(Component).empty;
    errdefer components.deinit(allocator);
    var producers = std.ArrayList(ProducerOutput).empty;
    errdefer {
        for (producers.items) |producer| producer.deinit(allocator);
        producers.deinit(allocator);
    }
    var feeds = std.ArrayList(claim_generator.FeedGeometry).empty;
    defer feeds.deinit(allocator);

    for (geometry.components, 0..) |claim_component, ordinal| {
        if (claim_generator.isFixedComponent(claim_component.name)) continue;
        const entry = programs.find(claim_component.name) orelse {
            if (claim_component.log_size == .deferred)
                return Error.IncompleteWitnessGraph;
            continue;
        };
        if (!deductions.supportsProgram(entry.program))
            return Error.UnsupportedWitnessProgram;

        var component_stage = try stage_profile.StageScope.begin(
            recorder,
            claim_component.name,
            claim_component.name,
        );
        defer component_stage.end();
        const result = if (proof_plan.compactGeometry(claim_component.name)) |compact_geometry| blk: {
            var active_edges = std.ArrayList(proof_plan.ProducerEdge).empty;
            defer active_edges.deinit(allocator);
            var sources = std.ArrayList(gathered_inputs.Producer).empty;
            defer sources.deinit(allocator);
            for (compact_geometry.edges) |edge| {
                const producer = findProducer(producers.items, edge.producer) orelse
                    continue;
                try active_edges.append(allocator, edge);
                try sources.append(allocator, gatheredProducer(producer));
            }
            if (active_edges.items.len == 0) return Error.MissingProducer;
            var compact = try compact_inputs.materializeDerived(
                allocator,
                compact_geometry,
                active_edges.items,
                sources.items,
            );
            defer compact.deinit();
            break :blk try executeComponent(
                allocator,
                input,
                entry.program,
                compact,
                claim_component,
                @intCast(ordinal),
                observer,
            );
        } else if (try direct_inputs.resolve(input, claim_component.name)) |direct| blk: {
            break :blk try executeComponent(
                allocator,
                input,
                entry.program,
                direct,
                claim_component,
                @intCast(ordinal),
                observer,
            );
        } else if (proof_plan.gatheredProducerEdges(claim_component.name)) |edges| blk: {
            const sources = try allocator.alloc(gathered_inputs.Producer, edges.len);
            defer allocator.free(sources);
            for (edges, sources) |edge, *source| {
                const producer = findProducer(producers.items, edge.producer) orelse
                    return Error.MissingProducer;
                source.* = gatheredProducer(producer);
            }
            var gathered = try gathered_inputs.materializeDerived(
                allocator,
                edges,
                sources,
            );
            defer gathered.deinit();
            break :blk try executeComponent(
                allocator,
                input,
                entry.program,
                gathered,
                claim_component,
                @intCast(ordinal),
                observer,
            );
        } else {
            std.log.err(
                "Cairo live witness component has no input source: {s}",
                .{claim_component.name},
            );
            return Error.IncompleteWitnessGraph;
        };
        errdefer result.producer.deinit(allocator);
        try components.append(allocator, result.component);
        try producers.append(allocator, result.producer);

        if (claim_component.log_size == .deferred) try feeds.append(allocator, .{
            .name = claim_component.name,
            .instance = claim_component.instance,
            .log_size = result.component.layout.logSize(),
        });
    }

    try geometry.resolveFeedGeometry(allocator, feeds.items);
    return .{
        .allocator = allocator,
        .components = try components.toOwnedSlice(allocator),
        .producers = try producers.toOwnedSlice(allocator),
    };
}

const ComponentResult = struct {
    component: Component,
    producer: ProducerOutput,
};

fn executeComponent(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: @import("program.zig").Program,
    source: anytype,
    claim_component: claim_generator.ComponentGeometry,
    ordinal: u32,
    observer: ?ComponentObserver,
) !ComponentResult {
    const padded_rows = std.math.cast(u32, try source.paddedRowCount()) orelse
        return Error.AllocationSizeOverflow;
    const layout = component_layout.ComponentLayout{
        .ordinal = ordinal,
        .label = claim_component.name,
        .row_count = padded_rows,
        .column_count = witness_program.n_cols,
    };
    try validateClaimGeometry(claim_component, layout);

    var execution = try component_executor.execute(
        allocator,
        input,
        witness_program,
        source,
        layout,
    );
    defer execution.deinit();
    if (observer) |active| try active.visit(active.context, layout, &execution);

    const active_rows = std.math.cast(
        u32,
        try source.realRowCount(execution.row_count),
    ) orelse return Error.AllocationSizeOverflow;
    const sub_words = try allocator.dupe(u32, execution.sub_words);
    errdefer allocator.free(sub_words);
    const lookup_words = try transposeLookupWords(
        allocator,
        execution.lookup_words,
        execution.row_count,
        witness_program.n_lookup_words,
    );
    return .{
        .component = .{
            .layout = layout,
            .active_rows = active_rows,
        },
        .producer = .{
            .label = claim_component.name,
            .row_count = padded_rows,
            .active_rows = active_rows,
            .words_per_row = witness_program.n_sub_words,
            .words = sub_words,
            .lookup_words_per_row = witness_program.n_lookup_words,
            .lookup_words = lookup_words,
        },
    };
}

fn validateClaimGeometry(
    claim_component: claim_generator.ComponentGeometry,
    layout: component_layout.ComponentLayout,
) Error!void {
    switch (claim_component.log_size) {
        .known => |expected| if (expected != layout.logSize())
            return Error.ClaimGeometryMismatch,
        .deferred => {},
    }
}

fn gatheredProducer(producer: ProducerOutput) gathered_inputs.Producer {
    return .{
        .label = producer.label,
        .row_count = producer.row_count,
        .active_rows = producer.active_rows,
        .words_per_row = producer.words_per_row,
        .words = producer.words,
    };
}

fn findProducer(entries: []const ProducerOutput, label: []const u8) ?ProducerOutput {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.label, label)) return entry;
    }
    return null;
}

fn transposeLookupWords(
    allocator: std.mem.Allocator,
    row_major: []const u32,
    rows: usize,
    columns: u32,
) ![]u32 {
    const expected = std.math.mul(usize, rows, columns) catch
        return Error.AllocationSizeOverflow;
    if (row_major.len != expected) return Error.IncompleteWitnessGraph;
    const column_major = try allocator.alloc(u32, expected);
    errdefer allocator.free(column_major);
    for (0..rows) |row| {
        for (0..columns) |column| {
            column_major[column * rows + row] =
                row_major[row * @as(usize, columns) + column];
        }
    }
    return column_major;
}
