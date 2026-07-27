//! CPU oracle runner for the dependency-ordered recorded witness graph.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const proof_plan = @import("../proof_plan.zig");
const compact_inputs = @import("../witness/compact_inputs.zig");
const component_executor = @import("../witness/component_executor.zig");
const deductions = @import("../witness/deductions/mod.zig");
const direct_inputs = @import("../witness/direct_inputs.zig");
const gathered_inputs = @import("../witness/gathered_inputs.zig");
const producer_output = @import("../witness/producer_output.zig");
const witness_bundle = @import("../witness/bundle.zig");
const base_execution = @import("base_execution.zig");
const checkpoint = @import("checkpoint.zig");

pub const Match = struct {
    ordinal: u32,
    label: []const u8,
    row_count: u64,
    column_count: u32,
};

pub const Mismatch = base_execution.Mismatch;

pub const Report = struct {
    allocator: std.mem.Allocator,
    matches: []Match,
    skipped_components: usize,
    mismatch: ?Mismatch,

    pub fn deinit(self: *Report) void {
        self.allocator.free(self.matches);
        self.* = undefined;
    }
};

/// Flattened subcomponent inputs retained from one exact witness execution.
///
/// `row_count` is the padded trace extent. `active_rows` is the exact extent
/// fed to downstream claim generators; compact consumers deliberately feed
/// their padded rows, matching Stwo-Cairo's ClaimGenerator implementations.
pub const ProducerOutput = producer_output.ProducerOutput;

pub const Execution = struct {
    allocator: std.mem.Allocator,
    matches: []Match,
    skipped_components: usize,
    mismatch: ?Mismatch,
    producers: []ProducerOutput,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.matches);
        self.deinitProducers();
        self.* = undefined;
    }

    fn deinitProducers(self: *Execution) void {
        for (self.producers) |producer| producer.deinit(self.allocator);
        self.allocator.free(self.producers);
    }
};

pub const Error = error{
    InvalidReceiptGeometry,
    MissingWitnessProgram,
};

/// Scoped access to one exact generated base component.
///
/// The execution remains owned by the witness runner and is valid only for the
/// duration of `visit`. Consumers that retain values must copy or transform
/// them before returning.
pub const ComponentObserver = struct {
    context: *anyopaque,
    visit: *const fn (
        context: *anyopaque,
        expected: checkpoint.Component,
        execution: *const component_executor.Execution,
    ) anyerror!void,
};

const ComponentResult = struct {
    mismatch: ?Mismatch,
    producer: ?ProducerOutput,
};

/// Executes every directly seeded or producer-gathered recorded component.
/// Receipt order is authoritative and is required to respect the source DAG.
pub fn compare(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    bundle: *const witness_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Report {
    var execution = try execute(allocator, input, bundle, expected_components);
    defer execution.deinitProducers();
    return .{
        .allocator = allocator,
        .matches = execution.matches,
        .skipped_components = execution.skipped_components,
        .mismatch = execution.mismatch,
    };
}

/// Executes the recorded graph once and retains its flattened feed outputs.
/// The caller owns the returned execution and must call `deinit`.
pub fn execute(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    bundle: *const witness_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Execution {
    return executeObserved(
        allocator,
        input,
        bundle,
        expected_components,
        null,
    );
}

/// Executes the same authenticated witness graph while exposing each exact
/// generated base component to a scoped consumer.
pub fn executeObserved(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    bundle: *const witness_bundle.Bundle,
    expected_components: []const checkpoint.Component,
    observer: ?ComponentObserver,
) !Execution {
    var matches = std.ArrayList(Match).empty;
    errdefer matches.deinit(allocator);
    var producers = std.ArrayList(ProducerOutput).empty;
    errdefer {
        for (producers.items) |producer| producer.deinit(allocator);
        producers.deinit(allocator);
    }
    var skipped_components: usize = 0;

    for (expected_components) |expected| {
        const entry = bundle.find(expected.label) orelse {
            skipped_components += 1;
            continue;
        };
        if (!deductions.supportsProgram(entry.program)) {
            skipped_components += 1;
            continue;
        }
        const result = if (proof_plan.compactGeometry(expected.label)) |geometry| blk: {
            var active_edges = std.ArrayList(proof_plan.ProducerEdge).empty;
            defer active_edges.deinit(allocator);
            var gathered_producers = std.ArrayList(gathered_inputs.Producer).empty;
            defer gathered_producers.deinit(allocator);
            for (geometry.edges) |edge| {
                const source = findProducer(producers.items, edge.producer) orelse continue;
                try active_edges.append(allocator, edge);
                try gathered_producers.append(allocator, .{
                    .label = source.label,
                    .row_count = source.row_count,
                    .active_rows = source.active_rows,
                    .words_per_row = source.words_per_row,
                    .words = source.words,
                });
            }
            if (active_edges.items.len == 0) {
                skipped_components += 1;
                break :blk null;
            }
            var compact = try compact_inputs.materialize(
                allocator,
                geometry,
                active_edges.items,
                gathered_producers.items,
                try componentRows(expected),
            );
            defer compact.deinit();
            break :blk try executeComponent(
                allocator,
                input,
                entry.program,
                compact,
                expected,
                observer,
            );
        } else if (try direct_inputs.resolve(input, expected.label)) |direct| try executeComponent(
            allocator,
            input,
            entry.program,
            direct,
            expected,
            observer,
        ) else if (proof_plan.gatheredProducerEdges(expected.label)) |edges| blk: {
            const gathered_producers = try allocator.alloc(gathered_inputs.Producer, edges.len);
            defer allocator.free(gathered_producers);
            for (edges, gathered_producers) |edge, *producer| {
                const source = findProducer(producers.items, edge.producer) orelse {
                    skipped_components += 1;
                    break :blk null;
                };
                producer.* = .{
                    .label = source.label,
                    .row_count = source.row_count,
                    .active_rows = source.active_rows,
                    .words_per_row = source.words_per_row,
                    .words = source.words,
                };
            }
            const rows = try componentRows(expected);
            var gathered = try gathered_inputs.materialize(
                allocator,
                edges,
                gathered_producers,
                rows,
            );
            defer gathered.deinit();
            break :blk try executeComponent(
                allocator,
                input,
                entry.program,
                gathered,
                expected,
                observer,
            );
        } else blk: {
            skipped_components += 1;
            break :blk null;
        };
        const component = result orelse continue;
        if (component.mismatch) |mismatch| {
            if (component.producer) |producer| producer.deinit(allocator);
            return .{
                .allocator = allocator,
                .matches = try matches.toOwnedSlice(allocator),
                .skipped_components = skipped_components,
                .mismatch = mismatch,
                .producers = try producers.toOwnedSlice(allocator),
            };
        }
        if (component.producer) |producer| try producers.append(allocator, producer);
        try matches.append(allocator, .{
            .ordinal = expected.ordinal,
            .label = expected.label,
            .row_count = expected.columns[0].row_count,
            .column_count = @intCast(expected.columns.len),
        });
    }
    return .{
        .allocator = allocator,
        .matches = try matches.toOwnedSlice(allocator),
        .skipped_components = skipped_components,
        .mismatch = null,
        .producers = try producers.toOwnedSlice(allocator),
    };
}

fn executeComponent(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: @import("../witness/program.zig").Program,
    source: anytype,
    expected: checkpoint.Component,
    observer: ?ComponentObserver,
) !ComponentResult {
    var execution = try component_executor.execute(
        allocator,
        input,
        witness_program,
        null,
        source,
        try base_execution.layout(expected),
        null,
        null,
    );
    defer execution.deinit();
    const mismatch = try base_execution.compare(expected, execution);
    if (mismatch == null) {
        if (observer) |active| {
            try active.visit(active.context, expected, &execution);
        }
    }
    const producer = if (witness_program.n_sub_words == 0 and
        witness_program.n_lookup_words == 0)
        null
    else blk: {
        const sub_words = execution.takeSubWords();
        errdefer allocator.free(sub_words);
        const lookup_words = execution.takeLookupWords();
        break :blk ProducerOutput{
            .label = expected.label,
            .row_count = @intCast(execution.row_count),
            .active_rows = @intCast(try source.realRowCount(execution.row_count)),
            .words_per_row = witness_program.n_sub_words,
            .words = sub_words,
            .lookup_words_per_row = witness_program.n_lookup_words,
            .lookup_words = lookup_words,
        };
    };
    return .{ .mismatch = mismatch, .producer = producer };
}

fn componentRows(component: checkpoint.Component) Error!u32 {
    if (component.columns.len == 0) return Error.InvalidReceiptGeometry;
    return std.math.cast(u32, component.columns[0].row_count) orelse
        Error.InvalidReceiptGeometry;
}

fn findProducer(entries: []const ProducerOutput, label: []const u8) ?ProducerOutput {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.label, label)) return entry;
    }
    return null;
}
