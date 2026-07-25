const std = @import("std");
const backend = @import("stwo_backend_contracts");
const arena_plan = backend.arena_plan;
const proof_program = backend.proof_program;
const proof_plan = @import("proof_plan.zig");

pub const BufferRole = enum {
    witness_input,
    retained_witness_input,
    retained_lookup_inputs,
    producer_slab,
    base_trace,
    base_coefficients,
    lookup_inputs,
    multiplicity,
    interaction_trace,
    interaction_coefficients,
    component_scratch,
    witness_shared,
    protocol_persistent,
};

pub const BufferSpec = struct {
    logical_id: u32,
    component_index: ?u32,
    role: BufferRole,
    size_bytes: u64,
    alignment: u32 = 256,
    spill_cost_ns: ?u64 = null,
    recompute_cost_ns: ?u64 = null,
};

pub const ProtocolTicks = struct {
    base_commit: u16,
    interaction_start: u16,
    interaction_commit: u16,
    composition: u16,
    oods: u16,
    quotient: u16,
    fri: u16,
    decommit: u16,
    assemble: u16,
};

pub const Error = error{
    InvalidComponentIndex,
    InvalidProtocolTicks,
    TooManyRanges,
    TickOverflow,
};

pub const Inputs = struct {
    allocator: std.mem.Allocator,
    logical: []arena_plan.LogicalBuffer,
    range_storage: []arena_plan.LiveRange,

    pub fn deinit(self: *Inputs) void {
        self.allocator.free(self.range_storage);
        self.allocator.free(self.logical);
        self.* = undefined;
    }
};

/// DAG-derived liveness for the epoch-local Metal arena. Producer slabs remain
/// live through their last consumer level; coefficients use disjoint protocol
/// ranges so the arena planner can choose retention, spill, or recomputation
/// without inventing dependencies from buffer names.
pub const StagedArenaPlanner = struct {
    const epoch_stride: u16 = 65;
    const witness_epoch: u16 = epoch_stride;

    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    component_ticks: []u16,
    last_consumer_ticks: []u16,
    ticks: ProtocolTicks,

    pub fn init(
        allocator: std.mem.Allocator,
        proof: *const proof_plan.CairoProofPlan,
    ) !StagedArenaPlanner {
        const component_ticks = try allocator.alloc(u16, proof.components.len);
        errdefer allocator.free(component_ticks);
        const last_consumer_ticks = try allocator.alloc(u16, proof.components.len);
        errdefer allocator.free(last_consumer_ticks);
        var witness_tick = witness_epoch;
        for (proof.levels) |level| {
            for (level.component_indices) |component_index| {
                witness_tick = std.math.add(u16, witness_tick, 1) catch return Error.TickOverflow;
                component_ticks[component_index] = witness_tick;
            }
        }
        @memcpy(last_consumer_ticks, component_ticks);
        for (proof.components, 0..) |component, consumer_index| {
            const consumer_tick = component_ticks[consumer_index];
            for (component.producer_edges) |edge| {
                const producer = proof.componentIndex(edge.producer) orelse return Error.InvalidComponentIndex;
                last_consumer_ticks[producer] = @max(last_consumer_ticks[producer], consumer_tick);
            }
            for (component.capacity_feeds) |feed| {
                const producer = proof.componentIndex(feed.producer) orelse return Error.InvalidComponentIndex;
                last_consumer_ticks[producer] = @max(last_consumer_ticks[producer], consumer_tick);
            }
        }
        const ticks = ProtocolTicks{
            .base_commit = 2 * epoch_stride,
            .interaction_start = 3 * epoch_stride + 1,
            .interaction_commit = 4 * epoch_stride,
            .composition = 5 * epoch_stride,
            .oods = 7 * epoch_stride,
            .quotient = 8 * epoch_stride,
            .fri = 9 * epoch_stride,
            .decommit = 10 * epoch_stride,
            .assemble = 11 * epoch_stride,
        };
        if (ticks.assemble >= arena_plan.max_ticks) return Error.InvalidProtocolTicks;
        return .{
            .allocator = allocator,
            .proof = proof,
            .component_ticks = component_ticks,
            .last_consumer_ticks = last_consumer_ticks,
            .ticks = ticks,
        };
    }

    pub fn deinit(self: *StagedArenaPlanner) void {
        self.allocator.free(self.last_consumer_ticks);
        self.allocator.free(self.component_ticks);
        self.* = undefined;
    }

    /// Maps the planner's exact live-range endpoints onto the coarse,
    /// backend-neutral proof-program lifecycle.
    pub fn programStageForTick(self: StagedArenaPlanner, tick: u16) Error!proof_program.Stage {
        if (tick == 0) return .ingress;
        if (tick < self.ticks.base_commit) return .trace_generation;
        if (tick < self.ticks.composition) return .trace_commit;
        if (tick == self.ticks.composition) return .constraint_evaluation;
        if (tick == self.ticks.oods) return .oods;
        if (tick == self.ticks.quotient) return .quotient;
        if (tick == self.ticks.fri) return .fri_commit;
        if (tick == self.ticks.decommit) return .decommit;
        if (tick == self.ticks.assemble) return .proof_assembly;
        return Error.InvalidProtocolTicks;
    }

    pub fn derive(self: StagedArenaPlanner, allocator: std.mem.Allocator, specs: []const BufferSpec) !Inputs {
        const logical = try allocator.alloc(arena_plan.LogicalBuffer, specs.len);
        errdefer allocator.free(logical);
        var range_count: usize = 0;
        for (specs) |spec| range_count += roleRangeCount(spec.role);
        const ranges = try allocator.alloc(arena_plan.LiveRange, range_count);
        errdefer allocator.free(ranges);
        var cursor: usize = 0;
        for (specs, logical) |spec, *buffer| {
            const count = roleRangeCount(spec.role);
            const destination = ranges[cursor .. cursor + count];
            try self.writeRanges(spec, destination);
            buffer.* = .{
                .id = spec.logical_id,
                .size_bytes = spec.size_bytes,
                .alignment = spec.alignment,
                .live_ranges = destination,
                .spill_cost_ns = spec.spill_cost_ns,
                .recompute_cost_ns = spec.recompute_cost_ns,
            };
            cursor += count;
        }
        return .{ .allocator = allocator, .logical = logical, .range_storage = ranges };
    }

    pub fn rangesFor(
        self: StagedArenaPlanner,
        role: BufferRole,
        component_index: ?u32,
        output: []arena_plan.LiveRange,
    ) ![]const arena_plan.LiveRange {
        const count = roleRangeCount(role);
        if (output.len < count) return Error.TooManyRanges;
        try self.writeRanges(.{
            .logical_id = 0,
            .component_index = component_index,
            .role = role,
            .size_bytes = 1,
        }, output[0..count]);
        return output[0..count];
    }

    fn writeRanges(self: StagedArenaPlanner, spec: BufferSpec, output: []arena_plan.LiveRange) !void {
        const component_tick = if (spec.component_index) |index| blk: {
            if (index >= self.proof.components.len) return Error.InvalidComponentIndex;
            break :blk self.component_ticks[index];
        } else 0;
        const interaction_tick = if (spec.component_index) |index|
            try self.interactionTickForWitnessTick(self.component_ticks[index])
        else
            self.ticks.interaction_start;
        switch (spec.role) {
            .witness_input => {
                output[0] = .{ .first = witness_epoch, .last = component_tick };
                output[1] = .{ .first = interaction_tick, .last = interaction_tick };
            },
            .retained_witness_input, .retained_lookup_inputs => {
                if (spec.component_index == null) return Error.InvalidComponentIndex;
                output[0] = .{ .first = component_tick, .last = interaction_tick };
            },
            .producer_slab => {
                const component_index = spec.component_index orelse return Error.InvalidComponentIndex;
                output[0] = .{
                    .first = component_tick,
                    .last = self.last_consumer_ticks[component_index],
                };
                output[1] = .{
                    .first = interaction_tick,
                    .last = try self.interactionTickForWitnessTick(self.last_consumer_ticks[component_index]),
                };
            },
            .base_trace => output[0] = .{ .first = component_tick, .last = component_tick },
            .base_coefficients => {
                output[0] = .{ .first = component_tick, .last = self.ticks.base_commit };
                output[1] = .{ .first = self.ticks.composition, .last = self.ticks.quotient };
                output[2] = .{ .first = self.ticks.decommit, .last = self.ticks.decommit };
            },
            .lookup_inputs => output[0] = .{ .first = interaction_tick, .last = interaction_tick },
            .multiplicity => output[0] = .{ .first = 0, .last = self.ticks.interaction_commit },
            .interaction_trace => output[0] = .{ .first = interaction_tick, .last = interaction_tick },
            .interaction_coefficients => {
                output[0] = .{ .first = interaction_tick, .last = self.ticks.interaction_commit };
                output[1] = .{ .first = self.ticks.composition, .last = self.ticks.quotient };
                output[2] = .{ .first = self.ticks.decommit, .last = self.ticks.decommit };
            },
            .component_scratch => {
                output[0] = .{ .first = component_tick, .last = component_tick };
                output[1] = .{ .first = interaction_tick, .last = interaction_tick };
            },
            .witness_shared => {
                const interaction_last = std.math.add(
                    u16,
                    self.ticks.interaction_start,
                    std.math.cast(u16, self.proof.components.len - 1) orelse return Error.TickOverflow,
                ) catch return Error.TickOverflow;
                output[0] = .{ .first = witness_epoch, .last = self.ticks.base_commit - 1 };
                output[1] = .{ .first = self.ticks.interaction_start, .last = interaction_last };
            },
            .protocol_persistent => output[0] = .{ .first = 0, .last = self.ticks.assemble },
        }
    }

    fn interactionTickForWitnessTick(self: StagedArenaPlanner, witness_tick: u16) !u16 {
        if (witness_tick <= witness_epoch) return Error.InvalidComponentIndex;
        const execution_ordinal = witness_tick - witness_epoch - 1;
        if (execution_ordinal >= self.proof.components.len) return Error.InvalidComponentIndex;
        return std.math.add(u16, self.ticks.interaction_start, execution_ordinal) catch return Error.TickOverflow;
    }
};

fn roleRangeCount(role: BufferRole) usize {
    return switch (role) {
        .base_coefficients, .interaction_coefficients => 3,
        .witness_input, .producer_slab, .component_scratch, .witness_shared => 2,
        else => 1,
    };
}

test "staged arena liveness retains producer through last dependent level" {
    const rows = [_]proof_plan.TracePart{.{ .id = .main, .rows = .{ .real_rows = 16, .padded_rows = 16 } }};
    const edge = [_]proof_plan.ProducerEdge{.{
        .producer = "producer",
        .word_base = 0,
        .words_per_instance = 1,
        .instances = 1,
    }};
    const components = [_]proof_plan.Component{
        .{
            .name = "producer",
            .canonical_ordinal = 0,
            .writer = .recorded_aot,
            .trace_parts = &rows,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
        .{
            .name = "consumer",
            .canonical_ordinal = 1,
            .writer = .recorded_aot,
            .trace_parts = &rows,
            .producer_edges = &edge,
            .capacity_feeds = &.{},
        },
    };
    var proof = try proof_plan.CairoProofPlan.init(std.testing.allocator, &components);
    defer proof.deinit();
    var planner = try StagedArenaPlanner.init(std.testing.allocator, &proof);
    defer planner.deinit();
    const specs = [_]BufferSpec{
        .{ .logical_id = 1, .component_index = 0, .role = .producer_slab, .size_bytes = 64 },
        .{ .logical_id = 2, .component_index = 0, .role = .base_coefficients, .size_bytes = 64, .recompute_cost_ns = 1 },
    };
    var inputs = try planner.derive(std.testing.allocator, &specs);
    defer inputs.deinit();
    try std.testing.expectEqual(@as(usize, 2), inputs.logical[0].live_ranges.len);
    try std.testing.expectEqual(arena_plan.LiveRange{ .first = 66, .last = 67 }, inputs.logical[0].live_ranges[0]);
    try std.testing.expectEqual(arena_plan.LiveRange{ .first = 196, .last = 197 }, inputs.logical[0].live_ranges[1]);
    try std.testing.expectEqual(@as(usize, 3), inputs.logical[1].live_ranges.len);
    try std.testing.expectEqual(planner.ticks.base_commit, inputs.logical[1].live_ranges[0].last);
}

test "interaction liveness follows topological execution rather than canonical index" {
    const rows = [_]proof_plan.TracePart{.{ .id = .main, .rows = .{ .real_rows = 16, .padded_rows = 16 } }};
    const edge = [_]proof_plan.ProducerEdge{.{
        .producer = "producer",
        .word_base = 0,
        .words_per_instance = 1,
        .instances = 1,
    }};
    const components = [_]proof_plan.Component{
        .{
            .name = "consumer",
            .canonical_ordinal = 0,
            .writer = .recorded_aot,
            .trace_parts = &rows,
            .producer_edges = &edge,
            .capacity_feeds = &.{},
        },
        .{
            .name = "producer",
            .canonical_ordinal = 1,
            .writer = .recorded_aot,
            .trace_parts = &rows,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
    };
    var proof = try proof_plan.CairoProofPlan.init(std.testing.allocator, &components);
    defer proof.deinit();
    var planner = try StagedArenaPlanner.init(std.testing.allocator, &proof);
    defer planner.deinit();
    const specs = [_]BufferSpec{
        .{ .logical_id = 1, .component_index = 1, .role = .producer_slab, .size_bytes = 64 },
        .{ .logical_id = 2, .component_index = 0, .role = .witness_input, .size_bytes = 64 },
    };
    var inputs = try planner.derive(std.testing.allocator, &specs);
    defer inputs.deinit();
    try std.testing.expectEqual(arena_plan.LiveRange{ .first = 196, .last = 197 }, inputs.logical[0].live_ranges[1]);
    try std.testing.expectEqual(arena_plan.LiveRange{ .first = 197, .last = 197 }, inputs.logical[1].live_ranges[1]);
}

test "staged arena liveness retains selected witness and lookup inputs through interaction" {
    const rows = [_]proof_plan.TracePart{.{ .id = .main, .rows = .{ .real_rows = 16, .padded_rows = 16 } }};
    const components = [_]proof_plan.Component{.{
        .name = "partial_ec_mul_generic",
        .canonical_ordinal = 0,
        .writer = .recorded_aot,
        .trace_parts = &rows,
        .producer_edges = &.{},
        .capacity_feeds = &.{},
    }};
    var proof = try proof_plan.CairoProofPlan.init(std.testing.allocator, &components);
    defer proof.deinit();
    var planner = try StagedArenaPlanner.init(std.testing.allocator, &proof);
    defer planner.deinit();
    const specs = [_]BufferSpec{
        .{
            .logical_id = 1,
            .component_index = 0,
            .role = .retained_witness_input,
            .size_bytes = 64,
        },
        .{
            .logical_id = 2,
            .component_index = 0,
            .role = .retained_lookup_inputs,
            .size_bytes = 128,
        },
        .{
            .logical_id = 3,
            .component_index = 0,
            .role = .lookup_inputs,
            .size_bytes = 128,
        },
    };
    var inputs = try planner.derive(std.testing.allocator, &specs);
    defer inputs.deinit();
    try std.testing.expectEqual(@as(usize, 1), inputs.logical[0].live_ranges.len);
    try std.testing.expectEqual(
        arena_plan.LiveRange{ .first = 66, .last = 196 },
        inputs.logical[0].live_ranges[0],
    );
    try std.testing.expectEqual(@as(usize, 1), inputs.logical[1].live_ranges.len);
    try std.testing.expectEqual(
        arena_plan.LiveRange{ .first = 66, .last = 196 },
        inputs.logical[1].live_ranges[0],
    );
    try std.testing.expectEqual(arena_plan.LiveRange{ .first = 196, .last = 196 }, inputs.logical[2].live_ranges[0]);
    var ranges: [1]arena_plan.LiveRange = undefined;
    try std.testing.expectError(
        Error.InvalidComponentIndex,
        planner.rangesFor(.retained_lookup_inputs, null, &ranges),
    );
}
