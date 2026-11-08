//! Backend-neutral arena liveness, coloring, and recovery planning contracts.

const std = @import("std");

pub const max_ticks = 1024;
const TickSet = [max_ticks / 64]u64;

pub const Materialization = enum {
    resident,
    spill,
    recompute,
};

pub const LiveRange = struct {
    first: u16,
    last: u16,
};

/// One device value and the exact schedule ticks at which a kernel consumes it.
/// A tick may be a whole proof phase or a component-local sub-epoch.
pub const LogicalBuffer = struct {
    id: u32,
    size_bytes: u64,
    alignment: u32 = 16 * 1024,
    placement_priority: u8 = 0,
    live_ranges: []const LiveRange,
    spill_cost_ns: ?u64 = null,
    recompute_cost_ns: ?u64 = null,
};

pub const Binding = struct {
    logical_id: u32,
    slot: u32,
    offset_bytes: u64,
    size_bytes: u64,
    materialization: Materialization,
    occupied: TickSet,
};

pub const Slot = struct {
    offset_bytes: u64,
    capacity_bytes: u64,
    alignment: u32,
    occupied: TickSet,
};

pub const ActionKind = enum { produce, restore, recompute, spill, release };

pub const Action = struct {
    tick: u16,
    logical_id: u32,
    kind: ActionKind,
};

pub const Error = error{
    EmptySchedule,
    DuplicateLogicalId,
    UnsortedBindings,
    InvalidAlignment,
    InvalidTick,
    InvalidUseOrder,
    SizeOverflow,
    BudgetExceeded,
    AliasOverlap,
    UnknownBinding,
    BindingOutOfBounds,
    NarrowAddressOverflow,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    bindings: []Binding,
    slots: []Slot,
    actions: []Action,
    action_offsets: []usize,
    total_bytes: u64,
    peak_live_bytes: u64,
    plan_hash: u64,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.slots);
        self.allocator.free(self.actions);
        self.allocator.free(self.action_offsets);
        self.* = undefined;
    }

    pub fn binding(self: Plan, logical_id: u32) Error!Binding {
        var low: usize = 0;
        var high = self.bindings.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const candidate = self.bindings[middle];
            if (candidate.logical_id < logical_id) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if (low < self.bindings.len and self.bindings[low].logical_id == logical_id)
            return self.bindings[low];
        return Error.UnknownBinding;
    }

    pub fn validate(self: Plan, budget_bytes: u64) (std.mem.Allocator.Error || Error)!void {
        if (self.total_bytes > budget_bytes) return Error.BudgetExceeded;
        if (self.bindings.len != self.slots.len) return Error.BindingOutOfBounds;
        if (self.bindings.len > 1) {
            for (self.bindings[1..], 1..) |bound, index| {
                if (self.bindings[index - 1].logical_id >= bound.logical_id)
                    return Error.UnsortedBindings;
            }
        }
        for (self.bindings, 0..) |bound, index| {
            const slot = self.slots[bound.slot];
            if (bound.slot != index or bound.offset_bytes != slot.offset_bytes or
                bound.size_bytes != slot.capacity_bytes or
                bound.offset_bytes + bound.size_bytes > self.total_bytes)
                return Error.BindingOutOfBounds;
        }
        const active = try self.allocator.alloc(Binding, self.bindings.len);
        defer self.allocator.free(active);
        for (0..max_ticks) |tick| {
            var count: usize = 0;
            for (self.bindings) |bound| {
                if (!hasTick(bound.occupied, @intCast(tick))) continue;
                active[count] = bound;
                count += 1;
            }
            std.mem.sortUnstable(Binding, active[0..count], {}, offsetLessThan);
            if (count > 1) {
                for (active[1..count], active[0 .. count - 1]) |current, previous| {
                    if (rangesOverlap(previous, current)) return Error.AliasOverlap;
                }
            }
        }
    }
};

/// Plans the smallest live range allowed by each buffer's recovery policy.
/// Values with no recovery recipe remain resident from first through last use.
/// Recoverable values occupy only their exact live ranges; the cheaper of restore
/// and recomputation is selected deterministically.
pub fn build(
    allocator: std.mem.Allocator,
    logical: []const LogicalBuffer,
    budget_bytes: u64,
) (std.mem.Allocator.Error || Error)!Plan {
    if (logical.len == 0) return Error.EmptySchedule;

    var work = try allocator.alloc(WorkBuffer, logical.len);
    defer allocator.free(work);
    for (logical, 0..) |buffer, index| {
        try validateBuffer(buffer);
        for (logical[0..index]) |previous| {
            if (previous.id == buffer.id) return Error.DuplicateLogicalId;
        }
        const materialization = chooseMaterialization(buffer);
        work[index] = .{
            .input_index = index,
            .materialization = materialization,
            .occupied = occupancy(buffer, materialization),
        };
    }
    std.mem.sortUnstable(WorkBuffer, work, logical, WorkBuffer.lessThan);

    var unsorted_bindings = std.ArrayList(Binding).empty;
    defer unsorted_bindings.deinit(allocator);
    var slots = std.ArrayList(Slot).empty;
    defer slots.deinit(allocator);
    var tick_bindings: [max_ticks]std.ArrayList(u32) = [_]std.ArrayList(u32){.empty} ** max_ticks;
    defer for (&tick_bindings) |*items| items.deinit(allocator);
    const seen = try allocator.alloc(u32, logical.len);
    defer allocator.free(seen);
    @memset(seen, 0);
    var generation: u32 = 0;
    var conflicts = std.ArrayList(MemoryRange).empty;
    defer conflicts.deinit(allocator);
    var total_bytes: u64 = 0;
    for (work) |item| {
        const buffer = logical[item.input_index];
        conflicts.clearRetainingCapacity();
        generation +%= 1;
        if (generation == 0) {
            @memset(seen, 0);
            generation = 1;
        }
        for (0..max_ticks) |tick| {
            if (!hasTick(item.occupied, @intCast(tick))) continue;
            for (tick_bindings[tick].items) |binding_index| {
                if (seen[binding_index] == generation) continue;
                seen[binding_index] = generation;
                const binding = unsorted_bindings.items[binding_index];
                try conflicts.append(allocator, .{
                    .start = binding.offset_bytes,
                    .end = std.math.add(u64, binding.offset_bytes, binding.size_bytes) catch return Error.SizeOverflow,
                });
            }
        }
        std.mem.sortUnstable(MemoryRange, conflicts.items, {}, MemoryRange.lessThan);
        var offset = try alignForward(0, buffer.alignment);
        for (conflicts.items) |conflict| {
            const end = std.math.add(u64, offset, buffer.size_bytes) catch return Error.SizeOverflow;
            if (end <= conflict.start) break;
            if (offset < conflict.end) offset = try alignForward(conflict.end, buffer.alignment);
        }
        const binding_index: u32 = @intCast(unsorted_bindings.items.len);
        try unsorted_bindings.append(allocator, .{
            .logical_id = buffer.id,
            .slot = binding_index,
            .offset_bytes = offset,
            .size_bytes = buffer.size_bytes,
            .materialization = item.materialization,
            .occupied = item.occupied,
        });
        try slots.append(allocator, .{
            .offset_bytes = offset,
            .capacity_bytes = buffer.size_bytes,
            .alignment = buffer.alignment,
            .occupied = item.occupied,
        });
        total_bytes = @max(total_bytes, std.math.add(u64, offset, buffer.size_bytes) catch return Error.SizeOverflow);
        for (0..max_ticks) |tick| {
            if (hasTick(item.occupied, @intCast(tick))) try tick_bindings[tick].append(allocator, binding_index);
        }
    }
    total_bytes = try alignForward(total_bytes, 16 * 1024);
    if (total_bytes > budget_bytes) return Error.BudgetExceeded;
    std.mem.sortUnstable(Binding, unsorted_bindings.items, {}, bindingLessThan);
    const ordered_slots = try allocator.alloc(Slot, slots.items.len);
    errdefer allocator.free(ordered_slots);
    for (unsorted_bindings.items, 0..) |*binding, index| {
        ordered_slots[index] = slots.items[binding.slot];
        binding.slot = @intCast(index);
    }

    var actions = std.ArrayList(Action).empty;
    defer actions.deinit(allocator);
    for (logical) |buffer| {
        const materialization = chooseMaterialization(buffer);
        try appendActions(allocator, &actions, buffer, materialization);
    }
    std.mem.sortUnstable(Action, actions.items, {}, actionLessThan);

    const owned_bindings = try unsorted_bindings.toOwnedSlice(allocator);
    errdefer allocator.free(owned_bindings);
    const owned_slots = ordered_slots;
    const owned_actions = try actions.toOwnedSlice(allocator);
    errdefer allocator.free(owned_actions);
    const action_offsets = try buildActionOffsets(allocator, owned_actions);
    errdefer allocator.free(action_offsets);
    const peak = peakLiveBytes(owned_slots);
    const hash = hashPlan(owned_bindings, owned_slots, owned_actions, total_bytes);
    var result = Plan{
        .allocator = allocator,
        .bindings = owned_bindings,
        .slots = owned_slots,
        .actions = owned_actions,
        .action_offsets = action_offsets,
        .total_bytes = total_bytes,
        .peak_live_bytes = peak,
        .plan_hash = hash,
    };
    try result.validate(budget_bytes);
    return result;
}

const WorkBuffer = struct {
    input_index: usize,
    materialization: Materialization,
    occupied: TickSet,

    fn lessThan(logical: []const LogicalBuffer, a: WorkBuffer, b: WorkBuffer) bool {
        const left = logical[a.input_index];
        const right = logical[b.input_index];
        if (left.placement_priority != right.placement_priority)
            return left.placement_priority > right.placement_priority;
        if (left.size_bytes != right.size_bytes) return left.size_bytes > right.size_bytes;
        const left_ticks = occupiedTickCount(a.occupied);
        const right_ticks = occupiedTickCount(b.occupied);
        if (left_ticks != right_ticks) return left_ticks > right_ticks;
        return left.id < right.id;
    }

    fn occupiedTickCount(occupied: TickSet) u32 {
        var count: u32 = 0;
        for (occupied) |word| count += @popCount(word);
        return count;
    }
};

const MemoryRange = struct {
    start: u64,
    end: u64,

    fn lessThan(_: void, lhs: MemoryRange, rhs: MemoryRange) bool {
        if (lhs.start != rhs.start) return lhs.start < rhs.start;
        return lhs.end < rhs.end;
    }
};

fn validateBuffer(buffer: LogicalBuffer) Error!void {
    if (buffer.size_bytes == 0 or buffer.live_ranges.len == 0) return Error.EmptySchedule;
    if (buffer.alignment == 0 or !std.math.isPowerOfTwo(buffer.alignment)) return Error.InvalidAlignment;
    var previous_last: ?u16 = null;
    for (buffer.live_ranges) |range| {
        if (range.first > range.last or range.last >= max_ticks) return Error.InvalidTick;
        if (previous_last) |value| if (range.first <= value) return Error.InvalidUseOrder;
        previous_last = range.last;
    }
}

fn chooseMaterialization(buffer: LogicalBuffer) Materialization {
    if (buffer.live_ranges.len <= 1) return .resident;
    if (buffer.recompute_cost_ns) |recompute| {
        if (buffer.spill_cost_ns) |spill| return if (recompute <= spill) .recompute else .spill;
        return .recompute;
    }
    if (buffer.spill_cost_ns != null) return .spill;
    return .resident;
}

fn occupancy(buffer: LogicalBuffer, materialization: Materialization) TickSet {
    var result = [_]u64{0} ** (max_ticks / 64);
    if (materialization == .resident) {
        var tick = buffer.live_ranges[0].first;
        const last = buffer.live_ranges[buffer.live_ranges.len - 1].last;
        while (tick <= last) : (tick += 1) setTick(&result, tick);
    } else {
        for (buffer.live_ranges) |range| {
            var tick = range.first;
            while (tick <= range.last) : (tick += 1) setTick(&result, tick);
        }
    }
    return result;
}

fn appendActions(allocator: std.mem.Allocator, actions: *std.ArrayList(Action), buffer: LogicalBuffer, materialization: Materialization) !void {
    if (materialization == .resident) {
        try actions.append(allocator, .{ .tick = buffer.live_ranges[0].first, .logical_id = buffer.id, .kind = .produce });
        try actions.append(allocator, .{ .tick = buffer.live_ranges[buffer.live_ranges.len - 1].last, .logical_id = buffer.id, .kind = .release });
        return;
    }
    for (buffer.live_ranges, 0..) |range, index| {
        const enter: ActionKind = if (index == 0) .produce else if (materialization == .spill) .restore else .recompute;
        try actions.append(allocator, .{ .tick = range.first, .logical_id = buffer.id, .kind = enter });
        if (materialization == .spill and index + 1 < buffer.live_ranges.len)
            try actions.append(allocator, .{ .tick = range.last, .logical_id = buffer.id, .kind = .spill });
        try actions.append(allocator, .{ .tick = range.last, .logical_id = buffer.id, .kind = .release });
    }
}

fn peakLiveBytes(slots: []const Slot) u64 {
    var peak: u64 = 0;
    for (0..max_ticks) |tick| {
        var live: u64 = 0;
        for (slots) |slot| {
            if (hasTick(slot.occupied, @intCast(tick))) live += slot.capacity_bytes;
        }
        peak = @max(peak, live);
    }
    return peak;
}

fn buildActionOffsets(allocator: std.mem.Allocator, actions: []const Action) ![]usize {
    const offsets = try allocator.alloc(usize, max_ticks + 1);
    var cursor: usize = 0;
    for (0..max_ticks) |tick| {
        offsets[tick] = cursor;
        while (cursor < actions.len and actions[cursor].tick == tick) cursor += 1;
    }
    offsets[max_ticks] = actions.len;
    return offsets;
}

fn bindingLessThan(_: void, a: Binding, b: Binding) bool {
    return a.logical_id < b.logical_id;
}
fn offsetLessThan(_: void, a: Binding, b: Binding) bool {
    if (a.offset_bytes != b.offset_bytes) return a.offset_bytes < b.offset_bytes;
    return a.size_bytes < b.size_bytes;
}
fn rangesOverlap(a: Binding, b: Binding) bool {
    const a_end = a.offset_bytes + a.size_bytes;
    const b_end = b.offset_bytes + b.size_bytes;
    return a.offset_bytes < b_end and b.offset_bytes < a_end;
}
fn actionLessThan(_: void, a: Action, b: Action) bool {
    if (a.tick != b.tick) return a.tick < b.tick;
    if (a.logical_id != b.logical_id) return a.logical_id < b.logical_id;
    return @intFromEnum(a.kind) < @intFromEnum(b.kind);
}

fn setTick(set: *TickSet, tick: u16) void {
    set[tick / 64] |= @as(u64, 1) << @intCast(tick % 64);
}
fn hasTick(set: TickSet, tick: u16) bool {
    return set[tick / 64] & (@as(u64, 1) << @intCast(tick % 64)) != 0;
}
fn intersects(a: TickSet, b: TickSet) bool {
    for (a, b) |x, y| if (x & y != 0) return true;
    return false;
}
fn unionInto(destination: *TickSet, source: TickSet) void {
    for (destination, source) |*x, y| x.* |= y;
}

fn alignForward(value: u64, alignment: u32) Error!u64 {
    const mask = @as(u64, alignment) - 1;
    const added = std.math.add(u64, value, mask) catch return Error.SizeOverflow;
    return added & ~mask;
}

fn hashPlan(bindings: []const Binding, slots: []const Slot, actions: []const Action, total: u64) u64 {
    var hash = std.hash.Fnv1a_64.init();
    hash.update(std.mem.asBytes(&total));
    for (bindings) |binding| {
        hash.update(std.mem.asBytes(&binding.logical_id));
        hash.update(std.mem.asBytes(&binding.slot));
        hash.update(std.mem.asBytes(&binding.offset_bytes));
        hash.update(std.mem.asBytes(&binding.size_bytes));
        const materialization: u8 = @intFromEnum(binding.materialization);
        hash.update(std.mem.asBytes(&materialization));
        hash.update(std.mem.sliceAsBytes(&binding.occupied));
    }
    for (slots) |slot| {
        hash.update(std.mem.asBytes(&slot.offset_bytes));
        hash.update(std.mem.asBytes(&slot.capacity_bytes));
        hash.update(std.mem.asBytes(&slot.alignment));
        hash.update(std.mem.sliceAsBytes(&slot.occupied));
    }
    for (actions) |action| {
        hash.update(std.mem.asBytes(&action.tick));
        hash.update(std.mem.asBytes(&action.logical_id));
        const kind: u8 = @intFromEnum(action.kind);
        hash.update(std.mem.asBytes(&kind));
    }
    return hash.final();
}

/// Highest physical byte touched by any binding live through `last_tick`.
/// This is the allocation boundary for an epoch-local arena; later bindings
/// retain their exact plan metadata but are not allocated until their stage.
pub fn bytesThroughTick(plan: Plan, last_tick: u16) u64 {
    var required: u64 = 0;
    for (plan.bindings) |binding| {
        var live = false;
        var tick: u16 = 0;
        while (tick <= last_tick) : (tick += 1) live = live or hasTick(binding.occupied, tick);
        if (live) required = @max(required, binding.offset_bytes + binding.size_bytes);
    }
    return std.mem.alignForward(u64, required, 16 * 1024);
}

/// Recolors only the bindings consumed through `last_tick`. Bindings owned by
/// later epochs remain present with their exact logical sizes so typed binders
/// can validate the whole protocol, but they have no physical occupancy until
/// a later projected arena is entered.
pub fn projectThroughTick(
    allocator: std.mem.Allocator,
    logical: []const LogicalBuffer,
    full: Plan,
    last_tick: u16,
    budget_bytes: u64,
) !Plan {
    var run_count: usize = 0;
    var active_count: usize = 0;
    for (full.bindings) |bound| {
        var in_run = false;
        var active = false;
        var tick: u16 = 0;
        while (tick <= last_tick) : (tick += 1) {
            const live = hasTick(bound.occupied, tick);
            active = active or live;
            if (live and !in_run) run_count += 1;
            in_run = live;
        }
        if (active) active_count += 1;
    }
    if (active_count == 0) return Error.EmptySchedule;
    const ranges = try allocator.alloc(LiveRange, run_count);
    defer allocator.free(ranges);
    const active = try allocator.alloc(LogicalBuffer, active_count);
    defer allocator.free(active);
    var range_cursor: usize = 0;
    var active_cursor: usize = 0;
    for (full.bindings) |bound| {
        const range_start = range_cursor;
        var open: ?u16 = null;
        var tick: u16 = 0;
        while (tick <= last_tick) : (tick += 1) {
            const live = hasTick(bound.occupied, tick);
            if (live and open == null) open = tick;
            if (open != null and (!live or tick == last_tick)) {
                const end = if (live and tick == last_tick) tick else tick - 1;
                ranges[range_cursor] = .{ .first = open.?, .last = end };
                range_cursor += 1;
                open = null;
            }
        }
        if (range_cursor == range_start) continue;
        const source = findLogical(logical, bound.logical_id) orelse return Error.UnknownBinding;
        active[active_cursor] = source;
        active[active_cursor].live_ranges = ranges[range_start..range_cursor];
        active_cursor += 1;
    }
    var projected = try build(allocator, active, budget_bytes);
    errdefer projected.deinit();
    const bindings = try allocator.alloc(Binding, full.bindings.len);
    errdefer allocator.free(bindings);
    const slots = try allocator.alloc(Slot, full.bindings.len);
    errdefer allocator.free(slots);
    for (full.bindings, bindings, slots, 0..) |source, *destination, *slot, index| {
        if (projected.binding(source.logical_id)) |active_binding| {
            destination.* = active_binding;
            destination.slot = @intCast(index);
            slot.* = projected.slots[active_binding.slot];
        } else |_| {
            destination.* = source;
            destination.slot = @intCast(index);
            destination.offset_bytes = 0;
            destination.materialization = .recompute;
            destination.occupied = [_]u64{0} ** (max_ticks / 64);
            slot.* = .{
                .offset_bytes = 0,
                .capacity_bytes = source.size_bytes,
                .alignment = 16 * 1024,
                .occupied = [_]u64{0} ** (max_ticks / 64),
            };
        }
    }
    allocator.free(projected.bindings);
    allocator.free(projected.slots);
    projected.bindings = bindings;
    projected.slots = slots;
    return projected;
}

fn findLogical(logical: []const LogicalBuffer, id: u32) ?LogicalBuffer {
    for (logical) |buffer| if (buffer.id == id) return buffer;
    return null;
}

pub fn peakLogicalBytes(bindings: []const Binding) u64 {
    var peak: u64 = 0;
    for (0..max_ticks) |tick| {
        var live: u64 = 0;
        for (bindings) |binding| {
            if (hasTick(binding.occupied, @intCast(tick))) live += binding.size_bytes;
        }
        peak = @max(peak, live);
    }
    return peak;
}

pub const RecoveryHooks = struct {
    context: *anyopaque,
    spill: *const fn (*anyopaque, u16, Binding) anyerror!void,
    restore: *const fn (*anyopaque, u16, Binding) anyerror!void,
    recompute: *const fn (*anyopaque, u16, Binding) anyerror!void,
};

pub const EpochRunner = struct {
    const State = enum { absent, live, spilled };

    allocator: std.mem.Allocator,
    plan: *const Plan,
    states: []State,

    pub fn init(allocator: std.mem.Allocator, plan: *const Plan) !EpochRunner {
        const states = try allocator.alloc(State, plan.bindings.len);
        @memset(states, .absent);
        return .{ .allocator = allocator, .plan = plan, .states = states };
    }

    pub fn deinit(self: *EpochRunner) void {
        self.allocator.free(self.states);
        self.* = undefined;
    }

    /// Restores or regenerates every input before kernels for `tick` launch.
    pub fn begin(self: *EpochRunner, tick: u16, hooks: RecoveryHooks) !void {
        if (tick >= max_ticks) return Error.InvalidTick;
        for (self.actionsAt(tick)) |action| {
            if (action.kind == .spill or action.kind == .release) continue;
            const index = self.bindingIndex(action.logical_id) orelse return Error.UnknownBinding;
            const binding = self.plan.bindings[index];
            for (self.plan.bindings, self.states) |other, state| {
                if (state == .live and rangesOverlap(binding, other)) return Error.AliasOverlap;
            }
            switch (action.kind) {
                .produce => {},
                .restore => try hooks.restore(hooks.context, tick, binding),
                .recompute => try hooks.recompute(hooks.context, tick, binding),
                else => unreachable,
            }
            self.states[index] = .live;
        }
    }

    /// Persists selected outputs and releases their slots after the tick's
    /// command buffer has completed. The caller owns that Metal barrier.
    pub fn end(self: *EpochRunner, tick: u16, hooks: RecoveryHooks) !void {
        if (tick >= max_ticks) return Error.InvalidTick;
        const actions = self.actionsAt(tick);
        for (actions) |action| {
            if (action.kind != .spill) continue;
            const index = self.bindingIndex(action.logical_id) orelse return Error.UnknownBinding;
            const binding = self.plan.bindings[index];
            if (self.states[index] != .live) return Error.InvalidUseOrder;
            try hooks.spill(hooks.context, tick, binding);
            self.states[index] = .spilled;
        }
        for (actions) |action| {
            if (action.kind != .release) continue;
            const index = self.bindingIndex(action.logical_id) orelse return Error.UnknownBinding;
            if (self.states[index] != .live and self.states[index] != .spilled) return Error.InvalidUseOrder;
            if (self.states[index] != .spilled) self.states[index] = .absent;
        }
    }

    fn bindingIndex(self: EpochRunner, id: u32) ?usize {
        var low: usize = 0;
        var high = self.plan.bindings.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const candidate = self.plan.bindings[middle].logical_id;
            if (candidate < id) low = middle + 1 else high = middle;
        }
        return if (low < self.plan.bindings.len and self.plan.bindings[low].logical_id == id) low else null;
    }

    fn actionsAt(self: EpochRunner, tick: u16) []const Action {
        return self.plan.actions[self.plan.action_offsets[tick]..self.plan.action_offsets[tick + 1]];
    }
};

test "metal arena: sparse recovery shortens ranges and aliases safely" {
    const uses_a = [_]LiveRange{ .{ .first = 1, .last = 1 }, .{ .first = 8, .last = 8 } };
    const uses_b = [_]LiveRange{.{ .first = 4, .last = 5 }};
    const uses_c = [_]LiveRange{ .{ .first = 2, .last = 2 }, .{ .first = 7, .last = 7 } };
    const logical = [_]LogicalBuffer{
        .{ .id = 1, .size_bytes = 4096, .alignment = 4096, .live_ranges = &uses_a, .recompute_cost_ns = 10 },
        .{ .id = 2, .size_bytes = 4096, .alignment = 4096, .live_ranges = &uses_b },
        .{ .id = 3, .size_bytes = 2048, .alignment = 4096, .live_ranges = &uses_c, .spill_cost_ns = 20 },
    };
    var plan = try build(std.testing.allocator, &logical, 16 * 1024);
    defer plan.deinit();
    try std.testing.expectEqual(@as(u64, 16 * 1024), plan.total_bytes);
    try std.testing.expectEqual(Materialization.recompute, (try plan.binding(1)).materialization);
    try std.testing.expectEqual(Materialization.spill, (try plan.binding(3)).materialization);
    try plan.validate(16 * 1024);
}

test "metal arena: binding lookup covers sorted boundaries and gaps" {
    const uses = [_]LiveRange{.{ .first = 1, .last = 1 }};
    const logical = [_]LogicalBuffer{
        .{ .id = 3, .size_bytes = 256, .alignment = 256, .live_ranges = &uses },
        .{ .id = 11, .size_bytes = 256, .alignment = 256, .live_ranges = &uses },
        .{ .id = 29, .size_bytes = 256, .alignment = 256, .live_ranges = &uses },
    };
    var plan = try build(std.testing.allocator, &logical, 16 * 1024);
    defer plan.deinit();

    try std.testing.expectEqual(@as(u32, 3), (try plan.binding(3)).logical_id);
    try std.testing.expectEqual(@as(u32, 11), (try plan.binding(11)).logical_id);
    try std.testing.expectEqual(@as(u32, 29), (try plan.binding(29)).logical_id);
    try std.testing.expectError(Error.UnknownBinding, plan.binding(0));
    try std.testing.expectError(Error.UnknownBinding, plan.binding(12));
    try std.testing.expectError(Error.UnknownBinding, plan.binding(30));

    std.mem.swap(Binding, &plan.bindings[0], &plan.bindings[1]);
    try std.testing.expectError(Error.UnsortedBindings, plan.validate(16 * 1024));
    std.mem.swap(Binding, &plan.bindings[0], &plan.bindings[1]);
}

test "metal arena: unrecoverable values retain their full interval" {
    const uses_a = [_]LiveRange{ .{ .first = 1, .last = 1 }, .{ .first = 8, .last = 8 } };
    const uses_b = [_]LiveRange{.{ .first = 4, .last = 4 }};
    const logical = [_]LogicalBuffer{
        .{ .id = 1, .size_bytes = 4096, .alignment = 4096, .live_ranges = &uses_a },
        .{ .id = 2, .size_bytes = 4096, .alignment = 4096, .live_ranges = &uses_b },
    };
    try std.testing.expectError(Error.BudgetExceeded, build(std.testing.allocator, &logical, 4096));
}

test "metal arena: epoch runner performs recovery around each local epoch" {
    const Hooks = struct {
        spills: usize = 0,
        restores: usize = 0,
        recomputes: usize = 0,
        fn spill(raw: *anyopaque, _: u16, _: Binding) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.spills += 1;
        }
        fn restore(raw: *anyopaque, _: u16, _: Binding) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.restores += 1;
        }
        fn recompute(raw: *anyopaque, _: u16, _: Binding) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.recomputes += 1;
        }
    };
    const uses_a = [_]LiveRange{ .{ .first = 1, .last = 1 }, .{ .first = 8, .last = 8 } };
    const uses_b = [_]LiveRange{ .{ .first = 2, .last = 2 }, .{ .first = 7, .last = 7 } };
    const logical = [_]LogicalBuffer{
        .{ .id = 1, .size_bytes = 4096, .alignment = 4096, .live_ranges = &uses_a, .spill_cost_ns = 10 },
        .{ .id = 2, .size_bytes = 4096, .alignment = 4096, .live_ranges = &uses_b, .recompute_cost_ns = 10 },
    };
    var plan = try build(std.testing.allocator, &logical, 16 * 1024);
    defer plan.deinit();
    var runner = try EpochRunner.init(std.testing.allocator, &plan);
    defer runner.deinit();
    var counters = Hooks{};
    const hooks = RecoveryHooks{ .context = &counters, .spill = Hooks.spill, .restore = Hooks.restore, .recompute = Hooks.recompute };
    for ([_]u16{ 1, 2, 7, 8 }) |tick| {
        try runner.begin(tick, hooks);
        try runner.end(tick, hooks);
    }
    try std.testing.expectEqual(@as(usize, 1), counters.spills);
    try std.testing.expectEqual(@as(usize, 1), counters.restores);
    try std.testing.expectEqual(@as(usize, 1), counters.recomputes);
}
