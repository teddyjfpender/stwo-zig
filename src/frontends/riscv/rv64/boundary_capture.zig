//! Bounded native first/last RAM words for one proving batch. No CPU registers,
//! per-access log, memory snapshot or execution replay is retained. This is
//! witness capture; the authenticated CellTable remains verifier authority.
const std = @import("std");
const Memory = @import("memory.zig").Memory;
const Retirement = @import("machine.zig").Retirement;
const Event = @import("ethereum_services/session.zig").Event;
pub const Cell = struct { address: u64, initial: u64, final: u64, terminal_clock: u32, rights: u2 };
const Transition = struct { address: u64, before: u64, after: u64, writable_required: bool };
pub const Capture = struct {
    allocator: std.mem.Allocator,
    initial_clock: u64,
    max_steps: u32,
    max_cells: u32,
    steps: u32 = 0,
    cells: std.AutoHashMap(u64, Cell),
    pub fn init(a: std.mem.Allocator, initial_clock: u64, max_steps: u32, max_cells: u32) !Capture {
        if (max_steps == 0 or max_steps >= 1 << 22 or max_cells == 0 or max_cells > 1 << 24 or initial_clock > std.math.maxInt(u64) - @as(u64, max_steps)) return error.InvalidBoundaryCapture;
        return .{ .allocator = a, .initial_clock = initial_clock, .max_steps = max_steps, .max_cells = max_cells, .cells = std.AutoHashMap(u64, Cell).init(a) };
    }
    pub fn deinit(self: *Capture) void {
        self.cells.deinit();
        self.* = undefined;
    }
    pub fn append(self: *Capture, record: Retirement, memory: *Memory) !void {
        if (record.opcode == .ECALL) return error.MissingBoundaryService;
        if (record.memory) |event| {
            const address = event.address.toInt() & ~@as(u64, 7);
            if (!event.write and event.before_word.toInt() != event.after_word.toInt()) return error.BoundaryReadMutation;
            const transition = Transition{ .address = address, .before = event.before_word.toInt(), .after = event.after_word.toInt(), .writable_required = event.write };
            try self.publish(record.clock, &.{transition}, memory);
        } else try self.publish(record.clock, &.{}, memory);
    }
    pub fn appendEvent(self: *Capture, event: Event, memory: *Memory) !void {
        var transitions: [25]Transition = undefined;
        var count: usize = 0;
        const clock = switch (event) {
            .keccak => |call| blk: {
                if (call.pointer & 7 != 0 or call.pointer > std.math.maxInt(u64) - 199) return error.InvalidBoundaryService;
                for (0..25) |lane| transitions[lane] = .{ .address = call.pointer + 8 * lane, .before = call.before[lane], .after = call.after[lane], .writable_required = true };
                count = 25;
                break :blk call.clock;
            },
            .secp => |call| blk: {
                count = call.wordCount();
                if (call.pointer & 31 != 0 or call.pointer > std.math.maxInt(u64) - (8 * count - 1)) return error.InvalidBoundaryService;
                for (0..count) |lane| {
                    if (lane >= 12 and call.before[lane] != call.after[lane]) return error.BoundaryReadMutation;
                    transitions[lane] = .{ .address = call.pointer + 8 * lane, .before = call.before[lane], .after = call.after[lane], .writable_required = lane < 12 };
                }
                break :blk call.clock;
            },
        };
        try self.publish(clock, transitions[0..count], memory);
    }
    fn publish(self: *Capture, clock: u64, transitions: []const Transition, memory: *Memory) !void {
        if (self.steps == self.max_steps or clock != self.initial_clock + self.steps + 1) return error.InvalidBoundaryClock;
        var masks: [25]u2 = undefined;
        var fresh: u32 = 0;
        const tick = 4 * (self.steps + 1);
        for (transitions, 0..) |transition, i| {
            if (transition.address & 7 != 0) return error.InvalidBoundaryAddress;
            try memory.mappings.check(transition.address, 8, .read);
            const writable = if (memory.mappings.check(transition.address, 8, .write)) |_| true else |_| false;
            if (transition.writable_required and !writable) return error.InvalidBoundaryPermission;
            masks[i] = 1 | (@as(u2, @intFromBool(writable)) << 1);
            if (self.cells.get(transition.address)) |previous| {
                if (previous.final != transition.before or previous.rights != masks[i] or previous.terminal_clock >= tick) return error.BoundaryWordDiscontinuity;
            } else fresh += 1;
        }
        if (@as(u64, self.cells.count()) + fresh > self.max_cells) return error.BoundaryCaptureResourceLimit;
        // Validate the entire atomic service and reserve before publishing any
        // word. Capacity failure preserves all prior words and the step clock.
        try self.cells.ensureUnusedCapacity(fresh);
        for (transitions, 0..) |transition, i| {
            const entry = self.cells.getOrPutAssumeCapacity(transition.address);
            if (!entry.found_existing) entry.value_ptr.* = .{ .address = transition.address, .initial = transition.before, .final = transition.after, .terminal_clock = tick, .rights = masks[i] } else {
                entry.value_ptr.final = transition.after;
                entry.value_ptr.terminal_clock = tick;
            }
        }
        self.steps += 1;
    }
    /// Freeze before advancing the image into the next batch: the openings
    /// adapter needs current final neighbors to reconstruct before chunks.
    pub fn sorted(self: *const Capture, a: std.mem.Allocator) ![]Cell {
        const result = try a.alloc(Cell, self.cells.count());
        var it = self.cells.valueIterator();
        var at: usize = 0;
        while (it.next()) |cell| : (at += 1) result[at] = cell.*;
        std.mem.sort(Cell, result, {}, less);
        return result;
    }
    pub fn clearRetainingCapacity(self: *Capture) !void {
        const next = self.initial_clock + self.steps;
        if (next > std.math.maxInt(u64) - @as(u64, self.max_steps)) return error.InvalidBoundaryClock;
        self.initial_clock = next;
        self.steps = 0;
        self.cells.clearRetainingCapacity();
    }
};
fn less(_: void, a: Cell, b: Cell) bool {
    return a.address < b.address;
}
