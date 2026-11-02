//! Single-coordinator residency credits, independent of CUDA driver calls.
//! Device worker owns its context, threads, allocations and completion events.
//! A ticket authorizes capacity, never a proof or security claim.
const std = @import("std");
pub const max_devices = 4;
pub const max_lanes = 4;
pub const Device = struct {
    ordinal: u32,
    free_bytes: u64,
    reserve_bytes: u64,
    lanes: u8 = 2,
};
pub const Ticket = struct {
    scheduler: u64,
    generation: u64,
    slot: u8,
    device: u32,
    lane: u8,
    bytes: u64,
    ordinal: u64,
};
const Slot = struct {
    generation: u64 = 0,
    live: bool = false,
    failed: bool = false,
    device_index: u8 = 0,
    ticket: Ticket = undefined,
};
pub const Scheduler = struct {
    identity: u64,
    devices: [max_devices]Device = undefined,
    budgets: [max_devices]u64 = @splat(0),
    charged: [max_devices]u64 = @splat(0),
    active_lanes: [max_devices]u8 = @splat(0),
    device_count: u8,
    slots: [max_devices * max_lanes]Slot = @splat(.{}),

    pub fn init(identity: u64, devices: []const Device) !Scheduler {
        if (identity == 0 or (devices.len != 2 and devices.len != 4)) return error.InvalidFleet;
        var self = Scheduler{ .identity = identity, .device_count = @intCast(devices.len) };
        for (devices, 0..) |device, i| {
            if (device.free_bytes <= device.reserve_bytes or device.lanes == 0 or device.lanes > max_lanes)
                return error.InvalidDeviceBudget;
            for (devices[0..i]) |previous| if (previous.ordinal == device.ordinal) return error.DuplicateDevice;
            self.devices[i] = device;
            self.budgets[i] = device.free_bytes - device.reserve_bytes;
        }
        return self;
    }
    /// Charge all live input, tree, Eq, fold, reduction and auxiliary capacity.
    /// No mutation on failed admission. Call in desired priority order (largest
    /// ready instances first); completion/assembly retain public ordinals.
    pub fn acquire(self: *Scheduler, ordinal: u64, bytes: u64) !Ticket {
        if (bytes == 0) return error.InvalidJobSize;
        var selected: ?usize = null;
        var fits_idle = false;
        for (0..self.device_count) |i| {
            if (bytes > self.budgets[i]) continue;
            fits_idle = true;
            if (bytes > self.budgets[i] - self.charged[i] or
                @popCount(self.active_lanes[i]) >= self.devices[i].lanes) continue;
            if (selected) |j| {
                if (@as(u128, self.charged[i]) * self.budgets[j] >= @as(u128, self.charged[j]) * self.budgets[i]) continue;
            }
            selected = i;
        }
        const device_index = selected orelse return if (fits_idle) error.FleetBusy else error.JobExceedsEveryDevice;
        for (self.slots) |slot| if (slot.live and slot.ticket.ordinal == ordinal) return error.DuplicateJob;
        var slot_index: ?usize = null;
        for (&self.slots, 0..) |*slot, i| if (!slot.live and slot.generation != std.math.maxInt(u64)) {
            slot_index = i;
            break;
        };
        const index = slot_index orelse return error.TicketCapacityExhausted;
        var lane: u3 = 0;
        while (self.active_lanes[device_index] & (@as(u8, 1) << lane) != 0) : (lane += 1) {}
        const generation = self.slots[index].generation + 1;
        const ticket = Ticket{ .scheduler = self.identity, .generation = generation, .slot = @intCast(index), .device = self.devices[device_index].ordinal, .lane = lane, .bytes = bytes, .ordinal = ordinal };
        self.slots[index] = .{ .generation = generation, .live = true, .device_index = @intCast(device_index), .ticket = ticket };
        self.charged[device_index] += bytes;
        self.active_lanes[device_index] |= @as(u8, 1) << lane;
        return ticket;
    }
    /// A failed launch still owns every byte and lane until abort joins.
    pub fn fail(self: *Scheduler, ticket: Ticket) !void {
        const slot = try self.validate(ticket);
        slot.failed = true;
    }
    pub const Completion = enum { success_joined, aborted_joined };
    /// Caller must have observed its worker's completion event AND verdict.
    /// This credit ledger cannot substitute for the CUDA stream's join.
    pub fn retire(self: *Scheduler, ticket: Ticket, completion: Completion) !void {
        const slot = try self.validate(ticket);
        if (slot.failed and completion == .success_joined) return error.FailedJobCannotPublish;
        const i = slot.device_index;
        self.charged[i] -= ticket.bytes;
        self.active_lanes[i] &= ~(@as(u8, 1) << @as(u3, @intCast(ticket.lane)));
        slot.live = false;
    }
    pub fn liveBytes(self: *const Scheduler) u128 {
        var total: u128 = 0;
        for (self.charged[0..self.device_count]) |value| total += value;
        return total;
    }
    fn validate(self: *Scheduler, ticket: Ticket) !*Slot {
        if (ticket.scheduler != self.identity or ticket.slot >= self.slots.len) return error.InvalidTicket;
        const slot = &self.slots[ticket.slot];
        if (!slot.live or !std.meta.eql(ticket, slot.ticket)) return error.InvalidTicket;
        return slot;
    }
};
