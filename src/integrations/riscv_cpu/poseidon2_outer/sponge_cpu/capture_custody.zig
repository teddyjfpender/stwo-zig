//! Bounded producer-only CPU metadata parking DURING ordered capture. No key,
//! public statement, source geometry, transcript or source-suite admission changes.
const std = @import("std");
const Capture = @import("../pure_p2_op_capture.zig");
const Events = @import("event_custody.zig");
const Parking = @import("../pure_p2_cpu_metadata_parking.zig");
const Store = @import("../pure_p2_retained_main.zig").Store;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
pub const Owner = struct {
    store: *Store,
    park_metadata: bool = true,
    park_events: bool = false,
    events: [256]?Events.Token = @splat(null),
    event_count: usize = 0,
    event_bytes: usize = 0,
    tokens: [256]?Parking.Token = @splat(null),
    count: usize = 0,
    bytes: usize = 0,
    pub fn deinit(self: *Owner) void {
        for (self.tokens[0..self.count]) |*token| if (token.*) |*value| value.deinit();
        self.count = 0;
        for (self.events[0..self.event_count]) |*token| if (token.*) |*value| value.deinit();
        self.event_count = 0;
    }
    pub fn hooks(self: *Owner) Capture.Hooks {
        return .{ .context = self, .completed = if (self.park_metadata) completed else null, .events = if (self.park_events) parkEvents else null, .prepare_events = if (self.park_events) prepareEvents else null, .release_events = if (self.park_events) releaseEvents else null };
    }
    fn completed(raw: ?*anyopaque, ordinal: usize, native: *Native) !void {
        const self: *Owner = @ptrCast(@alignCast(raw orelse return error.OpCaptureCustodyContext));
        if (ordinal != self.count or self.count >= self.tokens.len) return error.OpCaptureCustodyOrder;
        const cpu = if (native.cpu) |*value| value else return error.PreparedExecutionConsumed;
        const bytes = try std.math.add(usize, self.bytes, try Parking.roundedBytes(cpu));
        // park is failure-atomic: allocation/I/O/quota errors retain CPU owner.
        self.tokens[self.count] = try Parking.park(self.store, cpu);
        self.bytes = bytes;
        self.count += 1;
    }
    pub fn eventDescriptor(native: *const Native, ordinal: usize) !Events.Descriptor {
        const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
        return .{ .program = native.program_identity, .boundary = cpu.public, .epoch = cpu.epoch, .ordinal = std.math.cast(u32, ordinal) orelse return error.OpCaptureCustodyOrder, .count = native.raw_counts.memory };
    }
    fn parkEvents(raw: ?*anyopaque, ordinal: usize, native: *Native, events: *[]Events.Event) !void {
        const self: *Owner = @ptrCast(@alignCast(raw orelse return error.OpCaptureCustodyContext));
        if (ordinal != self.event_count or ordinal >= self.events.len) return error.OpCaptureCustodyOrder;
        const descriptor = try eventDescriptor(native, ordinal);
        if (events.len != descriptor.count) return error.OpCaptureCustodyCoverage;
        if (events.len != 0) {
            const bytes = try std.math.mul(usize, events.len, Events.record_bytes);
            const sum = try std.math.add(usize, self.event_bytes, bytes);
            self.events[ordinal] = try Events.park(self.store, native.allocator, descriptor, events);
            self.event_bytes = sum;
        }
        self.event_count += 1;
    }
    fn prepareEvents(raw: ?*anyopaque, ordinal: usize, native: *Native, events: *[]Events.Event) !void {
        const self: *Owner = @ptrCast(@alignCast(raw orelse return error.OpCaptureCustodyContext));
        if (ordinal >= self.event_count or events.len != 0) return error.OpCaptureCustodyCoverage;
        const descriptor = try eventDescriptor(native, ordinal);
        if (self.events[ordinal]) |*token| {
            try token.restore(native.allocator, descriptor, events);
        } else if (descriptor.count != 0) return error.OpCaptureCustodyCoverage;
    }
    fn releaseEvents(raw: ?*anyopaque, ordinal: usize, native: *Native, events: *[]Events.Event) !void {
        const self: *Owner = @ptrCast(@alignCast(raw orelse return error.OpCaptureCustodyContext));
        if (ordinal >= self.event_count) return error.OpCaptureCustodyCoverage;
        if (self.events[ordinal]) |*token| {
            try token.retire(native.allocator, events);
        } else if (events.len != 0 or (try eventDescriptor(native, ordinal)).count != 0) return error.OpCaptureCustodyCoverage;
    }
    pub fn eventSlice(self: *Owner) []?Events.Token {
        return self.events[0..self.event_count];
    }
    /// Borrowed until native proof completion. This owner closes files after
    /// the worker sources have released every restored heap view.
    pub fn slice(self: *Owner) []?Parking.Token {
        return self.tokens[0..self.count];
    }
};
