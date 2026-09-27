//! Allocation-free cleanup of actual successful supplemental writer files.
//! Slot pins are publication custody only, never proof/Fresh authority. Call
//! after producers/callbacks have joined, before destroying the original Store.
const std = @import("std");
pub const Result = struct {
    status: enum { complete, reader, active_readers, invalid_inventory, io_failure },
    removed: usize = 0,
    missing: usize = 0,
    failed: usize = 0,
};
pub fn rollbackWriter(comptime Module: type, store: *Module.Store) Result {
    store.mutex.lock();
    defer store.mutex.unlock();
    if (store.mode != .writer) return .{ .status = .reader };
    if (store.active_readers != 0) return .{ .status = .active_readers };
    if (store.limits.max_files == 0 or store.slots.len > store.limits.max_files or store.limits.max_total_bytes == 0) return .{ .status = .invalid_inventory };
    // Validate the complete bounded success inventory before deleting anything.
    // Pending slots/policies are never read to discover another destination.
    var total: u64 = 0;
    var previous: ?u32 = null;
    for (store.slots) |slot| {
        if (slot.state == .reading) return .{ .status = .active_readers };
        if (slot.pin) |pin| {
            if (pin.byte_len == 0 or !slot.template_bound or std.mem.allEqual(u8, &pin.sha256, 0) or
                (previous != null and previous.? >= pin.index)) return .{ .status = .invalid_inventory };
            total = std.math.add(u64, total, pin.byte_len) catch return .{ .status = .invalid_inventory };
            if (total > store.limits.max_total_bytes) return .{ .status = .invalid_inventory };
            previous = pin.index;
            var name: [96]u8 = undefined;
            _ = Module.fileName(&name, pin.index) catch return .{ .status = .invalid_inventory };
        }
    }
    if (total != store.total_bytes) return .{ .status = .invalid_inventory };
    var result = Result{ .status = .complete };
    for (store.slots) |*slot| if (slot.pin) |pin| {
        var name: [96]u8 = undefined;
        const path = Module.fileName(&name, pin.index) catch unreachable;
        store.dir.deleteFile(path) catch |failure| switch (failure) {
            error.FileNotFound => {
                result.missing += 1;
                slot.pin = null;
                store.total_bytes -= pin.byte_len;
                continue;
            },
            else => {
                result.status = .io_failure;
                result.failed += 1;
                continue; // Retain this exact pin for a later cleanup attempt.
            },
        };
        result.removed += 1;
        slot.pin = null;
        store.total_bytes -= pin.byte_len;
    };
    return result;
}
