//! Worker admission and plan/statistics observation ownership.
const std = @import("std");
const api = @import("api.zig");
const MP = @import("plan.zig");

const Worker = @import("worker.zig").Worker;
const Records = @import("worker_records.zig");
const ClassEntry = Worker.ClassEntry;

pub fn plan(self: *const Worker) ?*const MP.Policy {
    return self.policy;
}

pub fn resolve(self: *const Worker, job: api.Job) MP.Resolved {
    return resolveFootprint(self, job, job.footprint());
}

pub fn resolveFootprint(self: *const Worker, job: api.Job, fp: api.Footprint) MP.Resolved {
    const p = self.policy orelse return MP.declared(fp);
    return p.resolve(job.classKey(), fp);
}

pub fn fits(self: *Worker, job: api.Job) bool {
    if (self.policy == null) return true;
    const r = resolve(self, job);
    self.mutex.lock();
    defer self.mutex.unlock();
    if (!self.tail_live) return true;
    return MP.pairFits(self.config.arena_words, self.tail_peak, r.staged_words);
}

pub fn writePlanDir(self: *Worker, dir: []const u8) !void {
    const Row = struct { device: u32, class_key: [64]u8, stat: Records.ClassStat };
    var rows: std.ArrayListUnmanaged(Row) = .empty;
    defer rows.deinit(self.a);
    {
        // The worker thread records class stats under the mutex.
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.classes.iterator();
        while (it.next()) |e| try rows.append(self.a, .{ .device = self.device_ordinal, .class_key = std.fmt.bytesToHex(e.key_ptr.*, .lower), .stat = e.value_ptr.* });
    }
    var text: std.Io.Writer.Allocating = .init(self.a);
    defer text.deinit();
    try std.json.Stringify.value(.{
        .schema = "rv64-m8-jobs-class-plans/v2",
        .device = self.device_ordinal,
        .arena_words = self.config.arena_words,
        .allocator = if (self.config.reuse_frees) "reuse" else "lifo",
        .policy = self.policy != null,
        .persistent = .{ .budget_words = self.config.persistent_budget_words, .regions = self.regions.entries.items.len, .used_words = self.regions.used(), .high_water_words = self.regions.high_water, .evictions = self.regions.evictions, .evicted_words = self.regions.evicted_words, .unbudgeted_regions = if (self.shut_down) self.unbudgeted_regions else self.persistent_map.count() },
        .completed = self.completed,
        .retained = self.retained.stats,
        .service = .{ .parks = self.parks, .unparks = self.unparks, .arena_epoch = self.arena_epoch, .persistent_epoch = self.persistent_epoch, .pinned_allocated_bytes = self.pinned_allocated_bytes, .pinned_allocations = self.pinned_allocations, .pinned_lazy = self.config.pinned_lazy },
        .classes = rows.items,
    }, .{ .whitespace = .indent_1 }, &text.writer);
    std.fs.cwd().makePath(dir) catch {};
    var name_buf: [96]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "worker-d{d}-{d}-{x}.json", .{ self.device_ordinal, std.time.nanoTimestamp(), @intFromPtr(self) & 0xffffff });
    var d = try std.fs.cwd().openDir(dir, .{});
    defer d.close();
    try d.writeFile(.{ .sub_path = name, .data = text.written() });
}

pub fn accepts(self: *Worker) bool {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.fatal == null and !self.closing and !self.parked and !self.parking and self.mailbox == null and self.outstanding < self.config.max_outstanding;
}

pub fn classStats(self: *Worker, a: std.mem.Allocator) ![]ClassEntry {
    self.mutex.lock();
    defer self.mutex.unlock();
    const out = try a.alloc(ClassEntry, self.classes.count());
    var it = self.classes.iterator();
    var i: usize = 0;
    while (it.next()) |e| : (i += 1) out[i] = .{ .key = e.key_ptr.*, .stat = e.value_ptr.* };
    return out;
}

pub fn load(self: *Worker) usize {
    self.mutex.lock();
    defer self.mutex.unlock();
    return self.outstanding;
}
