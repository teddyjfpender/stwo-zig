const std = @import("std");

pub const SpanId = u64;

const SpanData = struct {
    class: []u8,
    start_ns: u64,
};

/// Collects span durations grouped by class label.
pub const SpanAccumulator = struct {
    allocator: std.mem.Allocator,
    spans: std.AutoHashMap(SpanId, SpanData),
    results: std.StringHashMap(u64),
    mutex: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .spans = std.AutoHashMap(SpanId, SpanData).init(allocator),
            .results = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var spans_it = self.spans.iterator();
        while (spans_it.next()) |entry| self.allocator.free(entry.value_ptr.class);
        self.spans.deinit();

        var results_it = self.results.iterator();
        while (results_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.results.deinit();
        self.* = undefined;
    }

    pub fn onNewSpan(self: *Self, id: SpanId, class: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.spans.fetchRemove(id)) |existing| {
            self.allocator.free(existing.value.class);
        }
        try self.spans.put(id, .{
            .class = try self.allocator.dupe(u8, class),
            .start_ns = std.time.nanoTimestamp(),
        });
    }

    pub fn onClose(self: *Self, id: SpanId) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const removed = self.spans.fetchRemove(id) orelse return;
        const elapsed = std.time.nanoTimestamp() - removed.value.start_ns;
        const duration_ns: u64 = @intCast(if (elapsed < 0) 0 else elapsed);

        if (self.results.getPtr(removed.value.class)) |total| {
            total.* += duration_ns;
            self.allocator.free(removed.value.class);
            return;
        }

        try self.results.put(removed.value.class, duration_ns);
    }

    pub fn exportCsv(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var rows = std.ArrayList(struct {
            label: []const u8,
            duration_ns: u64,
        }).init(allocator);
        defer rows.deinit();

        var it = self.results.iterator();
        while (it.next()) |entry| {
            try rows.append(.{
                .label = entry.key_ptr.*,
                .duration_ns = entry.value_ptr.*,
            });
        }

        std.sort.heap(
            @TypeOf(rows.items[0]),
            rows.items,
            {},
            struct {
                fn less(_: void, lhs: @TypeOf(rows.items[0]), rhs: @TypeOf(rows.items[0])) bool {
                    return std.mem.order(u8, lhs.label, rhs.label) == .lt;
                }
            }.less,
        );

        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();
        try out.writer().writeAll("Label,Duration_ms\n");
        for (rows.items) |row| {
            const duration_ms = @as(f64, @floatFromInt(row.duration_ns)) / 1_000_000.0;
            try out.writer().print("{s},{d:.6}\n", .{ row.label, duration_ms });
        }
        return out.toOwnedSlice();
    }

    pub fn resultsCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.results.count();
    }

    pub fn hasClass(self: *Self, class: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.results.contains(class);
    }
};

test "tracing span accumulator groups by class" {
    var accumulator = SpanAccumulator.init(std.testing.allocator);
    defer accumulator.deinit();

    try accumulator.onNewSpan(1, "class1");
    try accumulator.onNewSpan(2, "class2");
    try accumulator.onNewSpan(3, "class1");
    try accumulator.onClose(1);
    try accumulator.onClose(2);
    try accumulator.onClose(3);

    try std.testing.expectEqual(@as(usize, 2), accumulator.resultsCount());
    try std.testing.expect(accumulator.hasClass("class1"));
    try std.testing.expect(accumulator.hasClass("class2"));
}

test "tracing span accumulator exports csv" {
    var accumulator = SpanAccumulator.init(std.testing.allocator);
    defer accumulator.deinit();

    try accumulator.onNewSpan(5, "alpha");
    try accumulator.onClose(5);

    const csv = try accumulator.exportCsv(std.testing.allocator);
    defer std.testing.allocator.free(csv);

    try std.testing.expect(std.mem.startsWith(u8, csv, "Label,Duration_ms\n"));
    try std.testing.expect(std.mem.indexOf(u8, csv, "alpha,") != null);
}
