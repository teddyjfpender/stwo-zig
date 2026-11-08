//! Select only the columns referenced by an authenticated composition role.
//! Tree identities and shifted-row aliases retain the original full domain.
const std = @import("std");

pub fn supportsGeometry(trace_log: u32, eval_log: u32) bool {
    return trace_log >= 4 and trace_log <= 27 and eval_log >= 20 and eval_log <= 28 and
        eval_log >= trace_log + 1 and eval_log <= trace_log + 2;
}

pub fn arenaWords(count: usize, eval_log: u32) !u64 {
    if (count == 0 or eval_log > 28) return error.InvalidCompositionInputs;
    const n = @as(u64, 1) << @intCast(eval_log);
    return std.math.add(u64, try std.math.mul(u64, count, n), n / 2);
}

pub const Selection = struct {
    /// Flattened indices in the original FIXED, MAIN, INTER source roster.
    source_indices: []usize,
    /// One packed column slot per authenticated input mask, including aliases.
    mask_slots: []u32,

    pub fn init(a: std.mem.Allocator, widths: [3]usize, inputs: anytype) !Selection {
        const second = try std.math.add(usize, widths[0], widths[1]);
        const total = try std.math.add(usize, second, widths[2]);
        if (inputs.len == 0 or total > std.math.maxInt(u32)) return error.InvalidCompositionInputs;
        const bases = [_]usize{ 0, widths[0], second };
        const slots = try a.alloc(u32, total);
        defer a.free(slots);
        const missing = std.math.maxInt(u32);
        @memset(slots, missing);
        for (inputs) |input| {
            if (input.tree >= 3 or input.column >= widths[input.tree]) return error.InvalidCompositionInputs;
            slots[bases[input.tree] + input.column] = 0;
        }
        var count: usize = 0;
        for (slots) |slot| if (slot != missing) {
            count += 1;
        };
        const sources = try a.alloc(usize, count);
        errdefer a.free(sources);
        var at: usize = 0;
        for (slots, 0..) |*slot, i| if (slot.* != missing) {
            slot.* = @intCast(at);
            sources[at] = i;
            at += 1;
        };
        const masks = try a.alloc(u32, inputs.len);
        errdefer a.free(masks);
        for (inputs, masks) |input, *mask| mask.* = slots[bases[input.tree] + input.column];
        return .{ .source_indices = sources, .mask_slots = masks };
    }

    pub fn deinit(self: *Selection, a: std.mem.Allocator) void {
        a.free(self.source_indices);
        a.free(self.mask_slots);
        self.* = undefined;
    }
};

test "composition selection preserves trees, aliases and original source indices" {
    const Input = struct { tree: u8, column: u32, offset: i8 = 0 };
    var selected = try Selection.init(std.testing.allocator, .{ 3, 4, 2 }, &[_]Input{
        .{ .tree = 1, .column = 2 },               .{ .tree = 0, .column = 2 },
        .{ .tree = 1, .column = 2, .offset = -1 }, .{ .tree = 2, .column = 1 },
    });
    defer selected.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(usize, &.{ 2, 5, 8 }, selected.source_indices);
    try std.testing.expectEqualSlices(u32, &.{ 1, 0, 1, 2 }, selected.mask_slots);
    try std.testing.expectError(error.InvalidCompositionInputs, Selection.init(std.testing.allocator, .{ 3, 4, 2 }, &[_]Input{.{ .tree = 2, .column = 2 }}));
}
