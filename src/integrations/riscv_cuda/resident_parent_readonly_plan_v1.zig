//! Cold grouping of the original read-only table schedule. No input values,
//! numeric indices or CPU sorting permutation are accepted by this compiler.
const std = @import("std");
const core = @import("stwo_core");
const Storage = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Program = @import("resident_parent_program_v1.zig");
const Writers = @import("resident_parent_direct_writers_v1.zig");
pub const Group = extern struct { table: u32, chain: u32, first: u32, count: u32 };
pub const Limits = struct { max_entries: usize = 1 << 24, max_tables: usize = 4096, max_device_bytes: usize = 1 << 30 };
pub const Data = struct {
    groups: []const Group,
    input_rows: []const u32,
    output_rows: []const u32,
    input_log: u32,
    argument_rows: usize,
    max_group_entries: usize,
    /// Includes both index maps, four radix arrays, and final dynamic arguments;
    /// excludes CUB's explicitly queried temporary bytes and the main tree.
    resident_bytes_without_cub: usize,
    identity: [32]u8,
};
const Owned = struct { a: std.mem.Allocator, arena: std.heap.ArenaAllocator, data: Data };
pub const Plan = opaque {
    pub fn derive(a: std.mem.Allocator, program: *const Program.Owned, inputs: []const Storage.FixedRow(Storage.Airs[17]), outputs: []const Storage.FixedRow(Storage.Airs[16]), limits: Limits) !*Plan {
        if (inputs.len == 0 or inputs.len != outputs.len or inputs.len > limits.max_entries or
            inputs.len > 1 << 24 or limits.max_tables == 0 or limits.max_device_bytes == 0)
            return error.InvalidResidentReadonlyGeometry;
        const p = program.view();
        try p.admission.validate();
        if (inputs.len > @as(usize, 1) << @intCast(p.cohorts[17].trace_log) or
            outputs.len > @as(usize, 1) << @intCast(p.cohorts[16].trace_log)) return error.InvalidResidentReadonlyGeometry;
        const owned = try a.create(Owned);
        errdefer a.destroy(owned);
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const alloc = arena.allocator();
        var ids: std.AutoHashMapUnmanaged(u32, u32) = .{};
        var tables: std.ArrayList(u32) = .empty;
        for (inputs) |row| {
            const words = toWords(row);
            _ = try Writers.fixedRow(17, &words);
            const result = try ids.getOrPut(alloc, words[5]);
            if (!result.found_existing) {
                if (tables.items.len == limits.max_tables) return error.ResidentReadonlyResourceLimit;
                result.value_ptr.* = @intCast(tables.items.len);
                try tables.append(alloc, words[5]);
            }
        }
        std.mem.sort(u32, tables.items, {}, std.sort.asc(u32));
        for (tables.items, 0..) |table, i| ids.getPtr(table).?.* = @intCast(i);
        const groups = try alloc.alloc(Group, tables.items.len);
        const chains = try alloc.alloc(?u32, groups.len);
        @memset(chains, null);
        for (groups, tables.items) |*group, table| group.* = .{ .table = table, .chain = 0, .first = 0, .count = 0 };
        for (inputs) |row| groups[ids.get(row[5].v).?].count += 1;
        var first: u32 = 0;
        var max_group: usize = 0;
        for (groups) |*group| {
            group.first = first;
            first += group.count;
            max_group = @max(max_group, group.count);
        }
        const input_rows = try alloc.alloc(u32, inputs.len);
        const output_rows = try alloc.alloc(u32, outputs.len);
        @memset(output_rows, std.math.maxInt(u32));
        const cursors = try alloc.alloc(u32, groups.len);
        for (groups, cursors) |group, *cursor| cursor.* = group.first;
        for (inputs, 0..) |row, i| {
            const slot = ids.get(row[5].v).?;
            input_rows[cursors[slot]] = @intCast(i);
            cursors[slot] += 1;
        }
        for (outputs, 0..) |row, i| {
            const words = toWords(row);
            _ = try Writers.fixedRow(16, &words);
            const slot = ids.get(words[2]) orelse return error.UnclosedResidentReadonlyTable;
            const group = &groups[slot];
            const rank = words[4];
            if (rank >= group.count or words[0] != 1 or words[1] != @intFromBool(rank == 0) or
                words[5] != @intFromBool(rank + 1 != group.count)) return error.InvalidResidentReadonlyRank;
            if (chains[slot]) |chain| {
                if (chain != words[3]) return error.InvalidResidentReadonlyChain;
            } else chains[slot] = words[3];
            const at = group.first + rank;
            if (output_rows[at] != std.math.maxInt(u32)) return error.DuplicateResidentReadonlyRank;
            output_rows[at] = @intCast(i);
        }
        for (output_rows) |row| if (row == std.math.maxInt(u32)) return error.UnclosedResidentReadonlyTable;
        for (groups, chains) |*group, chain| group.chain = chain orelse return error.UnclosedResidentReadonlyTable;
        const metadata = try std.math.add(usize, try std.math.mul(usize, groups.len, @sizeOf(Group)), try std.math.mul(usize, inputs.len, 8));
        const bytes = try std.math.add(usize, metadata, try std.math.add(usize, try std.math.mul(usize, max_group, 16), try std.math.mul(usize, outputs.len, 16)));
        if (bytes > limits.max_device_bytes) return error.ResidentReadonlyResourceLimit;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/resident-parent/readonly-routing/v1\x00");
        hash.update(&p.identity);
        for (groups) |group| inline for (std.meta.fields(Group)) |field| mix(&hash, @field(group, field.name));
        for (input_rows) |row| mix(&hash, row);
        for (output_rows) |row| mix(&hash, row);
        owned.* = .{ .a = a, .arena = arena, .data = .{ .groups = groups, .input_rows = input_rows, .output_rows = output_rows, .input_log = p.cohorts[17].trace_log, .argument_rows = outputs.len, .max_group_entries = max_group, .resident_bytes_without_cub = bytes, .identity = hash.finalResult() } };
        return @ptrCast(owned);
    }
    pub fn view(self: *const Plan) *const Data {
        const p: *const Owned = @ptrCast(@alignCast(self));
        return &p.data;
    }
    pub fn deinit(self: *Plan) void {
        const p: *Owned = @ptrCast(@alignCast(self));
        const a = p.a;
        p.arena.deinit();
        a.destroy(p);
    }
};
fn toWords(row: anytype) [row.len]u32 {
    var result: [row.len]u32 = undefined;
    for (row, &result) |value, *out| out.* = value.v;
    return result;
}
fn mix(hash: anytype, value: u32) void {
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, value, .little);
    hash.update(&word);
}

test "resident readonly plan derives grouping without values and rejects duplicate ranks" {
    const a = std.testing.allocator;
    var admission = try Program.fixtureAdmission();
    admission.key.log_sizes[16] = 2;
    admission.key.log_sizes[17] = 2;
    admission.expected_id = try admission.key.identity();
    const program = try Program.Owned.derive(a, admission, .{});
    defer program.deinit();
    var inputs: [3]Storage.FixedRow(Storage.Airs[17]) = undefined;
    var outputs: [3]Storage.FixedRow(Storage.Airs[16]) = undefined;
    for (&inputs, &outputs, 0..) |*input, *output, rank| {
        input.* = Storage.compactFixed(Storage.Airs[17], try Storage.Airs[17].fixedRow(.{ .index = .{ .circuit = 1, .wire = @intCast(2 * rank) }, .value = .{ .circuit = 1, .wire = @intCast(2 * rank + 1) }, .table = 10 }));
        output.* = Storage.compactFixed(Storage.Airs[16], try Storage.Airs[16].fixedRow(.{ .table = 10, .chain = 11, .rank = @intCast(rank), .last = rank == 2 }));
    }
    const plan = try Plan.derive(a, program, &inputs, &outputs, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.view().groups.len);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2 }, plan.view().input_rows);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2 }, plan.view().output_rows);
    outputs[1] = outputs[0];
    try std.testing.expectError(error.DuplicateResidentReadonlyRank, Plan.derive(a, program, &inputs, &outputs, .{}));
}
