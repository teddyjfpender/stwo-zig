//! Finite, independently reconstructed five-tree shared Keccak geometry.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const K = @import("../air/guest_precompile/keccakf_component.zig");
const T = @import("../air/guest_precompile/keccakf_table_component.zig");
const Tables = @import("../air/guest_precompile/keccakf_tables.zig");
const Layout = @import("block_v7_keccak_window_layout_v1.zig");
const Memory = @import("block_v7_keccak_window_memory_v1.zig");
const Lookup = @import("block_v7_keccak_window_lookup_v1.zig");
const Source = @import("block_v7_keccak_batch_source_v1.zig");
pub const FIXED_PREFIX = K.preprocessed_column_count + 2 * T.preprocessed_column_count;
pub const ARITHMETIC_PREFIX = K.interaction_column_count + 2 * T.interaction_column_count;
pub const MEMORY_COLUMNS = Memory.SLOT_COUNT * Memory.INTERACTION_COUNT;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    layout: Layout.Owned,
    logs: [5][]u32,
    pub fn init(a: std.mem.Allocator, pin: Source.Pin, limits: Source.Limits) !Owned {
        if (pin.geometry.x0_local_custody_version != 1) return error.UnsupportedKeccakBatchRecipe;
        var layout = try pin.ownerLayout(a, limits);
        errdefer layout.deinit();
        var out = Owned{ .allocator = a, .layout = layout, .logs = @splat(&.{}) };
        errdefer for (out.logs) |logs| a.free(logs);
        const main = K.main_column_count + 2;
        out.logs[0] = try a.alloc(u32, FIXED_PREFIX + layout.windows.len + 8);
        out.logs[1] = try a.alloc(u32, main + 2 * T.main_column_count);
        out.logs[2] = try a.alloc(u32, Memory.SLOT_COUNT * @import("block_execution_integer_bridge_v2.zig").COLUMN_COUNT);
        out.logs[3] = try a.alloc(u32, ARITHMETIC_PREFIX + layout.windows.len * 12);
        out.logs[4] = try a.alloc(u32, MEMORY_COLUMNS + Lookup.SLOT_COUNT * 4);
        for (out.logs) |logs| @memset(logs, layout.log_size);
        inline for (.{ .{ 0, K.preprocessed_column_count, T.preprocessed_column_count }, .{ 1, main, T.main_column_count }, .{ 3, K.interaction_column_count, T.interaction_column_count } }) |part| {
            @memset(out.logs[part[0]][part[1]..][0..part[2]], Tables.logSize(.chi));
            @memset(out.logs[part[0]][part[1] + part[2] ..][0..part[2]], Tables.logSize(.xor5));
        }
        return out;
    }
    pub fn deinit(self: *Owned) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.layout.deinit();
        self.* = undefined;
    }
    pub fn clockOffset(self: *const Owned) usize {
        return FIXED_PREFIX + self.layout.windows.len;
    }
    /// All value allocations belong to a; an arena is convenient for callers.
    pub fn fixed(self: *const Owned, a: std.mem.Allocator) ![]Column {
        const prefix = try @import("guest_precompile/ethereum_preprocessed.zig").generateKeccakPrefix(a, self.layout.log_size, @intCast(self.layout.calls));
        errdefer {
            for (prefix) |c| a.free(@constCast(c.values));
            a.free(prefix);
        }
        const owners = try self.layout.fixed(a);
        errdefer Layout.Owned.freeFixed(a, owners);
        const clocks = try self.layout.clockFixed(a);
        errdefer Layout.Owned.freeFixed(a, clocks);
        const out = try a.alloc(Column, prefix.len + owners.len + clocks.len);
        @memcpy(out[0..prefix.len], prefix);
        @memcpy(out[prefix.len..][0..owners.len], owners);
        @memcpy(out[prefix.len + owners.len ..], clocks);
        a.free(prefix);
        a.free(owners);
        a.free(clocks);
        return out;
    }
};
