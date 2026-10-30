//! One bounded shared arithmetic inventory and one shared RAM byte witness.
//! First roots enter the complete execution epoch before any challenge draw.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Source = @import("block_v7_keccak_batch_source_v1.zig");
const Geometry = @import("block_v7_keccak_batch_geometry_v1.zig");
const Trace = @import("../air/guest_precompile/keccakf_trace.zig");
const Counts = @import("../air/guest_precompile/keccakf_multiplicities.zig");
const Tables = @import("../air/guest_precompile/keccakf_tables.zig");
const Memory = @import("block_v7_keccak_window_memory_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
pub const Limits = struct {
    owners: Source.Limits = .{},
    memory: Memory.Limits = .{},
    max_arithmetic_bytes: usize = 768 << 20,
};
pub const Timings = struct { witness_ns: u64 = 0, fixed_commit_ns: u64 = 0, main_commit_ns: u64 = 0, access_commit_ns: u64 = 0 };
pub fn For(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, Suite.Hasher, Suite.MerkleChannel);
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        geometry: Geometry.Owned,
        counters: Counts.Counters,
        shard: Trace.Shard,
        memory: Memory.Prepared,
        snapshots: [Memory.SLOT_COUNT]Range.SNAPSHOT,
        fixed: []Column,
        main: []Column,
        access: []Column,
        scheme: Scheme,
        owns_scheme: bool = true,
        pin: Source.Pin,
        limits: Limits,
        timings: Timings = .{},
        pub fn init(a: std.mem.Allocator, records: []const @import("../runner/guest_precompile/keccakf_call_buffer.zig").Record, windows: []const Source.Window, index: u32, config: core.pcs.PcsConfig, byte_counter: *Counter, limits: Limits) !*Self {
            if (records.len == 0 or byte_counter.kind != .range_check_8_8) return error.InvalidKeccakBatchWitness;
            const self = try a.create(Self);
            errdefer a.destroy(self);
            var timer = try std.time.Timer.start();
            self.timings = .{};
            self.allocator = a;
            self.limits = limits;
            self.arena = std.heap.ArenaAllocator.init(a);
            errdefer self.arena.deinit();
            const raw = self.arena.allocator();
            const rows = try std.math.mul(usize, try std.math.divCeil(usize, records.len, 2), 29);
            self.pin = .{ .index = index, .windows = try raw.dupe(Source.Window, windows), .geometry = .{ .call_count = @intCast(records.len), .log_size = @max(5, std.math.log2_int_ceil(usize, rows)), .n_rows = @intCast(rows), .x0_local_custody_version = 1 }, .roots = undefined, .access_root = undefined, .config = config };
            self.geometry = try Geometry.Owned.init(a, self.pin, limits.owners);
            errdefer self.geometry.deinit();
            const main_cells = try std.math.mul(usize, @as(usize, 1) << @intCast(self.geometry.layout.log_size), Trace.Layout.main_columns + 2);
            if (try std.math.mul(usize, main_cells, @sizeOf(core.fields.m31.M31)) > limits.max_arithmetic_bytes) return error.KeccakBatchArithmeticLimit;
            self.counters = try Counts.Counters.init(a);
            errdefer self.counters.deinit();
            self.shard = try Trace.generateShardForRecipe(a, records, 0, &self.counters, Trace.maximum_log_size, true);
            errdefer self.shard.deinit();
            try self.counters.validateTotals();
            self.memory = try Memory.Prepared.init(a, &self.shard, &self.geometry.layout, limits.memory);
            errdefer self.memory.deinit();
            // Add exact original range requests only after all witness work succeeds.
            var local = try Counter.init(a, .range_check_8_8);
            defer local.deinit(a);
            self.snapshots = try self.memory.collectCounter(a, &local);
            self.fixed = try self.geometry.fixed(raw);
            self.main = try raw.alloc(Column, self.shard.mainColumnCount() + 2);
            for (self.main[0..self.shard.mainColumnCount()], 0..) |*column, i| column.* = .{ .log_size = self.shard.log_size, .values = self.shard.mainColumn(i) };
            inline for (.{ Tables.Kind.chi, Tables.Kind.xor5 }, 0..) |kind, i| self.main[self.shard.mainColumnCount() + i] = .{ .log_size = Tables.logSize(kind), .values = try self.counters.committedColumn(raw, kind) };
            self.access = try self.memory.columns(raw);
            self.scheme = try Scheme.init(a, config);
            errdefer self.scheme.deinit(a);
            self.owns_scheme = true;
            self.timings.witness_ns = timer.lap();
            var ch = Suite.Channel{};
            try self.scheme.commitBorrowedStreaming(a, self.fixed, 8, &ch);
            self.timings.fixed_commit_ns = timer.lap();
            try self.scheme.commitBorrowedStreaming(a, self.main, 8, &ch);
            self.timings.main_commit_ns = timer.lap();
            try self.scheme.commitBorrowedStreaming(a, self.access, 8, &ch);
            self.timings.access_commit_ns = timer.lap();
            self.pin.roots = .{ self.scheme.trees.items[0].commitment.root(), self.scheme.trees.items[1].commitment.root() };
            self.pin.access_root = self.scheme.trees.items[2].commitment.root();
            if (local.values.len != byte_counter.values.len) return error.InvalidKeccakBatchCounter;
            for (byte_counter.values, local.values) |*v, delta| v.* = v.add(delta);
            return self;
        }
        pub fn deinit(self: *Self) void {
            if (self.owns_scheme) self.scheme.deinit(self.allocator);
            self.memory.deinit();
            self.shard.deinit();
            self.counters.deinit();
            self.geometry.deinit();
            self.arena.deinit();
            self.allocator.destroy(self);
        }
    };
}
