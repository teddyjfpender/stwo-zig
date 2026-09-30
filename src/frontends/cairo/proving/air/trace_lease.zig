//! Per-component expansion of coefficient-backed trace columns.
//! The source trace remains immutable. Duplicate mask reads share one buffer;
//! the caller retains this lease until all native, SIMD or device work joins.
//!
//! A captured component reads each column on the canonic coset of log size
//! `t + (evaluation_log_size - trace_log_size)`, `t` being the column's own
//! trace log size (smaller columns are then lifted by the mask resolver).
//! Under blowup 1 that coset is the committed evaluation itself. A column
//! with no retained evaluation (compact storage) or committed on a larger
//! coset (blowup above the constraint degree, as the circuit lane's blowup-3
//! proofs are) is evaluated from its coefficients on that coset instead.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("../../witness/composition_bundle.zig");
const geometry = @import("../../witness/resident_geometry.zig");
const M31 = core.fields.m31.M31;
const Trace = prover.air.component_prover.Trace;
const Poly = prover.air.component_prover.Poly;
const circle = prover.poly.circle;
const twiddles = prover.poly.twiddles;

pub const ExpansionRequest = struct { coefficients: []const M31, values: []M31, log_size: u32 };
pub const ExpansionExecutor = struct {
    context: *anyopaque,
    run: *const fn (*anyopaque, std.mem.Allocator, []const ExpansionRequest) anyerror!void,
};

pub const Address = struct { tree: usize, column: usize };

pub fn address(trace: *const Trace, captured: *const composition.Component, interaction: u8, local: u32) !Address {
    if (trace.polys.items.len < 3) return error.InvalidTraceShape;
    const index: usize = switch (interaction) {
        0 => blk: {
            if (local >= captured.preprocessed_indices.len) return error.InvalidTraceShape;
            break :blk captured.preprocessed_indices[local];
        },
        1, 2 => blk: {
            const span = try geometry.componentSpan(captured.*, interaction);
            const global = std.math.add(usize, span.start, local) catch return error.InvalidTraceShape;
            if (global >= span.end) return error.InvalidTraceShape;
            break :blk global;
        },
        else => return error.InvalidTraceShape,
    };
    if (index >= trace.polys.items[interaction].len) return error.InvalidTraceShape;
    return .{ .tree = interaction, .column = index };
}

const BufferOwner = union(enum) {
    host: []M31,
    native: []align(std.heap.page_size_max) M31,

    fn values(self: BufferOwner) []M31 {
        return switch (self) {
            .host => |owner| owner,
            .native => |owner| owner,
        };
    }

    fn deinit(self: BufferOwner, a: std.mem.Allocator) void {
        switch (self) {
            .host => |owner| a.free(owner),
            .native => |owner| a.free(owner),
        }
    }
};

/// The log size of the coset `captured` reads `column` on: the column's
/// trace log size (its coefficient count, or its committed log size under
/// blowup 1 when no coefficients are retained) plus the component's
/// evaluation blowup.
fn evaluationLogSize(column: Poly, captured: *const composition.Component) !u32 {
    const blowup = std.math.sub(u32, captured.evaluation_log_size, captured.trace_log_size) catch
        return error.InvalidTraceShape;
    const target = if (column.coefficients) |coefficients| blk: {
        const count = coefficients.coefficients().len;
        if (count == 0 or !std.math.isPowerOfTwo(count)) return error.InvalidTraceShape;
        break :blk @as(u32, @intCast(std.math.log2_int(usize, count))) + blowup;
    } else column.log_size;
    if (target > captured.evaluation_log_size) return error.InvalidTraceShape;
    if (column.values.len == 0 and column.coefficients == null) return error.InvalidTraceShape;
    if (column.log_size < target) return error.InvalidTraceShape;
    if (column.log_size != target and column.coefficients == null) return error.InvalidTraceShape;
    return target;
}

pub const Lease = struct {
    allocator: std.mem.Allocator,
    source: *const Trace,
    expanded: ?Trace = null,
    buffers: std.ArrayList(BufferOwner) = .empty,

    pub fn trace(self: *const Lease) *const Trace {
        return if (self.expanded) |*view| view else self.source;
    }

    pub fn deinit(self: *Lease) void {
        for (self.buffers.items) |buffer| buffer.deinit(self.allocator);
        self.buffers.deinit(self.allocator);
        if (self.expanded) |view| {
            for (view.polys.items) |columns| self.allocator.free(columns);
            self.allocator.free(view.polys.items);
        }
        self.* = undefined;
    }

    pub fn init(a: std.mem.Allocator, source: *const Trace, captured: *const composition.Component) !Lease {
        return initWithExecutor(a, source, captured, null);
    }

    pub fn initWithExecutor(a: std.mem.Allocator, source: *const Trace, captured: *const composition.Component, executor: ?ExpansionExecutor) !Lease {
        var result = Lease{ .allocator = a, .source = source };
        errdefer result.deinit();
        var keys = std.ArrayList(Address).empty;
        defer keys.deinit(a);
        var max_log: u32 = 0;
        for (captured.parts) |part| for (part.program.base_insts) |instruction| {
            if (instruction.op != .trace_col and instruction.op != .preprocessed_col) continue;
            const key = try address(source, captured, instruction.interaction, instruction.a);
            const column = source.polys.items[key.tree][key.column];
            try column.validate();
            const target_log = try evaluationLogSize(column, captured);
            if (column.values.len != 0 and column.log_size == target_log) continue;
            var exists = false;
            for (keys.items) |prior| if (prior.tree == key.tree and prior.column == key.column) {
                exists = true;
                break;
            };
            if (exists) continue;
            try keys.append(a, key);
            max_log = @max(max_log, target_log);
        };
        // Ordinary evaluation-backed proofs incur no allocation or FFT.
        if (keys.items.len == 0) return result;
        const trees = try a.alloc([]const Poly, source.polys.items.len);
        var copied: usize = 0;
        errdefer {
            for (trees[0..copied]) |columns| a.free(columns);
            a.free(trees);
        }
        for (source.polys.items, trees) |columns, *owned| {
            owned.* = try a.dupe(Poly, columns);
            copied += 1;
        }
        var transform: ?twiddles.TwiddleTree([]M31) = if (executor == null)
            try twiddles.precomputeM31(a, circle.CanonicCoset.new(max_log).circleDomain().half_coset)
        else
            null;
        defer if (transform) |*owned| twiddles.deinitM31(a, owned);
        if (executor != null) {
            const Sort = struct {
                trace: *const Trace,
                fn less(self: @This(), left: Address, right: Address) bool {
                    return self.log(left) < self.log(right);
                }
                fn log(self: @This(), key: Address) u32 {
                    return @intCast(std.math.log2_int(usize, self.trace.polys.items[key.tree][key.column].coefficients.?.coefficients().len));
                }
            };
            std.sort.heap(Address, keys.items, Sort{ .trace = source }, Sort.less);
        }
        const Job = struct {
            coefficients: []const M31,
            values: []M31,
            log_size: u32,
            transform: ?twiddles.TwiddleTree([]const M31),
            failure: ?anyerror = null,
            fn run(self: *@This()) void {
                @memcpy(self.values[0..self.coefficients.len], self.coefficients);
                @memset(self.values[self.coefficients.len..], M31.zero());
                circle.poly.evaluateBuffersWithTwiddles(&.{self.values}, circle.CanonicCoset.new(self.log_size).circleDomain(), self.transform.?) catch |err| {
                    self.failure = err;
                };
            }
        };
        const jobs = try a.alloc(Job, keys.items.len);
        defer a.free(jobs);
        try result.buffers.ensureTotalCapacity(a, keys.items.len);
        var next: usize = 0;
        while (next < keys.items.len) {
            const first = keys.items[next];
            const log = try evaluationLogSize(source.polys.items[first.tree][first.column], captured);
            var end = next + 1;
            if (executor != null) while (end < keys.items.len and try evaluationLogSize(source.polys.items[keys.items[end].tree][keys.items[end].column], captured) == log) : (end += 1) {};
            const rows = @as(usize, 1) << @intCast(log);
            const cells = try std.math.mul(usize, rows, end - next);
            const owned: BufferOwner = if (executor != null)
                .{ .native = try a.alignedAlloc(M31, comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max), cells) }
            else
                .{ .host = try a.alloc(M31, cells) };
            result.buffers.appendAssumeCapacity(owned);
            const owner = owned.values();
            for (keys.items[next..end], jobs[next..end], 0..) |key, *job, i| {
                const column = source.polys.items[key.tree][key.column];
                const values = owner[i * rows ..][0..rows];
                @constCast(trees[key.tree])[key.column].values = values;
                @constCast(trees[key.tree])[key.column].log_size = log;
                job.* = .{ .coefficients = column.coefficients.?.coefficients(), .values = values, .log_size = log, .transform = if (transform) |t| .{ .root_coset = t.root_coset, .twiddles = t.twiddles, .itwiddles = t.itwiddles } else null };
            }
            next = end;
        }
        if (executor) |native| {
            const requests = try a.alloc(ExpansionRequest, jobs.len);
            defer a.free(requests);
            for (jobs, requests) |job, *request| request.* = .{ .coefficients = job.coefficients, .values = job.values, .log_size = job.log_size };
            try native.run(native.context, a, requests);
        } else if (prover.work_pool.getGlobalPool()) |pool| {
            var group: std.Thread.WaitGroup = .{};
            for (jobs[1..]) |*job| pool.spawnWg(&group, Job.run, .{job});
            jobs[0].run();
            group.wait();
        } else for (jobs) |*job| job.run();
        for (jobs) |job| if (job.failure) |err| return err;
        result.expanded = source.*;
        result.expanded.?.polys = core.pcs.TreeVec([]const Poly).initOwned(trees);
        return result;
    }
};

/// Row tiles of the composition domain for coefficient-backed columns: the
/// low-memory alternative to `Lease` (design §9.3, recompute per tile).
///
/// A tile is an aligned run of `2^tile_log` bit-reversed rows of the
/// evaluation domain. At mask offset zero a row reads each column at
/// `((row >> s) << 1) + (row & 1)` (`simd_evaluator.ResolvedColumn`), so a
/// tile reads one contiguous bit-reversed block of each column's own coset
/// evaluation, which `prover.poly.circle.coset_blocks` evaluates from the
/// column's coefficients exactly (equal to the whole-coset FFT's values).
///
/// A read at a nonzero mask offset (LogUp's previous-row read) maps a tile's
/// rows into a few other blocks: a trace step rotates the half coset one way
/// and its conjugate the other. Those blocks are evaluated the same way and
/// gathered into a row-ordered halo (`ResolvedColumn.row_indexed`).
///
/// Only the tile's blocks, its group prefolds and its halos are resident:
/// about `budget + group_budget` bytes instead of every column's whole coset.
pub const Tiles = struct {
    allocator: std.mem.Allocator,
    source: *const Trace,
    trace_log: u32,
    evaluation_log: u32,
    tile_log: u32,
    /// Columns read at offset zero and their coset polynomials.
    keys: []Address,
    sources: []coset_blocks.Source,
    blocks: coset_blocks.Tiles,
    /// `slot_of[tree][column]`: index into `keys`, or `none`.
    slot_of: [][]u32,
    /// Columns read at a nonzero offset, gathered per tile into `halo_arena`
    /// (`tileRows()` values each).
    shifted: []Shifted,
    halo_arena: []M31,
    loaded: ?usize = null,

    const none = std.math.maxInt(u32);
    const coset_blocks = circle.coset_blocks;

    pub const Shifted = struct {
        key: Address,
        mask_offset: i32,
        coset_log: u32,
        block_log: u32,
    };

    pub const View = struct {
        values: []const M31,
        /// Index of `values[0]`: in the column's coset evaluation for a
        /// block, or the tile's first row for a row-indexed halo.
        base: usize,
        coset_log: u32,
        row_indexed: bool = false,
    };

    /// Plans tiles of about `budget` bytes (plus `group_budget` of group
    /// prefolds). Null when no column needs expanding or when the whole
    /// expansion already fits `budget`.
    pub fn plan(a: std.mem.Allocator, source: *const Trace, captured: *const composition.Component, budget: usize, group_budget: usize) !?Tiles {
        var keys = std.ArrayList(Address).empty;
        defer keys.deinit(a);
        var logs = std.ArrayList(u32).empty;
        defer logs.deinit(a);
        var shifted = std.ArrayList(Shifted).empty;
        defer shifted.deinit(a);
        for (captured.parts) |part| for (part.program.base_insts) |instruction| {
            if (instruction.op != .trace_col and instruction.op != .preprocessed_col) continue;
            const key = try address(source, captured, instruction.interaction, instruction.a);
            const column = source.polys.items[key.tree][key.column];
            try column.validate();
            const target_log = try evaluationLogSize(column, captured);
            if (column.values.len != 0 and column.log_size == target_log) continue;
            if (instruction.imm != 0) {
                for (shifted.items) |prior| {
                    if (prior.key.tree == key.tree and prior.key.column == key.column and prior.mask_offset == instruction.imm) break;
                } else try shifted.append(a, .{ .key = key, .mask_offset = instruction.imm, .coset_log = target_log, .block_log = 0 });
                continue;
            }
            for (keys.items) |prior| {
                if (prior.tree == key.tree and prior.column == key.column) break;
            } else {
                try keys.append(a, key);
                try logs.append(a, target_log);
            }
        };
        if (keys.items.len == 0 and shifted.items.len == 0) return null;
        const evaluation_log = captured.evaluation_log_size;
        var full_bytes: usize = 0;
        for (logs.items) |log| full_bytes +|= @as(usize, 4) << @intCast(log);
        for (shifted.items) |entry| full_bytes +|= @as(usize, 4) << @intCast(entry.coset_log);
        if (full_bytes <= budget) return null;

        // Every block keeps at least `min_block_log` rows; a halo costs its
        // row buffer plus about three blocks.
        const min_block_log: u32 = 4;
        var max_lift: u32 = 0;
        for (logs.items) |log| max_lift = @max(max_lift, evaluation_log - log);
        for (shifted.items) |entry| max_lift = @max(max_lift, evaluation_log - entry.coset_log);
        if (max_lift + min_block_log >= evaluation_log) return null;
        const Halos = struct {
            shifted: []const Shifted,
            evaluation_log: u32,
            pub fn bytes(self: @This(), tile_log: u32) usize {
                var total: usize = 0;
                for (self.shifted) |entry| total +|= (@as(usize, 4) << @intCast(tile_log)) + (@as(usize, 12) << @intCast(tile_log - (self.evaluation_log - entry.coset_log)));
                return total;
            }
        };
        const tile_log = coset_blocks.chooseTileLog(logs.items, evaluation_log, max_lift + min_block_log, budget, Halos{ .shifted = shifted.items, .evaluation_log = evaluation_log });

        var result = Tiles{
            .allocator = a,
            .source = source,
            .trace_log = captured.trace_log_size,
            .evaluation_log = evaluation_log,
            .tile_log = tile_log,
            .keys = &.{},
            .sources = &.{},
            .blocks = undefined,
            .slot_of = &.{},
            .shifted = &.{},
            .halo_arena = &.{},
        };
        var blocks_live = false;
        errdefer {
            if (blocks_live) result.blocks.deinit();
            result.freeOwned();
        }
        result.keys = try a.dupe(Address, keys.items);
        result.sources = try a.alloc(coset_blocks.Source, keys.items.len);
        for (result.sources, keys.items, logs.items) |*entry, key, log| entry.* = .{
            .coefficients = source.polys.items[key.tree][key.column].coefficients.?.coefficients(),
            .coset_log = log,
        };
        result.slot_of = try a.alloc([]u32, source.polys.items.len);
        for (result.slot_of) |*row| row.* = &.{};
        for (result.slot_of, source.polys.items) |*row, columns| {
            row.* = try a.alloc(u32, columns.len);
            @memset(row.*, none);
        }
        for (result.keys, 0..) |key, index| result.slot_of[key.tree][key.column] = @intCast(index);
        result.shifted = try a.dupe(Shifted, shifted.items);
        for (result.shifted) |*entry| entry.block_log = tile_log - (evaluation_log - entry.coset_log);
        result.halo_arena = try a.alloc(M31, shifted.items.len << @intCast(tile_log));
        result.blocks = try coset_blocks.Tiles.init(a, result.sources, evaluation_log, tile_log, group_budget);
        blocks_live = true;
        return result;
    }

    fn freeOwned(self: *Tiles) void {
        const a = self.allocator;
        a.free(self.halo_arena);
        a.free(self.shifted);
        for (self.slot_of) |row| a.free(row);
        a.free(self.slot_of);
        a.free(self.sources);
        a.free(self.keys);
    }

    pub fn deinit(self: *Tiles) void {
        self.blocks.deinit();
        self.freeOwned();
        self.* = undefined;
    }

    pub fn tileCount(self: *const Tiles) usize {
        return @as(usize, 1) << @intCast(self.evaluation_log - self.tile_log);
    }

    pub fn tileRows(self: *const Tiles) usize {
        return @as(usize, 1) << @intCast(self.tile_log);
    }

    /// The loaded tile's view of `key` read at `mask_offset`, or null for a
    /// column read in place (committed evaluation, or not tiled).
    pub fn view(self: *const Tiles, key: Address, mask_offset: i32) ?View {
        const tile = self.loaded orelse return null;
        if (mask_offset != 0) {
            for (self.shifted, 0..) |entry, index| {
                if (entry.key.tree == key.tree and entry.key.column == key.column and entry.mask_offset == mask_offset) return .{
                    .values = self.halo_arena[index << @intCast(self.tile_log) ..][0..self.tileRows()],
                    .base = tile << @intCast(self.tile_log),
                    .coset_log = entry.coset_log,
                    .row_indexed = true,
                };
            }
            return null;
        }
        if (key.tree >= self.slot_of.len or key.column >= self.slot_of[key.tree].len) return null;
        const index = self.slot_of[key.tree][key.column];
        if (index == none) return null;
        return .{
            .values = self.blocks.block(index),
            .base = tile << @intCast(self.blocks.block_logs[index]),
            .coset_log = self.sources[index].coset_log,
        };
    }

    /// Evaluates every block `tile` reads, then gathers the halos, each
    /// phase one job per block or halo on the global pool.
    pub fn load(self: *Tiles, tile: usize) !void {
        const a = self.allocator;
        self.loaded = null;
        const first_row = tile << @intCast(self.tile_log);
        const rows = self.tileRows();

        // Halo blocks: the distinct blocks each shifted read's rows land in,
        // from each halo's per-row source indices (one job per halo).
        const indices = try a.alloc(u32, self.shifted.len * rows);
        defer a.free(indices);
        const index_jobs = try a.alloc(IndexJob, self.shifted.len);
        defer a.free(index_jobs);
        for (self.shifted, index_jobs, 0..) |entry, *job, index| job.* = .{
            .tiles = self,
            .entry = entry,
            .first_row = first_row,
            .indices = indices[index * rows ..][0..rows],
        };
        coset_blocks.runJobs(IndexJob, index_jobs);
        var halo_blocks = std.ArrayList(HaloBlock).empty;
        defer halo_blocks.deinit(a);
        const halo_starts = try a.alloc(usize, self.shifted.len + 1);
        defer a.free(halo_starts);
        var halo_scratch_len: usize = 0;
        for (self.shifted, index_jobs, 0..) |entry, job, index| {
            if (job.failure) |err| return err;
            halo_starts[index] = halo_blocks.items.len;
            for (job.blocks[0..job.n_blocks]) |block| {
                try halo_blocks.append(a, .{ .block = block, .offset = halo_scratch_len });
                halo_scratch_len += @as(usize, 1) << @intCast(entry.block_log);
            }
        }
        halo_starts[self.shifted.len] = halo_blocks.items.len;
        const halo_scratch = try a.alloc(M31, halo_scratch_len);
        defer a.free(halo_scratch);

        var shapes = coset_blocks.Shapes.init(a);
        defer shapes.deinit();
        var jobs = std.ArrayList(coset_blocks.BlockJob).empty;
        defer jobs.deinit(a);
        try self.blocks.prepare(&shapes, tile, &jobs);
        for (self.shifted, 0..) |entry, index| for (halo_blocks.items[halo_starts[index]..halo_starts[index + 1]]) |block| {
            const coefficients = self.source.polys.items[entry.key.tree][entry.key.column].coefficients.?.coefficients();
            try jobs.append(a, try shapes.blockJob(coefficients, entry.coset_log, block.block, halo_scratch[block.offset..][0 .. @as(usize, 1) << @intCast(entry.block_log)]));
        };
        coset_blocks.runJobs(coset_blocks.BlockJob, jobs.items);
        for (jobs.items) |job| if (job.failure) |err| return err;

        const gathers = try a.alloc(GatherJob, self.shifted.len);
        defer a.free(gathers);
        for (self.shifted, gathers, 0..) |entry, *job, index| job.* = .{
            .block_log = entry.block_log,
            .blocks = halo_blocks.items[halo_starts[index]..halo_starts[index + 1]],
            .scratch = halo_scratch,
            .indices = indices[index * rows ..][0..rows],
            .out = self.halo_arena[index << @intCast(self.tile_log) ..][0..rows],
        };
        coset_blocks.runJobs(GatherJob, gathers);
        self.loaded = tile;
    }

    /// The index in `entry`'s coset evaluation that row `row` reads at
    /// `mask_offset` (the SIMD evaluator's mapping).
    fn shiftedIndex(self: *const Tiles, row: usize, mask_offset: i32, shift: u32) usize {
        const position = core.utils.offsetBitReversedCircleDomainIndex(row, self.trace_log, self.evaluation_log, mask_offset);
        return ((position >> @intCast(shift)) << 1) + (position & 1);
    }

    const HaloBlock = struct { block: usize, offset: usize };

    const IndexJob = struct {
        tiles: *const Tiles,
        entry: Shifted,
        first_row: usize,
        indices: []u32,
        /// The distinct blocks `indices` land in; a trace step reaches at
        /// most a handful.
        blocks: [max_halo_blocks]usize = undefined,
        n_blocks: usize = 0,
        failure: ?anyerror = null,

        const max_halo_blocks = 8;

        pub fn run(self: *IndexJob) void {
            const shift = self.tiles.evaluation_log - self.entry.coset_log + 1;
            for (self.indices, self.first_row..) |*out, row| {
                const index = self.tiles.shiftedIndex(row, self.entry.mask_offset, shift);
                out.* = @intCast(index);
                const block = index >> @intCast(self.entry.block_log);
                for (self.blocks[0..self.n_blocks]) |prior| {
                    if (prior == block) break;
                } else {
                    if (self.n_blocks == max_halo_blocks) {
                        self.failure = error.InvalidTraceShape;
                        return;
                    }
                    self.blocks[self.n_blocks] = block;
                    self.n_blocks += 1;
                }
            }
        }
    };

    const GatherJob = struct {
        block_log: u32,
        blocks: []const HaloBlock,
        scratch: []const M31,
        indices: []const u32,
        out: []M31,

        pub fn run(self: *GatherJob) void {
            const mask = (@as(usize, 1) << @intCast(self.block_log)) - 1;
            for (self.out, self.indices) |*value, index| {
                const block = @as(usize, index) >> @intCast(self.block_log);
                const source = for (self.blocks) |candidate| {
                    if (candidate.block == block) break candidate;
                } else unreachable;
                value.* = self.scratch[source.offset + (index & mask)];
            }
        }
    };
};
