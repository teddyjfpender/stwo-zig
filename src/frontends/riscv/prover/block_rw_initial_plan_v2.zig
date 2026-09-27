//! Bounded chunk planner and shared BLAKE3 path witness for initial RW words.
const std = @import("std");
const core = @import("stwo_core");
const snapshot_mod = @import("../recursion/air/blake3_memory_snapshot.zig");
const memory_state = @import("../runner/memory_state.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const shared = @import("blake3_shared_path_emit.zig");
const census_mod = @import("block_rw_initial_census_v2.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const bus = @import("block_memory_relation_v2.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const air = @import("block_rw_initial_air_v2.zig");
const trace_mod = @import("block_rw_initial_trace_v2.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Row = air.Row;
const Layout = air.Layout;
const Trace = trace_mod.Trace;
const Interaction = air.Interaction;
const MAX_FIRST_TOUCH_KEYS_PER_CHUNK = air.MAX_FIRST_TOUCH_KEYS_PER_CHUNK;
const tupleFromRow = air.tupleFromRow;
const digestRoster = trace_mod.digestRoster;
const digestCompleteSparseRoster = trace_mod.digestCompleteSparseRoster;
const digestZeroQueryRoster = trace_mod.digestZeroQueryRoster;
const digestSparseShardRoster = trace_mod.digestSparseShardRoster;
const writeSecure = trace_mod.writeSecure;
const readSecure = trace_mod.readSecure;
pub const Census = census_mod.Census;
pub const censusAddresses = census_mod.censusAddresses;
pub const censusCompleteSparseAddresses = census_mod.censusCompleteSparseAddresses;
pub const censusZeroQueryAddresses = census_mod.censusZeroQueryAddresses;
pub const Plan = struct {
    allocator: std.mem.Allocator,
    source: *const snapshot_mod.Source,
    owned_source: ?*snapshot_mod.Source = null,
    addresses: []u32,
    path_inputs: []shared.Input,
    rows: []Row,
    caller_base: u32,
    path_namespace: u32,
    complete_sparse: bool = false,
    zero_query: bool = false,
    shard_coordinate: ?tree.Coordinate = null,
    shard_root: ?tree.Digest = null,

    pub fn initCompleteSparseShardBorrowed(a: std.mem.Allocator, source: *const snapshot_mod.Source, layout: memory_state.MemoryLayout, job: spans.JobContext, selected_addresses: []const u32, caller_base: u32, path_namespace: u32, coordinate: tree.Coordinate) !Plan {
        var result = try initBorrowed(a, source, layout, job, selected_addresses, caller_base, path_namespace);
        errdefer result.deinit();
        const indices = try a.alloc(u32, selected_addresses.len);
        defer a.free(indices);
        for (selected_addresses, indices) |address, *index| index.* = try tree.memoryIndex(address);
        var graph = try @import("blake3_shared_path_topology.zig").Graph.initSubtree(a, indices, coordinate.level, coordinate.index);
        graph.deinit();
        var roots: [1]tree.Digest = undefined;
        const hasher = tree.TreeHasher.init(.memory);
        try hasher.subtreeRoots(source.leaves, &.{coordinate}, &roots);
        result.complete_sparse = true;
        result.shard_coordinate = coordinate;
        result.shard_root = roots[0];
        return result;
    }

    /// Prove zero-valued first-touch keys under the same admitted root. The
    /// typed initial bus remains active, while the hash leaf is a fixed empty
    /// digest rather than a private word source.
    pub fn initZeroQueryBorrowed(a: std.mem.Allocator, source: *const snapshot_mod.Source, layout: memory_state.MemoryLayout, job: spans.JobContext, selected_addresses: []const u32, caller_base: u32, path_namespace: u32) !Plan {
        var result = try initBorrowed(a, source, layout, job, selected_addresses, caller_base, path_namespace);
        errdefer result.deinit();
        for (result.path_inputs, result.rows, result.addresses) |*input, *row, address| {
            if (sourceValue(source, address) != 0) return error.NonzeroInitialRwZeroQuery;
            input.constant_zero = true;
            row[Layout.active] = M.zero();
        }
        result.zero_query = true;
        return result;
    }

    /// The selected addresses must include every nonzero continuation leaf.
    /// The emitter proves this by fixing every unselected frontier subtree to
    /// its empty digest under the same admitted root.
    pub fn initCompleteSparseBorrowed(
        a: std.mem.Allocator,
        source: *const snapshot_mod.Source,
        layout: memory_state.MemoryLayout,
        job: spans.JobContext,
        selected_addresses: []const u32,
        caller_base: u32,
        path_namespace: u32,
    ) !Plan {
        var result = try initBorrowed(a, source, layout, job, selected_addresses, caller_base, path_namespace);
        result.complete_sparse = true;
        return result;
    }

    pub fn init(
        a: std.mem.Allocator,
        snapshot: *const memory_state.Snapshot,
        job: spans.JobContext,
        selected_addresses: []const u32,
        caller_base: u32,
        path_namespace: u32,
    ) !Plan {
        const source = try a.create(snapshot_mod.Source);
        errdefer a.destroy(source);
        source.* = try snapshot_mod.fromSnapshot(a, snapshot, .entry, .continuation);
        errdefer source.deinit();
        var result = try initBorrowed(a, source, snapshot.layout, job, selected_addresses, caller_base, path_namespace);
        result.owned_source = source;
        return result;
    }

    /// Reuse one continuation projection across sequential or parallel chunks.
    /// The borrowed source must outlive each plan and remain immutable.
    pub fn initBorrowed(
        a: std.mem.Allocator,
        source: *const snapshot_mod.Source,
        layout: memory_state.MemoryLayout,
        job: spans.JobContext,
        selected_addresses: []const u32,
        caller_base: u32,
        path_namespace: u32,
    ) !Plan {
        try job.validate();
        if (source.side != .entry or source.projection != .continuation) return error.InvalidInitialRwProjection;
        if (!std.meta.eql(source.root.bytes, job.complete.initial_state.rw_memory.bytes)) return error.InitialRwRootMismatch;
        if (selected_addresses.len == 0) return error.EmptyInitialRwRoster;
        if (selected_addresses.len > MAX_FIRST_TOUCH_KEYS_PER_CHUNK) return error.InitialRwChunkTooLarge;
        const upper = try std.math.add(u32, caller_base, std.math.cast(u32, selected_addresses.len) orelse return error.InitialRwCallerOverflow);
        if (upper > path_namespace or path_namespace >= core.fields.m31.Modulus) return error.InitialRwCallerOverlap;
        const addresses = try a.dupe(u32, selected_addresses);
        errdefer a.free(addresses);
        const inputs = try a.alloc(shared.Input, addresses.len);
        errdefer a.free(inputs);
        const rows = try a.alloc(Row, addresses.len);
        errdefer a.free(rows);
        for (addresses, inputs, rows, 0..) |address, *input, *row, i| {
            if (address & 3 != 0 or address >= tree.ADDRESS_LIMIT or
                !(layout.isRwAddr(address) or layout.isInputAddr(address)) or layout.isProgramAddr(address)) return error.InvalidInitialRwAddress;
            if (i != 0 and addresses[i - 1] >= address) return error.UnsortedInitialRwRoster;
            const circuit = caller_base + @as(u32, @intCast(i));
            const value = sourceValue(source, address);
            input.* = .{ .address = try tree.memoryIndex(address), .caller = .{ .circuit = circuit, .wire = 0 } };
            row.* = @splat(M.zero());
            for (0..4) |j| {
                row[Layout.value + j] = M.fromCanonical(@as(u8, @truncate(value >> @intCast(j * 8))));
                row[Layout.address + j] = M.fromCanonical(@as(u8, @truncate(address >> @intCast(j * 8))));
            }
            row[Layout.circuit] = M.fromCanonical(circuit);
            row[Layout.wire] = M.zero();
            row[Layout.active] = M.one();
            row[Layout.initial_emit] = M.one();
        }
        return .{ .allocator = a, .source = source, .addresses = addresses, .path_inputs = inputs, .rows = rows, .caller_base = caller_base, .path_namespace = path_namespace };
    }

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.rows);
        self.allocator.free(self.path_inputs);
        self.allocator.free(self.addresses);
        if (self.owned_source) |source| {
            source.deinit();
            self.allocator.destroy(source);
        }
        self.* = undefined;
    }

    /// The sink must be the same typed hash-component sink whose recursion-wire
    /// interactions are closed against this provider's emitted source tuples.
    pub fn emitPaths(self: *const Plan, sink: anytype) !u32 {
        return if (self.shard_coordinate) |coordinate|
            shared.emitCompleteSparseSubtree(self.allocator, self.path_inputs, self.path_namespace, .memory, self.shard_root.?, self.source.leaves, coordinate, sink)
        else if (self.complete_sparse)
            shared.emitCompleteSparse(self.allocator, self.path_inputs, self.path_namespace, .memory, self.source.root, self.source.leaves, sink)
        else
            shared.emit(self.allocator, self.path_inputs, self.path_namespace, .memory, self.source.root, self.source.leaves, sink);
    }

    /// Exact hash-component row census from the same path emitter used for
    /// witness generation. Planning a chunk does not materialize hash rows.
    pub fn census(self: *const Plan) !Census {
        return if (self.shard_coordinate) |coordinate|
            census_mod.censusSparseShardAddresses(self.allocator, self.addresses, self.caller_base, self.path_namespace, coordinate)
        else
            census_mod.censusMode(self.allocator, self.addresses, self.caller_base, self.path_namespace, if (self.complete_sparse) .complete_sparse else if (self.zero_query) .zero_query else .ordinary);
    }

    pub fn tuple(self: *const Plan, index: usize) !bus.InitialTuple {
        if (index >= self.rows.len) return error.InitialRwRowOutOfRange;
        return tupleFromRow(self.rows[index]);
    }

    pub fn initialClaim(self: *const Plan, challenges: *const bus.Challenges) !Q {
        var sum = Q.zero();
        for (self.rows) |row| sum = sum.add(try challenges.initial.combineBase(tupleFromRow(row)).inv());
        return sum;
    }

    pub fn rosterDigest(self: *const Plan) [32]u8 {
        return if (self.zero_query)
            digestZeroQueryRoster(self.source.root, self.addresses, self.caller_base, self.path_namespace)
        else if (self.shard_coordinate) |coordinate|
            digestSparseShardRoster(self.source.root, self.shard_root.?, coordinate, self.addresses, self.caller_base, self.path_namespace)
        else if (self.complete_sparse)
            digestCompleteSparseRoster(self.source.root, self.addresses, self.caller_base, self.path_namespace)
        else
            digestRoster(self.source.root, self.addresses, self.caller_base, self.path_namespace);
    }

    pub fn trace(self: *const Plan) !Trace {
        const log_size: u32 = @max(2, std.math.log2_int_ceil(usize, self.rows.len));
        if (log_size > 30) return error.InvalidInitialRwClaim;
        const size: usize = @as(usize, 1) << @intCast(log_size);
        const storage = try self.allocator.alloc(M, 14 * size);
        errdefer self.allocator.free(storage);
        @memset(storage, M.zero());
        var result: Trace = .{ .allocator = self.allocator, .log_size = log_size, .fixed = undefined, .main = undefined, .storage = storage };
        for (&result.fixed, 0..) |*column, i| column.* = storage[i * size ..][0..size];
        for (&result.main, 0..) |*column, i| column.* = storage[(10 + i) * size ..][0..size];
        for (0..size) |logical| {
            const committed = framework.committedRow(logical, log_size);
            result.fixed[9][committed] = M.fromCanonical(@intFromBool(logical + 1 == size));
            if (logical >= self.rows.len) continue;
            const row = self.rows[logical];
            for (0..4) |i| {
                result.fixed[i][committed] = row[Layout.address + i];
                result.main[i][committed] = row[Layout.value + i];
            }
            result.fixed[4][committed] = row[Layout.circuit];
            result.fixed[5][committed] = row[Layout.wire];
            result.fixed[6][committed] = row[Layout.active];
            result.fixed[7][committed] = row[Layout.initial_emit];
            result.fixed[8][committed] = M.fromCanonical(@intFromBool(logical == 0));
        }
        return result;
    }

    /// Generate the positive initial interaction and its inclusive prefix.
    /// This is witness construction; the quotient above supplies proof
    /// authority only when used in a PCS component with the same fixed rows.
    pub fn interaction(self: *const Plan, challenges: *const bus.Challenges) !Interaction {
        const log_size: u32 = @max(2, std.math.log2_int_ceil(usize, self.rows.len));
        if (log_size > 30) return error.InvalidInitialRwClaim;
        const size: usize = @as(usize, 1) << @intCast(log_size);
        const storage = try self.allocator.alloc(M, 8 * size);
        errdefer self.allocator.free(storage);
        var columns: [8][]M = undefined;
        for (&columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
        var sum = Q.zero();
        for (0..size) |logical| {
            const term = if (logical < self.rows.len and self.rows[logical][Layout.initial_emit].toU32() != 0) try challenges.initial.combineBase(tupleFromRow(self.rows[logical])).inv() else Q.zero();
            sum = sum.add(term);
            writeSecure(&columns, 0, framework.committedRow(logical, log_size), term);
        }
        const shifted = try sum.divM31(M.fromCanonical(@intCast(size)));
        var prefix = Q.zero();
        for (0..size) |logical| {
            const index = framework.committedRow(logical, log_size);
            prefix = prefix.add(readSecure(&columns, 0, index)).sub(shifted);
            writeSecure(&columns, 4, index, prefix);
        }
        if (!prefix.isZero()) return error.InvalidInitialRwInteractionPrefix;
        return .{ .allocator = self.allocator, .columns = columns, .storage = storage, .claim = .{
            .roster_digest = self.rosterDigest(),
            .row_count = @intCast(self.rows.len),
            .log_size = log_size,
            .initial_sum = sum,
        } };
    }
};

fn sourceValue(source: *const snapshot_mod.Source, address: u32) u32 {
    var lo: usize = 0;
    var hi = source.words.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (source.words[mid].addr < address) lo = mid + 1 else hi = mid;
    }
    return if (lo < source.words.len and source.words[lo].addr == address) source.words[lo].initial_word else 0;
}
