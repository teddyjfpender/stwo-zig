//! Private RAM table witness. Frontiers and Poseidon rows are built once;
//! all multiplicities are sealed before challenges. Concrete main views use
//! either one owned ragged arena or the outer coordinator's borrowed arena.
const std = @import("std");
const core = @import("stwo_core");
const values = @import("values.zig");
const Native = @import("native_frontier.zig");
const batch = @import("batch.zig");
const policy = @import("policy.zig");
const CA = @import("chunk_air.zig");
const Cell = @import("cell_air.zig");
const Leaf = @import("leaf_air.zig");
const Node = @import("node_air.zig");
const Side = @import("side_air.zig");
const Permit = @import("permit_air.zig");
const PA = @import("policy_air.zig");
const Capture = @import("openings.zig");
pub const sameAllocator = @import("ownership.zig").same;
const physical = @import("../witness.zig").physical;
const universal = @import("../../../air/memory_commitment/poseidon2_universal_degree3_v1.zig");
const M = core.fields.m31.M31;
pub const Shapes = struct {
    chunk: CA.Shape,
    common_cells: Cell.Shape,
    edge_cells: Cell.Shape,
    leaf: Leaf.Shape,
    node: Node.Shape,
    side: Side.Shape,
    common_permits: Permit.Shape,
    edge_permits: Permit.Shape,
    provider_log: u32,
    pub fn validate(self: Shapes) !void {
        try self.chunk.validate();
        try self.common_cells.validate();
        try self.edge_cells.validate();
        try self.leaf.validate();
        try self.node.validate();
        try self.side.validate();
        try self.common_permits.validate();
        try self.edge_permits.validate();
        if (self.provider_log < 4 or self.provider_log > 24) return error.PrivateRamBatchResourceLimit;
    }
};
fn logSize(n: usize) !u32 {
    const log: u32 = @intCast(@max(4, std.math.log2_int_ceil(usize, @max(1, n))));
    if (log > 24) return error.PrivateRamBatchResourceLimit;
    return log;
}
fn view(backing: []M, cursor: *usize, width: usize, log: u32, clear: bool) []M {
    const len = width * (@as(usize, 1) << @intCast(log));
    const result = backing[cursor.*..][0..len];
    cursor.* += len;
    if (clear) @memset(result, M.zero());
    return result;
}
fn store(data: []M, log: u32, i: usize, row: []const M) void {
    const n = @as(usize, 1) << @intCast(log);
    const at = physical(i, log);
    std.debug.assert(data.len == n * row.len);
    for (row, 0..) |value, col| data[col * n + at] = value;
}
fn addBytes(counts: *[256]u64, row: []const M) !void {
    for (row) |value| {
        const byte = value.toU32();
        if (byte >= 256) return error.NoncanonicalPrivateRamByte;
        counts[byte] = try std.math.add(u64, counts[byte], 1);
    }
}
pub const Phase = enum { rows_ready, main_detached, interactions_ready, retired };
pub const EdgeCertificate = struct { opening: u32, cell: u16, grant: u16 };
pub const MainArena = struct { backing: []M, callers: [8][]M, provider: []M, policy: []M, byte_tail: []M, shapes: Shapes };
pub const Storage = enum { owned, borrowed };
pub const MainBuffers = struct {
    callers: [8][]M,
    provider: []M,
    policy_tail: []M,
    byte_tail: []M,
    pub fn validate(self: MainBuffers, shapes: Shapes, policy_size: usize) !void {
        try shapes.validate();
        for (TABLES) |table| if (self.callers[@intFromEnum(table)].len != try std.math.mul(usize, mainWidth(table), @as(usize, 1) << @intCast(tableLog(shapes, table)))) return error.InvalidPrivateRamMainBuffers;
        if (self.provider.len != try std.math.mul(usize, universal.N_MAIN_COLUMNS, @as(usize, 1) << @intCast(shapes.provider_log)) or self.policy_tail.len != policy_size or self.byte_tail.len != 256) return error.InvalidPrivateRamMainBuffers;
        var spans: [11][]M = undefined;
        @memcpy(spans[0..8], &self.callers);
        spans[8] = self.provider;
        spans[9] = self.policy_tail;
        spans[10] = self.byte_tail;
        for (spans, 0..) |first, i| for (spans[0..i]) |second| {
            const first_end = try std.math.add(usize, @intFromPtr(first.ptr), try std.math.mul(usize, first.len, @sizeOf(M)));
            const second_end = try std.math.add(usize, @intFromPtr(second.ptr), try std.math.mul(usize, second.len, @sizeOf(M)));
            if (@intFromPtr(first.ptr) < second_end and @intFromPtr(second.ptr) < first_end) return error.AliasedPrivateRamMainBuffers;
        };
    }
};
/// Small request preparation, before ANY wide allocation. Borrowed native
/// openings/policy stay immutable until construction; success consumes this
/// owner and the openings, failure consumes neither.
pub const Preparation = struct {
    allocator: std.mem.Allocator,
    mappings: *const policy.Policy,
    source: []const batch.Opening,
    shapes: Shapes,
    counts: batch.Counts,
    changes: []bool,
    indices: []u64,
    common_grants: []?usize,
    edge_certificates: []EdgeCertificate,
    observation: bool,
    available: bool = true,
    pub fn init(a: std.mem.Allocator, geometry: values.Geometry, mappings: *const policy.Policy, openings: []const batch.Opening) !Preparation {
        return initMode(a, geometry, mappings, openings, false);
    }
    pub fn initObservation(a: std.mem.Allocator, geometry: values.Geometry, mappings: *const policy.Policy, openings: []const batch.Opening) !Preparation {
        return initMode(a, geometry, mappings, openings, true);
    }
    fn initMode(a: std.mem.Allocator, geometry: values.Geometry, mappings: *const policy.Policy, openings: []const batch.Opening, observation: bool) !Preparation {
        try mappings.validate();
        if (observation) try batch.validateObservation(geometry, openings) else try batch.validate(geometry, openings);
        const changes = try a.alloc(bool, openings.len);
        errdefer a.free(changes);
        const counts = try batch.countPrepared(a, geometry, openings, changes, observation);
        const indices = try a.alloc(u64, openings.len);
        errdefer a.free(indices);
        for (indices, openings) |*index, opening| index.* = opening.index;
        const common_grants = try a.alloc(?usize, openings.len);
        errdefer a.free(common_grants);
        var edges: std.ArrayList(EdgeCertificate) = .empty;
        errdefer edges.deinit(a);
        var common_count: usize = 0;
        const span: policy.Span = if (geometry == .chunk512) .chunk512 else .page4096;
        for (common_grants, openings, 0..) |*grant, opening, i| {
            const mask = opening.rights[0];
            var uniform = mask != 0;
            for (opening.rights) |rights| uniform = uniform and rights == mask;
            grant.* = if (uniform) mappings.find(span, opening.index << geometry.logBytes(), mask) catch null else null;
            if (grant.* != null) {
                common_count += 1;
                continue;
            }
            for (opening.terminal_clocks, opening.rights, 0..) |clock, rights, cell| if (clock != 0) {
                const id = try mappings.find(.word8, (opening.index << geometry.logBytes()) + 8 * cell, rights);
                try edges.append(a, .{ .opening = @intCast(i), .cell = @intCast(cell), .grant = @intCast(id) });
            };
        }
        const edge_count = openings.len - common_count;
        const shapes = Shapes{
            .chunk = .{ .geometry = geometry, .hashes = @intCast(counts.leaves + counts.changed_leaves), .log_size = try logSize((counts.leaves + counts.changed_leaves) * (geometry.permutations() + 1)) },
            .common_cells = .{ .geometry = geometry, .chunks = @intCast(common_count), .log_size = try logSize(common_count * geometry.cells()), .policy_mode = .chunk },
            .edge_cells = .{ .geometry = geometry, .chunks = @intCast(edge_count), .log_size = try logSize(edge_count * geometry.cells()), .policy_mode = .word },
            .leaf = .{ .geometry = geometry, .leaves = @intCast(counts.leaves), .log_size = try logSize(counts.leaves) },
            .node = .{ .nodes = @intCast(counts.before_nodes + counts.after_nodes), .log_size = try logSize(counts.before_nodes + counts.after_nodes) },
            .side = .{ .geometry = geometry, .sides = @intCast(counts.sides), .log_size = try logSize(counts.sides) },
            .common_permits = .{ .span = span, .certificates = @intCast(common_count), .log_size = try logSize(common_count) },
            .edge_permits = .{ .span = .word8, .certificates = @intCast(edges.items.len), .log_size = try logSize(edges.items.len) },
            .provider_log = try logSize(try counts.permutations(geometry)),
        };
        try shapes.validate();
        return .{ .allocator = a, .mappings = mappings, .source = openings, .shapes = shapes, .counts = counts, .changes = changes, .indices = indices, .common_grants = common_grants, .edge_certificates = try edges.toOwnedSlice(a), .observation = observation };
    }
    fn validateSource(self: *const Preparation, a: std.mem.Allocator, geometry: values.Geometry, openings: []const batch.Opening) !void {
        if (!self.available or !sameAllocator(a, self.allocator) or self.shapes.chunk.geometry != geometry or openings.ptr != self.source.ptr or openings.len != self.source.len) return error.InvalidPrivateRamPreparation;
        try self.mappings.validate();
        if (self.observation) try batch.validateObservation(geometry, openings) else try batch.validate(geometry, openings);
        if (self.indices.len != openings.len or self.changes.len != openings.len or self.common_grants.len != openings.len) return error.InvalidPrivateRamPreparation;
        for (openings, self.indices, self.common_grants) |opening, index, grant| {
            if (opening.index != index or opening.before.len != geometry.cells() or opening.after.len != geometry.cells() or opening.terminal_clocks.len != geometry.cells() or opening.rights.len != geometry.cells() or (grant != null and grant.? >= self.mappings.grants.len)) return error.InvalidPrivateRamPreparation;
        }
        for (openings, self.changes) |opening, expected| {
            var changed = false;
            for (opening.before, opening.after) |before, after| changed = changed or before != after;
            if (changed != expected) return error.PrivateRamPreparationChanged;
        }
    }
    pub fn deinit(self: *Preparation) void {
        const a = self.allocator;
        a.free(self.changes);
        a.free(self.indices);
        a.free(self.common_grants);
        a.free(self.edge_certificates);
        self.* = undefined;
    }
};
pub const Trace = struct {
    allocator: std.mem.Allocator,
    shapes: Shapes,
    witness: batch.Witness,
    recorder: values.Recorder,
    chunk: []M,
    common_cells: []M,
    edge_cells: []M,
    leaf: []M,
    node: []M,
    side: []M,
    common_permits: []M,
    edge_permits: []M,
    provider: []M,
    byte_counts: [256]u64,
    policy_counts: []u64,
    main_backing: []M,
    policy_tail: []M,
    byte_tail: []M,
    captured: ?Capture.Owned = null,
    mappings: *const policy.Policy,
    common_grants: []?usize,
    cell_order: []u32,
    edge_certificates: []EdgeCertificate,
    clock_inverses: []M,
    phase: Phase = .rows_ready,
    storage: Storage = .owned,
    pub fn init(a: std.mem.Allocator, cache: *const values.Cache, mappings: *const policy.Policy, source: []const batch.Opening) !Trace {
        try batch.validate(cache.geometry, source);
        var owned = try Capture.Owned.copy(a, cache.geometry, source);
        errdefer owned.deinit();
        var result = try initCore(a, cache, mappings, owned.chunks, false);
        result.captured = owned;
        return result;
    }
    /// Move the already captured narrow chunk buffers. Failure leaves their
    /// original owner intact; success empties it without copying word arrays.
    pub fn initOwned(a: std.mem.Allocator, cache: *const values.Cache, mappings: *const policy.Policy, owned: *Capture.Owned) !Trace {
        if (!sameAllocator(a, owned.allocator)) return error.PrivateRamAllocatorMismatch;
        var result = try initCore(a, cache, mappings, owned.chunks, false);
        result.captured = owned.take();
        return result;
    }
    pub fn initObservation(a: std.mem.Allocator, cache: *const values.Cache, mappings: *const policy.Policy, source: []const batch.Opening) !Trace {
        try batch.validateObservation(cache.geometry, source);
        var owned = try Capture.Owned.copy(a, cache.geometry, source);
        errdefer owned.deinit();
        var result = try initCore(a, cache, mappings, owned.chunks, true);
        result.captured = owned;
        return result;
    }
    fn initCore(a: std.mem.Allocator, cache: *const values.Cache, mappings: *const policy.Policy, openings: []const batch.Opening, observation: bool) !Trace {
        var preparation = try Preparation.initMode(a, cache.geometry, mappings, openings, observation);
        defer preparation.deinit();
        return initPreparedCore(a, .{ .cache = cache }, &preparation, openings, null);
    }
    pub fn initPreparedBorrowedOwned(a: std.mem.Allocator, cache: *const values.Cache, preparation: *Preparation, owned: *Capture.Owned, buffers: MainBuffers) !Trace {
        if (!sameAllocator(a, owned.allocator)) return error.PrivateRamAllocatorMismatch;
        try @import("borrowed_admission.zig").validate(buffers, cache, preparation, owned);
        var result = try initPreparedCore(a, .{ .cache = cache }, preparation, owned.chunks, buffers);
        result.captured = owned.take();
        return result;
    }
    pub fn initFromPreparedGraphOwned(a: std.mem.Allocator, native: *Native.Prepared, preparation: *Preparation, owned: *Capture.Owned) !Trace {
        if (!sameAllocator(a, owned.allocator) or !sameAllocator(a, native.allocator)) return error.PrivateRamAllocatorMismatch;
        try native.requireMovable();
        var result = try initPreparedCore(a, .{ .prepared = native }, preparation, owned.chunks, null);
        result.captured = owned.take();
        return result;
    }
    pub fn initFromPreparedGraphBorrowedOwned(a: std.mem.Allocator, native: *Native.Prepared, preparation: *Preparation, owned: *Capture.Owned, buffers: MainBuffers) !Trace {
        if (!sameAllocator(a, owned.allocator) or !sameAllocator(a, native.allocator)) return error.PrivateRamAllocatorMismatch;
        try native.requireMovable();
        try @import("borrowed_admission.zig").validatePreparedGraph(buffers, native, preparation, owned);
        var result = try initPreparedCore(a, .{ .prepared = native }, preparation, owned.chunks, buffers);
        result.captured = owned.take();
        return result;
    }
    const GraphSource = union(enum) { cache: *const values.Cache, prepared: *Native.Prepared };
    fn initPreparedCore(a: std.mem.Allocator, source: GraphSource, preparation: *Preparation, openings: []const batch.Opening, external: ?MainBuffers) !Trace {
        const geometry = switch (source) {
            .cache => |cache| cache.geometry,
            .prepared => |native| native.witness.geometry,
        };

        try preparation.validateSource(a, geometry, openings);
        if (std.meta.activeTag(source) == .prepared) {
            const native = source.prepared;
            try native.requireMovable();
            try native.validate();
            if (!std.meta.eql(native.counts, preparation.counts)) return error.PrivateRamPreparationChanged;
            try native.validateOpenings(openings);
        }
        const mappings = preparation.mappings;
        const shapes = preparation.shapes;
        const common_grants = preparation.common_grants;
        const edge_metadata = preparation.edge_certificates;
        const common_count = shapes.common_cells.chunks;
        const span = shapes.common_permits.span;
        const policy_size = @as(usize, 1) << @intCast(try logSize(mappings.grants.len));
        var backing: []M = &.{};
        errdefer if (external == null) a.free(backing);
        var buffers: MainBuffers = undefined;
        if (external) |borrowed| {
            try borrowed.validate(shapes, policy_size);
            buffers = borrowed;
        } else {
            var total = try std.math.mul(usize, universal.N_MAIN_COLUMNS, @as(usize, 1) << @intCast(shapes.provider_log));
            for (TABLES) |table| total = try std.math.add(usize, total, try std.math.mul(usize, mainWidth(table), @as(usize, 1) << @intCast(tableLog(shapes, table))));
            total = try std.math.add(usize, total, policy_size + 256);
            backing = try a.alloc(M, total);
            var cursor: usize = 0;
            const provider = view(backing, &cursor, universal.N_MAIN_COLUMNS, shapes.provider_log, false);
            var callers: [8][]M = undefined;
            for (TABLES) |table| callers[@intFromEnum(table)] = view(backing, &cursor, mainWidth(table), tableLog(shapes, table), false);
            const policy_tail = backing[cursor..][0..policy_size];
            cursor += policy_size;
            const byte_tail = backing[cursor..][0..256];
            cursor += 256;
            @memset(policy_tail, M.zero());
            @memset(byte_tail, M.zero());
            std.debug.assert(cursor == backing.len);
            buffers = .{ .callers = callers, .provider = provider, .policy_tail = policy_tail, .byte_tail = byte_tail };
        }
        for (buffers.callers) |data| @memset(data, M.zero());
        const provider = buffers.provider;
        const chunk = buffers.callers[@intFromEnum(Table.chunk)];
        const common_cells = buffers.callers[@intFromEnum(Table.common_cells)];
        const edge_cells = buffers.callers[@intFromEnum(Table.edge_cells)];
        const leaf = buffers.callers[@intFromEnum(Table.leaf)];
        const node = buffers.callers[@intFromEnum(Table.node)];
        const side = buffers.callers[@intFromEnum(Table.side)];
        const common_permits = buffers.callers[@intFromEnum(Table.common_permits)];
        const edge_permits = buffers.callers[@intFromEnum(Table.edge_permits)];
        const policy_tail = buffers.policy_tail;
        const byte_tail = buffers.byte_tail;
        const cell_order = try a.alloc(u32, openings.len);
        errdefer a.free(cell_order);
        const clock_inverses = try a.alloc(M, openings.len * geometry.cells());
        errdefer a.free(clock_inverses);
        const policy_counts = try a.alloc(u64, mappings.grants.len);
        errdefer a.free(policy_counts);
        @memset(policy_counts, 0);
        var writer = try values.ProviderWriter.init(provider, shapes.provider_log);
        const detached = std.meta.activeTag(source) == .prepared;
        var recorder = if (detached) values.Recorder{ .allocator = a, .calls = .fromOwnedSlice(source.prepared.io) } else values.Recorder{ .allocator = a, .writer = &writer };
        // Detached descriptors are BORROWS until the final success barrier.
        errdefer if (!detached) recorder.deinit();
        var witness = if (detached) source.prepared.witness else try batch.Witness.initPrepared(a, source.cache, openings, &recorder, preparation.counts, preparation.changes);
        errdefer if (!detached) witness.deinit();
        if (detached) for (recorder.calls.items) |call| try writer.writeRecorded(call);
        try writer.finishPadding();
        recorder.writer = null;
        var byte_counts: [256]u64 = @splat(0);
        // Leaf permutations are contiguous BEFORE then changed AFTER messages;
        // internal-node permutations follow and use a separate caller table.
        for (0..shapes.chunk.hashes) |id| {
            var previous: [16]M = @splat(M.zero());
            for (0..geometry.permutations()) |phase| {
                const io = recorder.calls.items[id * geometry.permutations() + phase];
                var row: CA.Row = @splat(M.zero());
                @memcpy(row[CA.OUTPUT..][0..16], &io.output);
                if (phase < geometry.absorptions()) for (0..7) |lane| {
                    row[CA.PAYLOAD + lane] = io.input[lane].sub(previous[lane]);
                };
                row[CA.ACTIVE] = M.one();
                store(chunk, shapes.chunk.log_size, id * shapes.chunk.stride() + phase, &row);
                previous = io.output;
            }
            var reset: CA.Row = @splat(M.zero());
            reset[CA.ACTIVE] = M.one();
            store(chunk, shapes.chunk.log_size, id * shapes.chunk.stride() + geometry.permutations(), &reset);
        }
        var common_row: usize = 0;
        var edge_row: usize = 0;
        var common_permit_row: usize = 0;
        var edge_permit_row: usize = 0;
        for (openings, witness.leaves, common_grants, 0..) |opening, native_leaf, common_grant, i| {
            const header_row = try Leaf.fill(geometry, .{ .index = opening.index, .before_id = native_leaf.before_id, .after_id = native_leaf.after_id, .before = native_leaf.graph.before, .after = native_leaf.graph.after, .changed = native_leaf.graph.changed, .reuse = native_leaf.graph.reuse });
            store(leaf, shapes.leaf.log_size, i, &header_row);
            try addBytes(&byte_counts, header_row[0..15]);
            const base = opening.index << geometry.logBytes();
            cell_order[if (common_grant != null) common_row / geometry.cells() else common_count + edge_row / geometry.cells()] = @intCast(i);
            if (common_grant) |grant| {
                for (opening.rights) |rights| if (rights != mappings.grants[grant].mask) return error.PrivateRamPreparationChanged;
                const row = try Permit.fill(span, base, mappings.grants[grant]);
                store(common_permits, shapes.common_permits.log_size, common_permit_row, &row);
                common_permit_row += 1;
                policy_counts[grant] += 1;
                for (0..PA.RANGES) |j| try addBytes(&byte_counts, row[PA.rangeField(j)..][0..1]);
            }
            for (opening.before, opening.after, opening.terminal_clocks, opening.rights, 0..) |before, after, clock, rights, cell| {
                const row = try Cell.fill(geometry, .{ .base = base, .before_id = native_leaf.before_id, .after_id = native_leaf.after_id, .changed = native_leaf.graph.changed, .before = before, .after = after, .terminal_clock = clock, .readable = rights & 1 != 0, .writable = rights & 2 != 0 });
                clock_inverses[i * geometry.cells() + cell] = row[Cell.CLOCK_INVERSE];
                if (common_grant != null) {
                    store(common_cells, shapes.common_cells.log_size, common_row, &row);
                    common_row += 1;
                } else {
                    store(edge_cells, shapes.edge_cells.log_size, edge_row, &row);
                    edge_row += 1;
                }
                try addBytes(&byte_counts, row[0..19]);
                if (common_grant == null and clock != 0) {
                    if (edge_permit_row >= edge_metadata.len) return error.PrivateRamPreparationChanged;
                    const frozen = edge_metadata[edge_permit_row];
                    const grant = frozen.grant;
                    if (frozen.opening != i or frozen.cell != cell or grant >= mappings.grants.len or mappings.grants[grant].mask != rights) return error.PrivateRamPreparationChanged;
                    const certificate = try Permit.fill(.word8, base + 8 * cell, mappings.grants[grant]);
                    store(edge_permits, shapes.edge_permits.log_size, edge_permit_row, &certificate);
                    edge_permit_row += 1;
                    policy_counts[grant] += 1;
                    for (0..PA.RANGES) |j| try addBytes(&byte_counts, certificate[PA.rangeField(j)..][0..1]);
                }
            }
        }
        var node_row: usize = 0;
        for ([_][]const batch.Node{ witness.before_nodes, witness.after_nodes }, 0..) |list, epoch| for (list) |native_node| {
            const row = try Node.fill(native_node.graph.height, native_node.graph.index, @intCast(epoch), native_node.graph.reuse, native_node.graph.left, native_node.graph.right, recorder.calls.items[native_node.io..][0..4]);
            store(node, shapes.node.log_size, node_row, &row);
            node_row += 1;
            try addBytes(&byte_counts, row[Node.INDEX_BYTES..][0..14]);
        };
        for (witness.sides, 0..) |native_side, i| {
            const row = try Side.fill(geometry, native_side.height, native_side.index, native_side.digest, native_side.reuse);
            store(side, shapes.side.log_size, i, &row);
            try addBytes(&byte_counts, row[Side.INDEX_BYTES..][0..7]);
        }
        if (common_row != shapes.common_cells.activeRows() or edge_row != shapes.edge_cells.activeRows() or common_permit_row != shapes.common_permits.certificates or edge_permit_row != shapes.edge_permits.certificates) return error.PrivateRamPreparationChanged;
        if (detached) {
            const taken = try source.prepared.take();
            witness = taken.witness;
            recorder.calls = .fromOwnedSlice(taken.io);
        }
        preparation.common_grants = &.{};
        preparation.edge_certificates = &.{};
        preparation.available = false;
        return .{ .allocator = a, .shapes = shapes, .witness = witness, .recorder = recorder, .chunk = chunk, .common_cells = common_cells, .edge_cells = edge_cells, .leaf = leaf, .node = node, .side = side, .common_permits = common_permits, .edge_permits = edge_permits, .provider = provider, .byte_counts = byte_counts, .policy_counts = policy_counts, .main_backing = backing, .policy_tail = policy_tail, .byte_tail = byte_tail, .mappings = mappings, .common_grants = common_grants, .cell_order = cell_order, .edge_certificates = edge_metadata, .clock_inverses = clock_inverses, .storage = if (external == null) .owned else .borrowed };
    }
    /// All validation precedes the ownership handoff. The caller owns the
    /// returned ORIGINAL backing allocation, never an interior column slice.
    pub fn detachMain(self: *Trace, a: std.mem.Allocator, policy_main: []const M) !MainArena {
        if (!sameAllocator(a, self.allocator)) return error.PrivateRamAllocatorMismatch;
        if (self.storage != .owned) return error.PrivateRamBorrowedMain;
        if (self.phase != .rows_ready or self.main_backing.len == 0 or policy_main.len != self.policy_tail.len) return error.InvalidPrivateRamTracePhase;
        try self.validateMetadata();
        @memcpy(self.policy_tail, policy_main);
        var callers: [8][]M = undefined;
        for (TABLES) |table| callers[@intFromEnum(table)] = @constCast(mainData(self, table));
        const result = MainArena{ .backing = self.main_backing, .callers = callers, .provider = self.provider, .policy = self.policy_tail, .byte_tail = self.byte_tail, .shapes = self.shapes };
        self.clearMainViews();
        self.phase = .main_detached;
        return result;
    }
    /// The outer arena remains owned by its caller. Narrow metadata survives
    /// so challenges can be drawn after commitment and all wide sources freed.
    pub fn releaseBorrowedMain(self: *Trace) !void {
        if (self.storage != .borrowed or self.phase != .rows_ready) return error.InvalidPrivateRamTracePhase;
        try self.validateMetadata();
        self.clearMainViews();
        self.phase = .main_detached;
    }
    fn clearMainViews(self: *Trace) void {
        self.main_backing = &.{};
        self.policy_tail = &.{};
        self.byte_tail = &.{};
        self.provider = &.{};
        self.chunk = &.{};
        self.common_cells = &.{};
        self.edge_cells = &.{};
        self.leaf = &.{};
        self.node = &.{};
        self.side = &.{};
        self.common_permits = &.{};
        self.edge_permits = &.{};
    }
    pub fn validateMetadata(self: *const Trace) !void {
        if (self.phase == .retired or self.captured == null or self.captured.?.chunks.len != self.shapes.leaf.leaves or self.cell_order.len != self.shapes.leaf.leaves or self.common_grants.len != self.shapes.leaf.leaves or self.clock_inverses.len != @as(usize, self.shapes.leaf.leaves) * self.shapes.chunk.geometry.cells() or self.edge_certificates.len != self.shapes.edge_permits.certificates or self.recorder.calls.items.len != @as(usize, self.shapes.chunk.hashes) * self.shapes.chunk.geometry.permutations() + @as(usize, self.shapes.node.nodes) * 4) return error.InvalidPrivateRamTracePhase;
    }
    /// Restore only narrow canonical packets, never a S-box or CPU execution.
    /// The same native row constructors supply the committed main witness.
    pub fn restoreRow(self: *const Trace, table: Table, logical: usize, output: []M) !void {
        try self.validateMetadata();
        if (output.len != mainWidth(table)) return error.InvalidPrivateRamRows;
        @memset(output, M.zero());
        const geometry = self.shapes.chunk.geometry;
        const captured = self.captured.?.chunks;
        switch (table) {
            .chunk => {
                if (logical >= self.shapes.chunk.activeRows()) return;
                output[CA.ACTIVE] = M.one();
                const phase = logical % self.shapes.chunk.stride();
                if (phase == geometry.permutations()) return;
                const id = logical / self.shapes.chunk.stride();
                const io = self.recorder.calls.items[id * geometry.permutations() + phase];
                @memcpy(output[CA.OUTPUT..][0..16], &io.output);
                if (phase < geometry.absorptions()) for (0..7) |lane| {
                    const previous = if (phase == 0) M.zero() else self.recorder.calls.items[id * geometry.permutations() + phase - 1].output[lane];
                    output[CA.PAYLOAD + lane] = io.input[lane].sub(previous);
                };
            },
            .common_cells, .edge_cells => {
                const shape = if (table == .common_cells) self.shapes.common_cells else self.shapes.edge_cells;
                if (logical >= shape.activeRows()) return;
                const order = logical / geometry.cells() + if (table == .edge_cells) @as(usize, self.shapes.common_cells.chunks) else 0;
                const source = self.cell_order[order];
                const slot = logical % geometry.cells();
                const opening = captured[source];
                const leaf = self.witness.leaves[source];
                const flags = opening.rights[slot];
                const row = try Cell.restore(geometry, .{ .base = opening.index << geometry.logBytes(), .before_id = leaf.before_id, .after_id = leaf.after_id, .changed = leaf.graph.changed, .before = opening.before[slot], .after = opening.after[slot], .terminal_clock = opening.terminal_clocks[slot], .readable = flags & 1 != 0, .writable = flags & 2 != 0 }, self.clock_inverses[source * geometry.cells() + slot]);
                @memcpy(output, &row);
            },
            .leaf => {
                if (logical >= self.witness.leaves.len) return;
                const leaf = self.witness.leaves[logical];
                const row = try Leaf.fill(geometry, .{ .index = leaf.graph.index, .before_id = leaf.before_id, .after_id = leaf.after_id, .before = leaf.graph.before, .after = leaf.graph.after, .changed = leaf.graph.changed, .reuse = leaf.graph.reuse });
                @memcpy(output, &row);
            },
            .node => {
                if (logical >= self.shapes.node.nodes) return;
                const before = logical < self.witness.before_nodes.len;
                const node = if (before) self.witness.before_nodes[logical] else self.witness.after_nodes[logical - self.witness.before_nodes.len];
                const row = try Node.rowFromRecorded(node.graph.height, node.graph.index, @intFromBool(!before), node.graph.reuse, node.graph.left, node.graph.right, self.recorder.calls.items[node.io..][0..4]);
                @memcpy(output, &row);
            },
            .side => {
                if (logical >= self.witness.sides.len) return;
                const side = self.witness.sides[logical];
                const row = try Side.fill(geometry, side.height, side.index, side.digest, side.reuse);
                @memcpy(output, &row);
            },
            .common_permits => {
                if (logical >= self.shapes.common_permits.certificates) return;
                const source = self.cell_order[logical];
                const opening = captured[source];
                const grant = self.common_grants[source] orelse return error.InvalidPrivateRamTracePhase;
                const row = try Permit.fill(self.shapes.common_permits.span, opening.index << geometry.logBytes(), self.mappings.grants[grant]);
                @memcpy(output, &row);
            },
            .edge_permits => {
                if (logical >= self.edge_certificates.len) return;
                const certificate = self.edge_certificates[logical];
                const opening = captured[certificate.opening];
                const row = try Permit.fill(.word8, (opening.index << geometry.logBytes()) + 8 * @as(u64, certificate.cell), self.mappings.grants[certificate.grant]);
                @memcpy(output, &row);
            },
        }
    }
    /// Call only after typed claim closure succeeds. Patches remain available
    /// for atomic sparse-cache publication after the containing proof succeeds.
    pub fn retireMetadata(self: *Trace) !void {
        if (self.phase != .interactions_ready) return error.InvalidPrivateRamTracePhase;
        if (self.captured) |*owned| owned.deinit();
        self.captured = null;
        const a = self.allocator;
        a.free(self.common_grants);
        self.common_grants = &.{};
        a.free(self.cell_order);
        self.cell_order = &.{};
        a.free(self.edge_certificates);
        self.edge_certificates = &.{};
        a.free(self.clock_inverses);
        self.clock_inverses = &.{};
        self.recorder.deinit();
        self.recorder = .{ .allocator = a };
        a.free(self.witness.leaves);
        self.witness.leaves = &.{};
        a.free(self.witness.before_nodes);
        self.witness.before_nodes = &.{};
        a.free(self.witness.after_nodes);
        self.witness.after_nodes = &.{};
        a.free(self.witness.sides);
        self.witness.sides = &.{};
        self.phase = .retired;
    }
    pub fn deinit(self: *Trace) void {
        const a = self.allocator;
        self.witness.deinit();
        self.recorder.deinit();
        a.free(self.policy_counts);
        a.free(self.main_backing);
        if (self.captured) |*owned| owned.deinit();
        a.free(self.common_grants);
        a.free(self.cell_order);
        a.free(self.edge_certificates);
        a.free(self.clock_inverses);
        self.* = undefined;
    }
};

pub const Table = enum(u3) { chunk, common_cells, edge_cells, leaf, node, side, common_permits, edge_permits };
pub const TABLES = [_]Table{ .chunk, .common_cells, .edge_cells, .leaf, .node, .side, .common_permits, .edge_permits };
pub fn mainData(trace: *const Trace, table: Table) []const M {
    return switch (table) {
        .chunk => trace.chunk,
        .common_cells => trace.common_cells,
        .edge_cells => trace.edge_cells,
        .leaf => trace.leaf,
        .node => trace.node,
        .side => trace.side,
        .common_permits => trace.common_permits,
        .edge_permits => trace.edge_permits,
    };
}
pub fn tableLog(shapes: Shapes, table: Table) u32 {
    return switch (table) {
        .chunk => shapes.chunk.log_size,
        .common_cells => shapes.common_cells.log_size,
        .edge_cells => shapes.edge_cells.log_size,
        .leaf => shapes.leaf.log_size,
        .node => shapes.node.log_size,
        .side => shapes.side.log_size,
        .common_permits => shapes.common_permits.log_size,
        .edge_permits => shapes.edge_permits.log_size,
    };
}
pub fn mainWidth(table: Table) usize {
    return switch (table) {
        .chunk => CA.MAIN,
        .common_cells, .edge_cells => Cell.MAIN,
        .leaf => Leaf.MAIN,
        .node => Node.MAIN,
        .side => Side.MAIN,
        .common_permits, .edge_permits => Permit.MAIN,
    };
}
pub fn fixedWidth(table: Table) usize {
    return switch (table) {
        .chunk => CA.FIXED,
        .common_cells, .edge_cells => Cell.FIXED,
        .leaf => Leaf.FIXED,
        .node => Node.FIXED,
        .side => Side.FIXED,
        .common_permits, .edge_permits => Permit.FIXED,
    };
}
pub fn sumCount(table: Table) usize {
    return switch (table) {
        .chunk => CA.SUMS,
        .common_cells, .edge_cells => Cell.SUMS,
        .leaf => Leaf.SUMS,
        .node => Node.SUMS,
        .side => Side.SUMS,
        .common_permits, .edge_permits => Permit.SUMS,
    };
}
pub fn byteGroupCount(table: Table) usize {
    return switch (table) {
        .chunk => 0,
        .common_cells, .edge_cells => Cell.BYTE_SUMS,
        .leaf => 5,
        .node => 5,
        .side => 3,
        .common_permits, .edge_permits => PA.BYTE_SUMS,
    };
}
pub fn fixedAt(shapes: Shapes, table: Table, logical: usize, result: []M) void {
    switch (table) {
        .chunk => @memcpy(result, &shapes.chunk.fixedAt(logical)),
        .common_cells => @memcpy(result, &shapes.common_cells.fixedAt(logical)),
        .edge_cells => @memcpy(result, &shapes.edge_cells.fixedAt(logical)),
        .leaf => @memcpy(result, &shapes.leaf.fixedAt(logical)),
        .node => @memcpy(result, &shapes.node.fixedAt(logical)),
        .side => @memcpy(result, &shapes.side.fixedAt(logical)),
        .common_permits => @memcpy(result, &shapes.common_permits.fixedAt(logical)),
        .edge_permits => @memcpy(result, &shapes.edge_permits.fixedAt(logical)),
    }
}
