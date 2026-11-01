//! Optional worker-local storage for already committed compact polynomials.
//! No witness/FFT replay and no transcript change. Unlinked shared mappings
//! remain owned by the PCS tree until its existing teardown barrier fires.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const P = @import("protocol.zig");
const M = @import("stwo_core").fields.m31.M31;
const Tree = P.T.Scheme.CommittedTree;
const Parking = @import("retained_main_parking.zig");
pub const Prefetch = @import("retained_main_prefetch.zig");
const ALIGNMENT: std.mem.Alignment = .fromByteUnits(64);
pub const Store = struct {
    backing: engine.file_backed_allocator.FileBackedAllocator,
    limit: usize,
    park: bool = false,
    parking: Parking.Registry = .{},
    owner_mutex: std.Thread.Mutex = .{},
    owners: ?*Owner = null,
    prefetch_calls: std.atomic.Value(usize) = .init(0),
    prefetch_requested: std.atomic.Value(usize) = .init(0),
    prefetch_advised: std.atomic.Value(usize) = .init(0),
    prefetch_failed: std.atomic.Value(usize) = .init(0),
    prefetch_unsupported: std.atomic.Value(usize) = .init(0),
    mapped: std.atomic.Value(usize) = .init(0),
    peak_mapped: std.atomic.Value(usize) = .init(0),
    reserved: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),
    total: std.atomic.Value(usize) = .init(0),
    pub fn init(path: []const u8, limit: usize) !Store {
        if (limit == 0) return error.InvalidRetainedMainLimit;
        return .{ .backing = try engine.file_backed_allocator.FileBackedAllocator.init(path), .limit = limit };
    }
    pub fn initParked(path: []const u8, limit: usize) !Store {
        var self = try init(path, limit);
        self.park = true;
        return self;
    }
    pub fn deinit(self: *Store) void {
        std.debug.assert(self.reserved.load(.acquire) == 0);
        std.debug.assert(self.mapped.load(.acquire) == 0 and self.parking.head == null and self.owners == null);
        self.backing.deinit();
        self.* = undefined;
    }
    pub fn stats(self: *const Store) struct { live_bytes: usize, peak_reserved_bytes: usize, total_bytes: usize, limit_bytes: usize, live_mapped_bytes: usize, peak_mapped_bytes: usize, parking_enabled: bool, prefetch_calls: usize, prefetch_requested_bytes: usize, prefetch_advised_bytes: usize, prefetch_failed_calls: usize, prefetch_unsupported_calls: usize } {
        return .{ .live_bytes = self.reserved.load(.acquire), .peak_reserved_bytes = self.peak.load(.acquire), .total_bytes = self.total.load(.acquire), .limit_bytes = self.limit, .live_mapped_bytes = self.mapped.load(.acquire), .peak_mapped_bytes = self.peak_mapped.load(.acquire), .parking_enabled = self.park, .prefetch_calls = self.prefetch_calls.load(.acquire), .prefetch_requested_bytes = self.prefetch_requested.load(.acquire), .prefetch_advised_bytes = self.prefetch_advised.load(.acquire), .prefetch_failed_calls = self.prefetch_failed.load(.acquire), .prefetch_unsupported_calls = self.prefetch_unsupported.load(.acquire) };
    }
    pub fn addMapped(self: *Store, size: usize) void {
        const next = self.mapped.fetchAdd(size, .acq_rel) + size;
        var peak = self.peak_mapped.load(.acquire);
        while (peak < next) peak = self.peak_mapped.cmpxchgWeak(peak, next, .acq_rel, .acquire) orelse break;
    }
    pub fn removeMapped(self: *Store, size: usize) void {
        const before = self.mapped.fetchSub(size, .acq_rel);
        std.debug.assert(before >= size);
    }
    pub fn restore(self: *Store, tree: *Tree) !usize {
        if (!self.park) {
            if (Parking.hasParkedOwner(tree)) return error.ForeignRetainedMainOwner;
            return 0;
        }
        return Parking.restore(self, tree);
    }
    /// Caller exclusively owns this live worker/tree through the call. No
    /// lookahead at another worker and no ownership transfer is performed.
    pub fn prefetchMain(self: *Store, tree: *Tree, cap: usize) !Prefetch.Result {
        if (cap == 0) return .{};
        const result = if (comptime !Prefetch.supported) Prefetch.Result{ .unsupported = true } else if (self.park) try Parking.prefetch(self, tree, cap) else try self.prefetchMapped(tree, cap);
        _ = self.prefetch_calls.fetchAdd(1, .monotonic);
        _ = self.prefetch_requested.fetchAdd(result.requested_bytes, .monotonic);
        _ = self.prefetch_advised.fetchAdd(result.advised_bytes, .monotonic);
        if (result.failed) _ = self.prefetch_failed.fetchAdd(1, .monotonic);
        if (result.unsupported) _ = self.prefetch_unsupported.fetchAdd(1, .monotonic);
        return result;
    }
    fn prefetchMapped(self: *Store, tree: *Tree, cap: usize) !Prefetch.Result {
        self.owner_mutex.lock();
        defer self.owner_mutex.unlock();
        const token = tree.backing_teardown orelse return error.MissingRetainedMainOwner;
        if (token.release_fn != Owner.release) return error.ForeignRetainedMainOwner;
        const context = token.context orelse return error.ForeignRetainedMainOwner;
        var next = self.owners;
        while (next) |owner| : (next = owner.next) {
            // Numeric registry lookup precedes any interpretation of a token's
            // context. The registry lock protects the owner and mapping lease.
            if (@intFromPtr(owner) != @intFromPtr(context)) continue;
            if (token.value != owner.reserved_bytes or !tree.compact_polynomials or tree.shared_owner != null or tree.coefficient_backing_buffers != null or !std.mem.eql(u8, &tree.root(), &owner.root)) return error.RetainedMainShapeMismatch;
            const coefficients = tree.coefficients orelse return error.RetainedMainShapeMismatch;
            if (coefficients.len != tree.columns.len or @intFromPtr(coefficients.ptr) != owner.coefficient_descriptors or @intFromPtr(tree.columns.ptr) != owner.column_descriptors) return error.RetainedMainShapeMismatch;
            var offset: usize = 0;
            for (coefficients, tree.columns) |coefficient, column| {
                const values = coefficient.coefficients();
                if (values.len == 0 or values.len > owner.arena.len -| offset or coefficient.owns_coeffs or coefficient.log_size >= @bitSizeOf(usize) or values.len != @as(usize, 1) << @intCast(coefficient.log_size) or column.values.len != 0) return error.RetainedMainShapeMismatch;
                const retained = column.coefficient_values orelse return error.RetainedMainShapeMismatch;
                const wanted = owner.arena[offset..][0..values.len];
                if (values.ptr != wanted.ptr or retained.len != wanted.len or retained.ptr != wanted.ptr) return error.RetainedMainShapeMismatch;
                offset += values.len;
            }
            if (offset != owner.arena.len) return error.RetainedMainShapeMismatch;
            const mapping: []align(std.heap.page_size_min) u8 = @alignCast(std.mem.sliceAsBytes(owner.arena).ptr[0..owner.reserved_bytes]);
            return Prefetch.advise(mapping, cap);
        }
        return error.ForeignRetainedMainOwner;
    }
    pub fn reserve(self: *Store, size: usize) !void {
        var old = self.reserved.load(.acquire);
        while (true) {
            const next = std.math.add(usize, old, size) catch return error.RetainedMainBudgetExceeded;
            if (next > self.limit) return error.RetainedMainBudgetExceeded;
            if (self.reserved.cmpxchgWeak(old, next, .acq_rel, .acquire)) |observed| {
                old = observed;
                continue;
            }
            var peak = self.peak.load(.acquire);
            while (peak < next) {
                peak = self.peak.cmpxchgWeak(peak, next, .acq_rel, .acquire) orelse break;
            }
            return;
        }
    }
    /// a is the tree original owner allocator. No borrowed native/poly views
    /// may survive this ownership mutation. Caller has exclusive tree/worker access; this is failure-atomic, not
    /// concurrent mutation. All fallible work precedes ownership transfer.
    /// Failure leaves the tree,
    /// sealed roots, channel and existing coefficients untouched and retryable.
    pub fn spill(self: *Store, a: std.mem.Allocator, tree: *Tree) !usize {
        if (!tree.compact_polynomials or tree.shared_owner != null or tree.backing_teardown != null) return error.UnsupportedRetainedMainTree;
        const coefficients = tree.coefficients orelse return error.MissingCompactCoefficients;
        if (coefficients.len == 0 or coefficients.len != tree.columns.len) return error.RetainedMainShapeMismatch;
        if (tree.coefficient_backing_buffers) |buffers| for (buffers, 0..) |buffer, i| {
            if (buffer.len != 0) _ = try endAddress(buffer);
            for (buffers[0..i]) |prior| if (try overlaps(buffer, prior)) return error.UnsupportedRetainedMainAlias;
        };
        var words: usize = 0;
        for (coefficients, tree.columns, 0..) |coefficient, column, i| {
            const values = coefficient.coefficients();
            const retained = column.coefficient_values orelse return error.RetainedMainShapeMismatch;
            if (values.len < 32 or !std.math.isPowerOfTwo(values.len) or coefficient.log_size != std.math.log2_int(usize, values.len) or column.values.len != 0 or retained.len != values.len or retained.ptr != values.ptr) return error.RetainedMainShapeMismatch;
            _ = try endAddress(values);
            for (coefficients[0..i]) |prior| if (try overlaps(values, prior.coefficients())) return error.UnsupportedRetainedMainAlias;
            if (coefficient.owns_coeffs) {
                for (tree.coefficient_backing_buffers orelse &.{}) |buffer| if (try overlaps(values, buffer)) return error.UnsupportedRetainedMainAlias;
            } else if (!contained(values, tree.coefficient_backing_buffers)) return error.UnsupportedRetainedMainBorrow;
            words = try std.math.add(usize, words, values.len);
        }
        const bytes = try std.math.mul(usize, words, @sizeOf(M));
        const rounded = try engine.file_backed_allocator.ReservedFile.roundedLength(bytes);
        if (self.park) return Parking.spill(self, a, tree, words, rounded);
        try self.reserve(rounded);
        errdefer _ = self.reserved.fetchSub(rounded, .acq_rel);
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        const arena = try self.backing.allocator().alignedAlloc(M, ALIGNMENT, words);
        errdefer self.backing.allocator().free(arena);
        var offset: usize = 0;
        for (coefficients) |coefficient| {
            const values = coefficient.coefficients();
            @memcpy(arena[offset..][0..values.len], values);
            offset += values.len;
        }
        const mapping: []align(std.heap.page_size_min) u8 = @alignCast(std.mem.sliceAsBytes(arena).ptr[0..rounded]);
        try std.posix.msync(mapping, std.posix.MSF.SYNC);
        // These are shared FILE pages. Anonymous MADV_FREE would be incorrect.
        try std.posix.madvise(mapping.ptr, mapping.len, std.posix.MADV.DONTNEED);
        owner.* = .{ .allocator = a, .store = self, .arena = arena, .reserved_bytes = rounded, .root = tree.root(), .coefficient_descriptors = @intFromPtr(coefficients.ptr), .column_descriptors = @intFromPtr(tree.columns.ptr) };
        // From here ownership transfer and cleanup cannot fail. Compact column
        // and coefficient views are re-pointed together; no stale aliases stay.
        offset = 0;
        for (coefficients, tree.columns) |*coefficient, *column| {
            const count = coefficient.coefficients().len;
            const log = coefficient.log_size;
            coefficient.deinit(a);
            const values = arena[offset..][0..count];
            coefficient.* = .{ .coeffs = values, .log_size = log, .owns_coeffs = false };
            column.coefficient_values = values;
            offset += count;
        }
        if (tree.coefficient_backing_buffers) |buffers| {
            for (buffers) |buffer| if (buffer.len != 0) {
                a.rawFree(std.mem.sliceAsBytes(buffer), tree.coefficient_backing_alignment, @returnAddress());
            };
            a.free(buffers);
            tree.coefficient_backing_buffers = null;
        }
        tree.backing_teardown = engine.pcs.BackingTeardownToken.init(owner, rounded, Owner.release);
        self.owner_mutex.lock();
        owner.next = self.owners;
        if (owner.next) |next| next.previous = owner;
        self.owners = owner;
        self.addMapped(rounded);
        self.owner_mutex.unlock();
        _ = self.total.fetchAdd(rounded, .acq_rel);
        return rounded;
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    arena: []align(64) M,
    reserved_bytes: usize,
    root: [32]u8,
    coefficient_descriptors: usize,
    column_descriptors: usize,
    next: ?*Owner = null,
    previous: ?*Owner = null,
    fn release(context: ?*anyopaque, bytes: u64) void {
        const self: *Owner = @ptrCast(@alignCast(context.?));
        std.debug.assert(bytes == self.reserved_bytes);
        self.store.owner_mutex.lock();
        if (self.previous) |previous| previous.next = self.next else self.store.owners = self.next;
        if (self.next) |next| next.previous = self.previous;
        self.store.backing.allocator().free(self.arena);
        self.store.removeMapped(self.reserved_bytes);
        self.store.owner_mutex.unlock();
        const before = self.store.reserved.fetchSub(self.reserved_bytes, .acq_rel);
        std.debug.assert(before >= self.reserved_bytes);
        self.allocator.destroy(self);
    }
};
fn contained(values: []const M, buffers: ?[][]M) bool {
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, std.mem.sliceAsBytes(values).len) catch return false;
    for (buffers orelse return false) |buffer| {
        const first = @intFromPtr(buffer.ptr);
        const last = std.math.add(usize, first, std.mem.sliceAsBytes(buffer).len) catch return false;
        if (first <= start and end <= last) return true;
    }
    return false;
}

fn endAddress(values: []const M) !usize {
    return std.math.add(usize, @intFromPtr(values.ptr), try std.math.mul(usize, values.len, @sizeOf(M)));
}
fn overlaps(left: []const M, right: []const M) !bool {
    if (left.len == 0 or right.len == 0) return false;
    return @intFromPtr(left.ptr) < try endAddress(right) and @intFromPtr(right.ptr) < try endAddress(left);
}
