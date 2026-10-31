//! Optional worker-local storage for already committed compact polynomials.
//! No witness/FFT replay and no transcript change. Unlinked shared mappings
//! remain owned by the PCS tree until its existing teardown barrier fires.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const P = @import("protocol.zig");
const M = @import("stwo_core").fields.m31.M31;
const Tree = P.T.Scheme.CommittedTree;
const ALIGNMENT: std.mem.Alignment = .fromByteUnits(64);
pub const Store = struct {
    backing: engine.file_backed_allocator.FileBackedAllocator,
    limit: usize,
    reserved: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),
    total: std.atomic.Value(usize) = .init(0),
    pub fn init(path: []const u8, limit: usize) !Store {
        if (limit == 0) return error.InvalidRetainedMainLimit;
        return .{ .backing = try engine.file_backed_allocator.FileBackedAllocator.init(path), .limit = limit };
    }
    pub fn deinit(self: *Store) void {
        std.debug.assert(self.reserved.load(.acquire) == 0);
        self.backing.deinit();
        self.* = undefined;
    }
    pub fn stats(self: *const Store) struct { live_bytes: usize, peak_reserved_bytes: usize, total_bytes: usize, limit_bytes: usize } {
        return .{ .live_bytes = self.reserved.load(.acquire), .peak_reserved_bytes = self.peak.load(.acquire), .total_bytes = self.total.load(.acquire), .limit_bytes = self.limit };
    }
    fn reserve(self: *Store, size: usize) !void {
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
    /// Caller has exclusive tree/worker access; this is failure-atomic, not
    /// concurrent mutation. All fallible work precedes ownership transfer.
    /// Failure leaves the tree,
    /// sealed roots, channel and existing coefficients untouched and retryable.
    pub fn spill(self: *Store, a: std.mem.Allocator, tree: *Tree) !usize {
        if (!tree.compact_polynomials or tree.shared_owner != null or tree.backing_teardown != null) return error.UnsupportedRetainedMainTree;
        const coefficients = tree.coefficients orelse return error.MissingCompactCoefficients;
        if (coefficients.len == 0 or coefficients.len != tree.columns.len) return error.RetainedMainShapeMismatch;
        var words: usize = 0;
        for (coefficients, tree.columns) |coefficient, column| {
            const values = coefficient.coefficients();
            const retained = column.coefficient_values orelse return error.RetainedMainShapeMismatch;
            if (values.len < 32 or !std.math.isPowerOfTwo(values.len) or coefficient.log_size != std.math.log2_int(usize, values.len) or column.values.len != 0 or retained.len != values.len or retained.ptr != values.ptr) return error.RetainedMainShapeMismatch;
            if (!coefficient.owns_coeffs and !contained(values, tree.coefficient_backing_buffers)) return error.UnsupportedRetainedMainBorrow;
            words = try std.math.add(usize, words, values.len);
        }
        const bytes = try std.math.mul(usize, words, @sizeOf(M));
        const rounded = std.mem.alignBackward(usize, try std.math.add(usize, bytes, std.heap.pageSize() - 1), std.heap.pageSize());
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
        owner.* = .{ .allocator = a, .store = self, .arena = arena, .reserved_bytes = rounded };
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
        _ = self.total.fetchAdd(rounded, .acq_rel);
        return rounded;
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    store: *Store,
    arena: []align(64) M,
    reserved_bytes: usize,
    fn release(context: ?*anyopaque, bytes: u64) void {
        const self: *Owner = @ptrCast(@alignCast(context.?));
        std.debug.assert(bytes == self.reserved_bytes);
        self.store.backing.allocator().free(self.arena);
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
