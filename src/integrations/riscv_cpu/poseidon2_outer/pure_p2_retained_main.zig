//! Concrete pure-P2 retained MAIN parking. Streams already constructed native
//! coefficients and Merkle layers once to an unlinked file; no witness replay,
//! rehash or transcript mutation. Restore is bounded and integrity checked.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const W = @import("pure_p2_worker_protocol.zig").W;
const M = @import("stwo_core").fields.m31.M31;
const Tree = W.Scheme.CommittedTree;
const Hash = W.H.Hash;
const Reserved = engine.file_backed_allocator.ReservedFile;
const Column = struct { offset: usize, count: usize };
pub const Store = struct {
    backing: engine.file_backed_allocator.FileBackedAllocator,
    allocator: std.mem.Allocator,
    disk_limit: usize,
    mapped_limit: usize,
    reserved: usize = 0,
    mapped: usize = 0,
    peak_mapped: usize = 0,
    mutex: std.Thread.Mutex = .{},
    head: ?*Owner = null,
    pub fn init(a: std.mem.Allocator, path: []const u8, disk_limit: usize, mapped_limit: usize) !Store {
        if (disk_limit == 0 or mapped_limit == 0) return error.InvalidOpParkingLimit;
        return .{ .backing = try engine.file_backed_allocator.FileBackedAllocator.init(path), .allocator = a, .disk_limit = disk_limit, .mapped_limit = mapped_limit };
    }
    pub fn deinit(self: *Store) void {
        std.debug.assert(self.head == null and self.reserved == 0 and self.mapped == 0);
        self.backing.deinit();
        self.* = undefined;
    }
    /// Exclusive tree ownership; all fallible work precedes publication.
    pub fn park(self: *Store, a: std.mem.Allocator, tree: *Tree) !usize {
        if (!tree.compact_polynomials or tree.shared_owner != null or tree.backing_teardown != null or tree.commitment.layer_values_borrowed or tree.commitment.layers_parked) return error.InvalidOpParkingTree;
        const coefficients = tree.coefficients orelse return error.InvalidOpParkingTree;
        if (coefficients.len == 0 or coefficients.len != tree.columns.len or tree.commitment.layers.len == 0) return error.InvalidOpParkingTree;
        var bytes: usize = 0;
        for (coefficients, tree.columns, 0..) |c, col, i| {
            const values = c.coefficients();
            const alias = col.coefficient_values orelse return error.InvalidOpParkingTree;
            if (values.len < 32 or !std.math.isPowerOfTwo(values.len) or c.log_size != std.math.log2_int(usize, values.len) or col.values.len != 0 or alias.ptr != values.ptr or alias.len != values.len) return error.InvalidOpParkingTree;
            for (coefficients[0..i]) |prior| if (overlap(values, prior.coefficients())) return error.InvalidOpParkingAlias;
            if (c.owns_coeffs) {
                for (tree.coefficient_backing_buffers orelse &.{}) |buffer| if (overlap(values, buffer)) return error.InvalidOpParkingAlias;
            } else {
                var found = false;
                for (tree.coefficient_backing_buffers orelse &.{}) |buffer| if (contains(buffer, values)) {
                    found = true;
                    break;
                };
                if (!found) return error.InvalidOpParkingAlias;
            }
            bytes = try std.math.add(usize, bytes, std.mem.sliceAsBytes(values).len);
        }
        for (tree.coefficient_backing_buffers orelse &.{}, 0..) |buffer, i| for ((tree.coefficient_backing_buffers.?)[0..i]) |prior| if (overlap(buffer, prior)) return error.InvalidOpParkingAlias;
        var pruned = false;
        for (tree.commitment.layers, 0..) |layer, i| {
            if (layer.len == 0) {
                if (i == 0) return error.InvalidOpParkingTree;
                pruned = true;
            } else if (pruned or layer.len != @as(usize, 1) << @intCast(i)) return error.InvalidOpParkingTree;
            bytes = try std.math.add(usize, bytes, std.mem.sliceAsBytes(layer).len);
        }
        const rounded = try Reserved.roundedLength(bytes);
        self.mutex.lock();
        if (rounded > self.disk_limit - self.reserved) {
            self.mutex.unlock();
            return error.OpParkingDiskLimit;
        }
        self.reserved += rounded;
        self.mutex.unlock();
        errdefer {
            self.mutex.lock();
            self.reserved -= rounded;
            self.mutex.unlock();
        }
        const owner = try self.allocator.create(Owner);
        errdefer self.allocator.destroy(owner);
        const columns = try self.allocator.alloc(Column, coefficients.len);
        errdefer self.allocator.free(columns);
        const layers = try self.allocator.alloc(Column, tree.commitment.layers.len);
        errdefer self.allocator.free(layers);
        var file = try Reserved.init(self.backing.dir, bytes);
        errdefer file.deinit();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var offset: usize = 0;
        for (coefficients, columns) |c, *descriptor| {
            const values = c.coefficients();
            const data = std.mem.sliceAsBytes(values);
            descriptor.* = .{ .offset = offset, .count = values.len };
            try file.file.writeAll(data);
            hash.update(data);
            offset += data.len;
        }
        for (tree.commitment.layers, layers) |layer, *descriptor| {
            const data = std.mem.sliceAsBytes(layer);
            descriptor.* = .{ .offset = offset, .count = layer.len };
            try file.file.writeAll(data);
            hash.update(data);
            offset += data.len;
        }
        if (offset != bytes) return error.InvalidOpParkingTree;
        owner.* = .{ .store = self, .file = file, .columns = columns, .layers = layers, .root = .{tree.root()}, .payload_bytes = bytes, .digest = hash.finalResult(), .descriptors = @intFromPtr(coefficients.ptr), .tree_columns = @intFromPtr(tree.columns.ptr), .tree_layers = @intFromPtr(tree.commitment.layers.ptr) };
        // Original buffers are released only after the complete durable write.
        for (coefficients, tree.columns) |*c, *col| {
            const log = c.log_size;
            c.deinit(a);
            c.* = .{ .coeffs = &.{}, .log_size = log, .owns_coeffs = false };
            col.coefficient_values = &.{};
        }
        if (tree.coefficient_backing_buffers) |buffers| {
            for (buffers) |buffer| if (buffer.len != 0) a.rawFree(std.mem.sliceAsBytes(buffer), tree.coefficient_backing_alignment, @returnAddress());
            a.free(buffers);
            tree.coefficient_backing_buffers = null;
        }
        for (tree.commitment.layers) |*layer| {
            tree.commitment.layer_allocator.free(layer.*);
            layer.* = &.{};
        }
        tree.commitment.layers[0] = &owner.root;
        tree.commitment.layer_values_borrowed = true;
        tree.commitment.layers_parked = true;
        tree.backing_teardown = engine.pcs.BackingTeardownToken.init(owner, rounded, Owner.release);
        self.mutex.lock();
        owner.next = self.head;
        if (self.head) |first| first.previous = owner;
        self.head = owner;
        self.mutex.unlock();
        return rounded;
    }
    pub fn restore(self: *Store, tree: *Tree) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const coefficients = tree.coefficients orelse return error.InvalidOpParkingTree;
        var cursor = self.head;
        const owner = while (cursor) |item| {
            if (item.descriptors == @intFromPtr(coefficients.ptr)) break item;
            cursor = item.next;
        } else return error.InvalidOpParkingTree;
        if (owner.tree_columns != @intFromPtr(tree.columns.ptr) or owner.tree_layers != @intFromPtr(tree.commitment.layers.ptr) or coefficients.len != owner.columns.len or tree.commitment.layers.len != owner.layers.len or !std.mem.eql(u8, &tree.root(), &owner.root[0])) return error.InvalidOpParkingTree;
        if (owner.mapping != null) return 0;
        if (!tree.commitment.layers_parked or owner.file.size > self.mapped_limit - self.mapped) return error.OpParkingMappedLimit;
        const mapping = try std.posix.mmap(null, owner.file.size, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED }, owner.file.file.handle, 0);
        errdefer std.posix.munmap(mapping);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(mapping[0..owner.payload_bytes], &digest, .{});
        if (!std.mem.eql(u8, &digest, &owner.digest)) return error.OpParkingIntegrity;
        for (coefficients, tree.columns, owner.columns) |*c, *col, d| {
            const values: []M = @alignCast(std.mem.bytesAsSlice(M, mapping[d.offset..][0 .. d.count * @sizeOf(M)]));
            c.coeffs = values;
            col.coefficient_values = values;
        }
        for (tree.commitment.layers, owner.layers) |*layer, d| layer.* = std.mem.bytesAsSlice(Hash, mapping[d.offset..][0 .. d.count * @sizeOf(Hash)]);
        owner.mapping = mapping;
        tree.commitment.layers_parked = false;
        self.mapped += owner.file.size;
        self.peak_mapped = @max(self.peak_mapped, self.mapped);
        return owner.file.size;
    }
};
const Owner = struct {
    store: *Store,
    file: Reserved,
    columns: []Column,
    layers: []Column,
    root: [1]Hash,
    payload_bytes: usize,
    digest: [32]u8,
    descriptors: usize,
    tree_columns: usize,
    tree_layers: usize,
    mapping: ?[]align(std.heap.page_size_min) u8 = null,
    next: ?*Owner = null,
    previous: ?*Owner = null,
    fn release(context: ?*anyopaque, bytes: u64) void {
        const self: *Owner = @ptrCast(@alignCast(context.?));
        const store = self.store;
        const a = store.allocator;
        std.debug.assert(bytes == self.file.size);
        store.mutex.lock();
        if (self.previous) |p| p.next = self.next else store.head = self.next;
        if (self.next) |n| n.previous = self.previous;
        if (self.mapping) |m| {
            std.posix.munmap(m);
            store.mapped -= self.file.size;
        }
        store.reserved -= self.file.size;
        store.mutex.unlock();
        self.file.deinit();
        a.free(self.columns);
        a.free(self.layers);
        a.destroy(self);
    }
};
fn contains(outer: []const M, inner: []const M) bool {
    return @intFromPtr(inner.ptr) >= @intFromPtr(outer.ptr) and @intFromPtr(inner.ptr) + std.mem.sliceAsBytes(inner).len <= @intFromPtr(outer.ptr) + std.mem.sliceAsBytes(outer).len;
}
fn overlap(a: []const M, b: []const M) bool {
    if (a.len == 0 or b.len == 0) return false;
    return @intFromPtr(a.ptr) < @intFromPtr(b.ptr) + std.mem.sliceAsBytes(b).len and @intFromPtr(b.ptr) < @intFromPtr(a.ptr) + std.mem.sliceAsBytes(a).len;
}

test "OP parking retains nine-coordinate roots exact coefficients and bounded integrity" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(a, path, 1 << 20, 1 << 20);
    defer store.deinit();
    var scheme = try W.Prover.init(a, @import("pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1.config());
    defer scheme.deinit(a);
    scheme.setStorePolynomialsCoefficients();
    scheme.setCompactPolynomialStorage(1);
    var data: [64]M = undefined;
    for (&data, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 73 + 11));
    var channel = W.Channel.init();
    const columns = [_]engine.pcs.ColumnEvaluation{ .{ .log_size = 5, .values = data[0..32] }, .{ .log_size = 5, .values = data[32..64] } };
    try scheme.commitBorrowedStreaming(a, &columns, 64, &channel);
    const tree = &scheme.trees.items[0];
    const root = tree.root();
    const old = try a.dupe(M, tree.coefficients.?[0].coeffs);
    defer a.free(old);
    var tiny = try Store.init(a, path, 1, 1);
    defer tiny.deinit();
    try std.testing.expectError(error.OpParkingDiskLimit, tiny.park(a, tree));
    try std.testing.expectEqualSlices(u8, &root, &tree.root());
    const bytes = try store.park(a, tree);
    try std.testing.expect(bytes > 0);
    try std.testing.expect(tree.commitment.layers_parked and tree.coefficients.?[0].coeffs.len == 0);
    try std.testing.expectEqualSlices(u8, &root, &tree.root());
    const owner = store.head.?;
    var one: [1]u8 = undefined;
    _ = try owner.file.file.pread(&one, 0);
    const saved = one;
    one[0] ^= 1;
    try owner.file.file.pwriteAll(&one, 0);
    try std.testing.expectError(error.OpParkingIntegrity, store.restore(tree));
    try owner.file.file.pwriteAll(&saved, 0);
    const cap = store.mapped_limit;
    store.mapped_limit = 1;
    try std.testing.expectError(error.OpParkingMappedLimit, store.restore(tree));
    store.mapped_limit = cap;
    try std.testing.expectEqual(bytes, try store.restore(tree));
    try std.testing.expectEqual(@as(usize, 0), try store.restore(tree));
    try std.testing.expectEqualSlices(M, old, tree.coefficients.?[0].coeffs);
    try std.testing.expectEqualSlices(u8, &root, &tree.root());
}
