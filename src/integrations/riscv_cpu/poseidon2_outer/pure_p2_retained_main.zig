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
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Binding = struct { setup: [32]u8, statement: [32]u8 };
/// Optional enclosing cache custody for independently owned request views.
/// Retain runs under the Store lock and must be infallible/non-reentrant;
/// release runs after descriptor, mapping and allocator-custody teardown.
pub const ViewLifetime = struct {
    context: ?*anyopaque,
    retain_fn: *const fn (?*anyopaque) void,
    release_fn: *const fn (?*anyopaque) void,
};
const Column = struct { offset: usize, count: usize, native_log: u32 = 0, column_log: u32 = 0 };
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
    view_lifetime: ?ViewLifetime = null,
    pub fn init(a: std.mem.Allocator, path: []const u8, disk_limit: usize, mapped_limit: usize) !Store {
        if (disk_limit == 0 or mapped_limit == 0) return error.InvalidOpParkingLimit;
        return .{ .backing = try engine.file_backed_allocator.FileBackedAllocator.init(path), .allocator = a, .disk_limit = disk_limit, .mapped_limit = mapped_limit };
    }
    pub fn initWithViewLifetime(a: std.mem.Allocator, path: []const u8, disk_limit: usize, mapped_limit: usize, lifetime: ViewLifetime) !Store {
        var store = try init(a, path, disk_limit, mapped_limit);
        store.view_lifetime = lifetime;
        return store;
    }
    pub fn deinit(self: *Store) void {
        std.debug.assert(self.head == null and self.reserved == 0 and self.mapped == 0);
        self.backing.deinit();
        self.* = undefined;
    }
    /// Raw advice custody shares the exact MAIN/FIXED disk quota. Callers must
    /// retain the Store until every reservation has released.
    pub fn reserveAdvice(self: *Store, bytes: usize) !usize {
        const rounded = try Reserved.roundedLength(bytes);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (rounded > self.disk_limit - self.reserved) return error.OpParkingDiskLimit;
        self.reserved += rounded;
        return rounded;
    }
    pub fn releaseAdvice(self: *Store, rounded: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(rounded <= self.reserved);
        self.reserved -= rounded;
    }
    /// The Store must remain at a stable address until every tree token releases.
    /// Unbound custody is a test control; OP producers must supply source authority.
    pub fn park(self: *Store, a: std.mem.Allocator, tree: *Tree) !usize {
        if (!@import("builtin").is_test) return error.OpParkingBindingRequired;
        return self.parkInner(a, tree, null);
    }
    pub fn parkBound(self: *Store, a: std.mem.Allocator, tree: *Tree, binding: Binding) !usize {
        return self.parkInner(a, tree, binding);
    }
    /// Exclusive tree ownership; all fallible work precedes publication.
    fn parkInner(self: *Store, a: std.mem.Allocator, tree: *Tree, binding: ?Binding) !usize {
        if (!tree.compact_polynomials or tree.shared_owner != null or tree.backing_teardown != null or tree.column_backing_buffers != null or tree.streaming_column_backings != null or tree.commitment.layer_values_borrowed or tree.commitment.layers_parked) return error.InvalidOpParkingTree;
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
        for (coefficients, tree.columns, columns) |c, col, *descriptor| {
            const values = c.coefficients();
            const data = std.mem.sliceAsBytes(values);
            descriptor.* = .{ .offset = offset, .count = values.len, .native_log = c.log_size, .column_log = col.log_size };
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
        owner.* = .{ .binding = binding, .budget = if (Budget.fromAllocator(a)) |budget| budget.retain() else null, .store = self, .file = file, .columns = columns, .layers = layers, .root = .{tree.root()}, .payload_bytes = bytes, .digest = hash.finalResult(), .descriptors = @intFromPtr(coefficients.ptr), .tree_columns = @intFromPtr(tree.columns.ptr), .tree_layers = @intFromPtr(tree.commitment.layers.ptr) };
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
        if (!@import("builtin").is_test) return error.OpParkingBindingRequired;
        return self.restoreInner(tree, null);
    }
    pub fn restoreBound(self: *Store, tree: *Tree, binding: Binding) !usize {
        return self.restoreInner(tree, binding);
    }
    /// Read-only request lease of one immutable parked FIXED template. Only
    /// descriptors are copied. The template stays parked and may be destroyed
    /// before this lease; its file and budget custody survive until last release.
    pub fn leaseBound(self: *Store, a: std.mem.Allocator, template: *const Tree, binding: Binding) !Tree {
        return self.requestView(a, template, binding, true);
    }
    /// Stage-one root and geometry only. This cannot evaluate or open values;
    /// the worker must replace it with a full admitted lease before proving.
    pub fn shapeBound(self: *Store, a: std.mem.Allocator, template: *const Tree, binding: Binding) !Tree {
        return self.requestView(a, template, binding, false);
    }
    fn requestView(self: *Store, a: std.mem.Allocator, template: *const Tree, binding: Binding, comptime mapped: bool) !Tree {
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = try self.validateOwnerLocked(template, binding);
        if (owner.mapping != null) return error.OpParkingTemplateNotParked;
        if (try owner.file.file.getEndPos() != owner.file.size) return error.OpParkingIntegrity;
        if (mapped and owner.file.size > self.mapped_limit - self.mapped) return error.OpParkingMappedLimit;
        const references = try std.math.add(usize, owner.references, 1);
        const budget = Budget.fromAllocator(a);
        if (budget == null and !@import("builtin").is_test) return error.OpParkingLeaseRequiresBudget;
        var reservation: Budget.ExternalReservation = if (budget) |b| try b.reserveExternal(if (mapped) owner.file.size else 0) else .empty();
        errdefer reservation.deinit();
        const columns = try a.dupe(@TypeOf(template.columns[0]), template.columns);
        errdefer a.free(columns);
        const coefficients = try a.dupe(@TypeOf(template.coefficients.?[0]), template.coefficients.?);
        errdefer a.free(coefficients);
        const layers = try a.dupe([]Hash, template.commitment.layers);
        errdefer a.free(layers);
        const lease = try a.create(Lease);
        errdefer a.destroy(lease);
        const memory: ?[]align(std.heap.page_size_min) u8 = if (mapped) try owner.file.map(true) else null;
        errdefer if (memory) |values| std.posix.munmap(values);
        if (memory) |values| {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(values[0..owner.payload_bytes], &digest, .{});
            if (!std.mem.eql(u8, &digest, &owner.digest)) return error.OpParkingIntegrity;
            for (coefficients, columns, owner.columns) |*coefficient, *column, descriptor| {
                const cells: []M = @alignCast(std.mem.bytesAsSlice(M, values[descriptor.offset..][0 .. descriptor.count * @sizeOf(M)]));
                coefficient.coeffs = cells;
                column.coefficient_values = cells;
            }
            for (layers, owner.layers) |*layer, descriptor| layer.* = std.mem.bytesAsSlice(Hash, values[descriptor.offset..][0 .. descriptor.count * @sizeOf(Hash)]);
        }
        if (self.view_lifetime) |lifetime| lifetime.retain_fn(lifetime.context);
        lease.* = .{ .allocator = a, .owner = owner, .memory = memory, .reservation = reservation.take(), .lifetime = self.view_lifetime };
        var result = template.*;
        result.columns = columns;
        result.coefficients = coefficients;
        result.commitment.layers = layers;
        result.commitment.layer_allocator = a;
        result.commitment.layers_parked = !mapped;
        result.backing_teardown = engine.pcs.BackingTeardownToken.init(lease, owner.file.size, Lease.release);
        owner.references = references;
        if (mapped) self.mapped += owner.file.size;
        self.peak_mapped = @max(self.peak_mapped, self.mapped);
        return result;
    }
    // Caller holds mutex and a live exclusive template reference.
    fn validateOwnerLocked(self: *Store, tree: *const Tree, binding: ?Binding) !*Owner {
        const token = tree.backing_teardown orelse return error.InvalidOpParkingTree;
        if (token.release_fn != Owner.release) return error.InvalidOpParkingTree;
        const context = token.context orelse return error.InvalidOpParkingTree;
        var cursor = self.head;
        const owner = while (cursor) |item| {
            if (@intFromPtr(context) == @intFromPtr(item)) break item;
            cursor = item.next;
        } else return error.InvalidOpParkingTree;
        if (token.value != owner.file.size) return error.InvalidOpParkingTree;
        if (!std.meta.eql(owner.binding, binding)) return error.OpParkingBindingMismatch;
        const coefficients = tree.coefficients orelse return error.InvalidOpParkingTree;
        if (!tree.compact_polynomials or tree.shared_owner != null or tree.coefficient_backing_buffers != null or tree.column_backing_buffers != null or tree.streaming_column_backings != null or !tree.commitment.layer_values_borrowed or
            owner.descriptors != @intFromPtr(coefficients.ptr) or owner.tree_columns != @intFromPtr(tree.columns.ptr) or owner.tree_layers != @intFromPtr(tree.commitment.layers.ptr) or
            coefficients.len != owner.columns.len or tree.columns.len != owner.columns.len or tree.commitment.layers.len != owner.layers.len or
            !std.mem.eql(u8, &tree.root(), &owner.root[0])) return error.InvalidOpParkingTree;
        var offset: usize = 0;
        for (coefficients, tree.columns, owner.columns) |c, col, d| {
            if (d.offset != offset or d.native_log >= @bitSizeOf(usize) or d.count != @as(usize, 1) << @intCast(d.native_log) or
                c.log_size != d.native_log or col.log_size != d.column_log or c.owns_coeffs or col.values.len != 0) return error.InvalidOpParkingTree;
            const alias = col.coefficient_values orelse return error.InvalidOpParkingTree;
            if (owner.mapping) |memory| {
                const expected = std.mem.bytesAsSlice(M, memory[d.offset..][0 .. d.count * @sizeOf(M)]);
                if (c.coeffs.ptr != expected.ptr or c.coeffs.len != expected.len or alias.ptr != expected.ptr or alias.len != expected.len) return error.InvalidOpParkingTree;
            } else if (c.coeffs.len != 0 or alias.len != 0) return error.InvalidOpParkingTree;
            offset = try std.math.add(usize, offset, try std.math.mul(usize, d.count, @sizeOf(M)));
        }
        for (tree.commitment.layers, owner.layers, 0..) |layer, d, i| {
            if (d.offset != offset) return error.InvalidOpParkingTree;
            if (owner.mapping) |memory| {
                const expected = std.mem.bytesAsSlice(Hash, memory[d.offset..][0 .. d.count * @sizeOf(Hash)]);
                if (layer.ptr != expected.ptr or layer.len != expected.len) return error.InvalidOpParkingTree;
            } else if (i == 0) {
                if (layer.ptr != &owner.root or layer.len != 1) return error.InvalidOpParkingTree;
            } else if (layer.len != 0) return error.InvalidOpParkingTree;
            offset = try std.math.add(usize, offset, try std.math.mul(usize, d.count, @sizeOf(Hash)));
        }
        if (offset != owner.payload_bytes or try Reserved.roundedLength(offset) != owner.file.size or tree.commitment.layers_parked != (owner.mapping == null)) return error.InvalidOpParkingTree;
        return owner;
    }
    fn restoreInner(self: *Store, tree: *Tree, binding: ?Binding) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = try self.validateOwnerLocked(tree, binding);
        const coefficients = tree.coefficients.?;
        if (owner.mapping != null) return 0;
        if (try owner.file.file.getEndPos() != owner.file.size) return error.OpParkingIntegrity;
        if (owner.file.size > self.mapped_limit - self.mapped) return error.OpParkingMappedLimit;
        var reservation: Budget.ExternalReservation = if (owner.budget) |budget| try budget.reserveExternal(owner.file.size) else .empty();
        errdefer reservation.deinit();
        const mapping = try owner.file.map(true);
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
        owner.mapping_reservation = reservation.take();
        tree.commitment.layers_parked = false;
        self.mapped += owner.file.size;
        self.peak_mapped = @max(self.peak_mapped, self.mapped);
        return owner.file.size;
    }
};
const Owner = struct {
    references: usize = 1,
    binding: ?Binding,
    budget: ?*Budget,
    mapping_reservation: Budget.ExternalReservation = .empty(),
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
        var reservation = self.mapping_reservation.take();
        std.debug.assert(bytes == self.file.size);
        store.mutex.lock();
        if (self.mapping) |m| {
            std.posix.munmap(m);
            store.mapped -= self.file.size;
        }
        self.mapping = null;
        const last = self.dropLocked();
        store.mutex.unlock();
        if (last) self.destroy();
        reservation.deinit();
    }
    fn dropLocked(self: *Owner) bool {
        std.debug.assert(self.references != 0);
        self.references -= 1;
        if (self.references != 0) return false;
        const store = self.store;
        if (self.previous) |p| p.next = self.next else store.head = self.next;
        if (self.next) |n| n.previous = self.previous;
        store.reserved -= self.file.size;
        return true;
    }
    fn destroy(self: *Owner) void {
        const a = self.store.allocator;
        const budget = self.budget;
        self.file.deinit();
        a.free(self.columns);
        a.free(self.layers);
        a.destroy(self);
        if (budget) |b| b.destroy();
    }
};
const Lease = struct {
    allocator: std.mem.Allocator,
    owner: *Owner,
    memory: ?[]align(std.heap.page_size_min) u8,
    reservation: Budget.ExternalReservation,
    lifetime: ?ViewLifetime,
    fn release(context: ?*anyopaque, bytes: u64) void {
        const self: *Lease = @ptrCast(@alignCast(context.?));
        const owner = self.owner;
        const store = owner.store;
        const a = self.allocator;
        var reservation = self.reservation.take();
        const lifetime = self.lifetime;
        std.debug.assert(bytes == owner.file.size);
        if (self.memory) |memory| std.posix.munmap(memory);
        store.mutex.lock();
        if (self.memory != null) store.mapped -= owner.file.size;
        const last = owner.dropLocked();
        store.mutex.unlock();
        if (last) owner.destroy();
        a.destroy(self);
        reservation.deinit();
        if (lifetime) |retained| retained.release_fn(retained.context);
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
    const budget = try Budget.create(a, 1 << 24);
    var budget_lease = true;
    defer if (budget_lease) budget.destroy();
    const b = budget.allocator();
    var scheme = try W.Prover.init(b, @import("pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1.config());
    var scheme_live = true;
    defer if (scheme_live) scheme.deinit(b);
    scheme.setStorePolynomialsCoefficients();
    scheme.setCompactPolynomialStorage(1);
    var data: [64]M = undefined;
    for (&data, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 73 + 11));
    var channel = W.Channel.init();
    const columns = [_]engine.pcs.ColumnEvaluation{ .{ .log_size = 5, .values = data[0..32] }, .{ .log_size = 5, .values = data[32..64] } };
    try scheme.commitBorrowedStreaming(b, &columns, 64, &channel);
    const tree = &scheme.trees.items[0];
    const root = tree.root();
    const old = try a.dupe(M, tree.coefficients.?[0].coeffs);
    defer a.free(old);
    var tiny = try Store.init(a, path, 1, 1);
    defer tiny.deinit();
    try std.testing.expectError(error.OpParkingDiskLimit, tiny.park(b, tree));
    try std.testing.expectEqualSlices(u8, &root, &tree.root());
    const binding: Binding = .{ .setup = @splat(17), .statement = @splat(29) };
    const bytes = try store.parkBound(b, tree, binding);
    try std.testing.expect(bytes > 0);
    try std.testing.expect(tree.commitment.layers_parked and tree.coefficients.?[0].coeffs.len == 0);
    try std.testing.expectEqualSlices(u8, &root, &tree.root());
    const owner = store.head.?;
    var wrong = binding;
    wrong.setup[31] ^= 1;
    try std.testing.expectError(error.OpParkingBindingMismatch, store.restoreBound(tree, wrong));
    wrong = binding;
    wrong.statement[31] ^= 1;
    try std.testing.expectError(error.OpParkingBindingMismatch, store.restoreBound(tree, wrong));
    try std.testing.expectError(error.OpParkingBindingMismatch, store.restore(tree));
    const saved_token_value = tree.backing_teardown.?.value;
    tree.backing_teardown.?.value += 1;
    try std.testing.expectError(error.InvalidOpParkingTree, store.restoreBound(tree, binding));
    tree.backing_teardown.?.value = saved_token_value;
    const native_log = tree.coefficients.?[0].log_size;
    tree.coefficients.?[0].log_size += 1;
    try std.testing.expectError(error.InvalidOpParkingTree, store.restoreBound(tree, binding));
    tree.coefficients.?[0].log_size = native_log;
    const column_log = tree.columns[0].log_size;
    tree.columns[0].log_size += 1;
    try std.testing.expectError(error.InvalidOpParkingTree, store.restoreBound(tree, binding));
    tree.columns[0].log_size = column_log;
    // The last root word is authority too, not a truncated 32-byte digest.
    var fake_root = root;
    fake_root[35] ^= 1;
    tree.commitment.layers[0] = @as(*[1]Hash, @ptrCast(&fake_root));
    try std.testing.expectError(error.InvalidOpParkingTree, store.restoreBound(tree, binding));
    tree.commitment.layers[0] = &owner.root;
    const file_size = owner.file.size;
    try owner.file.file.setEndPos(file_size - 1);
    try std.testing.expectError(error.OpParkingIntegrity, store.restoreBound(tree, binding));
    try owner.file.file.setEndPos(file_size);
    try owner.file.file.setEndPos(file_size + 1);
    try std.testing.expectError(error.OpParkingIntegrity, store.restoreBound(tree, binding));
    try owner.file.file.setEndPos(file_size);
    const budget_limit = budget.limit;
    budget.limit = budget.snapshot().live_bytes;
    try std.testing.expectError(error.OutOfMemory, store.restoreBound(tree, binding));
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.mapped);
    budget.limit = budget_limit;
    var one: [1]u8 = undefined;
    _ = try owner.file.file.pread(&one, 0);
    const saved = one;
    one[0] ^= 1;
    try owner.file.file.pwriteAll(&one, 0);
    try std.testing.expectError(error.OpParkingIntegrity, store.restoreBound(tree, binding));
    try owner.file.file.pwriteAll(&saved, 0);
    const cap = store.mapped_limit;
    store.mapped_limit = 1;
    try std.testing.expectError(error.OpParkingMappedLimit, store.restoreBound(tree, binding));
    store.mapped_limit = cap;
    try std.testing.expectEqual(bytes, try store.restoreBound(tree, binding));
    try std.testing.expectEqual(bytes, budget.snapshot().external_live_bytes);
    tree.columns[0].log_size += 1;
    try std.testing.expectError(error.InvalidOpParkingTree, store.restoreBound(tree, binding));
    tree.columns[0].log_size = column_log;
    try std.testing.expectEqual(@as(usize, 0), try store.restoreBound(tree, binding));
    try std.testing.expectEqualSlices(M, old, tree.coefficients.?[0].coeffs);
    try std.testing.expectEqualSlices(u8, &root, &tree.root());
    // The caller's budget lease may end before the tree's custody token. The
    // owner retains both its budget lifetime and the mapping reservation.
    var detached = scheme.trees.pop().?;
    scheme.deinit(b);
    scheme_live = false;
    budget.destroy();
    budget_lease = false;
    detached.deinit(b);
    try std.testing.expectEqual(@as(usize, 0), store.mapped);
    try std.testing.expectEqual(@as(usize, 0), store.reserved);
    try std.testing.expect(store.head == null);
}

test "OP immutable FIXED leases retain parked custody with independent request budgets" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var custody = TestViewCustody{};
    var store = try Store.initWithViewLifetime(a, path, 1 << 20, 1 << 20, .{ .context = &custody, .retain_fn = TestViewCustody.retain, .release_fn = TestViewCustody.release });
    defer store.deinit();
    const template_budget = try Budget.create(a, 1 << 24);
    defer template_budget.destroy();
    const b = template_budget.allocator();
    var scheme = try W.Prover.init(b, @import("pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1.config());
    defer scheme.deinit(b);
    scheme.setStorePolynomialsCoefficients();
    scheme.setCompactPolynomialStorage(1);
    var data: [64]M = undefined;
    for (&data, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 19 + 7));
    var channel = W.Channel.init();
    try scheme.commitBorrowedStreaming(b, &.{ .{ .log_size = 5, .values = data[0..32] }, .{ .log_size = 5, .values = data[32..64] } }, 64, &channel);
    var template = scheme.trees.pop().?;
    var template_live = true;
    defer if (template_live) template.deinit(b);
    const original = try a.dupe(M, template.coefficients.?[0].coefficients());
    defer a.free(original);
    const root = template.root();
    const binding: Binding = .{ .setup = @splat(23), .statement = @splat(41) };
    const bytes = try store.parkBound(b, &template, binding);
    try std.testing.expectEqual(@as(usize, 0), custody.references);
    var wrong = binding;
    wrong.setup[31] ^= 1;
    try std.testing.expectError(error.OpParkingBindingMismatch, store.leaseBound(a, &template, wrong));
    const owner = store.head.?;
    try owner.file.file.setEndPos(owner.file.size - 1);
    try std.testing.expectError(error.OpParkingIntegrity, store.leaseBound(a, &template, binding));
    try owner.file.file.setEndPos(owner.file.size);
    try std.testing.checkAllAllocationFailures(a, leaseAndRelease, .{ &store, &template, binding });
    try std.testing.expectEqual(@as(usize, 0), store.mapped);
    try std.testing.expectEqual(@as(usize, 1), owner.references);
    try std.testing.expectEqual(@as(usize, 0), custody.references);
    const request_budget = try Budget.create(a, 1 << 20);
    var request_live = true;
    defer if (request_live) request_budget.destroy();
    const r = request_budget.allocator();
    request_budget.limit = bytes - 1;
    try std.testing.expectError(error.OutOfMemory, store.leaseBound(r, &template, binding));
    try std.testing.expectEqual(@as(usize, 0), request_budget.snapshot().live_bytes);
    request_budget.limit = 1 << 20;
    var pending = try store.shapeBound(r, &template, binding);
    var pending_live = true;
    defer if (pending_live) pending.deinit(r);
    try std.testing.expectEqual(@as(usize, 0), store.mapped);
    try std.testing.expectEqual(@as(usize, 0), request_budget.snapshot().external_live_bytes);
    try std.testing.expect(pending.commitment.layers_parked and pending.coefficients.?[0].coeffs.len == 0);
    try std.testing.expectEqualSlices(u8, &root, &pending.root());
    try std.testing.expectError(error.InvalidColumnSize, pending.decommit(std.testing.failing_allocator, &.{0}));
    try std.testing.checkAllAllocationFailures(a, shapeAndRelease, .{ &store, &template, binding });
    var first = try store.leaseBound(r, &template, binding);
    var first_live = true;
    defer if (first_live) first.deinit(r);
    try std.testing.expectEqual(bytes, request_budget.snapshot().external_live_bytes);
    store.mapped_limit = bytes;
    try std.testing.expectError(error.OpParkingMappedLimit, store.leaseBound(r, &template, binding));
    store.mapped_limit = 1 << 20;
    const second_budget = try Budget.create(a, 1 << 20);
    var second_budget_live = true;
    defer if (second_budget_live) second_budget.destroy();
    const s = second_budget.allocator();
    var second = try store.leaseBound(s, &template, binding);
    var second_live = true;
    defer if (second_live) second.deinit(s);
    try std.testing.expectEqual(2 * bytes, store.mapped);
    try std.testing.expectEqual(bytes, request_budget.snapshot().external_live_bytes);
    try std.testing.expectEqual(bytes, second_budget.snapshot().external_live_bytes);
    try std.testing.expect(first.columns.ptr != second.columns.ptr and first.columns.ptr != template.columns.ptr);
    try std.testing.expect(first.coefficients.?[0].coeffs.ptr != second.coefficients.?[0].coeffs.ptr);
    try std.testing.expect(template.commitment.layers_parked and template.coefficients.?[0].coeffs.len == 0);
    try std.testing.expectEqualSlices(M, original, first.coefficients.?[0].coefficients());
    try std.testing.expectEqualSlices(u8, &root, &second.root());
    try std.testing.expectEqual(@as(usize, 3), custody.references);
    // Template destruction must not close a file still leased by two workers.
    template.deinit(b);
    template_live = false;
    try std.testing.expectEqual(bytes, store.reserved);
    try std.testing.expectEqualSlices(M, original, second.coefficients.?[0].coefficients());
    pending.deinit(r);
    pending_live = false;
    request_budget.destroy();
    request_live = false;
    first.deinit(r);
    first_live = false;
    try std.testing.expectEqual(bytes, store.mapped);
    try std.testing.expectEqual(bytes, second_budget.snapshot().external_live_bytes);
    second_budget.destroy();
    second_budget_live = false;
    second.deinit(s);
    second_live = false;
    try std.testing.expectEqual(@as(usize, 0), store.mapped);
    try std.testing.expectEqual(@as(usize, 0), store.reserved);
    try std.testing.expect(store.head == null);
    try std.testing.expectEqual(@as(usize, 0), custody.references);
}
fn leaseAndRelease(a: std.mem.Allocator, store: *Store, tree: *const Tree, binding: Binding) !void {
    var lease = try store.leaseBound(a, tree, binding);
    defer lease.deinit(a);
}
fn shapeAndRelease(a: std.mem.Allocator, store: *Store, tree: *const Tree, binding: Binding) !void {
    var shape = try store.shapeBound(a, tree, binding);
    defer shape.deinit(a);
}

const TestViewCustody = struct {
    references: usize = 0,
    fn retain(raw: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        self.references += 1;
    }
    fn release(raw: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        std.debug.assert(self.references != 0);
        self.references -= 1;
    }
};
