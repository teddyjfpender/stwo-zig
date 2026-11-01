//! Host-only custody for sealed native MAIN coefficients: unlinked FD while
//! parked, read-only shared mapping during stage2. No witness or FFT replay.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Store = @import("retained_main_store.zig").Store;
const Tree = @import("protocol.zig").T.Scheme.CommittedTree;
const M = @import("stwo_core").fields.m31.M31;
const Reserved = engine.file_backed_allocator.ReservedFile;
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Registry = struct { mutex: std.Thread.Mutex = .{}, head: ?*Owner = null };
const Column = struct { offset: usize, count: usize, native_log: u32, column_log: u32 };
const Owner = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    store: *Store,
    file: Reserved,
    columns: []Column,
    coefficient_descriptors: usize,
    column_descriptors: usize,
    root: [32]u8,
    mapping: ?[]align(std.heap.page_size_min) u8 = null,
    next: ?*Owner = null,
    previous: ?*Owner = null,
    fn release(context: ?*anyopaque, bytes: u64) void {
        const self: *Owner = @ptrCast(@alignCast(context.?));
        const store = self.store;
        const a = self.allocator;
        const budget = self.budget;
        std.debug.assert(bytes == self.file.size);
        store.parking.mutex.lock();
        if (self.previous) |previous| previous.next = self.next else store.parking.head = self.next;
        if (self.next) |next| next.previous = self.previous;
        // Serialize mmap/unmap and accounting in this Store: the published
        // mapping high-water cannot miss overlap with another restoring lane.
        if (self.mapping) |memory| {
            std.posix.munmap(memory);
            store.removeMapped(self.file.size);
        }
        store.parking.mutex.unlock();
        self.file.deinit();
        const before = store.reserved.fetchSub(@intCast(bytes), .acq_rel);
        std.debug.assert(before >= bytes);
        a.free(self.columns);
        a.destroy(self);
        if (budget) |owner| owner.destroy();
    }
};
/// Shape and all disk/metadata allocation are validated before any descriptor or
/// original owner changes. Failure leaves the old resident tree retryable.
pub fn spill(store: *Store, a: std.mem.Allocator, tree: *Tree, words: usize, rounded: usize) !usize {
    try store.reserve(rounded);
    errdefer _ = store.reserved.fetchSub(rounded, .acq_rel);
    const owner = try a.create(Owner);
    errdefer a.destroy(owner);
    const coefficients = tree.coefficients.?;
    const columns = try a.alloc(Column, coefficients.len);
    errdefer a.free(columns);
    var file = try Reserved.init(store.backing.dir, try std.math.mul(usize, words, @sizeOf(M)));
    errdefer file.deinit();
    std.debug.assert(file.size == rounded);
    var offset: usize = 0;
    for (coefficients, tree.columns, columns) |coefficient, column, *description| {
        const values = coefficient.coefficients();
        description.* = .{ .offset = offset, .count = values.len, .native_log = coefficient.log_size, .column_log = column.log_size };
        // No second wide allocation or initial mmap: stream the existing owner.
        try file.file.writeAll(std.mem.sliceAsBytes(values));
        offset += values.len;
    }
    std.debug.assert(offset == words);
    try file.file.sync();
    owner.* = .{ .allocator = a, .budget = if (Budget.fromAllocator(a)) |budget| budget.retain() else null, .store = store, .file = file, .columns = columns, .coefficient_descriptors = @intFromPtr(coefficients.ptr), .column_descriptors = @intFromPtr(tree.columns.ptr), .root = tree.root() };
    // Infallible publication under exclusive tree access. No unmapped pointer is
    // left anywhere in the compact polynomial/column descriptors.
    for (coefficients, tree.columns) |*coefficient, *column| {
        const log = coefficient.log_size;
        coefficient.deinit(a);
        coefficient.* = .{ .coeffs = &.{}, .log_size = log, .owns_coeffs = false };
        column.coefficient_values = &.{};
    }
    if (tree.coefficient_backing_buffers) |buffers| {
        for (buffers) |buffer| if (buffer.len != 0) a.rawFree(std.mem.sliceAsBytes(buffer), tree.coefficient_backing_alignment, @returnAddress());
        a.free(buffers);
        tree.coefficient_backing_buffers = null;
    }
    store.parking.mutex.lock();
    owner.next = store.parking.head;
    if (owner.next) |next| next.previous = owner;
    store.parking.head = owner;
    store.parking.mutex.unlock();
    tree.backing_teardown = engine.pcs.BackingTeardownToken.init(owner, rounded, Owner.release);
    _ = store.total.fetchAdd(rounded, .acq_rel);
    return rounded;
}
pub fn hasParkedOwner(tree: *const Tree) bool {
    const token = tree.backing_teardown orelse return false;
    return token.release_fn == Owner.release;
}
fn findOwner(store: *Store, tree: *const Tree) !*Owner {
    const token = tree.backing_teardown orelse return error.MissingRetainedMainOwner;
    // Never interpret an unrelated callback context, even with matching size.
    if (token.release_fn != Owner.release) return error.ForeignRetainedMainOwner;
    const context = token.context orelse return error.ForeignRetainedMainOwner;
    var found = store.parking.head;
    while (found) |owner| : (found = owner.next) {
        if (@intFromPtr(owner) == @intFromPtr(context)) {
            if (token.value != owner.file.size) return error.RetainedMainShapeMismatch;
            return owner;
        }
    }
    return error.ForeignRetainedMainOwner;
}
pub fn restore(store: *Store, tree: *Tree) !usize {
    store.parking.mutex.lock();
    defer store.parking.mutex.unlock();
    const owner = try findOwner(store, tree);
    const coefficients = tree.coefficients orelse return error.RetainedMainShapeMismatch;
    if (!tree.compact_polynomials or tree.shared_owner != null or tree.coefficient_backing_buffers != null or tree.columns.len != owner.columns.len or coefficients.len != owner.columns.len or @intFromPtr(coefficients.ptr) != owner.coefficient_descriptors or @intFromPtr(tree.columns.ptr) != owner.column_descriptors or !std.mem.eql(u8, &tree.root(), &owner.root)) return error.RetainedMainShapeMismatch;
    var offset: usize = 0;
    for (coefficients, tree.columns, owner.columns) |coefficient, column, description| {
        if (description.offset != offset or description.native_log >= @bitSizeOf(usize) or description.count != @as(usize, 1) << @intCast(description.native_log) or coefficient.log_size != description.native_log or column.log_size != description.column_log or column.values.len != 0 or coefficient.owns_coeffs) return error.RetainedMainShapeMismatch;
        const retained = column.coefficient_values orelse return error.RetainedMainShapeMismatch;
        if (owner.mapping) |memory| {
            const expected = std.mem.bytesAsSlice(M, memory)[offset..][0..description.count];
            if (coefficient.coeffs.len != expected.len or coefficient.coeffs.ptr != expected.ptr or retained.len != expected.len or retained.ptr != expected.ptr) return error.RetainedMainShapeMismatch;
        } else if (coefficient.coeffs.len != 0 or retained.len != 0) return error.RetainedMainShapeMismatch;
        offset = try std.math.add(usize, offset, description.count);
    }
    if (try Reserved.roundedLength(try std.math.mul(usize, offset, @sizeOf(M))) != owner.file.size) return error.RetainedMainShapeMismatch;
    if (owner.mapping != null) return 0;
    // Read-only mapping. Validation and mmap precede a single infallible publish;
    // mmap/length failure leaves all safe-invalid parked descriptors untouched.
    const memory = try owner.file.map(true);
    const values = std.mem.bytesAsSlice(M, memory);
    for (coefficients, tree.columns, owner.columns) |*coefficient, *column, description| {
        const slice = values[description.offset..][0..description.count];
        coefficient.coeffs = slice;
        column.coefficient_values = slice;
    }
    owner.mapping = memory;
    store.addMapped(memory.len);
    return memory.len;
}
