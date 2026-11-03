//! Owner-thread immutable GPU setup. Identities come from independently derived
//! authority or audited constant generators, never request-supplied cache names.
const std = @import("std");
const A = @import("pcs_native_abi.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Bind = *const fn (*anyopaque, *const A.Lease, *const [8]u32, *const [8]u32) callconv(.c) c_int;
const Unbind = *const fn (*anyopaque, *const [8]u32) callconv(.c) c_int;
const Entry = struct { key: [8]u32, lease: A.Lease, users: usize = 0, columns: []D.Column = &.{}, fixed_root: ?[32]u8 = null };
const Borrow = struct { scope: [8]u32, key: [8]u32 };
pub const Cache = struct {
    session: *anyopaque,
    allocate: A.LeaseAllocate,
    release: A.LeaseRelease,
    bind: Bind,
    unbind: Unbind,
    upload: A.Upload,
    sync: A.Sync,
    limit: u64,
    bytes: u64 = 0,
    entries: std.ArrayList(Entry) = .empty,
    borrows: std.ArrayList(Borrow) = .empty,
    hits: u64 = 0,
    uploads: u64 = 0,
    const allocator = std.heap.page_allocator;
    pub fn init(library: *std.DynLib, session: *anyopaque, allocate: A.LeaseAllocate, release: A.LeaseRelease, limit: u64) !Cache {
        if (limit == 0) return error.InvalidImmutableSetupBudget;
        return .{ .session = session, .allocate = allocate, .release = release, .limit = limit, .bind = library.lookup(Bind, "stwo_rv64_gpu_immutable_bind") orelse return error.MissingImmutableSetupCapability, .unbind = library.lookup(Unbind, "stwo_rv64_gpu_immutable_unbind_scope") orelse return error.MissingImmutableSetupCapability, .upload = library.lookup(A.Upload, "stwo_exec_context_memcpy_h2d_async") orelse return error.MissingImmutableSetupCapability, .sync = library.lookup(A.Sync, "stwo_exec_context_sync") orelse return error.MissingImmutableSetupCapability };
    }
    fn index(self: *const Cache, key: [8]u32) ?usize {
        for (self.entries.items, 0..) |entry, i| if (std.mem.eql(u32, &entry.key, &key)) return i;
        return null;
    }
    pub fn lookup(self: *Cache, scope: [8]u32, key: [8]u32, count: u64) !?A.Lease {
        const i = self.index(key) orelse return null;
        if (count == 0 or self.entries.items[i].lease.count != count) return error.ImmutableSetupShapeMismatch;
        self.hits += 1;
        return try self.acquire(i, scope);
    }
    pub fn fixedColumn(self: *Cache, scope: D.Scope, column_index: usize, original: D.Column) !?D.DeviceCoefficients {
        for (self.entries.items, 0..) |entry, i| {
            const root = entry.fixed_root orelse continue;
            if (!std.mem.eql(u8, &root, &scope.fixed)) continue;
            if (column_index >= entry.columns.len) return error.ImmutableSetupShapeMismatch;
            const column = entry.columns[column_index];
            if (column.log_size != original.log_size) return error.ImmutableSetupShapeMismatch;
            _ = try self.acquire(i, @import("pcs_scope.zig").identity(scope));
            return column.device orelse return error.InvalidImmutableFixedSource;
        }
        return null;
    }
    fn acquire(self: *Cache, index_: usize, scope: [8]u32) !A.Lease {
        const entry = &self.entries.items[index_];
        for (self.borrows.items) |borrow| if (std.mem.eql(u32, &borrow.scope, &scope) and std.mem.eql(u32, &borrow.key, &entry.key)) return entry.lease;
        if (self.borrows.items.len >= 65536) return error.ImmutableSetupBorrowLimit;
        try self.borrows.ensureUnusedCapacity(allocator, 1);
        if (self.bind(self.session, &entry.lease, &entry.key, &scope) != 0) return error.InvalidImmutableSetupBorrow;
        self.borrows.appendAssumeCapacity(.{ .scope = scope, .key = entry.key });
        entry.users += 1;
        return entry.lease;
    }
    fn evict(self: *Cache, required: u64) !void {
        if (required > self.limit) return error.ImmutableSetupBudgetExceeded;
        while (self.bytes > self.limit - required or self.entries.items.len >= 256) {
            var victim: ?usize = null;
            for (self.entries.items, 0..) |entry, i| if (entry.users == 0) {
                victim = i;
                break;
            };
            const i = victim orelse return error.ImmutableSetupStillBorrowed;
            var entry = self.entries.swapRemove(i);
            const bytes = entry.lease.count * 4;
            if (self.release(self.session, &entry.lease) != 0) return error.InvalidImmutableSetupLease;
            self.bytes -= bytes;
            allocator.free(entry.columns);
        }
    }
    /// Synchronous upload only on a cold identity. The returned lease is borrowed
    /// until releaseScope; callers must never release or mutate its storage.
    pub fn words(self: *Cache, native_context: *anyopaque, scope: [8]u32, key: [8]u32, values: []const u32) !A.Lease {
        if (values.len == 0) return error.InvalidImmutableSetupWords;
        if (self.index(key)) |i| {
            if (self.entries.items[i].lease.count != values.len) return error.ImmutableSetupShapeMismatch;
            self.hits += 1;
            return self.acquire(i, scope);
        }
        const bytes = try std.math.mul(u64, values.len, 4);
        try self.evict(bytes);
        try self.entries.ensureUnusedCapacity(allocator, 1);
        var lease: A.Lease = .{};
        if (self.allocate(self.session, values.len, 4, &key, &lease) != 0) return error.ImmutableSetupAllocationFailed;
        var adopted = false;
        errdefer if (!adopted) {
            _ = self.release(self.session, &lease);
        };
        if (self.upload(native_context, @ptrCast(lease.words.?), @ptrCast(values.ptr), @intCast(bytes)) != 0 or self.sync(native_context) != 0) return error.ImmutableSetupUploadFailed;
        self.entries.appendAssumeCapacity(.{ .key = key, .lease = lease });
        adopted = true;
        self.bytes += bytes;
        self.uploads += 1;
        // This allocation is now cache-owned, including on failed alias admission.
        return self.acquire(self.entries.items.len - 1, scope);
    }
    pub fn fixed(self: *Cache, native_context: *anyopaque, scope: D.Scope, columns: []const D.Column) ![]const D.Column {
        const key = fixedIdentity(scope.fixed, columns);
        const request = @import("pcs_scope.zig").identity(scope);
        if (self.index(key)) |i| {
            if (self.entries.items[i].columns.len != columns.len) return error.ImmutableSetupShapeMismatch;
            _ = try self.acquire(i, request);
            self.hits += 1;
            return self.entries.items[i].columns;
        }
        var total: usize = 0;
        for (columns) |column| {
            if (column.log_size > 28) return error.InvalidImmutableFixedSource;
            const count = @as(usize, 1) << @intCast(column.log_size);
            if (column.device != null or column.coefficients.len != count) return error.InvalidImmutableFixedSource;
            total = try std.math.add(usize, total, count);
        }
        const values = try allocator.alloc(u32, total);
        defer allocator.free(values);
        const output = try allocator.alloc(D.Column, columns.len);
        errdefer allocator.free(output);
        var offset: usize = 0;
        for (columns) |column| {
            for (column.coefficients, values[offset..][0..column.coefficients.len]) |value, *word| word.* = value.v;
            offset += column.coefficients.len;
        }
        const lease = try self.words(native_context, request, key, values);
        offset = 0;
        for (columns, output) |column, *out| {
            const count = column.coefficients.len;
            out.* = .{ .log_size = column.log_size, .device = .{ .words = lease.words.? + offset, .count = count, .context_token = lease.context_token, .generation = lease.generation } };
            offset += count;
        }
        self.entries.items[self.index(key).?].columns = output;
        self.entries.items[self.index(key).?].fixed_root = scope.fixed;
        return output;
    }
    pub fn releaseScope(self: *Cache, scope: [8]u32) !void {
        if (self.unbind(self.session, &scope) != 0) return error.ImmutableSetupUnbindFailed;
        var i: usize = 0;
        while (i < self.borrows.items.len) {
            if (!std.mem.eql(u32, &self.borrows.items[i].scope, &scope)) {
                i += 1;
                continue;
            }
            const borrow = self.borrows.swapRemove(i);
            const entry = &self.entries.items[self.index(borrow.key) orelse return error.InvalidImmutableSetupBorrow];
            if (entry.users == 0) return error.InvalidImmutableSetupBorrow;
            entry.users -= 1;
        }
    }
    pub fn deinit(self: *Cache) !void {
        if (self.borrows.items.len != 0) return error.ImmutableSetupStillBorrowed;
        for (self.entries.items) |*entry| {
            if (self.release(self.session, &entry.lease) != 0) return error.InvalidImmutableSetupLease;
            allocator.free(entry.columns);
        }
        self.entries.deinit(allocator);
        self.borrows.deinit(allocator);
    }
};
pub fn fixedIdentity(root: [32]u8, columns: []const D.Column) [8]u32 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/rv64/cuda/authenticated-fixed-coefficients/v1\x00");
    hash.update(&root);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, columns.len, .little);
    hash.update(&number);
    for (columns) |column| {
        std.mem.writeInt(u64, &number, column.log_size, .little);
        hash.update(&number);
    }
    const bytes = hash.finalResult();
    var words_: [8]u32 = undefined;
    for (&words_, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
    return words_;
}

const Fake = struct {
    allocations: usize = 0,
    frees: usize = 0,
    uploads: usize = 0,
    fail_bind: bool = false,
    fn allocate(raw: *anyopaque, count: u64, kind: u32, _: *const [8]u32, out: *A.Lease) callconv(.c) c_int {
        const self: *@This() = @ptrCast(@alignCast(raw));
        const values = std.heap.page_allocator.alloc(u32, @intCast(count)) catch return 1;
        self.allocations += 1;
        out.* = .{ .context_token = 1, .generation = self.allocations, .words = values.ptr, .count = count, .kind = kind };
        return 0;
    }
    fn release(raw: *anyopaque, lease: *A.Lease) callconv(.c) c_int {
        const self: *@This() = @ptrCast(@alignCast(raw));
        std.heap.page_allocator.free(lease.words.?[0..@intCast(lease.count)]);
        self.frees += 1;
        lease.* = .{};
        return 0;
    }
    fn bind(raw: *anyopaque, _: *const A.Lease, _: *const [8]u32, _: *const [8]u32) callconv(.c) c_int {
        const self: *@This() = @ptrCast(@alignCast(raw));
        return if (self.fail_bind) 1 else 0;
    }
    fn unbind(_: *anyopaque, _: *const [8]u32) callconv(.c) c_int {
        return 0;
    }
    fn upload(raw: *anyopaque, destination: *anyopaque, source: *const anyopaque, len: usize) callconv(.c) c_int {
        const self: *@This() = @ptrCast(@alignCast(raw));
        const dst: [*]u8 = @ptrCast(destination);
        const src: [*]const u8 = @ptrCast(source);
        @memcpy(dst[0..len], src[0..len]);
        self.uploads += 1;
        return 0;
    }
    fn sync(_: *anyopaque) callconv(.c) c_int {
        return 0;
    }
    fn cache(self: *@This(), limit: u64) Cache {
        return .{ .session = self, .allocate = allocate, .release = release, .bind = bind, .unbind = unbind, .upload = upload, .sync = sync, .limit = limit };
    }
};
test "immutable setup reuses one upload and protects live requests from eviction" {
    var fake = Fake{};
    var cache = fake.cache(64);
    const words_ = [_]u32{7} ** 16;
    const scope = [_]u32{1} ** 8;
    const key = [_]u32{2} ** 8;
    const first = try cache.words(&fake, scope, key, &words_);
    const again = (try cache.lookup(scope, key, words_.len)).?;
    try std.testing.expectEqual(first.generation, again.generation);
    try std.testing.expectEqual(@as(usize, 1), fake.uploads);
    try std.testing.expectError(error.ImmutableSetupStillBorrowed, cache.words(&fake, scope, @splat(3), &words_));
    try std.testing.expectError(error.ImmutableSetupShapeMismatch, cache.lookup(scope, key, 15));
    try std.testing.expectError(error.ImmutableSetupStillBorrowed, cache.deinit());
    try cache.releaseScope(scope);
    _ = try cache.words(&fake, scope, @splat(3), &words_);
    try std.testing.expectEqual(@as(u64, 64), cache.bytes);
    try std.testing.expectEqual(@as(usize, 1), fake.frees);
    try cache.releaseScope(scope);
    try cache.deinit();
    try std.testing.expectEqual(fake.allocations, fake.frees);
}
test "failed immutable alias admission leaves exactly one cache owner" {
    var fake = Fake{ .fail_bind = true };
    var cache = fake.cache(64);
    const words_ = [_]u32{1} ** 16;
    try std.testing.expectError(error.InvalidImmutableSetupBorrow, cache.words(&fake, @splat(1), @splat(2), &words_));
    try std.testing.expectEqual(@as(usize, 0), fake.frees);
    fake.fail_bind = false;
    _ = (try cache.lookup(@splat(1), @splat(2), 16)).?;
    try cache.releaseScope(@splat(1));
    try cache.deinit();
    try std.testing.expectEqual(@as(usize, 1), fake.allocations);
    try std.testing.expectEqual(@as(usize, 1), fake.frees);
}
