//! Owner-thread immutable GPU setup. Identities come from independently derived
//! authority or audited constant generators, never request-supplied cache names.
const std = @import("std");
const A = @import("pcs_native_abi.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Bind = *const fn (*anyopaque, *const A.Lease, *const [8]u32, *const [8]u32) callconv(.c) c_int;
const Seal = *const fn (*anyopaque, *const A.Lease, *const [8]u32) callconv(.c) c_int;
const Unbind = *const fn (*anyopaque, *const [8]u32) callconv(.c) c_int;
const Entry = struct { key: [8]u32, lease: A.Lease, users: usize = 0, columns: []D.Column = &.{}, fixed_root: ?[32]u8 = null };
const Borrow = struct { scope: [8]u32, key: [8]u32 };
pub const Cache = struct {
    session: *anyopaque,
    allocate: A.LeaseAllocate,
    release: A.LeaseRelease,
    bind: Bind,
    seal: Seal,
    unbind: Unbind,
    upload: A.Upload,
    sync: A.Sync,
    copy: A.CopyDevice,
    validate: A.LeaseValidateRange,
    limit: u64,
    bytes: u64 = 0,
    entries: std.ArrayList(Entry) = .empty,
    borrows: std.ArrayList(Borrow) = .empty,
    hits: u64 = 0,
    uploads: u64 = 0,
    evictions: u64 = 0,
    const allocator = std.heap.page_allocator;
    pub fn init(library: *std.DynLib, session: *anyopaque, allocate: A.LeaseAllocate, release: A.LeaseRelease, limit: u64) !Cache {
        if (limit == 0) return error.InvalidImmutableSetupBudget;
        return .{ .session = session, .allocate = allocate, .release = release, .limit = limit, .bind = library.lookup(Bind, "stwo_rv64_gpu_immutable_bind") orelse return error.MissingImmutableSetupCapability, .seal = library.lookup(Seal, "stwo_rv64_gpu_immutable_seal") orelse return error.MissingImmutableSetupCapability, .unbind = library.lookup(Unbind, "stwo_rv64_gpu_immutable_unbind_scope") orelse return error.MissingImmutableSetupCapability, .upload = library.lookup(A.Upload, "stwo_exec_context_memcpy_h2d_async") orelse return error.MissingImmutableSetupCapability, .sync = library.lookup(A.Sync, "stwo_exec_context_sync") orelse return error.MissingImmutableSetupCapability, .copy = library.lookup(A.CopyDevice, "stwo_exec_context_memcpy_d2d_async") orelse return error.MissingImmutableSetupCapability, .validate = library.lookup(A.LeaseValidateRange, "stwo_rv64_gpu_lease_validate_range") orelse return error.MissingImmutableSetupCapability };
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
            var entry = self.entries.items[i];
            const bytes = entry.lease.count * 4;
            if (self.release(self.session, &entry.lease) != 0) return error.InvalidImmutableSetupLease;
            _ = self.entries.swapRemove(i);
            self.bytes -= bytes;
            self.evictions += 1;
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
        if (self.seal(self.session, &lease, &key) != 0) return error.ImmutableSetupSealFailed;
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
            if (column.device) |device| {
                if (column.coefficients.len != 0 or device.count != count) return error.InvalidImmutableFixedSource;
            } else if (column.coefficients.len != count) return error.InvalidImmutableFixedSource;
            total = try std.math.add(usize, total, count);
        }
        if (total == 0) return error.InvalidImmutableFixedSource;
        const bytes = try std.math.mul(u64, total, 4);
        try self.evict(bytes);
        try self.entries.ensureUnusedCapacity(allocator, 1);
        const output = try allocator.alloc(D.Column, columns.len);
        var lease: A.Lease = .{};
        var adopted = false;
        errdefer if (!adopted) {
            if (lease.words != null) _ = self.release(self.session, &lease);
            allocator.free(output);
        };
        if (self.allocate(self.session, total, 4, &key, &lease) != 0) return error.ImmutableSetupAllocationFailed;
        var offset: usize = 0;
        for (columns, output) |column, *out| {
            const count = @as(usize, 1) << @intCast(column.log_size);
            const destination: *anyopaque = @ptrCast(lease.words.? + offset);
            if (column.device) |device| {
                if (self.validate(self.session, device.words, device.count, device.context_token, device.generation, &request) != 0 or self.copy(native_context, destination, @ptrCast(device.words), count * 4) != 0) return error.InvalidImmutableFixedSource;
            } else if (self.upload(native_context, destination, @ptrCast(column.coefficients.ptr), count * 4) != 0) return error.ImmutableSetupUploadFailed;
            out.* = .{ .log_size = column.log_size, .device = .{ .words = lease.words.? + offset, .count = count, .context_token = lease.context_token, .generation = lease.generation } };
            offset += count;
        }
        if (self.sync(native_context) != 0) return error.ImmutableSetupUploadFailed;
        if (self.seal(self.session, &lease, &key) != 0) return error.ImmutableSetupSealFailed;
        self.entries.appendAssumeCapacity(.{ .key = key, .lease = lease, .columns = output, .fixed_root = scope.fixed });
        self.bytes += bytes;
        self.uploads += 1;
        adopted = true;
        _ = try self.acquire(self.entries.items.len - 1, request);
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
            if (entry.lease.words != null and self.release(self.session, &entry.lease) != 0) return error.InvalidImmutableSetupLease;
        }
        self.freeMetadata();
    }
    /// Terminal poisoned sessions still own device allocations until destroy.
    /// Host-only descriptors can be reclaimed independently after callers join.
    pub fn freeMetadata(self: *Cache) void {
        for (self.entries.items) |entry| allocator.free(entry.columns);
        self.entries.deinit(allocator);
        self.borrows.deinit(allocator);
        self.entries = .empty;
        self.borrows = .empty;
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
    fn seal(_: *anyopaque, _: *const A.Lease, _: *const [8]u32) callconv(.c) c_int {
        return 0;
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
    fn validate(_: *anyopaque, _: [*]const u32, _: u64, _: u64, _: u64, _: *const [8]u32) callconv(.c) c_int {
        return 0;
    }
    fn cache(self: *@This(), limit: u64) Cache {
        return .{ .session = self, .allocate = allocate, .release = release, .bind = bind, .seal = seal, .unbind = unbind, .upload = upload, .copy = upload, .validate = validate, .sync = sync, .limit = limit };
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

test "immutable FIXED forest reuses geometry across statements without host copies" {
    var fake = Fake{};
    var cache = fake.cache(1024);
    const values = [_]D.M{D.M{ .v = 7 }} ** 32;
    const columns = [_]D.Column{.{ .log_size = 5, .coefficients = &values }};
    var scope = D.Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const first = try cache.fixed(&fake, scope, &columns);
    const generation = first[0].device.?.generation;
    try std.testing.expectEqual(@as(usize, 0), first[0].coefficients.len);
    try std.testing.expectEqual(@as(u32, 7), first[0].device.?.words[31]);
    const prior = @import("pcs_scope.zig").identity(scope);
    scope.statement = @splat(4);
    scope.main = @splat(5);
    const second = try cache.fixed(&fake, scope, &columns);
    try std.testing.expectEqual(generation, second[0].device.?.generation);
    try std.testing.expectEqual(@as(usize, 1), fake.uploads);
    try std.testing.expect((try cache.fixedColumn(scope, 0, columns[0])) != null);
    try cache.releaseScope(prior);
    try cache.releaseScope(@import("pcs_scope.zig").identity(scope));
    try cache.deinit();
    try std.testing.expectEqual(fake.allocations, fake.frees);
}
