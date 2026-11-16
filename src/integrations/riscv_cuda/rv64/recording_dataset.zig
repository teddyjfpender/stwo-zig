//! Optional diagnostic captures, explicitly owned by one execution and attempt.
//! No record is proof authority. A failed/incomplete capture never completes.
const std = @import("std");
pub const Role = enum { pack, nodes };
pub const Purpose = enum { execution, class_install };
pub const Identity = struct {
    execution: [32]u8,
    program: [32]u8,
    input: [32]u8,
    request: [32]u8 = @splat(0),
    attempt: [16]u8,
    purpose: Purpose,
    fn key(self: Identity) [64]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/rv64/diagnostic-dataset/v1\x00");
        hash.update(&self.execution);
        hash.update(&self.program);
        hash.update(&self.input);
        hash.update(&self.request);
        hash.update(&self.attempt);
        hash.update(&.{@intFromEnum(self.purpose)});
        return std.fmt.bytesToHex(hash.finalResult(), .lower);
    }
};
const Manifest = struct { schema: u32 = 1, identity: Identity };
const Entry = struct { role: Role, name: []const u8, bytes: u64, sha256: [32]u8 };
const Complete = struct { schema: u32 = 1, identity: Identity, files: []const Entry };

pub fn rootFromEnv(a: std.mem.Allocator) !?[]u8 {
    const root = std.process.getEnvVarOwned(a, "STWO_RV64_LEAN_ARTIFACT_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    if (root.len == 0) {
        a.free(root);
        return error.InvalidRv64ArtifactRoot;
    }
    return root;
}

pub const Dataset = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    dir: std.fs.Dir,
    identity: Identity,
    mutex: std.Thread.Mutex = .{},
    write_mutex: std.Thread.Mutex = .{},
    borrows: usize = 0,
    failure: ?anyerror = null,
    finished: bool = false,

    pub fn create(a: std.mem.Allocator, root: []const u8, id: Identity) !*Dataset {
        if (root.len == 0) return error.InvalidRv64ArtifactRoot;
        const parent = try std.fs.path.join(a, &.{ root, "recordings", "executions" });
        defer a.free(parent);
        var collection = try std.fs.cwd().makeOpenPath(parent, .{});
        defer collection.close();
        const key = id.key();
        try collection.makeDir(&key);
        const path = try std.fs.path.join(a, &.{ parent, &key });
        errdefer a.free(path);
        var dir = try collection.openDir(&key, .{});
        errdefer dir.close();
        const owner = try a.create(Dataset);
        errdefer a.destroy(owner);
        owner.* = .{ .allocator = a, .path = path, .dir = dir, .identity = id };
        try owner.json("manifest.json", Manifest{ .identity = id });
        inline for (std.meta.tags(Role)) |role| try dir.makeDir(@tagName(role));
        return owner;
    }
    fn json(self: *Dataset, name: []const u8, value: anytype) !void {
        const bytes = try std.json.Stringify.valueAlloc(self.allocator, value, .{});
        defer self.allocator.free(bytes);
        var file = try self.dir.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
    }
    pub fn fail(self: *Dataset, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.failure == null) self.failure = err;
    }
    pub fn borrow(self: *Dataset) !Borrow {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.finished) return error.RecordingClosed;
        self.borrows += 1;
        return .{ .owner = self };
    }
    pub fn rolePath(self: *Dataset, a: std.mem.Allocator, role: Role) ![]u8 {
        return std.fs.path.join(a, &.{ self.path, @tagName(role) });
    }
    pub fn write(self: *Dataset, role: Role, name: []const u8, bytes: []const u8) !bool {
        var lease = try self.borrow();
        defer lease.release() catch unreachable;
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        return self.writeInner(role, name, bytes) catch |err| {
            self.fail(err);
            return err;
        };
    }
    fn writeInner(self: *Dataset, role: Role, name: []const u8, bytes: []const u8) !bool {
        if (name.len == 0 or !std.mem.eql(u8, name, std.fs.path.basename(name)) or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.RecordingInvalidName;
        var dir = try self.dir.openDir(@tagName(role), .{});
        defer dir.close();
        var file = dir.createFile(name, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                const existing = try dir.readFileAlloc(self.allocator, name, bytes.len + 1);
                defer self.allocator.free(existing);
                if (!std.mem.eql(u8, existing, bytes)) return error.RecordingContentConflict;
                return false;
            },
            else => return err,
        };
        defer file.close();
        try file.writeAll(bytes);
        return true;
    }
    pub fn finish(self: *Dataset, success: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.borrows != 0) return error.RecordingStillBorrowed;
        if (self.finished) return error.RecordingClosed;
        self.finished = true;
        try self.publish(success);
    }
    fn publish(self: *Dataset, success: bool) !void {
        if (!success or self.failure != null) return self.json("incomplete.json", .{ .error_name = if (self.failure) |err| @errorName(err) else "ExecutionIncomplete" });
        var files = inventory(self.allocator, self.dir) catch |err| {
            self.failure = err;
            self.json("incomplete.json", .{ .error_name = @errorName(err) }) catch {};
            return err;
        };
        defer files.deinit();
        self.json("complete.json", Complete{ .identity = self.identity, .files = files.items }) catch |err| {
            self.failure = err;
            return err;
        };
    }
    pub fn destroy(self: *Dataset) !void {
        self.mutex.lock();
        if (self.borrows != 0) {
            self.mutex.unlock();
            return error.RecordingStillBorrowed;
        }
        const publish_abort = !self.finished;
        self.finished = true; // Close borrow admission before dropping the lock.
        self.mutex.unlock();
        if (publish_abort) self.publish(false) catch |err| std.log.err("recording abort metadata: {s}", .{@errorName(err)});
        self.dir.close();
        const a = self.allocator;
        a.free(self.path);
        a.destroy(self);
    }
};

/// Consuming borrow: copying this value does not retain another lease.
pub const Borrow = struct {
    owner: *Dataset,
    active: bool = true,
    pub fn release(self: *Borrow) !void {
        if (!self.active) return error.RecordingBorrowReleased;
        self.owner.mutex.lock();
        defer self.owner.mutex.unlock();
        std.debug.assert(self.owner.borrows != 0);
        self.owner.borrows -= 1;
        self.active = false;
    }
};
/// Stable request-owned slot, never a process-global/current-thread identity.
/// Attach/detach run only at the actual caller's quiescent request boundary.
pub const Slot = struct {
    held: ?Borrow = null,
    pub fn attach(self: *Slot, owner: ?*Dataset) !void {
        if (self.held != null) return error.RecordingSlotOccupied;
        if (owner) |dataset| self.held = try dataset.borrow();
    }
    pub fn detach(self: *Slot) void {
        if (self.held) |*held| held.release() catch unreachable;
        self.held = null;
    }
    pub fn borrow(self: *const Slot) !?Borrow {
        return if (self.held) |held| try held.owner.borrow() else null;
    }
    pub fn borrowDiagnostic(self: *const Slot) ?Borrow {
        return self.borrow() catch |err| {
            if (self.held) |held| held.owner.fail(err);
            std.debug.print("RV64_CAPTURE borrow error={s} complete=false\n", .{@errorName(err)});
            return null;
        };
    }
    pub fn requireExecution(self: *const Slot, execution: [32]u8) !void {
        if (self.held) |held| if (!std.mem.eql(u8, &held.owner.identity.execution, &execution)) return error.RecordingExecutionMismatch;
    }
};

pub const DeviceSlot = struct { ordinal: u32, slot: *Slot };
pub fn selectSlot(selected: ?*Slot, candidate: *Slot) !*Slot {
    if (selected != null) return error.AmbiguousRecordingDevice;
    return candidate;
}
/// Diagnostic ambiguity never selects the first of two different contexts.
pub fn uniqueSlot(services: []const DeviceSlot, ordinal: u32) !?*Slot {
    var selected: ?*Slot = null;
    for (services) |service| if (service.ordinal == ordinal) {
        selected = try selectSlot(selected, service.slot);
    };
    return selected;
}

pub fn hashFile(file: std.fs.File) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [32768]u8 = undefined;
    while (true) {
        const n = try file.read(&buffer);
        if (n == 0) break;
        hash.update(buffer[0..n]);
    }
    return hash.finalResult();
}
const Files = struct {
    a: std.mem.Allocator,
    items: []Entry,
    fn deinit(self: *Files) void {
        for (self.items) |row| self.a.free(row.name);
        self.a.free(self.items);
    }
};
fn less(_: void, left: Entry, right: Entry) bool {
    if (left.role != right.role) return @intFromEnum(left.role) < @intFromEnum(right.role);
    return std.mem.lessThan(u8, left.name, right.name);
}
fn inventory(a: std.mem.Allocator, dir: std.fs.Dir) !Files {
    var rows: std.ArrayList(Entry) = .empty;
    errdefer {
        for (rows.items) |row| a.free(row.name);
        rows.deinit(a);
    }
    inline for (std.meta.tags(Role)) |role| {
        var sub = try dir.openDir(@tagName(role), .{ .iterate = true });
        defer sub.close();
        var it = sub.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) return error.RecordingUnexpectedEntry;
            var file = try sub.openFile(entry.name, .{});
            defer file.close();
            const name = try a.dupe(u8, entry.name);
            errdefer a.free(name);
            try rows.append(a, .{ .role = role, .name = name, .bytes = (try file.stat()).size, .sha256 = try hashFile(file) });
        }
    }
    std.mem.sort(Entry, rows.items, {}, less);
    return .{ .a = a, .items = try rows.toOwnedSlice(a) };
}
pub fn verify(a: std.mem.Allocator, path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    if (dir.access("incomplete.json", .{})) |_| return error.RecordingIncomplete else |err| if (err != error.FileNotFound) return err;
    const manifest_bytes = try dir.readFileAlloc(a, "manifest.json", 4096);
    defer a.free(manifest_bytes);
    const manifest = try std.json.parseFromSlice(Manifest, a, manifest_bytes, .{});
    defer manifest.deinit();
    const bytes = dir.readFileAlloc(a, "complete.json", 64 << 20) catch |err| return if (err == error.FileNotFound) error.RecordingIncomplete else err;
    defer a.free(bytes);
    const complete = try std.json.parseFromSlice(Complete, a, bytes, .{});
    defer complete.deinit();
    if (manifest.value.schema != 1 or complete.value.schema != 1 or !std.meta.eql(manifest.value.identity, complete.value.identity) or !std.mem.eql(u8, &manifest.value.identity.key(), std.fs.path.basename(path))) return error.RecordingInventoryMismatch;
    var actual = try inventory(a, dir);
    defer actual.deinit();
    if (actual.items.len != complete.value.files.len) return error.RecordingInventoryMismatch;
    for (actual.items, complete.value.files) |left, right| {
        if (left.role != right.role or !std.mem.eql(u8, left.name, right.name) or left.bytes != right.bytes or !std.mem.eql(u8, &left.sha256, &right.sha256)) return error.RecordingInventoryMismatch;
    }
}
pub const Paths = struct {
    allocator: std.mem.Allocator,
    items: [][]u8,
    pub fn deinit(self: *Paths) void {
        for (self.items) |item| self.allocator.free(item);
        self.allocator.free(self.items);
    }
};
fn pathLess(_: void, left: []u8, right: []u8) bool {
    return std.mem.lessThan(u8, left, right);
}
pub fn replay(a: std.mem.Allocator, root: []const u8, role: Role) !Paths {
    var paths: std.ArrayList([]u8) = .empty;
    errdefer {
        for (paths.items) |path| a.free(path);
        paths.deinit(a);
    }
    for ([_]bool{ false, true }) |historical| {
        const parent = if (historical) try std.fs.path.join(a, &.{ root, "recordings/historical", @tagName(role) }) else try std.fs.path.join(a, &.{ root, "recordings/executions" });
        defer a.free(parent);
        var collection = std.fs.cwd().openDir(parent, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer collection.close();
        var it = collection.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory and !(historical and entry.kind == .sym_link)) return error.RecordingUnexpectedEntry;
            const dataset = try std.fs.path.join(a, &.{ parent, entry.name });
            defer a.free(dataset);
            if (!historical) try verify(a, dataset);
            const path = if (historical) try a.dupe(u8, dataset) else try std.fs.path.join(a, &.{ dataset, @tagName(role) });
            errdefer a.free(path);
            var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
            defer dir.close();
            var files = dir.iterate();
            var present = historical; // Every explicitly imported old family is replayed.
            while (try files.next()) |file| {
                const primary = if (role == .nodes) std.mem.endsWith(u8, file.name, ".gnr") else std.mem.startsWith(u8, file.name, "seg-") and std.mem.endsWith(u8, file.name, ".gnp");
                if (primary) present = true;
            }
            if (present) try paths.append(a, path) else a.free(path);
        }
    }
    std.mem.sort([]u8, paths.items, {}, pathLess);
    if (paths.items.len == 0) return error.NoRecordingDatasets;
    return .{ .allocator = a, .items = try paths.toOwnedSlice(a) };
}

test {
    _ = @import("recording_dataset_test.zig");
    _ = @import("recorded_replay.zig");
}
