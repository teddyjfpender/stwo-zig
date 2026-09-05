//! Persistent concurrent-writer-safe content-addressed raw object store.

const std = @import("std");
const builtin = @import("builtin");
const encoding = @import("encoding.zig");
const types = @import("types.zig");

extern "c" fn fclonefileat(
    source_fd: std.posix.fd_t,
    destination_dir_fd: std.posix.fd_t,
    destination: [*:0]const u8,
    flags: u32,
) c_int;

const clone_no_owner_copy: u32 = 0x0002;
const io_buffer_bytes: usize = 4 * 1024 * 1024;

pub const FileIdentity = struct {
    inode: std.fs.File.INode,
    size: u64,
    mtime: i128,
    ctime: i128,

    pub fn fromStat(stat: std.fs.File.Stat) FileIdentity {
        return .{
            .inode = stat.inode,
            .size = stat.size,
            .mtime = stat.mtime,
            .ctime = stat.ctime,
        };
    }

    pub fn eql(a: FileIdentity, b: FileIdentity) bool {
        return a.inode == b.inode and a.size == b.size and
            a.mtime == b.mtime and a.ctime == b.ctime;
    }
};

pub const Measurement = struct {
    bytes: u64,
    sha256: encoding.Digest,
    identity: FileIdentity,
};

pub const CopyMethod = enum {
    cache,
    apfs_clone,
    byte_copy,
};

pub const IngestPolicy = enum {
    prefer_apfs_clone,
    byte_copy,
};

pub const ObjectRef = struct {
    object_id: encoding.Digest,
    bytes: u64,
};

pub const Snapshot = struct {
    object_id: encoding.Digest,
    path: []u8,
    measurement: Measurement,
    source_identity: ?FileIdentity,
    method: CopyMethod,
    bytes_hashed: u64,

    pub fn ref(self: *const Snapshot) ObjectRef {
        return .{ .object_id = self.object_id, .bytes = self.measurement.bytes };
    }

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const OwnedBlobV1 = struct {
    ref: types.BlobRefV1,
    bytes: []u8,

    pub fn deinit(self: *OwnedBlobV1, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

const AccessPolicy = enum { owner_thread, concurrent };

const CacheEntry = struct {
    object_path: []u8,
    measurement: Measurement,
};

/// `initNew` retains the Metal service's exclusive, owner-thread contract.
/// `openOrCreate` is the stable persistent API and permits concurrent calls and
/// concurrent store instances. `deinit` still requires caller quiescence.
pub const Store = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    objects_path: []u8,
    cleanup_on_deinit: bool,
    objects: std.AutoHashMap(encoding.Digest, CacheEntry),
    mutex: std.Thread.Mutex = .{},
    owner_thread_id: std.Thread.Id,
    access_policy: AccessPolicy,

    pub fn initNew(
        allocator: std.mem.Allocator,
        root_path: []const u8,
        cleanup_on_deinit: bool,
    ) !Store {
        return initialize(allocator, root_path, cleanup_on_deinit, true, .owner_thread);
    }

    pub fn openOrCreate(
        allocator: std.mem.Allocator,
        root_path: []const u8,
        cleanup_on_deinit: bool,
    ) !Store {
        return initialize(allocator, root_path, cleanup_on_deinit, false, .concurrent);
    }

    pub fn deinit(self: *Store) void {
        if (self.access_policy == .owner_thread and
            self.owner_thread_id != std.Thread.getCurrentId())
        {
            @panic("artifact store deinitialized from non-owner thread");
        }
        var iterator = self.objects.iterator();
        while (iterator.next()) |entry| self.allocator.free(entry.value_ptr.object_path);
        self.objects.deinit();
        if (self.cleanup_on_deinit) std.fs.deleteTreeAbsolute(self.root_path) catch {};
        self.allocator.free(self.objects_path);
        self.allocator.free(self.root_path);
        self.* = undefined;
    }

    /// Rebuilds the in-memory index by rehashing every immutable object. Temp
    /// files are ignored because another process may still be publishing them.
    pub fn rebuildIndex(self: *Store) !void {
        try self.requireAccess();
        var directory = try std.fs.openDirAbsolute(self.objects_path, .{
            .iterate = true,
            .no_follow = true,
        });
        defer directory.close();
        var iterator = directory.iterate();
        while (try iterator.next()) |entry| {
            if (std.mem.startsWith(u8, entry.name, ".ingest-") and
                std.mem.endsWith(u8, entry.name, ".tmp"))
            {
                continue;
            }
            if (entry.kind != .directory or !isShardName(entry.name))
                return error.ArtifactStoreCorrupt;
            const shard_path = try std.fs.path.join(
                self.allocator,
                &.{ self.objects_path, entry.name },
            );
            defer self.allocator.free(shard_path);
            var shard = try std.fs.openDirAbsolute(shard_path, .{
                .iterate = true,
                .no_follow = true,
            });
            defer shard.close();
            var shard_iterator = shard.iterate();
            while (try shard_iterator.next()) |object_entry| {
                if (object_entry.kind != .file) return error.ArtifactStoreCorrupt;
                const expected = parseObjectName(object_entry.name) catch
                    return error.ArtifactStoreCorrupt;
                const digest_hex = std.fmt.bytesToHex(expected, .lower);
                if (!std.mem.eql(u8, entry.name, digest_hex[0..2]))
                    return error.ArtifactStoreCorrupt;
                const object_path = try std.fs.path.join(
                    self.allocator,
                    &.{ shard_path, object_entry.name },
                );
                defer self.allocator.free(object_path);
                const measured = try measureStoredObject(self.allocator, object_path);
                if (!std.mem.eql(u8, &measured.sha256, &expected))
                    return error.ArtifactStoreCorrupt;
                try self.cacheObject(expected, object_path, measured);
            }
        }
    }

    pub fn auditAndRebuildIndex(self: *Store) !void {
        return self.rebuildIndex();
    }

    pub fn putBytes(
        self: *Store,
        kind: types.ArtifactKindV1,
        schema_version: u16,
        bytes: []const u8,
    ) !types.BlobRefV1 {
        try self.requireAccess();
        const temporary_path = try self.temporaryPath();
        defer self.allocator.free(temporary_path);
        defer std.fs.deleteFileAbsolute(temporary_path) catch {};
        const file = try std.fs.createFileAbsolute(temporary_path, .{
            .read = true,
            .exclusive = true,
            .mode = 0o600,
        });
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        try file.chmod(0o400);
        try file.sync();
        const sha256 = encoding.digestBytes(bytes);
        const measured = Measurement{
            .bytes = @intCast(bytes.len),
            .sha256 = sha256,
            .identity = FileIdentity.fromStat(try file.stat()),
        };
        _ = try self.publishTemporary(temporary_path, measured);
        return types.BlobRefV1.create(kind, schema_version, @intCast(bytes.len), sha256);
    }

    pub fn openBlob(
        self: *Store,
        ref: types.BlobRefV1,
        expected_kind: types.ArtifactKindV1,
        expected_schema_version: u16,
        maximum_bytes: u64,
    ) !OwnedBlobV1 {
        try self.requireAccess();
        try ref.validate();
        if (ref.kind != expected_kind) return error.ArtifactKindMismatch;
        if (ref.schema_version != expected_schema_version)
            return error.ArtifactSchemaMismatch;
        if (ref.byte_count > maximum_bytes or ref.byte_count > std.math.maxInt(usize))
            return error.ArtifactTooLarge;
        const object_path = try self.objectPath(ref.sha256);
        defer self.allocator.free(object_path);
        const file = openRegularNoFollow(object_path) catch |err|
            switch (err) {
                error.FileNotFound => return error.UnknownArtifactObject,
                else => return err,
            };
        defer file.close();
        const before = try file.stat();
        if (before.kind != .file or before.size != ref.byte_count or before.mode & 0o222 != 0)
            return error.ArtifactStoreCorrupt;
        const bytes = try self.allocator.alloc(u8, @intCast(ref.byte_count));
        errdefer self.allocator.free(bytes);
        if (try file.readAll(bytes) != bytes.len) return error.TruncatedArtifactObject;
        var extra: [1]u8 = undefined;
        if (try file.read(&extra) != 0) return error.ArtifactObjectLengthMismatch;
        const after = try file.stat();
        if (!FileIdentity.fromStat(before).eql(FileIdentity.fromStat(after)))
            return error.ArtifactChangedDuringMeasurement;
        const observed_sha256 = encoding.digestBytes(bytes);
        if (!std.mem.eql(u8, &observed_sha256, &ref.sha256))
            return error.ArtifactStoreCorrupt;
        try self.cacheObject(ref.sha256, object_path, .{
            .bytes = ref.byte_count,
            .sha256 = ref.sha256,
            .identity = FileIdentity.fromStat(after),
        });
        return .{ .ref = ref, .bytes = bytes };
    }

    pub fn ingestPath(self: *Store, source_path: []const u8) !Snapshot {
        return self.ingestPathWithPolicy(source_path, .prefer_apfs_clone);
    }

    pub fn ingestPathWithPolicy(
        self: *Store,
        source_path: []const u8,
        policy: IngestPolicy,
    ) !Snapshot {
        try self.requireAccess();
        const canonical = try std.fs.realpathAlloc(self.allocator, source_path);
        defer self.allocator.free(canonical);
        const source = try std.fs.openFileAbsolute(canonical, .{});
        defer source.close();
        const source_stat = try source.stat();
        if (source_stat.kind != .file or source_stat.size == 0)
            return error.InvalidArtifact;
        const source_identity = FileIdentity.fromStat(source_stat);
        return self.ingest(source, source_identity, policy);
    }

    /// Authenticated Metal compatibility lookup. It intentionally performs no
    /// content read on a cache hit, but checks the retained file identity.
    pub fn resolveRef(self: *Store, object_ref: ObjectRef) !Snapshot {
        try self.requireAccess();
        const cached = try self.copyCacheEntry(object_ref.object_id) orelse
            return error.UnknownArtifactObject;
        defer self.allocator.free(cached.object_path);
        if (!std.mem.eql(u8, &cached.measurement.sha256, &object_ref.object_id))
            return error.ArtifactStoreCorrupt;
        if (cached.measurement.bytes != object_ref.bytes)
            return error.ArtifactObjectLengthMismatch;
        try requireStoredIdentity(cached.object_path, cached.measurement.identity);
        return .{
            .object_id = object_ref.object_id,
            .path = try self.allocator.dupe(u8, cached.object_path),
            .measurement = cached.measurement,
            .source_identity = null,
            .method = .cache,
            .bytes_hashed = 0,
        };
    }

    pub fn resolveObject(self: *Store, object_id: encoding.Digest) !Snapshot {
        try self.requireAccess();
        const cached = try self.copyCacheEntry(object_id) orelse
            return error.UnknownArtifactObject;
        defer self.allocator.free(cached.object_path);
        return self.resolveRef(.{ .object_id = object_id, .bytes = cached.measurement.bytes });
    }

    fn ingest(
        self: *Store,
        source: std.fs.File,
        source_identity: FileIdentity,
        policy: IngestPolicy,
    ) !Snapshot {
        const temporary_path = try self.temporaryPath();
        defer self.allocator.free(temporary_path);
        defer std.fs.deleteFileAbsolute(temporary_path) catch {};
        const clone_succeeded = policy == .prefer_apfs_clone and
            try cloneOpenFile(source, temporary_path);
        const method = if (clone_succeeded) CopyMethod.apfs_clone else CopyMethod.byte_copy;
        var measured = if (clone_succeeded)
            try measureFile(self.allocator, temporary_path)
        else
            try copyOpenFile(self.allocator, source, temporary_path);
        const source_after = FileIdentity.fromStat(try source.stat());
        if (!source_identity.eql(source_after) or measured.bytes != source_identity.size)
            return error.ArtifactChangedDuringSnapshot;
        const temporary = try std.fs.openFileAbsolute(temporary_path, .{ .mode = .read_write });
        defer temporary.close();
        try temporary.chmod(0o400);
        try temporary.sync();
        measured = try self.publishTemporary(temporary_path, measured);
        return .{
            .object_id = measured.sha256,
            .path = try self.objectPath(measured.sha256),
            .measurement = measured,
            .source_identity = source_identity,
            .method = method,
            .bytes_hashed = measured.bytes,
        };
    }

    fn publishTemporary(
        self: *Store,
        temporary_path: []const u8,
        source_measurement: Measurement,
    ) !Measurement {
        const shard_path = try self.ensureShard(source_measurement.sha256);
        defer self.allocator.free(shard_path);
        const object_path = try self.objectPath(source_measurement.sha256);
        defer self.allocator.free(object_path);
        var linked = true;
        std.posix.link(temporary_path, object_path) catch |err| switch (err) {
            error.PathAlreadyExists => linked = false,
            else => return err,
        };
        const measured = measureStoredObject(self.allocator, object_path) catch |err| {
            if (!linked) return error.ArtifactStoreCollision;
            return err;
        };
        if (measured.bytes != source_measurement.bytes or
            !std.mem.eql(u8, &measured.sha256, &source_measurement.sha256))
        {
            return if (linked) error.ArtifactStoreCorrupt else error.ArtifactStoreCollision;
        }
        var shard = try std.fs.openDirAbsolute(shard_path, .{ .iterate = true });
        defer shard.close();
        try syncDirectory(shard);
        try self.cacheObject(measured.sha256, object_path, measured);
        return measured;
    }

    fn cacheObject(
        self: *Store,
        digest: encoding.Digest,
        object_path: []const u8,
        measurement: Measurement,
    ) !void {
        const retained_path = try self.allocator.dupe(u8, object_path);
        errdefer self.allocator.free(retained_path);
        self.mutex.lock();
        defer self.mutex.unlock();
        const result = try self.objects.getOrPut(digest);
        if (result.found_existing) {
            self.allocator.free(retained_path);
            if (result.value_ptr.measurement.bytes != measurement.bytes)
                return error.ArtifactStoreCorrupt;
            result.value_ptr.measurement = measurement;
            return;
        }
        result.value_ptr.* = .{
            .object_path = retained_path,
            .measurement = measurement,
        };
    }

    fn copyCacheEntry(self: *Store, digest: encoding.Digest) !?CacheEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        const cached = self.objects.get(digest) orelse return null;
        return .{
            .object_path = try self.allocator.dupe(u8, cached.object_path),
            .measurement = cached.measurement,
        };
    }

    fn objectPath(self: *Store, digest: encoding.Digest) ![]u8 {
        const digest_hex = std.fmt.bytesToHex(digest, .lower);
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/{s}.blob",
            .{ self.objects_path, digest_hex[0..2], digest_hex },
        );
    }

    fn ensureShard(self: *Store, digest: encoding.Digest) ![]u8 {
        const digest_hex = std.fmt.bytesToHex(digest, .lower);
        const shard_path = try std.fs.path.join(
            self.allocator,
            &.{ self.objects_path, digest_hex[0..2] },
        );
        errdefer self.allocator.free(shard_path);
        std.posix.mkdir(shard_path, 0o700) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        var shard = try std.fs.openDirAbsolute(shard_path, .{
            .iterate = true,
            .no_follow = true,
        });
        defer shard.close();
        try shard.chmod(0o700);
        var objects = try std.fs.openDirAbsolute(self.objects_path, .{ .iterate = true });
        defer objects.close();
        try syncDirectory(objects);
        return shard_path;
    }

    fn temporaryPath(self: *Store) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/.ingest-{}-{x}.tmp",
            .{ self.objects_path, std.Thread.getCurrentId(), std.crypto.random.int(u128) },
        );
    }

    fn requireAccess(self: *const Store) !void {
        if (self.access_policy == .owner_thread and
            self.owner_thread_id != std.Thread.getCurrentId())
        {
            return error.ArtifactStoreWrongThread;
        }
    }
};

fn initialize(
    allocator: std.mem.Allocator,
    root_path: []const u8,
    cleanup_on_deinit: bool,
    exclusive: bool,
    access_policy: AccessPolicy,
) !Store {
    if (!std.fs.path.isAbsolute(root_path)) return error.InvalidArtifactStorePath;
    const owned_root = try allocator.dupe(u8, root_path);
    errdefer allocator.free(owned_root);
    if (exclusive) {
        try std.posix.mkdir(owned_root, 0o700);
    } else {
        std.posix.mkdir(owned_root, 0o700) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    errdefer if (exclusive) std.fs.deleteTreeAbsolute(owned_root) catch {};
    var root = try std.fs.openDirAbsolute(owned_root, .{ .iterate = true, .no_follow = true });
    defer root.close();
    try root.chmod(0o700);
    const raw_objects_path = try std.fs.path.join(allocator, &.{ owned_root, "objects" });
    defer allocator.free(raw_objects_path);
    std.posix.mkdir(raw_objects_path, 0o700) catch |err| switch (err) {
        error.PathAlreadyExists => if (exclusive) return error.PathAlreadyExists,
        else => return err,
    };
    var raw_objects = try std.fs.openDirAbsolute(raw_objects_path, .{
        .iterate = true,
        .no_follow = true,
    });
    defer raw_objects.close();
    try raw_objects.chmod(0o700);
    const objects_path = try std.fs.path.join(allocator, &.{ raw_objects_path, "sha256" });
    errdefer allocator.free(objects_path);
    std.posix.mkdir(objects_path, 0o700) catch |err| switch (err) {
        error.PathAlreadyExists => if (exclusive) return error.PathAlreadyExists,
        else => return err,
    };
    var objects_dir = try std.fs.openDirAbsolute(objects_path, .{
        .iterate = true,
        .no_follow = true,
    });
    defer objects_dir.close();
    try objects_dir.chmod(0o700);
    try syncDirectory(objects_dir);
    try syncDirectory(raw_objects);
    try syncDirectory(root);
    var store = Store{
        .allocator = allocator,
        .root_path = owned_root,
        .objects_path = objects_path,
        .cleanup_on_deinit = cleanup_on_deinit,
        .objects = std.AutoHashMap(encoding.Digest, CacheEntry).init(allocator),
        .owner_thread_id = std.Thread.getCurrentId(),
        .access_policy = access_policy,
    };
    errdefer store.deinit();
    return store;
}

pub fn measureFile(allocator: std.mem.Allocator, path: []const u8) !Measurement {
    const canonical = try std.fs.realpathAlloc(allocator, path);
    defer allocator.free(canonical);
    const file = try std.fs.openFileAbsolute(canonical, .{});
    defer file.close();
    return measureOpenFile(allocator, file, false);
}

pub fn digestBytes(bytes: []const u8) encoding.Digest {
    return encoding.digestBytes(bytes);
}

fn measureStoredObject(allocator: std.mem.Allocator, path: []const u8) !Measurement {
    const file = try openRegularNoFollow(path);
    defer file.close();
    return measureOpenFile(allocator, file, true);
}

fn measureOpenFile(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    require_read_only: bool,
) !Measurement {
    const before = try file.stat();
    if (before.kind != .file or (require_read_only and before.mode & 0o222 != 0)) {
        return error.InvalidArtifact;
    }
    const buffer = try allocator.alloc(u8, io_buffer_bytes);
    defer allocator.free(buffer);
    try file.seekTo(0);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var bytes: u64 = 0;
    while (true) {
        const count = try file.read(buffer);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
        bytes = std.math.add(u64, bytes, count) catch return error.InvalidArtifact;
    }
    const after = try file.stat();
    const before_identity = FileIdentity.fromStat(before);
    const after_identity = FileIdentity.fromStat(after);
    if (!before_identity.eql(after_identity) or bytes != before.size)
        return error.ArtifactChangedDuringMeasurement;
    return .{
        .bytes = bytes,
        .sha256 = hasher.finalResult(),
        .identity = after_identity,
    };
}

fn cloneOpenFile(source: std.fs.File, destination: []const u8) !bool {
    if (comptime builtin.os.tag != .macos) return false;
    const destination_z = try std.posix.toPosixPath(destination);
    const result = fclonefileat(
        source.handle,
        std.posix.AT.FDCWD,
        &destination_z,
        clone_no_owner_copy,
    );
    return switch (std.posix.errno(result)) {
        .SUCCESS => true,
        .XDEV, .OPNOTSUPP => false,
        .EXIST => error.PathAlreadyExists,
        .ACCES, .PERM => error.AccessDenied,
        .NOSPC, .DQUOT => error.NoSpaceLeft,
        .IO => error.InputOutput,
        .ROFS => error.ReadOnlyFileSystem,
        .NAMETOOLONG => error.NameTooLong,
        .NOENT => error.FileNotFound,
        else => |err| std.posix.unexpectedErrno(err),
    };
}

fn copyOpenFile(
    allocator: std.mem.Allocator,
    source: std.fs.File,
    destination: []const u8,
) !Measurement {
    try source.seekTo(0);
    const output = try std.fs.createFileAbsolute(destination, .{
        .read = true,
        .exclusive = true,
        .mode = 0o600,
    });
    errdefer output.close();
    errdefer std.fs.deleteFileAbsolute(destination) catch {};
    const buffer = try allocator.alloc(u8, io_buffer_bytes);
    defer allocator.free(buffer);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var bytes: u64 = 0;
    while (true) {
        const count = try source.read(buffer);
        if (count == 0) break;
        try output.writeAll(buffer[0..count]);
        hasher.update(buffer[0..count]);
        bytes = std.math.add(u64, bytes, count) catch return error.InvalidArtifact;
    }
    try output.sync();
    const stat = try output.stat();
    if (stat.kind != .file or stat.size != bytes) return error.ArtifactChangedDuringSnapshot;
    output.close();
    return .{
        .bytes = bytes,
        .sha256 = hasher.finalResult(),
        .identity = FileIdentity.fromStat(stat),
    };
}

fn isShardName(name: []const u8) bool {
    if (name.len != 2) return false;
    for (name) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

fn parseObjectName(name: []const u8) !encoding.Digest {
    if (name.len != 64 + ".blob".len or !std.mem.endsWith(u8, name, ".blob"))
        return error.InvalidArtifactObjectName;
    const encoded = name[0..64];
    var digest: encoding.Digest = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return error.InvalidArtifactObjectName;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidArtifactObjectName;
    return digest;
}

fn requireStoredIdentity(path: []const u8, expected: FileIdentity) !void {
    const object = try openRegularNoFollow(path);
    defer object.close();
    const stat = try object.stat();
    if (stat.kind != .file or !FileIdentity.fromStat(stat).eql(expected))
        return error.ArtifactStoreCorrupt;
}

fn openRegularNoFollow(path: []const u8) !std.fs.File {
    const parent_path = std.fs.path.dirname(path) orelse return error.InvalidArtifactStorePath;
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or
        std.mem.eql(u8, basename, ".."))
    {
        return error.InvalidArtifactStorePath;
    }
    var parent = try std.fs.openDirAbsolute(parent_path, .{ .no_follow = true });
    defer parent.close();
    const entry = try std.posix.fstatat(
        parent.fd,
        basename,
        std.posix.AT.SYMLINK_NOFOLLOW,
    );
    if (entry.mode & std.posix.S.IFMT != std.posix.S.IFREG)
        return error.ArtifactStoreCorrupt;
    var flags: std.posix.O = .{ .ACCMODE = .RDONLY };
    if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(std.posix.O, "NOFOLLOW")) flags.NOFOLLOW = true;
    const fd = try std.posix.openat(parent.fd, basename, flags, 0);
    errdefer std.posix.close(fd);
    const file = std.fs.File{ .handle = fd };
    const opened = try file.stat();
    if (opened.kind != .file or opened.inode != entry.ino)
        return error.ArtifactStoreCorrupt;
    return file;
}

fn syncDirectory(directory: std.fs.Dir) !void {
    try std.posix.fsync(directory.fd);
}
