//! Bounded preprocessed-cache behaviour: least-recently-used eviction, the
//! protections that keep a live run's artifacts, per-run ops accounting, and
//! the fail-open paths a concurrent eviction can expose.
//!
//! These live in the frontend test root (rather than beside the module) because
//! this is the root module `test-cairo-frontend` compiles, so every case here is
//! actually gated.

const std = @import("std");
const cairo = @import("cairo_frontend");

const product_cache = cairo.preprocessed.product_cache;

/// A cache directory plus the configuration that points the module at it.
const Fixture = struct {
    tmp: std.testing.TmpDir,
    directory: []u8,
    saved: product_cache.Config,

    fn init(budget_bytes: u64) !Fixture {
        var tmp = std.testing.tmpDir(.{});
        const directory = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
        const saved = product_cache.currentConfig();
        product_cache.configure(.{
            .enabled = true,
            .product_digest = @splat(0x5a),
            .directory = directory,
            .budget_bytes = budget_bytes,
        });
        return .{ .tmp = tmp, .directory = directory, .saved = saved };
    }

    fn deinit(self: *Fixture) void {
        product_cache.configure(self.saved);
        std.testing.allocator.free(self.directory);
        self.tmp.cleanup();
    }

    /// Writes a synthetic artifact of `size` bytes with an explicit last-used
    /// marker `age_ns` in the past. The contents are irrelevant here: eviction
    /// is a filesystem policy and never parses an artifact.
    fn writeArtifact(
        self: *Fixture,
        name: []const u8,
        size: usize,
        age_ns: i128,
    ) !void {
        const file = try self.tmp.dir.createFile(name, .{ .mode = 0o600 });
        defer file.close();
        const filler = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(filler);
        @memset(filler, 0xab);
        try file.writeAll(filler);
        const marker = std.time.nanoTimestamp() - age_ns;
        try file.updateTimes(marker, marker);
    }

    fn exists(self: *Fixture, name: []const u8) bool {
        self.tmp.dir.access(name, .{}) catch return false;
        return true;
    }

    fn entryCount(self: *Fixture) !usize {
        var directory = try std.fs.openDirAbsolute(
            self.directory,
            .{ .iterate = true },
        );
        defer directory.close();
        var count: usize = 0;
        var iterator = directory.iterate();
        while (try iterator.next()) |_| count += 1;
        return count;
    }
};

/// Distinct 64-hex artifact stems. Only the shape matters to the policy.
fn stem(index: u8) [64]u8 {
    const key: [32]u8 = @splat(index);
    return std.fmt.bytesToHex(key, .lower);
}

fn artifactName(buffer: []u8, index: u8, extension: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ stem(index), extension });
}

const second = std.time.ns_per_s;

test "eviction reclaims least-recently-used artifacts down to the budget" {
    var fixture = try Fixture.init(3 * 1024);
    defer fixture.deinit();

    var names: [4][128]u8 = undefined;
    var resolved: [4][]const u8 = undefined;
    // Four 1 KiB artifacts, oldest last-used marker first.
    for (0..4) |index| {
        resolved[index] = try artifactName(
            &names[index],
            @intCast(index),
            ".preprocessed",
        );
        try fixture.writeArtifact(
            resolved[index],
            1024,
            @as(i128, @intCast(400 - index * 100)) * second,
        );
    }

    product_cache.enforceBudget(std.testing.allocator);

    // 4 KiB against a 3 KiB budget: exactly the single oldest artifact goes.
    try std.testing.expect(!fixture.exists(resolved[0]));
    try std.testing.expect(fixture.exists(resolved[1]));
    try std.testing.expect(fixture.exists(resolved[2]));
    try std.testing.expect(fixture.exists(resolved[3]));

    const accounting = product_cache.accountingSnapshot();
    try std.testing.expectEqual(@as(u64, 1), accounting.evictions);
    try std.testing.expectEqual(@as(u64, 1024), accounting.evicted_bytes);
    try std.testing.expectEqual(@as(u64, 3 * 1024), accounting.directory_bytes);
}

test "a refreshed last-used marker moves an artifact to the back of the queue" {
    var fixture = try Fixture.init(2 * 1024);
    defer fixture.deinit();

    var old_buffer: [128]u8 = undefined;
    var middle_buffer: [128]u8 = undefined;
    var new_buffer: [128]u8 = undefined;
    const old = try artifactName(&old_buffer, 1, ".preprocessed");
    const middle = try artifactName(&middle_buffer, 2, ".preprocessed-tree");
    const new = try artifactName(&new_buffer, 3, ".preprocessed");
    try fixture.writeArtifact(old, 1024, 500 * second);
    try fixture.writeArtifact(middle, 1024, 300 * second);
    try fixture.writeArtifact(new, 1024, 100 * second);

    // A verified load refreshes the marker in band; simulate that on the
    // oldest artifact, which must then outlive the middle one.
    {
        const file = try fixture.tmp.dir.openFile(old, .{});
        defer file.close();
        product_cache.touchArtifact(file);
    }

    product_cache.enforceBudget(std.testing.allocator);
    try std.testing.expect(fixture.exists(old));
    try std.testing.expect(!fixture.exists(middle));
    try std.testing.expect(fixture.exists(new));
}

test "eviction never reclaims the current product identity's artifacts" {
    var fixture = try Fixture.init(1024);
    defer fixture.deinit();

    // The protected key is the oldest artifact and the only eviction candidate
    // large enough to matter, so an unprotected policy would take it first.
    const protected_key: [32]u8 = @splat(0x11);
    var protected_buffer: [128]u8 = undefined;
    const protected = try std.fmt.bufPrint(
        &protected_buffer,
        "{s}.preprocessed",
        .{std.fmt.bytesToHex(protected_key, .lower)},
    );
    var other_buffer: [128]u8 = undefined;
    const other = try artifactName(&other_buffer, 0x22, ".preprocessed");
    try fixture.writeArtifact(protected, 4096, 900 * second);
    try fixture.writeArtifact(other, 4096, 100 * second);

    product_cache.protectKey(protected_key);
    product_cache.enforceBudget(std.testing.allocator);

    try std.testing.expect(fixture.exists(protected));
    try std.testing.expect(!fixture.exists(other));
    // Still over budget, and honestly reported rather than forced.
    const accounting = product_cache.accountingSnapshot();
    try std.testing.expectEqual(@as(u64, 4096), accounting.directory_bytes);
    try std.testing.expect(accounting.directory_bytes > accounting.budget_bytes);
}

test "a fresh store survives the eviction pass it triggers" {
    var fixture = try Fixture.init(1024);
    defer fixture.deinit();

    // Simulates the store path: register the key, write the artifact, enforce.
    const fresh_key: [32]u8 = @splat(0x33);
    var fresh_buffer: [128]u8 = undefined;
    const fresh = try std.fmt.bufPrint(
        &fresh_buffer,
        "{s}.preprocessed-tree",
        .{std.fmt.bytesToHex(fresh_key, .lower)},
    );
    var stale_buffer: [128]u8 = undefined;
    const stale = try artifactName(&stale_buffer, 0x44, ".preprocessed-tree");
    try fixture.writeArtifact(stale, 2048, 10 * second);

    product_cache.protectKey(fresh_key);
    try fixture.writeArtifact(fresh, 2048, 0);
    product_cache.enforceBudget(std.testing.allocator);

    try std.testing.expect(fixture.exists(fresh));
    try std.testing.expect(!fixture.exists(stale));
}

test "eviction leaves foreign files and in-flight temporaries alone" {
    var fixture = try Fixture.init(1024);
    defer fixture.deinit();

    // The marker is in band (the artifact's own mtime), so there is no sidecar
    // that can be corrupted independently of the artifact. The analogous
    // hazard is a directory the cache does not fully own: junk it cannot parse,
    // and another process's in-flight temporary. Neither may be unlinked, and
    // neither may make the pass fail.
    var junk_name: [128]u8 = undefined;
    const junk = try std.fmt.bufPrint(&junk_name, "not-an-artifact.txt", .{});
    var short_name: [128]u8 = undefined;
    const short = try std.fmt.bufPrint(&short_name, "ab.preprocessed", .{});
    var temporary_name: [192]u8 = undefined;
    const temporary = try std.fmt.bufPrint(
        &temporary_name,
        "{s}.preprocessed.0011223344556677.tmp",
        .{stem(0x55)},
    );
    var evictable_name: [128]u8 = undefined;
    const evictable = try artifactName(&evictable_name, 0x66, ".preprocessed");

    try fixture.writeArtifact(junk, 2048, 800 * second);
    try fixture.writeArtifact(short, 8, 800 * second);
    try fixture.writeArtifact(temporary, 2048, 30 * second);
    try fixture.writeArtifact(evictable, 2048, 700 * second);

    product_cache.enforceBudget(std.testing.allocator);

    try std.testing.expect(fixture.exists(junk));
    try std.testing.expect(fixture.exists(temporary));
    try std.testing.expect(!fixture.exists(evictable));
    // `ab.preprocessed` carries this cache's extension but cannot be a key, so
    // it is a legitimate candidate; it is only 8 bytes, so it goes last.
    _ = fixture.exists(short);
}

test "a crashed writer's stale temporary is reclaimed before real artifacts" {
    var fixture = try Fixture.init(2048);
    defer fixture.deinit();

    var stale_name: [192]u8 = undefined;
    const stale = try std.fmt.bufPrint(
        &stale_name,
        "{s}.preprocessed.8899aabbccddeeff.tmp",
        .{stem(0x77)},
    );
    var artifact_name_buffer: [128]u8 = undefined;
    const artifact = try artifactName(
        &artifact_name_buffer,
        0x88,
        ".preprocessed",
    );
    // Two hours old: past the in-flight window, so it is garbage.
    try fixture.writeArtifact(stale, 2048, 2 * 60 * 60 * second);
    // Older last-used marker than the temporary's write time, and still kept:
    // garbage is always reclaimed before cache value.
    try fixture.writeArtifact(artifact, 2048, 3 * 60 * 60 * second);

    product_cache.enforceBudget(std.testing.allocator);
    try std.testing.expect(!fixture.exists(stale));
    try std.testing.expect(fixture.exists(artifact));
}

test "a zero budget disables eviction entirely" {
    var fixture = try Fixture.init(0);
    defer fixture.deinit();

    var name_buffer: [128]u8 = undefined;
    const artifact = try artifactName(&name_buffer, 0x99, ".preprocessed");
    try fixture.writeArtifact(artifact, 4096, 900 * second);

    product_cache.enforceBudget(std.testing.allocator);
    try std.testing.expect(fixture.exists(artifact));
    const accounting = product_cache.accountingSnapshot();
    try std.testing.expectEqual(@as(u64, 0), accounting.evictions);
    try std.testing.expectEqual(@as(u64, 0), accounting.budget_bytes);
}

test "a disabled cache short-circuits without touching the directory" {
    var fixture = try Fixture.init(1024);
    defer fixture.deinit();

    var name_buffer: [128]u8 = undefined;
    const artifact = try artifactName(&name_buffer, 0xaa, ".preprocessed");
    try fixture.writeArtifact(artifact, 4096, 900 * second);
    const before = try fixture.entryCount();

    const configuration = product_cache.currentConfig();
    product_cache.configure(.{
        .enabled = false,
        .product_digest = configuration.product_digest,
        .directory = configuration.directory,
        .budget_bytes = configuration.budget_bytes,
    });
    try std.testing.expect(!product_cache.isEnabled());
    product_cache.enforceBudget(std.testing.allocator);

    try std.testing.expectEqual(before, try fixture.entryCount());
    try std.testing.expect(fixture.exists(artifact));
    const accounting = product_cache.accountingSnapshot();
    try std.testing.expectEqual(@as(u64, 0), accounting.evictions);
    try std.testing.expectEqual(@as(u64, 0), accounting.directory_bytes);
    try std.testing.expect(!accounting.enabled);
}

test "an inert cache with no directory never scans anything" {
    const saved = product_cache.currentConfig();
    defer product_cache.configure(saved);
    product_cache.configure(.{ .enabled = true, .directory = "" });
    try std.testing.expect(!product_cache.isEnabled());
    product_cache.enforceBudget(std.testing.allocator);
    try std.testing.expectEqual(
        @as(u64, 0),
        product_cache.accountingSnapshot().evictions,
    );
}

test "an eviction concurrent with a reader cannot truncate the reader" {
    var fixture = try Fixture.init(1024);
    defer fixture.deinit();

    var name_buffer: [128]u8 = undefined;
    const artifact = try artifactName(&name_buffer, 0xbb, ".preprocessed");
    try fixture.writeArtifact(artifact, 4096, 900 * second);

    // The losing reader opened its file first. Eviction only ever unlinks whole
    // artifacts, so the open descriptor keeps reading the complete inode: the
    // reader either verifies a whole artifact or never opened it at all. There
    // is no third state, which is why the existing integrity checks are
    // sufficient for a concurrent eviction.
    const reader = try fixture.tmp.dir.openFile(artifact, .{});
    defer reader.close();

    product_cache.enforceBudget(std.testing.allocator);
    try std.testing.expect(!fixture.exists(artifact));

    var payload: [4096]u8 = undefined;
    var filled: usize = 0;
    while (filled < payload.len) {
        const count = try reader.read(payload[filled..]);
        if (count == 0) break;
        filled += count;
    }
    try std.testing.expectEqual(@as(usize, 4096), filled);
    for (payload) |byte| try std.testing.expectEqual(@as(u8, 0xab), byte);

    // A reader that had not opened yet sees the fail-open path.
    try std.testing.expectError(
        error.FileNotFound,
        fixture.tmp.dir.openFile(artifact, .{}),
    );
}

test "concurrent stores and eviction passes leave a coherent directory" {
    var fixture = try Fixture.init(16 * 1024);
    defer fixture.deinit();

    const Worker = struct {
        fixture: *Fixture,
        base: u8,
        mutex: *std.Thread.Mutex,

        fn run(self: *@This()) void {
            for (0..24) |round| {
                var name_buffer: [128]u8 = undefined;
                const name = std.fmt.bufPrint(
                    &name_buffer,
                    "{s}.preprocessed",
                    .{stem(self.base +% @as(u8, @intCast(round)))},
                ) catch return;
                // The store itself is serialised only because this fixture
                // writes through one shared `Dir` handle; eviction below runs
                // unsynchronised, which is the case under test.
                self.mutex.lock();
                self.fixture.writeArtifact(name, 2048, 0) catch {
                    self.mutex.unlock();
                    return;
                };
                self.mutex.unlock();
                product_cache.enforceBudget(std.testing.allocator);
            }
        }
    };

    var mutex = std.Thread.Mutex{};
    var first = Worker{ .fixture = &fixture, .base = 0, .mutex = &mutex };
    var second_worker = Worker{ .fixture = &fixture, .base = 128, .mutex = &mutex };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&second_worker});
    first.run();
    thread.join();

    // No pass may leave the directory over budget, and no pass may crash.
    var directory = try std.fs.openDirAbsolute(
        fixture.directory,
        .{ .iterate = true },
    );
    defer directory.close();
    var total: u64 = 0;
    var iterator = directory.iterate();
    while (try iterator.next()) |entry| {
        if (entry.kind != .file) continue;
        total += (try directory.statFile(entry.name)).size;
    }
    try std.testing.expect(total <= 16 * 1024);
    const accounting = product_cache.accountingSnapshot();
    try std.testing.expect(accounting.evictions > 0);
}

test "accounting counts hits, misses, stores and bytes independently" {
    var fixture = try Fixture.init(product_cache.default_budget_bytes);
    defer fixture.deinit();

    try std.testing.expectEqual(
        @as(u64, 0),
        product_cache.accountingSnapshot().hits,
    );
    product_cache.recordMiss();
    product_cache.recordStore(2_097_248);
    product_cache.recordHit(2_097_248);
    product_cache.recordHit(134_217_856);

    const accounting = product_cache.accountingSnapshot();
    try std.testing.expectEqual(@as(u64, 2), accounting.hits);
    try std.testing.expectEqual(@as(u64, 1), accounting.misses);
    try std.testing.expectEqual(@as(u64, 1), accounting.stores);
    try std.testing.expectEqual(@as(u64, 2_097_248), accounting.stored_bytes);
    try std.testing.expectEqual(
        @as(u64, 2_097_248 + 134_217_856),
        accounting.loaded_bytes,
    );
    try std.testing.expect(accounting.enabled);
    try std.testing.expectEqual(
        product_cache.default_budget_bytes,
        accounting.budget_bytes,
    );

    // Reconfiguration is what a new run does, and it must not inherit counts.
    product_cache.resetAccounting();
    try std.testing.expectEqual(
        @as(u64, 0),
        product_cache.accountingSnapshot().hits,
    );
}
