//! Fail-closed startup policy for the persistent Metal prover session.

const std = @import("std");
const artifact_store = @import("stwo").metal_session.artifact_store;

pub const CoreAot = struct {
    metallib_path: []const u8,
    sha256: [32]u8,
};

pub const RuntimeMode = union(enum) {
    diagnostic_source,
    production_core_aot: CoreAot,
};

pub const Options = struct {
    rust_verifier_path: []const u8,
    rust_verifier_lockfile_path: []const u8,
    composition_metallib_sha256: ?[]const u8 = null,
    runtime_mode: RuntimeMode = .diagnostic_source,
};

pub fn parseArgs(args: []const []const u8) !Options {
    if (args.len < 6 or (args.len - 6) % 2 != 0 or
        !std.mem.eql(u8, args[1], "--jsonl") or
        !std.mem.eql(u8, args[2], "--rust-verifier") or
        !std.mem.eql(u8, args[4], "--rust-verifier-lockfile"))
        return error.InvalidArguments;

    var options = Options{
        .rust_verifier_path = args[3],
        .rust_verifier_lockfile_path = args[5],
    };
    var core_metallib_path: ?[]const u8 = null;
    var core_metallib_sha256: ?[32]u8 = null;

    var index: usize = 6;
    while (index < args.len) : (index += 2) {
        const flag = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, flag, "--composition-metallib-sha256")) {
            if (options.composition_metallib_sha256 != null)
                return error.InvalidArguments;
            options.composition_metallib_sha256 = value;
        } else if (std.mem.eql(u8, flag, "--core-metallib")) {
            if (core_metallib_path != null or value.len == 0)
                return error.InvalidArguments;
            core_metallib_path = value;
        } else if (std.mem.eql(u8, flag, "--core-metallib-sha256")) {
            if (core_metallib_sha256 != null)
                return error.InvalidArguments;
            core_metallib_sha256 = try parseCoreMetallibDigest(value);
        } else {
            return error.InvalidArguments;
        }
    }

    if ((core_metallib_path == null) != (core_metallib_sha256 == null))
        return error.IncompleteCoreAotConfiguration;
    if (core_metallib_path) |path| {
        options.runtime_mode = .{ .production_core_aot = .{
            .metallib_path = path,
            .sha256 = core_metallib_sha256.?,
        } };
    }
    return options;
}

pub fn snapshotCoreMetallib(
    store: *artifact_store.Store,
    core_aot: CoreAot,
) !artifact_store.Snapshot {
    var snapshot = try store.ingestPathWithPolicy(core_aot.metallib_path, .byte_copy);
    errdefer snapshot.deinit(store.allocator);
    if (!std.mem.eql(u8, &snapshot.measurement.sha256, &core_aot.sha256))
        return error.CoreMetallibDigestMismatch;
    return snapshot;
}

fn parseCoreMetallibDigest(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidCoreMetallibDigest;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch
        return error.InvalidCoreMetallibDigest;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical))
        return error.InvalidCoreMetallibDigest;
    return digest;
}

test "existing session invocation selects diagnostic source runtime" {
    const options = try parseArgs(&.{
        "metal-arena-session",
        "--jsonl",
        "--rust-verifier",
        "/verifier",
        "--rust-verifier-lockfile",
        "/Cargo.lock",
    });
    try std.testing.expectEqualStrings("/verifier", options.rust_verifier_path);
    try std.testing.expectEqualStrings("/Cargo.lock", options.rust_verifier_lockfile_path);
    try std.testing.expectEqual(RuntimeMode.diagnostic_source, options.runtime_mode);
}

test "production session invocation pins the core metallib" {
    const digest = [_]u8{0xab} ** 32;
    const encoded = std.fmt.bytesToHex(digest, .lower);
    const options = try parseArgs(&.{
        "metal-arena-session",
        "--jsonl",
        "--rust-verifier",
        "/verifier",
        "--rust-verifier-lockfile",
        "/Cargo.lock",
        "--core-metallib",
        "/core.metallib",
        "--core-metallib-sha256",
        &encoded,
        "--composition-metallib-sha256",
        &encoded,
    });
    try std.testing.expectEqualStrings(&encoded, options.composition_metallib_sha256.?);
    const core_aot = options.runtime_mode.production_core_aot;
    try std.testing.expectEqualStrings("/core.metallib", core_aot.metallib_path);
    try std.testing.expectEqualSlices(u8, &digest, &core_aot.sha256);
}

test "core AOT startup arguments fail closed" {
    const digest = "abababababababababababababababababababababababababababababababab";
    const base = [_][]const u8{
        "metal-arena-session",
        "--jsonl",
        "--rust-verifier",
        "/verifier",
        "--rust-verifier-lockfile",
        "/Cargo.lock",
    };
    try std.testing.expectError(
        error.IncompleteCoreAotConfiguration,
        parseArgs(&(base ++ .{ "--core-metallib", "/core.metallib" })),
    );
    try std.testing.expectError(
        error.IncompleteCoreAotConfiguration,
        parseArgs(&(base ++ .{ "--core-metallib-sha256", digest })),
    );
    try std.testing.expectError(
        error.InvalidCoreMetallibDigest,
        parseArgs(&(base ++ .{
            "--core-metallib",
            "/core.metallib",
            "--core-metallib-sha256",
            "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
        })),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseArgs(&(base ++ .{
            "--core-metallib",
            "/core.metallib",
            "--core-metallib",
            "/other.metallib",
            "--core-metallib-sha256",
            digest,
        })),
    );
}

test "core metallib startup snapshots immutable verified bytes" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "core.metallib", .data = "core-aot" });
    const directory = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(directory);
    const path = try std.fs.path.join(std.testing.allocator, &.{ directory, "core.metallib" });
    defer std.testing.allocator.free(path);
    const store_path = try std.fs.path.join(std.testing.allocator, &.{ directory, "store" });
    defer std.testing.allocator.free(store_path);
    var store = try artifact_store.Store.initNew(std.testing.allocator, store_path, true);
    defer store.deinit();

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("core-aot", &digest, .{});
    var snapshot = try snapshotCoreMetallib(&store, .{
        .metallib_path = path,
        .sha256 = digest,
    });
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(artifact_store.CopyMethod.byte_copy, snapshot.method);
    try std.testing.expect(!std.mem.eql(u8, path, snapshot.path));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o400), (try std.fs.cwd().statFile(snapshot.path)).mode & 0o777);

    try temporary.dir.writeFile(.{ .sub_path = "core.metallib", .data = "mutated" });
    const stored = try std.fs.openFileAbsolute(snapshot.path, .{});
    defer stored.close();
    var stored_bytes: ["core-aot".len]u8 = undefined;
    try std.testing.expectEqual(stored_bytes.len, try stored.readAll(&stored_bytes));
    try std.testing.expectEqualStrings("core-aot", &stored_bytes);

    digest[0] ^= 1;
    try std.testing.expectError(
        error.CoreMetallibDigestMismatch,
        snapshotCoreMetallib(&store, .{
            .metallib_path = path,
            .sha256 = digest,
        }),
    );
}
