//! The StarkWare-parity surface pin: one SHA-256 over every file whose bytes
//! define the circuits pinned to `proving@5a7c5ed` (the in-circuit verifier,
//! the statements, the evaluators and their projection, the builder, the
//! shared component facts, the registries and the recorded circuit AIR).
//! Work on other circuit lanes (the native-protocol verifier, RV64 leaves)
//! must not move these bytes; when a StarkWare-side change is intended, the
//! parity ladder is run and the pin in `vectors/circuit/official/
//! starkware_surface_pin.txt` is updated in the same commit.
//!
//! Runs from the repository root (`zig build circuit-starkware-pin`).
const std = @import("std");

const pin_path = "vectors/circuit/official/starkware_surface_pin.txt";

/// Directories (every regular file under them, recursively) and files.
const directories = [_][]const u8{
    "src/frontends/circuit/builder",
    "src/frontends/circuit/common",
    "src/frontends/circuit/stark_verifier",
    "src/frontends/circuit/statements",
    "src/frontends/circuit/air_eval",
    "src/integrations/circuit_cpu/recursion",
    "vectors/circuit/official/registries",
};
const files = [_][]const u8{
    "src/frontends/circuit/mod.zig",
    "src/integrations/circuit_cpu/prove.zig",
    "src/integrations/circuit_cpu/verify.zig",
    "src/integrations/circuit_cpu/verifier_proof.zig",
    "src/integrations/circuit_cpu/air.zig",
    "src/interop/circuit_recursion/circuit_serialize.zig",
    "vectors/circuit/official/compiled_air_constraints_v1.bin",
    "vectors/circuit/official/circuit_air.air_programs_v1.bin",
};

pub fn surfaceDigest(allocator: std.mem.Allocator) ![64]u8 {
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    for (directories) |directory| try collect(allocator, &paths, directory);
    for (files) |file| try paths.append(allocator, try allocator.dupe(u8, file));
    std.mem.sort([]const u8, paths.items, {}, lessThan);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (paths.items) |path| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 64 << 20);
        defer allocator.free(bytes);
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, path.len, .little);
        hasher.update(&length);
        hasher.update(path);
        std.mem.writeInt(u64, &length, bytes.len, .little);
        hasher.update(&length);
        hasher.update(bytes);
    }
    return std.fmt.bytesToHex(hasher.finalResult(), .lower);
}

fn collect(allocator: std.mem.Allocator, paths: *std.ArrayListUnmanaged([]const u8), directory: []const u8) !void {
    var dir = try std.fs.cwd().openDir(directory, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.indexOf(u8, entry.path, ".zig-cache") != null) continue;
        try paths.append(allocator, try std.fs.path.join(allocator, &.{ directory, entry.path }));
    }
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

test "StarkWare-parity circuit surface is pinned" {
    const allocator = std.testing.allocator;
    const actual = try surfaceDigest(allocator);
    const pinned = std.fs.cwd().readFileAlloc(allocator, pin_path, 256) catch |err| {
        std.debug.print("starkware surface pin: cannot read {s} ({s}); current digest is {s}\n", .{ pin_path, @errorName(err), actual });
        return err;
    };
    defer allocator.free(pinned);
    const expected = std.mem.trim(u8, pinned, " \r\n\t");
    if (!std.mem.eql(u8, expected, &actual)) {
        std.debug.print(
            \\starkware surface pin: the StarkWare-parity circuit surface changed.
            \\  pinned  {s}
            \\  current {s}
            \\If this change is intended, run `zig build circuit-parity` and update
            \\{s} in the same commit. Work on other circuit lanes must not touch
            \\this surface.
            \\
        , .{ expected, actual, pin_path });
        return error.StarkwareSurfaceChanged;
    }
}
