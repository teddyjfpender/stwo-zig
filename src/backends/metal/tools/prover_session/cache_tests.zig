//! Prepared-geometry key/cache and atomic-publication invariants.

const std = @import("std");
const state = @import("state.zig");
const preparation = @import("preparation.zig");
const verification = @import("verification.zig");
const test_support = @import("test_support.zig");

const ArtifactObjectEvidence = state.ArtifactObjectEvidence;
const ArtifactObjectsEvidence = state.ArtifactObjectsEvidence;
const PreparedGeometryKey = state.PreparedGeometryKey;
const PreparedGeometryPolicy = state.PreparedGeometryPolicy;
const PreparedHostGeometryCache = state.PreparedHostGeometryCache;
const CompositionAotAdmissionCache = state.CompositionAotAdmissionCache;
const composition_aot_admission_capacity = state.composition_aot_admission_capacity;
const measureExecutableIdentity = verification.measureExecutableIdentity;
const preparedGeometryKey = preparation.preparedGeometryKey;
const compositionAotAdmissionKey = preparation.compositionAotAdmissionKey;
const preparedStateKey = preparation.preparedStateKey;
const publishExclusive = verification.publishExclusive;
const publishOutputsExclusive = verification.publishOutputsExclusive;
const testArtifactObjects = test_support.testArtifactObjects;

test "prepared state key excludes block input and diagnostics and binds immutable geometry" {
    const root = [_]u8{'a'} ** 64;
    const executable = [_]u8{0x11} ** 32;
    const protocol_digest = [_]u8{0x22} ** 32;
    const base = testArtifactObjects();
    const expected = try preparedStateKey(base, root, "24", .metallib, executable, protocol_digest);

    var per_block = base;
    per_block.adapted_input.object_id[0] ^= 0xff;
    per_block.adapted_input.bytes += 1;
    per_block.adapted_input.diagnostic_path = "/different/block";
    per_block.transcript_reference = .{
        .object_id = [_]u8{0x44} ** 32,
        .bytes = 999,
        .diagnostic_path = "/reference",
    };
    try std.testing.expectEqual(expected, try preparedStateKey(
        per_block,
        root,
        "24",
        .metallib,
        executable,
        protocol_digest,
    ));
    var diagnostic = base;
    diagnostic.schedule.diagnostic_path = "/same/object/different/path";
    try std.testing.expectEqual(expected, try preparedStateKey(
        diagnostic,
        root,
        "24",
        .metallib,
        executable,
        protocol_digest,
    ));

    inline for (.{
        "schedule",
        "witness_programs",
        "multiplicity_feeds",
        "relation_templates",
        "fixed_tables",
        "composition",
        "composition_program",
        "preprocessed_evaluations",
        "preprocessed_tree0_merkle",
        "preprocessed_coefficients",
    }) |name| {
        var changed = base;
        @field(changed, name).object_id[0] ^= 0x01;
        const actual = try preparedStateKey(
            changed,
            root,
            "24",
            .metallib,
            executable,
            protocol_digest,
        );
        try std.testing.expect(!std.mem.eql(u8, &expected, &actual));
    }
    var changed_root = root;
    changed_root[0] = 'b';
    const root_key = try preparedStateKey(base, changed_root, "24", .metallib, executable, protocol_digest);
    const budget_key = try preparedStateKey(base, root, "23", .metallib, executable, protocol_digest);
    const kind_key = try preparedStateKey(base, root, "24", .metal, executable, protocol_digest);
    try std.testing.expect(!std.mem.eql(u8, &expected, &root_key));
    try std.testing.expect(!std.mem.eql(u8, &expected, &budget_key));
    try std.testing.expect(!std.mem.eql(u8, &expected, &kind_key));
    var changed_executable = executable;
    changed_executable[0] ^= 1;
    const executable_key = try preparedStateKey(base, root, "24", .metallib, changed_executable, protocol_digest);
    try std.testing.expect(!std.mem.eql(u8, &expected, &executable_key));
    var changed_protocol = protocol_digest;
    changed_protocol[0] ^= 1;
    const protocol_key = try preparedStateKey(base, root, "24", .metallib, executable, changed_protocol);
    try std.testing.expect(!std.mem.eql(u8, &expected, &protocol_key));
}

test "prepared geometry key reuses different adapted objects with compatible row geometry" {
    const root = [_]u8{'a'} ** 64;
    const executable = [_]u8{0x11} ** 32;
    const protocol_digest = [_]u8{0x22} ** 32;
    const policy = PreparedGeometryPolicy{ .replay_retained_lookups = false };
    const base = testArtifactObjects();
    const row_geometry = [_]u8{0x33} ** 32;
    const resident_key = try preparedStateKey(base, root, "24", .metallib, executable, protocol_digest);
    const geometry_key = preparedGeometryKey(resident_key, row_geometry, policy);

    var changed_identity = base;
    changed_identity.adapted_input.object_id[0] ^= 0xff;
    const identity_resident_key = try preparedStateKey(
        changed_identity,
        root,
        "24",
        .metallib,
        executable,
        protocol_digest,
    );
    try std.testing.expectEqual(resident_key, identity_resident_key);
    const identity_geometry_key = preparedGeometryKey(identity_resident_key, row_geometry, policy);
    try std.testing.expectEqual(geometry_key, identity_geometry_key);

    var changed_bytes = base;
    changed_bytes.adapted_input.bytes += 1;
    const bytes_resident_key = try preparedStateKey(
        changed_bytes,
        root,
        "24",
        .metallib,
        executable,
        protocol_digest,
    );
    try std.testing.expectEqual(resident_key, bytes_resident_key);
    const bytes_geometry_key = preparedGeometryKey(bytes_resident_key, row_geometry, policy);
    try std.testing.expectEqual(geometry_key, bytes_geometry_key);

    var incompatible_geometry = row_geometry;
    incompatible_geometry[0] ^= 0xff;
    const incompatible_key = preparedGeometryKey(resident_key, incompatible_geometry, policy);
    try std.testing.expect(!std.mem.eql(u8, &geometry_key, &incompatible_key));
    try std.testing.expect(!std.mem.eql(u8, &resident_key, &geometry_key));
}

test "prepared geometry key binds retained lookup policy" {
    const root = [_]u8{'a'} ** 64;
    const executable = [_]u8{0x11} ** 32;
    const protocol_digest = [_]u8{0x22} ** 32;
    const row_geometry = [_]u8{0x33} ** 32;
    const objects = testArtifactObjects();
    const resident_key = try preparedStateKey(objects, root, "24", .metallib, executable, protocol_digest);
    const retained = preparedGeometryKey(
        resident_key,
        row_geometry,
        .{ .replay_retained_lookups = false },
    );
    const replayed = preparedGeometryKey(
        resident_key,
        row_geometry,
        .{ .replay_retained_lookups = true },
    );
    try std.testing.expect(!std.mem.eql(u8, &retained, &replayed));
}

test "composition AOT admission key binds bundle and metallib identity only" {
    const base = testArtifactObjects();
    const expected = compositionAotAdmissionKey(base);

    var changed_input = base;
    changed_input.adapted_input.object_id[0] ^= 1;
    changed_input.adapted_input.bytes += 1;
    try std.testing.expectEqual(expected, compositionAotAdmissionKey(changed_input));

    var changed_bundle = base;
    changed_bundle.composition.object_id[0] ^= 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &compositionAotAdmissionKey(changed_bundle),
    ));

    var changed_metallib = base;
    changed_metallib.composition_program.object_id[0] ^= 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &compositionAotAdmissionKey(changed_metallib),
    ));
}

test "composition AOT admission cache is bounded and exact" {
    var cache = CompositionAotAdmissionCache{};
    const first = [_]u8{0x11} ** 32;
    cache.put(first);
    try std.testing.expect(cache.contains(first));
    cache.put(first);
    try std.testing.expectEqual(@as(usize, 1), cache.next_victim);

    for (1..composition_aot_admission_capacity + 1) |index| {
        var key = [_]u8{0} ** 32;
        key[0] = @intCast(index + 0x20);
        cache.put(key);
        try std.testing.expect(cache.contains(key));
    }
    try std.testing.expect(!cache.contains(first));
}

test "prepared host geometry cache owns exact-key parsed schedule transactionally" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.writeFile(.{
        .sub_path = "a.json",
        .data = "{\"arena\":{\"logical_buffer_schedule\":[]}}",
    });
    try directory.dir.writeFile(.{
        .sub_path = "b.json",
        .data = "{\"arena\":{\"logical_buffer_schedule\":[{\"id\":1}]}}",
    });
    const root = try directory.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path_a = try std.fs.path.join(std.testing.allocator, &.{ root, "a.json" });
    defer std.testing.allocator.free(path_a);
    const path_b = try std.fs.path.join(std.testing.allocator, &.{ root, "b.json" });
    defer std.testing.allocator.free(path_b);
    const args_a = [_][]const u8{ "metal-arena-plan", path_a, "1" };
    const args_b = [_][]const u8{ "metal-arena-plan", path_b, "1" };
    const key_a = [_]u8{0x11} ** 32;
    const key_b = [_]u8{0x22} ** 32;
    var cache = PreparedHostGeometryCache.init(std.testing.allocator);
    defer cache.deinit();

    const first = try cache.begin(key_a, &args_a);
    try std.testing.expect(!first.cache_hit);
    try cache.commit();
    try directory.dir.deleteFile("a.json");

    const reused = try cache.begin(key_a, &args_a);
    try std.testing.expect(reused.cache_hit);
    try std.testing.expect(reused.geometry == first.geometry);
    try cache.commit();

    const pending = try cache.begin(key_b, &args_b);
    try std.testing.expect(!pending.cache_hit);
    cache.poison();
    var committed: usize = 0;
    for (cache.entries) |entry| if (entry != null) {
        committed += 1;
        try std.testing.expectEqual(key_a, entry.?.key);
    };
    try std.testing.expectEqual(@as(usize, 1), committed);

    const fill_keys = [_]PreparedGeometryKey{
        key_b,
        [_]u8{0x33} ** 32,
        [_]u8{0x44} ** 32,
    };
    for (fill_keys) |key| {
        _ = try cache.begin(key, &args_b);
        try cache.commit();
    }
    _ = try cache.begin(key_a, &args_a);
    try cache.commit();
    const key_e = [_]u8{0x55} ** 32;
    _ = try cache.begin(key_e, &args_b);
    try cache.commit();
    var retained_a = false;
    var retained_b = false;
    for (cache.entries) |entry| if (entry) |value| {
        retained_a = retained_a or std.mem.eql(u8, &value.key, &key_a);
        retained_b = retained_b or std.mem.eql(u8, &value.key, &key_b);
    };
    try std.testing.expect(retained_a);
    try std.testing.expect(!retained_b);
}

test "executable identity measures this in-process runner" {
    const identity = try measureExecutableIdentity(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        &identity.daemon_executable_sha256,
        &identity.runner_executable_sha256,
    );
    for (identity.daemon_executable_sha256) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return error.InvalidExecutableDigest,
    };
}

test "publishExclusive never replaces a stale output" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();

    const temporary = try directory.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(temporary);
    const temporary_path = try std.fs.path.join(std.testing.allocator, &.{ temporary, "proof.tmp" });
    defer std.testing.allocator.free(temporary_path);
    const output_path = try std.fs.path.join(std.testing.allocator, &.{ temporary, "proof.bin" });
    defer std.testing.allocator.free(output_path);

    {
        const file = try std.fs.createFileAbsolute(temporary_path, .{ .exclusive = true });
        defer file.close();
        try file.writeAll("verified-proof");
        try file.sync();
    }
    try publishExclusive(temporary_path, output_path);
    try std.testing.expectError(error.FileNotFound, std.fs.accessAbsolute(temporary_path, .{}));

    const published = try std.fs.openFileAbsolute(output_path, .{});
    defer published.close();
    var published_bytes: [14]u8 = undefined;
    try std.testing.expectEqual(published_bytes.len, try published.readAll(&published_bytes));
    try std.testing.expectEqualStrings("verified-proof", &published_bytes);

    {
        const file = try std.fs.createFileAbsolute(temporary_path, .{ .exclusive = true });
        defer file.close();
        try file.writeAll("replacement");
    }
    try std.testing.expectError(error.PathAlreadyExists, publishExclusive(temporary_path, output_path));
    try std.fs.accessAbsolute(temporary_path, .{});
}

test "output publication removes proof when report publication fails" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const root = try directory.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const proof_temporary = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.tmp" });
    defer std.testing.allocator.free(proof_temporary);
    const proof_output = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.bin" });
    defer std.testing.allocator.free(proof_output);
    const report_temporary = try std.fs.path.join(std.testing.allocator, &.{ root, "report.tmp" });
    defer std.testing.allocator.free(report_temporary);
    const report_output = try std.fs.path.join(std.testing.allocator, &.{ root, "report.json" });
    defer std.testing.allocator.free(report_output);

    for ([_][]const u8{ proof_temporary, report_temporary, report_output }) |path| {
        const file = try std.fs.createFileAbsolute(path, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(path);
    }
    try std.testing.expectError(
        error.PathAlreadyExists,
        publishOutputsExclusive(proof_temporary, proof_output, report_temporary, report_output),
    );
    try std.testing.expectError(error.FileNotFound, std.fs.accessAbsolute(proof_output, .{}));
    try std.fs.accessAbsolute(report_output, .{});
}
