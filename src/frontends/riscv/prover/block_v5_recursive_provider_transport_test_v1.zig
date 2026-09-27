//! Metadata/ownership/file-state fixtures only; literal bytes cannot verify.
const std = @import("std");
const F = @import("block_v5_recursive_provider_transport_fixture_v1.zig");
const T = F.T;
const D = F.D;
const Store = @import("block_v5_recursive_provider_store_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Templates = @import("block_v5_recursive_provider_templates_v1.zig");
fn templateOwnership(a: std.mem.Allocator) !void {
    const fixture = try F.Fixture.init();
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const original = try F.Fixture.template(&prepared);
    const mutable = try a.dupe(D.Bus.Wire, original.schedule);
    var owns_mutable = true;
    defer if (owns_mutable) a.free(mutable);
    var borrowed = original;
    borrowed.schedule = mutable;
    var catalog = try Templates.ForFamily(.range16).init(a, .{});
    defer catalog.deinit();
    const first = try catalog.intern(&prepared, &borrowed);
    try std.testing.expect(@intFromPtr(first.schedule.ptr) != @intFromPtr(mutable.ptr));
    try std.testing.expect(first == try catalog.intern(&prepared, &original));
    mutable[0].uses += 1;
    a.free(mutable);
    owns_mutable = false;
    try std.testing.expectEqualDeep(original.schedule[0], first.schedule[0]);
    const initial_capacity = catalog.entries.capacity;
    for (1..initial_capacity + 2) |index| {
        var other = original;
        std.mem.writeInt(u64, other.key.preprocessed_root[0..8], @intCast(index), .little);
        other.key_id = try other.key.identity();
        _ = try catalog.intern(&prepared, &other);
    }
    try std.testing.expect(catalog.entries.capacity > initial_capacity);
    try std.testing.expect(first == try catalog.intern(&prepared, &original));
    try std.testing.expectEqual(initial_capacity + 2, catalog.count());
}
test "provider transport: shared owned templates survive borrowed schedule destruction and later insertion" {
    try templateOwnership(std.testing.allocator);
}
test "provider transport: every shared template allocation failure releases custody" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, templateOwnership, .{});
}
test "provider transport: shared template count and heap limits are enforced before retention" {
    const a = std.testing.allocator;
    const fixture = try F.Fixture.init();
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const original = try F.Fixture.template(&prepared);
    var catalog = try Templates.ForFamily(.range16).init(a, .{ .max_templates = 1 });
    defer catalog.deinit();
    _ = try catalog.intern(&prepared, &original);
    var other = original;
    other.key.preprocessed_root[0] ^= 1;
    other.key_id = try other.key.identity();
    try std.testing.expectError(error.RecursiveProviderTemplateResourceLimit, catalog.intern(&prepared, &other));
    var tiny = try Templates.ForFamily(.range16).init(a, .{ .max_owned_bytes = 1 });
    defer tiny.deinit();
    try std.testing.expectError(error.OutOfMemory, tiny.intern(&prepared, &original));
    try std.testing.expectEqual(@as(usize, 0), tiny.count());
}
fn roundtrip(a: std.mem.Allocator) !void {
    const fixture = try F.Fixture.init();
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const template = try F.Fixture.template(&prepared);
    const policy = T.Policy{ .prepared = &prepared, .template = &template };
    var artifact = try F.Fixture.artifact(a, policy);
    defer artifact.deinit(a);
    var encoded = try T.Codec.encode(a, &artifact, policy, .{});
    defer encoded.deinit();
    try std.testing.expectEqual(@intFromPtr(artifact.bytes.ptr), @intFromPtr(encoded.proof.ptr));
    const raw = try F.assemble(a, &encoded);
    defer a.free(raw);
    const parts = encoded.parts();
    try std.testing.expectEqualDeep(Files.hash(raw), Files.hashParts(&parts));
    var view = try T.Codec.decodeMetadata(a, raw, policy, .{});
    defer view.deinit();
    try std.testing.expectEqualDeep(artifact.native, view.open);
    try std.testing.expectEqualDeep(artifact.public_values, view.values);
    try std.testing.expectEqualSlices(u8, artifact.bytes, view.proof);
    try std.testing.expect(!@hasField(T.Codec.View, "equation"));
}
test "provider transport: shared independent template and zero-copy proof framing retain structural claims only" {
    try roundtrip(std.testing.allocator);
}
test "provider transport: encode decode metadata budgets and every allocation failure release owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, roundtrip, .{});
}
test "provider transport: envelope cannot select family version index key schedule or trailing bytes" {
    const a = std.testing.allocator;
    const fixture = try F.Fixture.init();
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    var template = try F.Fixture.template(&prepared);
    const policy = T.Policy{ .prepared = &prepared, .template = &template };
    var artifact = try F.Fixture.artifact(a, policy);
    defer artifact.deinit(a);
    var encoded = try T.Codec.encode(a, &artifact, policy, .{});
    defer encoded.deinit();
    const raw = try F.assemble(a, &encoded);
    defer a.free(raw);
    for ([_]usize{ 0, 8, 12, 16 }) |offset| {
        raw[offset] ^= 1;
        try std.testing.expectError(error.InvalidRecursiveProviderEnvelope, T.Codec.decodeMetadata(a, raw, policy, .{}));
        raw[offset] ^= 1;
    }
    try std.testing.expectError(error.InvalidRecursiveProviderEnvelope, T.Codec.decodeMetadata(a, raw[0 .. raw.len - 1], policy, .{}));
    const trailing = try a.alloc(u8, raw.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..raw.len], raw);
    trailing[raw.len] = 0;
    try std.testing.expectError(error.InvalidRecursiveProviderEnvelope, T.Codec.decodeMetadata(a, trailing, policy, .{}));
    template.key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedRecursiveProviderTemplate, T.Codec.decodeMetadata(a, raw, policy, .{}));
    template.key_id[0] ^= 1;
    artifact.schedule[0].uses += 1;
    try std.testing.expectError(error.UntrustedRecursiveProviderArtifact, T.Codec.encode(a, &artifact, policy, .{}));
    artifact.schedule[0].uses -= 1;
    var tiny: @import("block_v5_recursive_provider_codec_v1.zig").Limits = .{};
    tiny.max_metadata_bytes = 1;
    try std.testing.expectError(error.RecursiveProviderFileResourceLimit, T.Codec.decodeMetadata(a, raw, policy, tiny));
    tiny = .{};
    tiny.max_schedule_wires = 1;
    try std.testing.expectError(error.UntrustedRecursiveProviderTemplate, T.Codec.encode(a, &artifact, policy, tiny));
}
test "provider transport: exact independent roster rejects omitted policies and malformed file pins" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try F.Fixture.init();
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const template = try F.Fixture.template(&prepared);
    const policy = T.Policy{ .prepared = &prepared, .template = &template };
    try std.testing.expectError(error.IncompleteRecursiveProviderPolicies, T.Store.initWriter(a, dir.dir, fixture.roster(), &.{}, .{}));
    var writer = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{});
    defer writer.deinit();
    try std.testing.expectError(error.IncompleteRecursiveProviderFiles, writer.filePins(a));
    var caps: Store.Limits = .{};
    caps.max_slot_bytes = 1;
    try std.testing.expectError(error.RecursiveProviderSlotResourceLimit, T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, caps));
    try std.testing.expectError(error.UntrustedRecursiveProviderFilePin, T.validatePins(&.{.{ .index = 1, .byte_len = 100, .sha256 = @splat(1) }}, .{}));
    caps = .{};
    caps.max_total_bytes = 99;
    try std.testing.expectError(error.RecursiveProviderTotalResourceLimit, T.validatePins(&.{.{ .index = 0, .byte_len = 100, .sha256 = @splat(1) }}, caps));
}
test "provider transport: exclusive publication transfers ownership but literal proof never completes fresh reader" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try F.Fixture.init();
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const template = try F.Fixture.template(&prepared);
    const policy = T.Policy{ .prepared = &prepared, .template = &template };
    var writer = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{});
    defer writer.deinit();
    var artifact = try F.Fixture.artifact(a, policy);
    var owns = true;
    defer if (owns) artifact.deinit(a);
    try writer.put(0, &artifact);
    owns = false;
    var duplicate = try F.Fixture.artifact(a, policy);
    defer duplicate.deinit(a);
    try std.testing.expectError(error.DuplicateRecursiveProviderLeaf, writer.put(0, &duplicate));
    try std.testing.expectEqualStrings("literal not a recursive proof", duplicate.bytes);
    const pins = try writer.filePins(a);
    defer a.free(pins);
    var reader = try T.Store.initReader(a, dir.dir, fixture.roster(), &.{policy}, pins, .{});
    defer reader.deinit();
    try std.testing.expectError(error.IncompleteRecursiveProviderVerification, reader.requireVerified());
    if (reader.takeFresh(0)) |received| {
        var unexpected = received;
        unexpected.deinit();
        return error.LiteralFixtureWasAcceptedAsProof;
    } else |err| {
        if (err == error.OutOfMemory) return err;
    }
    try std.testing.expectError(error.IncompleteRecursiveProviderVerification, reader.requireVerified());
    try std.testing.expectError(error.InvalidRecursiveProviderLoadState, reader.takeFresh(0));
    var second = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{});
    defer second.deinit();
    try std.testing.expectError(error.ExistingV5BundleArtifact, second.put(0, &duplicate));
    try std.testing.expectEqualStrings("literal not a recursive proof", duplicate.bytes);
}
test "provider transport: total-cap and tamper failures retain publisher ownership and fail reader closed" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const fixture = try F.Fixture.init();
    var prepared = try fixture.prepare(a);
    defer prepared.deinit();
    const template = try F.Fixture.template(&prepared);
    const policy = T.Policy{ .prepared = &prepared, .template = &template };
    var limits: Store.Limits = .{};
    limits.max_total_bytes = 33;
    var small = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, limits);
    defer small.deinit();
    var artifact = try F.Fixture.artifact(a, policy);
    var owns = true;
    defer if (owns) artifact.deinit(a);
    try std.testing.expectError(error.RecursiveProviderTotalResourceLimit, small.put(0, &artifact));
    try std.testing.expectEqualStrings("literal not a recursive proof", artifact.bytes);
    var writer = try T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{});
    defer writer.deinit();
    try writer.put(0, &artifact);
    owns = false;
    const pins = try writer.filePins(a);
    defer a.free(pins);
    var name: [96]u8 = undefined;
    {
        var file = try dir.dir.openFile(try T.fileName(&name, 0), .{ .mode = .read_write });
        defer file.close();
        try file.pwriteAll("X", 0);
    }
    var reader = try T.Store.initReader(a, dir.dir, fixture.roster(), &.{policy}, pins, .{});
    defer reader.deinit();
    try std.testing.expectError(error.TamperedV5BundleFileHash, reader.takeFresh(0));
    try std.testing.expectError(error.IncompleteRecursiveProviderVerification, reader.requireVerified());
}
