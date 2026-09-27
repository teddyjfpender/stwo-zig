//! Transport metadata/bytes only. Label roots are not commitments; zero claims
//! are unproved proposals. No fixture constructs a successful STARK or receipt.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Artifact = @import("block_v5_readonly_provider_artifact_v2.zig");
const New = @import("block_v5_readonly_provider_files_v2.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Air = @import("block_v5_readonly_input_provider_component_v2.zig");
pub const behavioral_test_count = 8;
const ordinals = [_]u32{ 0, 0, 2 };
fn expected() !Artifact.Expected {
    const shape = Table.Shard{ .index = 2, .group_id = 7, .first_fragment = 4, .fragment_count = 3, .row_log = 2, .counts = .{ .events = 9, .readonly = 3, .range_requests = 36 } };
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    const plan: [32]u8 = @splat(1);
    const result = Artifact.Expected{ .provider = .{ .shape = shape, .roots = .{ @splat(2), @splat(3) }, .ordinal_digest = try Table.ordinalDigest(shape, plan, &ordinals), .plan_digest = plan, .config = config, .range_index = 5 }, .range = .{ .index = 5, .provider_index = 2, .group_id = 7, .shard = .{ .index = 5, .first_instance = 2, .instance_count = 1, .request_count = 36 }, .plan_digest = Roster.rangePlanDigest(plan, shape), .roots = .{ @splat(4), @splat(5) }, .counter_digest = @splat(6), .config = config }, .epoch = .{ .plan_digest = plan, .roster_digest = @splat(7) }, .sealed_digest = @splat(8) };
    try result.validate();
    return result;
}
fn ordinalBytes(pin: Artifact.Expected, buffer: []u8) ![]u8 {
    var writer = std.Io.Writer.fixed(buffer);
    try New.writeOrdinals(&writer, pin, &ordinals, 3, .{});
    return writer.buffered();
}
fn envelope(pin: Artifact.Expected, buffer: []u8) ![]u8 {
    var writer = std.Io.Writer.fixed(buffer);
    const claim = Air.Claim{ .classification_sum = Q.zero(), .read_sum = Q.zero(), .range_sums = @splat(Q.zero()), .counts = pin.provider.shape.counts };
    // Intentionally NOT a serialized proof; only the framing may pass split.
    const nonproof = "not-a-proof";
    try Artifact.writeHeader(&writer, pin, claim, nonproof.len);
    try writer.writeAll(nonproof);
    return writer.buffered();
}
fn rejectsWithoutAllocation(raw: []const u8, pin: Artifact.Expected, ord: bool) !void {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    if (ord) {
        if (New.decodeOrdinals(fail.allocator(), raw, pin, 3, .{})) |value| {
            fail.allocator().free(value);
            return error.UnexpectedTransportAcceptance;
        } else |err| try std.testing.expect(err != error.OutOfMemory);
    } else {
        if (Artifact.decode(fail.allocator(), raw, pin, .{})) |received| {
            var value = received;
            value.deinit(fail.allocator());
            return error.UnexpectedTransportAcceptance;
        } else |err| try std.testing.expect(err != error.OutOfMemory);
    }
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
}
test "readonly provider transport: ordered ordinal framing caps and truncation" {
    const pin = try expected();
    var buffer: [New.ORDINAL_HEADER + 12]u8 = undefined;
    const raw = try ordinalBytes(pin, &buffer);
    const decoded = try New.decodeOrdinals(std.testing.allocator, raw, pin, 3, .{});
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u32, &ordinals, decoded);
    for (0..raw.len) |len| try std.testing.expectError(error.ReadonlyProviderOrdinalLength, New.decodeOrdinals(std.testing.allocator, raw[0..len], pin, 3, .{}));
    try std.testing.expectError(error.ReadonlyProviderMetadataLimit, New.decodeOrdinals(std.testing.allocator, raw, pin, 3, .{ .max_ordinal_bytes = raw.len - 1 }));
    try std.testing.expectError(error.ReadonlyProviderMetadataLimit, New.decodeOrdinals(std.testing.allocator, raw, pin, 3, .{ .max_metadata_bytes = 1 }));
}
test "readonly provider transport: ordinal scope order bounds and digest cannot substitute" {
    const pin = try expected();
    var buffer: [New.ORDINAL_HEADER + 12]u8 = undefined;
    const raw = try ordinalBytes(pin, &buffer);
    for ([_]usize{ 0, 8, 40, 44, 48 }) |at| {
        raw[at] ^= 1;
        try rejectsWithoutAllocation(raw, pin, true);
        raw[at] ^= 1;
    }
    std.mem.writeInt(u32, raw[New.ORDINAL_HEADER..][0..4], 2, .little);
    try rejectsWithoutAllocation(raw, pin, true);
    std.mem.writeInt(u32, raw[New.ORDINAL_HEADER..][0..4], 0, .little);
    std.mem.writeInt(u32, raw[New.ORDINAL_HEADER + 8 ..][0..4], 3, .little);
    try rejectsWithoutAllocation(raw, pin, true);
    std.mem.writeInt(u32, raw[New.ORDINAL_HEADER + 8 ..][0..4], 1, .little);
    try std.testing.expectError(error.UntrustedReadonlyProviderOrdinals, New.decodeOrdinals(std.testing.allocator, raw, pin, 3, .{}));
}
fn ordinalOom(a: std.mem.Allocator, pin: Artifact.Expected, raw: []const u8) !void {
    const result = try New.decodeOrdinals(a, raw, pin, 3, .{});
    defer a.free(result);
    try std.testing.expectEqualSlices(u32, &ordinals, result);
}
test "readonly provider transport: ordinal decoder allocation unwind" {
    const pin = try expected(); // Authentic metadata proposal prepared outside injection.
    var buffer: [New.ORDINAL_HEADER + 12]u8 = undefined;
    const raw = try ordinalBytes(pin, &buffer);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ordinalOom, .{ pin, raw });
}
test "readonly provider transport: envelope exact claims scope size and canonical limbs" {
    const pin = try expected();
    var buffer: [Artifact.HEADER_BYTES + 11]u8 = undefined;
    const raw = try envelope(pin, &buffer);
    const framed = try Artifact.split(raw, pin, .{});
    try std.testing.expectEqualStrings("not-a-proof", framed.proof);
    for ([_]usize{ 0, 8, 40, 44, Artifact.HEADER_BYTES - 8 }) |at| {
        raw[at] ^= 1;
        try rejectsWithoutAllocation(raw, pin, false);
        raw[at] ^= 1;
    }
    for (0..raw.len) |len| try rejectsWithoutAllocation(raw[0..len], pin, false);
    try std.testing.expectError(error.ReadonlyProviderProofTooLarge, Artifact.split(raw, pin, .{ .max_proof_bytes = 10 }));
    std.mem.writeInt(u32, raw[56..][0..4], core.fields.m31.Modulus, .little);
    try rejectsWithoutAllocation(raw, pin, false);
}
test "readonly provider transport: original proof parser preflight precedes allocations" {
    const pin = try expected();
    var buffer: [Artifact.HEADER_BYTES + 11]u8 = undefined;
    try rejectsWithoutAllocation(try envelope(pin, &buffer), pin, false);
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    if (Artifact.decodeRange(fail.allocator(), "not-a-range-proof", pin, .{})) |received| {
        var proof = received;
        proof.deinit(fail.allocator());
        return error.UnexpectedTransportAcceptance;
    } else |err| try std.testing.expect(err != error.OutOfMemory);
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    var changed = pin;
    changed.range.group_id += 1;
    try std.testing.expectError(error.UntrustedReadonlyProviderArtifactScope, changed.validate());
    changed = pin;
    changed.provider.config.pow_bits = 0;
    try std.testing.expectError(error.UntrustedReadonlyProviderArtifactScope, changed.validate());
}
test "readonly provider transport: actual file hash scope and preallocation cap" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pin = try expected();
    var buffer: [New.ORDINAL_HEADER + 12]u8 = undefined;
    const raw = try ordinalBytes(pin, &buffer);
    var name_buffer: [96]u8 = undefined;
    const name = try New.fileName(&name_buffer, .ordinals, pin.provider.shape.index);
    try Files.publish(tmp.dir, name, raw);
    const file_pin = New.ArtifactPin{ .kind = .ordinals, .index = pin.provider.shape.index, .group_id = pin.provider.shape.group_id, .scope_digest = try pin.scopeDigest(), .byte_len = raw.len, .sha256 = Files.hash(raw) };
    try New.requirePin(file_pin, pin, .ordinals, .{});
    var changed = file_pin;
    changed.kind = .range;
    try std.testing.expectError(error.UntrustedReadonlyProviderFilePin, New.requirePin(changed, pin, .ordinals, .{}));
    changed = file_pin;
    changed.scope_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedReadonlyProviderFilePin, New.requirePin(changed, pin, .ordinals, .{}));
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.V5BundleFileResourceLimit, Files.readPinned(fail.allocator(), tmp.dir, name, raw.len, file_pin.sha256, raw.len - 1));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    changed = file_pin;
    changed.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleFileHash, Files.readPinned(std.testing.allocator, tmp.dir, name, raw.len, changed.sha256, raw.len));
    try std.testing.expectError(error.TamperedV5BundleFileLength, Files.readPinned(std.testing.allocator, tmp.dir, name, raw.len + 1, file_pin.sha256, raw.len + 1));
}
fn retainedRecord(dir: std.fs.Dir, kind: New.Kind, index: u32) !New.CleanupOwner.Record {
    var buffer: [96]u8 = undefined;
    const file = try dir.openFile(try New.fileName(&buffer, kind, index), .{});
    errdefer file.close();
    return .{ .inode = (try file.stat()).inode, .retained_file = file, .kind = kind, .index = index, .published = true };
}
test "readonly provider transport: cleanup retains its directory after original handle closes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source_dir = try tmp.dir.openDir(".", .{});
    try Files.publish(source_dir, "readonly-provider-2.proof", "ordinary transport bytes, not a proof");
    var cleanup = try New.CleanupOwner.init(source_dir);
    cleanup.records[0] = try retainedRecord(source_dir, .provider, 2);
    source_dir.close();
    try cleanup.retry();
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("readonly-provider-2.proof", .{}));
}
test "readonly provider transport: failed cleanup retains owned inode and never deletes replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try Files.publish(tmp.dir, "readonly-provider-2.proof", "ordinary owned bytes");
    try Files.publish(tmp.dir, "readonly-provider-5.range", "ordinary range-labelled bytes, not a proof");
    var cleanup = try New.CleanupOwner.init(tmp.dir);
    cleanup.records[0] = try retainedRecord(tmp.dir, .provider, 2);
    cleanup.records[1] = try retainedRecord(tmp.dir, .range, 5);
    try tmp.dir.rename("readonly-provider-5.range", "retained-original");
    try Files.publish(tmp.dir, "readonly-provider-5.range", "ordinary replacement bytes");
    var outcome = New.Publication{ .failed = .{ .cause = error.TestPublicationFailure, .cleanup = cleanup } };
    try std.testing.expectError(error.ReplacedReadonlyProviderPublication, outcome.deinit());
    try std.testing.expect(outcome.failed.cleanup.?.records[0].retained_file == null);
    try std.testing.expect(outcome.failed.cleanup.?.records[1].retained_file != null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("readonly-provider-2.proof", .{}));
    const replacement = try Files.readPinned(std.testing.allocator, tmp.dir, "readonly-provider-5.range", "ordinary replacement bytes".len, Files.hash("ordinary replacement bytes"), 128);
    defer std.testing.allocator.free(replacement);
    try tmp.dir.deleteFile("readonly-provider-5.range");
    try tmp.dir.rename("retained-original", "readonly-provider-5.range");
    try outcome.deinit();
    try std.testing.expect(outcome == .released);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("readonly-provider-5.range", .{}));
}
