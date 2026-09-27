//! Literal postcard/file transport only; no proof, guest or device execution.
const std = @import("std");
const Store = @import("block_v5_native_capacity_store_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const Codec = @import("block_v5_native_capacity_codec_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Statement = @import("../air/statement.zig");
const limits: Store.Limits = .{ .max_files = 4, .max_file_bytes = 65536, .max_total_bytes = 131072, .max_metadata_bytes = 1 << 20, .max_manifest_bytes = 4096 };
const Authority = struct {
    shape: Statement.Blake3ExecutionStatement,
    entries: [5]Seal.Entry,
    records: [1]Catalog.Record,
    policy: Store.Policy,
    fn init(self: *Authority) !void {
        self.shape = Fixture.shape(5);
        const template = try Protocol.Template.fromShape(&self.shape, 0, Fixture.config, .rv32im_zkvm_v1, @splat(4));
        self.records = .{try Catalog.Record.fromTemplate(0, template)};
        const admission = try Public.Admission.init(.{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = 5 }, &self.shape.public_data);
        const roots: Seal.Roots = .{ template.fixed_root, @splat(2) };
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = try Protocol.instanceId(self.records[0].template_id, &self.shape, 0, admission, roots, 0), .roots = roots },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
        };
        const catalog: Catalog.Admission = .{ .records = &self.records };
        var counts: [Seal.family_count]u32 = @splat(0);
        inline for (.{ Seal.Family.program, Seal.Family.execution, Seal.Family.execution_sidecar, Seal.Family.program_request, Seal.Family.memory }) |family| counts[@intFromEnum(family) - 1] = 1;
        const pins: Seal.Pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .native_template_catalog_digest = try catalog.digest(), .config = Fixture.config, .counts = counts };
        self.policy = .{ .shape = &self.shape, .external_retirements = 0, .admission = admission, .template = template, .template_id = self.records[0].template_id, .index = 0, .sealed = try Seal.seal(pins, &self.entries), .pins = pins, .entries = &self.entries, .catalog = catalog };
    }
    fn literal(self: *const Authority, a: std.mem.Allocator) !Native.Proof {
        var fixture = try Fixture.Fixture.init(a, &self.shape, true);
        defer fixture.deinit();
        var proof = fixture.capacity();
        const expected = try self.policy.expected(a);
        proof.template_id = expected.template_id;
        proof.instance_id = expected.instance_id;
        fixture.stark.commitment_scheme_proof.commitments.items[0] = self.entries[1].roots[0];
        const raw = try Codec.encode(a, &proof, expected, .{});
        defer a.free(raw);
        return Codec.decode(a, raw, expected, .{});
    }
};

test "capacity store actual admitted policy publishes consumes loads independent literal proof" {
    const a = std.testing.allocator;
    var authority: Authority = undefined;
    try authority.init();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, limits);
    defer writer.deinit();
    try std.testing.expectError(error.IncompleteNativeCapacityFiles, writer.filePins(a));
    var proof = try authority.literal(a);
    const sink = writer.sink();
    try sink.put(sink.context, 0, &proof);
    try std.testing.expectError(error.DuplicateNativeCapacityArtifact, writer.put(0, undefined));
    const pins = try writer.filePins(a);
    defer a.free(pins);
    const sha = try Store.writePins(a, tmp.dir, pins, limits);
    var manifest = try Store.readPins(a, tmp.dir, sha, limits);
    defer manifest.deinit();
    try std.testing.expectEqualDeep(pins, @as([]const Store.FilePin, manifest.pins));
    var reader = try Store.Store.initReader(a, tmp.dir, &.{authority.policy}, manifest.pins, Fixture.config, limits);
    defer reader.deinit();
    try std.testing.expectError(error.IncompleteNativeCapacityConsumption, reader.requireConsumed());
    const loader = reader.loader();
    var decoded = try loader.take(loader.context, 0);
    defer decoded.deinit(a);
    try std.testing.expectEqualDeep(authority.entries[1].instance_id, decoded.instance_id);
    try std.testing.expectEqualDeep(authority.entries[1].roots, decoded.stark.commitment_scheme_proof.commitments.items[0..2].*);
    try reader.requireConsumed();
    try std.testing.expectError(error.RepeatedNativeCapacityLoad, reader.take(0));
}

test "capacity store publication failures retain proof caps roots identity and existing bytes" {
    const a = std.testing.allocator;
    var authority: Authority = undefined;
    try authority.init();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var proof = try authority.literal(a);
    defer proof.deinit(a);
    const expected = try authority.policy.expected(a);
    const original = try Codec.encode(a, &proof, expected, .{});
    defer a.free(original);
    var capped = limits;
    capped.max_total_bytes = original.len - 1;
    var writer = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, capped);
    defer writer.deinit();
    try std.testing.expectError(error.NativeCapacityStoreTotalLimit, writer.put(0, &proof));
    try std.testing.expectError(error.IncompleteNativeCapacityFiles, writer.filePins(a));
    try std.testing.expectError(error.UnadmittedNativeCapacityStoreIndex, writer.put(1, undefined));
    proof.stark.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityStoreRoots, writer.put(0, &proof));
    proof.stark.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    proof.instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityWireIdentity, writer.put(0, &proof));
    proof.instance_id[0] ^= 1;
    var normal = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, limits);
    defer normal.deinit();
    var name: [96]u8 = undefined;
    const path = try Store.fileName(&name, 0);
    try Files.publish(tmp.dir, path, "keep original");
    try std.testing.expectError(error.ExistingV5BundleArtifact, normal.put(0, &proof));
    const kept = try Files.readPinned(a, tmp.dir, path, 13, Files.hash("keep original"), 32);
    defer a.free(kept);
    try std.testing.expectEqualStrings("keep original", kept);
    const after = try Codec.encode(a, &proof, expected, .{});
    defer a.free(after);
    try std.testing.expectEqualSlices(u8, original, after);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access("block-v5-native-capacity-0.proof.part", .{}));
}

test "capacity store failed tampered load burns slot and cannot substitute file" {
    const a = std.testing.allocator;
    var authority: Authority = undefined;
    try authority.init();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, limits);
    defer writer.deinit();
    var proof = try authority.literal(a);
    try writer.put(0, &proof);
    const pins = try writer.filePins(a);
    defer a.free(pins);
    var name: [96]u8 = undefined;
    var file = try tmp.dir.openFile(try Store.fileName(&name, 0), .{ .mode = .read_write });
    try file.pwriteAll("X", 0);
    file.close();
    var reader = try Store.Store.initReader(a, tmp.dir, &.{authority.policy}, pins, Fixture.config, limits);
    defer reader.deinit();
    try std.testing.expectError(error.TamperedV5BundleFileHash, reader.take(0));
    try std.testing.expectError(error.RepeatedNativeCapacityLoad, reader.take(0));
    try reader.requireConsumed();
    var wrong = pins[0];
    wrong.index = 1;
    try std.testing.expectError(error.UntrustedNativeCapacityFileIndex, Store.Store.initReader(a, tmp.dir, &.{authority.policy}, &.{wrong}, Fixture.config, limits));
}

test "capacity store manifest rejects count metadata grammar total and hashes before bulk allocation" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pins = [_]Store.FilePin{.{ .index = 0, .byte_len = 100, .sha256 = @splat(1) }};
    const sha = try Store.writePins(a, tmp.dir, &pins, limits);
    try std.testing.expectError(error.ExistingV5BundleArtifact, Store.writePins(a, tmp.dir, &pins, limits));
    try std.testing.expectError(error.NoncanonicalNativeCapacityFiles, Store.writePins(a, tmp.dir, &.{ pins[0], pins[0] }, limits));
    var wrong = sha;
    wrong[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleFileHash, Store.readPins(a, tmp.dir, wrong, limits));
    var capped = limits;
    capped.max_total_bytes = 99;
    try std.testing.expectError(error.NativeCapacityStoreTotalLimit, Store.readPins(a, tmp.dir, sha, capped));
    var rejected = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var file = try tmp.dir.openFile("block-v5-native-capacity.files", .{ .mode = .read_write });
    defer file.close();
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, std.math.maxInt(u32), .little);
    try file.pwriteAll(&count, 8);
    try std.testing.expectError(error.NativeCapacityManifestLimit, Store.readPins(rejected.allocator(), tmp.dir, sha, limits));
    try file.pwriteAll("B5FILES1", 0);
    try std.testing.expectError(error.InvalidNativeCapacityManifest, Store.readPins(rejected.allocator(), tmp.dir, sha, limits));
}

fn allocationRoundtrip(a: std.mem.Allocator, authority: *const Authority) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try Store.Store.initWriter(a, tmp.dir, &.{authority.policy}, Fixture.config, limits);
    defer writer.deinit();
    var proof = try authority.literal(a);
    var owns = true;
    defer if (owns) proof.deinit(a);
    try writer.put(0, &proof);
    owns = false;
    const pins = try writer.filePins(a);
    defer a.free(pins);
    const sha = try Store.writePins(a, tmp.dir, pins, limits);
    var loaded = try Store.readPins(a, tmp.dir, sha, limits);
    defer loaded.deinit();
    var reader = try Store.Store.initReader(a, tmp.dir, &.{authority.policy}, loaded.pins, Fixture.config, limits);
    defer reader.deinit();
    var decoded = try reader.take(0);
    defer decoded.deinit(a);
    try reader.requireConsumed();
}
test "capacity store exhaustive allocation failures retain publication and deep load ownership" {
    var authority: Authority = undefined;
    try authority.init();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRoundtrip, .{&authority});
}
fn fresh(store: *Store.Store, index: u32) !Native.VerifiedCapture {
    return store.verifyCaptured(@import("stwo_cpu_backend").CpuBackend, index);
}
const LegacyStore = @import("block_v5_cpu_bundle_store_v1.zig");
fn legacyTake(store: *LegacyStore.Store) !LegacyStore.ProofFor(.rom) {
    return store.take(.rom, 0);
}
fn legacyPut(store: *LegacyStore.Store, proof: *LegacyStore.ProofFor(.rom)) !void {
    return store.put(.rom, 0, proof);
}
test "capacity store real fresh capture loader and legacy I O bodies compile without invocation" {
    std.mem.doNotOptimizeAway(&fresh);
    std.mem.doNotOptimizeAway(&legacyTake);
    std.mem.doNotOptimizeAway(&legacyPut);
}
