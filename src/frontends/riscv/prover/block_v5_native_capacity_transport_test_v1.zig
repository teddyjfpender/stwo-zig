//! No guest, STARK, FRI, recursion or device execution. Literal envelopes only.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const Codec = @import("block_v5_native_capacity_codec_v1.zig");
const Legacy = @import("block_v5_native_codec_v3.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Receiver = @import("block_v5_native_capacity_artifact_receiver_v1.zig");
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const Statement = @import("../air/statement.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const suite = core.proof_suites.Blake3;
const Cpu = @import("stwo_cpu_backend").CpuBackend;

test "capacity transport one buffer preserves exact legacy native bytes and independently owned roundtrip" {
    const a = std.testing.allocator;
    var shape = Fixture.shape(5);
    var fixture = try Fixture.Fixture.init(a, &shape, false);
    defer fixture.deinit();
    const proof = fixture.native();
    const expected = Fixture.legacyExpected(&shape);
    const raw = try Legacy.encode(a, &proof, expected, .{});
    defer a.free(raw);
    var body = std.Io.Writer.Allocating.init(a);
    defer body.deinit();
    try postcard.serializeProof(suite.Hasher, &body.writer, proof.stark);
    var reference = std.Io.Writer.Allocating.init(a);
    defer reference.deinit();
    try reference.writer.writeAll("B5NEART3");
    try reference.writer.writeAll(&proof.template_id);
    try reference.writer.writeAll(&proof.instance_id);
    try wire.writeInt(&reference.writer, u64, body.written().len);
    for (shape.component_descs[0..shape.n_components], 0..) |desc, index| for (try proof.claims.opcodeClaims(desc.family, index)) |claim| try wire.writeQm31(&reference.writer, claim);
    try reference.writer.writeAll(body.written());
    try std.testing.expectEqualSlices(u8, reference.written(), raw);
    var decoded = try Legacy.decode(a, raw, expected, .{});
    defer decoded.deinit(a);
    try std.testing.expect(decoded.claims != proof.claims);
    try std.testing.expect(decoded.stark.commitment_scheme_proof.sampled_values.items[0][0].ptr != proof.stark.commitment_scheme_proof.sampled_values.items[0][0].ptr);
    fixture.claims.opcode_claims[0][0] = core.fields.qm31.QM31.one();
    fixture.stark.commitment_scheme_proof.sampled_values.items[0][0][0] = core.fields.qm31.QM31.zero();
    try std.testing.expect(decoded.claims.opcode_claims[0][0].isZero());
    try std.testing.expect(!decoded.stark.commitment_scheme_proof.sampled_values.items[0][0][0].isZero());
    const again = try Legacy.encode(a, &decoded, expected, .{});
    defer a.free(again);
    try std.testing.expectEqualSlices(u8, raw, again);
}

test "capacity transport literal envelope binds version capacities claims config and rejects old grammar before allocation" {
    const a = std.testing.allocator;
    var shape = Fixture.shape(5);
    var fixture = try Fixture.Fixture.init(a, &shape, true);
    defer fixture.deinit();
    const proof = fixture.capacity();
    const expected = try Fixture.expected(&shape);
    const raw = try Codec.encode(a, &proof, expected, .{});
    defer a.free(raw);
    var decoded = try Codec.decode(a, raw, expected, .{});
    defer decoded.deinit(a);
    const again = try Codec.encode(a, &decoded, expected, .{});
    defer a.free(again);
    try std.testing.expectEqualSlices(u8, raw, again);
    try std.testing.expectEqual(@as(u32, 4), try Codec.maximumProofColumnLog(expected));
    const bad = try a.dupe(u8, raw);
    defer a.free(bad);
    var rejected = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    std.mem.writeInt(u32, bad[8..12], 3, .little);
    try std.testing.expectError(error.UntrustedNativeCapacityProtocol, Codec.decode(rejected.allocator(), bad, expected, .{}));
    @memcpy(bad, raw);
    @memcpy(bad[0..8], "B5NEART3");
    try std.testing.expectError(error.InvalidNativeCapacityWireMagic, Codec.decode(rejected.allocator(), bad, expected, .{}));
    @memcpy(bad, raw);
    bad[76] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityWireIdentity, Codec.decode(rejected.allocator(), bad, expected, .{}));
    @memcpy(bad, raw);
    std.mem.writeInt(u32, bad[116..120], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidNativeCapacityWireClaims, Codec.decode(rejected.allocator(), bad, expected, .{}));
    @memcpy(bad, raw);
    std.mem.writeInt(u32, bad[Codec.HEADER_BYTES..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalM31, Codec.decode(rejected.allocator(), bad, expected, .{}));
    @memcpy(bad, raw);
    std.mem.writeInt(u64, bad[108..116], std.math.maxInt(u64), .little);
    try std.testing.expectError(error.NativeCapacityWireProofTooLarge, Codec.decode(rejected.allocator(), bad, expected, .{}));
    var changed = expected;
    changed.config.pow_bits = 1;
    try std.testing.expectError(error.InvalidProofConfig, Codec.decode(a, raw, changed, .{}));
    try std.testing.expectError(error.NativeCapacityWireClaimLimit, Codec.decode(rejected.allocator(), raw, expected, .{ .max_claims = 1 }));
    try std.testing.expectError(error.InvalidNativeCapacityWireLimits, Codec.decode(rejected.allocator(), raw, expected, .{ .max_claim_bytes = 1 }));
    const trailing = try a.alloc(u8, raw.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..raw.len], raw);
    trailing[raw.len] = 0;
    try std.testing.expectError(error.TrailingSectionBytes, Codec.decode(rejected.allocator(), trailing, expected, .{}));
}

fn allocationRoundTrip(a: std.mem.Allocator, fixture: *const Fixture.Fixture, expected: Codec.Expected) !void {
    const proof = fixture.capacity();
    const raw = try Codec.encode(a, &proof, expected, .{});
    defer a.free(raw);
    var decoded = try Codec.decode(a, raw, expected, .{});
    defer decoded.deinit(a);
    const copy = try Codec.encode(a, &decoded, expected, .{});
    defer a.free(copy);
    try std.testing.expectEqualSlices(u8, raw, copy);
}
test "capacity transport all allocation failures preserve artifact and decoded proof ownership" {
    var shape = Fixture.shape(5);
    var fixture = try Fixture.Fixture.init(std.testing.allocator, &shape, true);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRoundTrip, .{ &fixture, try Fixture.expected(&shape) });
}

test "capacity transport writer caps constructors and serializers before growing backing storage" {
    const a = std.testing.allocator;
    var output = Writer.init(a, 300);
    defer output.deinit();
    try output.writeAll(&(@as([299]u8, @splat(5))));
    try output.writeByte(7);
    try std.testing.expectEqual(@as(usize, 300), output.bytes.capacity);
    const old = output.bytes.items.ptr;
    try std.testing.expectError(error.ArtifactTooLarge, output.writeByte(9));
    try std.testing.expectEqual(@as(usize, 300), output.bytes.items.len);
    try std.testing.expect(old == output.bytes.items.ptr);
    var rejected = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var empty = Writer.init(rejected.allocator(), 0);
    defer empty.deinit();
    try std.testing.expectError(error.ArtifactTooLarge, empty.writeByte(1));
    var source = Fixture.shape(5);
    var fixture = try Fixture.Fixture.init(a, &source, false);
    defer fixture.deinit();
    const proof = fixture.native();
    try std.testing.expectError(error.NativeV3WireProofTooLarge, Legacy.encode(a, &proof, Fixture.legacyExpected(&source), .{ .proof_bytes = 1 }));
    try std.testing.expectError(error.NativeV3WireArtifactTooLarge, Legacy.encode(rejected.allocator(), &proof, Fixture.legacyExpected(&source), .{ .proof_bytes = 1, .artifact_bytes = 1 }));
    fixture.claims.opcode_claims[0][0].c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidInteractionClaim, Legacy.encode(a, &proof, Fixture.legacyExpected(&source), .{}));
}

fn catalogAllocation(a: std.mem.Allocator, records: []const Catalog.Record) !void {
    var owned = try Catalog.Owned.init(a, records, .{});
    defer owned.deinit();
    try std.testing.expectEqualDeep(records, @as([]const Catalog.Record, owned.records));
}
test "capacity transport catalog count invariant capacity authority ordered ownership and independent caps" {
    var one = Fixture.shape(5);
    var two = Fixture.shape(7);
    const first = try Protocol.Template.fromShape(&one, 0, Fixture.config, .rv32im_zkvm_v1, @splat(4));
    const second = try Protocol.Template.fromShape(&two, 0, Fixture.config, .rv32im_zkvm_v1, @splat(4));
    try std.testing.expectEqualDeep(first, second);
    var records = [_]Catalog.Record{ try Catalog.Record.fromTemplate(0, first), try Catalog.Record.fromTemplate(1, second) };
    const expected = try (Catalog.Admission{ .records = &records }).digest();
    const old = @import("block_v5_native_template_catalog_v1.zig");
    const old_records = [_]old.Record{ .{ .index = 0, .template_id = records[0].template_id, .geometry_digest = records[0].capacity_digest, .fixed_root = records[0].fixed_root }, .{ .index = 1, .template_id = records[1].template_id, .geometry_digest = records[1].capacity_digest, .fixed_root = records[1].fixed_root } };
    try std.testing.expect(!std.meta.eql(expected, try (old.Admission{ .records = &old_records }).digest()));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, catalogAllocation, .{@as([]const Catalog.Record, &records)});
    var owned = try Catalog.Owned.init(std.testing.allocator, &records, .{});
    defer owned.deinit();
    records[1].fixed_root[0] ^= 1;
    try std.testing.expectEqualDeep(expected, try owned.admission().digest());
    try std.testing.expect(!std.meta.eql(expected, try (Catalog.Admission{ .records = &records }).digest()));
    records[0].index = 1;
    try std.testing.expectError(error.InvalidNativeCapacityCatalog, (Catalog.Admission{ .records = &records }).digest());
    try std.testing.expectError(error.NativeCapacityCatalogResourceLimit, (Catalog.Admission{ .records = owned.records, .limits = .{ .max_records = 1 } }).digest());
    try std.testing.expectError(error.NativeCapacityCatalogResourceLimit, (Catalog.Admission{ .records = owned.records, .limits = .{ .max_metadata_bytes = @sizeOf(Catalog.Record) * 2 - 1 } }).digest());
}

fn context(rows: u32, index: u32) Public.Context {
    return .{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = index, .first_cycle = 1, .last_cycle = rows };
}
test "capacity transport real sealed catalog policy binds exact source counts without proof selected authority" {
    var shapes = [_]Statement.Blake3ExecutionStatement{ Fixture.shape(5), Fixture.shape(7) };
    var templates: [2]Protocol.Template = undefined;
    var records: [2]Catalog.Record = undefined;
    var admissions: [2]Public.Admission = undefined;
    var entries: [8]Seal.Entry = undefined;
    entries[0] = .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } };
    for (&shapes, &templates, &records, &admissions, 0..) |*shape, *template, *record, *admission, index| {
        template.* = try Protocol.Template.fromShape(shape, 0, Fixture.config, .rv32im_zkvm_v1, @splat(4));
        record.* = try Catalog.Record.fromTemplate(@intCast(index), template.*);
        admission.* = try Public.Admission.init(context(shape.total_steps, @intCast(index)), &shape.public_data);
        const roots: Seal.Roots = .{ template.fixed_root, @splat(@intCast(20 + index)) };
        entries[index + 1] = .{ .family = .execution, .index = @intCast(index), .instance_id = try Protocol.instanceId(record.template_id, shape, 0, admission.*, roots, @intCast(index)), .roots = roots };
        entries[index + 3] = .{ .family = .execution_sidecar, .index = @intCast(index), .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } };
        entries[index + 5] = .{ .family = .program_request, .index = @intCast(index), .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } };
    }
    entries[7] = .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } };
    const catalog = Catalog.Admission{ .records = &records };
    var counts: [Seal.family_count]u32 = @splat(0);
    counts[@intFromEnum(Seal.Family.program) - 1] = 1;
    counts[@intFromEnum(Seal.Family.execution) - 1] = 2;
    counts[@intFromEnum(Seal.Family.execution_sidecar) - 1] = 2;
    counts[@intFromEnum(Seal.Family.program_request) - 1] = 2;
    counts[@intFromEnum(Seal.Family.memory) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .native_template_catalog_digest = try catalog.digest(), .config = Fixture.config, .counts = counts };
    const sealed = try Seal.seal(pins, &entries);
    var rejected = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var policies: [2]Receiver.Policy = undefined;
    var expected: [2]Codec.Expected = undefined;
    for (&policies, &expected, 0..) |*policy, *result, index| {
        policy.* = .{ .shape = &shapes[index], .external_retirements = 0, .admission = admissions[index], .template = templates[index], .template_id = records[index].template_id, .index = @intCast(index), .sealed = sealed, .pins = pins, .entries = &entries, .catalog = catalog };
        result.* = try policy.expected(rejected.allocator());
    }
    try std.testing.expectEqualDeep(expected[0].template_id, expected[1].template_id);
    try std.testing.expect(!std.meta.eql(expected[0].instance_id, expected[1].instance_id));
    var changed = policies[0];
    changed.shape = &shapes[1];
    try std.testing.expectError(error.UntrustedNativeV5PublicAdmission, changed.expected(rejected.allocator()));
    changed = policies[0];
    changed.catalog = null;
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, changed.expected(rejected.allocator()));
    var altered = records;
    altered[0].fixed_root[0] ^= 1;
    changed = policies[0];
    changed.catalog = .{ .records = &altered };
    try std.testing.expectError(error.UntrustedNativeCapacityCatalog, changed.expected(rejected.allocator()));
    changed = policies[0];
    changed.index = 2;
    try std.testing.expectError(error.UntrustedNativeCapacityArtifactRoster, changed.expected(rejected.allocator()));
}

fn ownedCapture(a: std.mem.Allocator, proof: Native.Proof, p: Receiver.Policy) anyerror!Native.VerifiedCapture {
    if (p.catalog) |catalog| return Native.ForBackend(Cpu).verifyCaptureOwnedWithCatalog(a, proof, p.shape, p.external_retirements, p.admission, p.template, p.template_id, p.index, p.sealed, p.pins, p.entries, p.native_limits, catalog);
    return Native.ForBackend(Cpu).verifyCaptureOwned(a, proof, p.shape, p.external_retirements, p.admission, p.template, p.template_id, p.index, p.sealed, p.pins, p.entries, p.native_limits);
}
fn borrowedCapture(a: std.mem.Allocator, proof: *const Native.Proof, p: Receiver.Policy) anyerror!Native.VerifiedCapture {
    if (p.catalog) |catalog| return Native.ForBackend(Cpu).verifyCaptureBorrowedWithCatalog(a, proof, p.shape, p.external_retirements, p.admission, p.template, p.template_id, p.index, p.sealed, p.pins, p.entries, p.native_limits, catalog);
    return Native.ForBackend(Cpu).verifyCaptureBorrowed(a, proof, p.shape, p.external_retirements, p.admission, p.template, p.template_id, p.index, p.sealed, p.pins, p.entries, p.native_limits);
}
test "capacity transport actual artifact fresh owned borrowed capture and catalog producer bodies compile only" {
    const Api = Receiver.ForBackend(Cpu);
    const Prover = Native.ForBackend(Cpu);
    inline for (.{ &Api.verify, &Api.verifyCaptured, &ownedCapture, &borrowedCapture, &Prover.proveWithCatalog }) |method| std.mem.doNotOptimizeAway(method);
}
