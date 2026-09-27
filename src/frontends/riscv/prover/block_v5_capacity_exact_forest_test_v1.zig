//! Metadata and fail-before-load tests only; no proof, worker or guest runs.
const std = @import("std");
const core = @import("stwo_core");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Prepared = @import("block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Statement = @import("../air/statement.zig");
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const Adapter = @import("../recursion/block_v5_capacity_exact_leaf_adapter_v1.zig");
const Exact = @import("../recursion/block_v5_capacity_exact_forest_receiver_v1.zig");
const Bus = @import("../recursion/block_v5_capacity_recursive_public_bus_v1.zig");
const LeafProtocol = @import("../recursion/block_v5_reusable_capacity_parent_protocol_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const OpenProtocol = @import("../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const OpenBus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
fn context(rows: u32) Public.Context {
    return .{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = rows };
}
fn frameShape(rows: u32) Statement.Blake3ExecutionStatement {
    var result = Fixture.shape(rows);
    result.n_components = 0;
    return result;
}
/// Independent policy metadata. It contains no native/recursive proof/capture.
const Metadata = struct {
    template: Capacity.Template,
    record: [1]Catalog.Record,
    public_pin: Public.Admission,
    entries: [5]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    schedule: [1]Bus.Wire = .{.{ .circuit = 1500, .wire = 0, .uses = 2, .source = .frame_retirements, .coordinate = 0 }},
    key: LeafProtocol.Key,
    exported: Native.OpenReceipt,
    fn init(shape: *const Statement.Blake3ExecutionStatement) !Metadata {
        const template = try Capacity.Template.fromShape(shape, shape.total_steps, Parent.PCS_CONFIG, .rv32im_zkvm_v1, @splat(4));
        const record = [_]Catalog.Record{try Catalog.Record.fromTemplate(0, template)};
        const public_pin = try Public.Admission.init(context(shape.total_steps), &shape.public_data);
        const roots: Seal.Roots = .{ template.fixed_root, @splat(20) };
        const entries = [_]Seal.Entry{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = try Capacity.instanceId(record[0].template_id, shape, shape.total_steps, public_pin, roots, 0), .roots = roots },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .native_template_catalog_digest = try (Catalog.Admission{ .records = &record }).digest(), .config = Parent.PCS_CONFIG, .counts = counts };
        const sealed = try Seal.seal(pins, &entries);
        const schedule = [_]Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 2, .source = .frame_retirements, .coordinate = 0 }};
        const geometry = Parent.Key{ .context = .{ .child_key_id = record[0].template_id, .child_config = Parent.PCS_CONFIG, .graph_ids = .{ @splat(10), @splat(11), @splat(12) }, .transcript_plan_id = @splat(13) }, .log_sizes = @splat(1), .preprocessed_root = @splat(14) };
        return .{ .template = template, .record = record, .public_pin = public_pin, .entries = entries, .pins = pins, .sealed = sealed, .schedule = schedule, .key = try LeafProtocol.Key.fromGeometry(geometry, &schedule), .exported = .{ .template_id = record[0].template_id, .instance_id = entries[1].instance_id, .first_roots = roots, .sealed_digest = sealed.digest, .exact_geometry_digest = try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(shape, shape.total_steps), .open_sum = Q.fromBase(M.fromCanonical(17)) } };
    }
    fn prepare(self: *const Metadata, a: std.mem.Allocator, shape: *const Statement.Blake3ExecutionStatement) !Prepared {
        return Prepared.init(a, shape, shape.total_steps, self.public_pin, self.template, self.record[0].template_id, 0, self.sealed, self.pins, &self.entries, .{ .records = &self.record }, .{});
    }
    fn policy(self: *const Metadata, prepared: *const Prepared) !Adapter.Policy {
        return .{ .native = prepared, .exported = self.exported, .recursive_key = self.key, .recursive_key_id = try self.key.identity(), .recursive_schedule = &self.schedule };
    }
};
test "capacity exact: adapter preserves actual B5CT frames counts and immutable geometry without legacy receipt conversion" {
    var first_shape = frameShape(3);
    var second_shape = frameShape(7);
    const first = try Metadata.init(&first_shape);
    const second = try Metadata.init(&second_shape);
    var first_prepared = try first.prepare(std.testing.allocator, &first_shape);
    defer first_prepared.deinit();
    var second_prepared = try second.prepare(std.testing.allocator, &second_shape);
    defer second_prepared.deinit();
    const first_policy = try first.policy(&first_prepared);
    const second_policy = try second.policy(&second_prepared);
    var one = try Adapter.normalize(std.testing.allocator, first_policy);
    defer one.deinit();
    var two = try Adapter.normalize(std.testing.allocator, second_policy);
    defer two.deinit();
    try std.testing.expectEqualDeep(try one.key.identity(), try two.key.identity());
    try std.testing.expectEqualDeep(first_policy.recursive_key_id, second_policy.recursive_key_id);
    try std.testing.expect(!std.meta.eql(one.public_input_digest, two.public_input_digest));
    try std.testing.expectEqual(LeafProtocol.CLAIM_TAG, one.claim_frame[0]);
    try std.testing.expectEqual(@as(u32, 1), one.claim_frame[1]);
    try std.testing.expectEqualDeep(M.fromCanonical(3), one.terms[0].coordinates[0]);
    try std.testing.expectEqualDeep(M.fromCanonical(7), two.terms[0].coordinates[0]);
    try std.testing.expectEqual(@as(u64, 3), one.span.last_cycle);
    try std.testing.expectEqual(@as(u64, 7), two.span.last_cycle);
    try std.testing.expect(one.native_open_sum.eql(first.exported.open_sum));
    try std.testing.expectError(error.TruncatedBlake3ParentArtifact, Adapter.verify(std.testing.allocator, &.{}, first_policy));
    var altered = first_policy;
    altered.exported.instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityPublicInputs, Adapter.normalize(std.testing.allocator, altered));
}
const RejectLoader = struct {
    calls: *usize,
    pub fn load(self: @This(), _: std.mem.Allocator) ![]u8 {
        self.calls.* += 1;
        return error.UnexpectedCapacityProofLoad;
    }
};
fn outerMetadata() !Exact.NodePin {
    const wire = &[_]OpenBus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .kind = .frame_cell, .child = 0, .coordinate = 0 }};
    const geometry = Parent.Key{ .context = .{ .child_key_id = @splat(21), .child_config = Parent.PCS_CONFIG, .graph_ids = .{ @splat(22), @splat(23), @splat(24) }, .transcript_plan_id = @splat(25) }, .log_sizes = @splat(1), .preprocessed_root = @splat(26) };
    const key = try OpenProtocol.Key.fromGeometry(geometry, wire);
    return .{ .key = key, .expected_id = try key.identity(), .schedule = wire };
}
test "capacity exact: independent security census and fresh base claim reject before outer proof loader" {
    var shape = frameShape(3);
    const metadata = try Metadata.init(&shape);
    var prepared = try metadata.prepare(std.testing.allocator, &shape);
    defer prepared.deinit();
    const leaf = try metadata.policy(&prepared);
    const outer = try outerMetadata();
    var calls: usize = 0;
    const loader = RejectLoader{ .calls = &calls };
    const file = Exact.FilePin{ .byte_len = 1, .sha256 = @splat(1) };
    const public_pins = Exact.OuterPins{ .job_id = metadata.pins.job_id, .source_image_digest = metadata.pins.source_image_digest, .sealed_digest = metadata.sealed.digest, .segment_count = 1, .first_cycle = 1, .last_cycle = 3, .initial_pc = 0, .final_pc = 0 };
    try std.testing.expectError(error.NativeV5BaseRecursiveClaimMismatch, Exact.verifyLoaded(std.testing.allocator, loader, file, &.{leaf}, &.{}, outer, public_pins, Q.zero()));
    var wrong = leaf;
    wrong.recursive_key.context.child_config.pow_bits = 1;
    try std.testing.expectError(error.V5ExactForestSecurityMismatch, Exact.verifyLoaded(std.testing.allocator, loader, file, &.{wrong}, &.{}, outer, public_pins, metadata.exported.open_sum));
    var count = public_pins;
    count.segment_count = 2;
    try std.testing.expectError(error.InvalidV5ExactNativeRoster, Exact.verifyLoaded(std.testing.allocator, loader, file, &.{leaf}, &.{}, outer, count, metadata.exported.open_sum));
    try std.testing.expectEqual(@as(usize, 0), calls);
}

test "capacity exact: default public policy stays NativeV3 and transport output types stay shared" {
    const DefaultExact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
    const DefaultStage = @import("block_v5_open_forest_stage_v1.zig");
    const CapacityStage = @import("block_v5_capacity_open_forest_stage_v1.zig");
    try std.testing.expect(DefaultExact.LeafPolicy == @import("../recursion/block_v5_native_exact_leaf_adapter_v1.zig").Policy);
    try std.testing.expect(DefaultExact.LeafPolicy != Adapter.Policy);
    try std.testing.expect(CapacityStage.Stage == DefaultStage.Stage);
    try std.testing.expect(CapacityStage.ParentPin == DefaultStage.ParentPin);
    try std.testing.expect(@FieldType(CapacityStage.LeafFile, "policy") == Adapter.Policy);
    try std.testing.expect(@FieldType(Adapter.Wire, "coordinate") == u32);
}

test "capacity exact: detached manifest preserves canonical grammar and independently pins outer before file consumption" {
    const Manifest = @import("block_v5_capacity_open_forest_manifest_v1.zig");
    const DefaultManifest = @import("block_v5_open_forest_manifest_v1.zig");
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shape = frameShape(3);
    const metadata = try Metadata.init(&shape);
    var prepared = try metadata.prepare(a, &shape);
    defer prepared.deinit();
    const leaf = try metadata.policy(&prepared);
    const outer = try outerMetadata();
    const file = Exact.FilePin{ .byte_len = 1, .sha256 = @splat(1) };
    const public_pins = Exact.OuterPins{ .job_id = metadata.pins.job_id, .source_image_digest = metadata.pins.source_image_digest, .sealed_digest = metadata.sealed.digest, .segment_count = 1, .first_cycle = 1, .last_cycle = 3, .initial_pc = 0, .final_pc = 0 };
    const limits = Manifest.Limits{ .max_execution_count = 1, .max_manifest_bytes = 1 << 20, .max_proof_bytes = 1 << 20 };
    // Pure metadata proposal: no leaf/outer proof file is created. Negative
    // authority/pin checks must precede any attempt to consume those files.
    const wire = Manifest.Wire{ .version = Manifest.VERSION, .profile = .diagnostic_q8_pow0, .execution_count = 1, .leaf_files = &.{file}, .parents = &.{}, .outer = .{ .node = outer, .file = file }, .public_pins = public_pins, .combined_native_open_sum = metadata.exported.open_sum };
    const sha = try Manifest.writeWire(a, tmp.dir, wire, limits);
    var parsed = try DefaultManifest.read(a, tmp.dir, sha, limits);
    defer parsed.deinit();
    try std.testing.expectEqualDeep(file, parsed.view().outer.file);
    try std.testing.expect(parsed.view().combined_native_open_sum.eql(metadata.exported.open_sum));
    var wrong_file = file;
    wrong_file.sha256[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5DetachedOuterFile, Manifest.verifyDetachedPinned(a, tmp.dir, sha, &.{leaf}, &.{}, outer, wrong_file, public_pins, metadata.exported.open_sum, limits));
    try std.testing.expectError(error.UntrustedV5DetachedForestStatement, Manifest.verifyDetachedPinned(a, tmp.dir, sha, &.{leaf}, &.{}, outer, file, public_pins, Q.zero(), limits));
    var wrong_leaf = leaf;
    wrong_leaf.recursive_key.context.child_config.pow_bits = 1;
    try std.testing.expectError(error.V5ExactForestSecurityMismatch, Manifest.verifyDetachedPinned(a, tmp.dir, sha, &.{wrong_leaf}, &.{}, outer, file, public_pins, metadata.exported.open_sum, limits));
    wrong_leaf = leaf;
    wrong_leaf.exported.instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityPublicInputs, Manifest.verifyDetachedPinned(a, tmp.dir, sha, &.{wrong_leaf}, &.{}, outer, file, public_pins, metadata.exported.open_sum, limits));
    var wrong_sha = sha;
    wrong_sha[0] ^= 1;
    try std.testing.expectError(error.TamperedV5OpenManifest, Manifest.verifyDetachedPinned(a, tmp.dir, wrong_sha, &.{leaf}, &.{}, outer, file, public_pins, metadata.exported.open_sum, limits));
}
