//! Nonproving custody/identity fixtures. Literal bytes and metadata are never
//! admitted as a successful capture, native receipt or recursive equation.
const std = @import("std");
const core = @import("stwo_core");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Literal = @import("block_v5_native_capacity_fused_transport_fixture_v1.zig");
const Codec = @import("block_v5_native_capacity_fused_codec_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const API = Fused.ForBackend(Cpu);

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    shape: @import("../air/statement.zig").Blake3ExecutionStatement,
    native: Native.OpenReceipt,
    policy: Fused.CaptureAdmission,
    claims: []Fused.Claim,
    access_claims: []@import("block_v5_opcode_memory_sidecar_proof_v1.zig").Claim,
    witness: []u32,
    interaction: []u32,
    /// Metadata-only policy fixture; never calls policy.require or creates a
    /// VerifiedCapture. Its pins/roots cannot verify a STARK.
    fn init(self: *Fixture, a: std.mem.Allocator, rw: bool) !void {
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const scratch = self.arena.allocator();
        self.shape = Literal.shape(rw);
        const expected = try Literal.expected(scratch, &self.shape);
        self.native = .{ .template_id = expected.template_id, .instance_id = expected.native_instance_id, .first_roots = expected.native_roots, .sealed_digest = expected.sealed_digest, .exact_geometry_digest = try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(&self.shape, 0), .open_sum = core.fields.qm31.QM31.zero() };
        const projections = try Source.slotsFromShapeForMode(scratch, &self.shape, 0, 1);
        const slots = try Source.memorySlots(scratch, &self.shape, 0, expected.frame, 1);
        var sealed = std.mem.zeroes(Seal.Sealed);
        sealed.digest = expected.sealed_digest;
        sealed.register_custody_mode = 1;
        var pins = std.mem.zeroes(Seal.Pins);
        pins.config = Literal.config;
        self.policy = .{ .sealed = sealed, .pins = pins, .entries = &.{}, .native = &self.native, .index = 0, .frame = expected.frame, .projections = projections, .slots = slots, .fixed_logs = try Capacity.columnLogs(scratch, &self.shape, 0, .fixed), .main_logs = try Capacity.columnLogs(scratch, &self.shape, 0, .main), .witness_root = expected.witness_root, .empty_entry = null, .shape = &self.shape, .external_retirements = 0, .limits = .{} };
        self.claims = try scratch.alloc(Fused.Claim, projections.len);
        for (self.claims, projections) |*claim, slot| claim.* = .{ .row_count = slot.n_rows, .sum = core.fields.qm31.QM31.zero() };
        self.access_claims = try scratch.alloc(@import("block_v5_opcode_memory_sidecar_proof_v1.zig").Claim, slots.len);
        @memset(self.access_claims, .{ .active_count = 0, .transition_sum = core.fields.qm31.QM31.zero(), .universal_sum = core.fields.qm31.QM31.zero(), .range_claims = @splat(core.fields.qm31.QM31.zero()) });
        self.witness = try Fused.witnessLogs(scratch, slots);
        self.interaction = try Fused.interactionLogs(scratch, projections, slots);
    }
    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn copyFailure(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var metadata = try Fused.CaptureMetadata.init(a, fixture.policy, fixture.claims, fixture.access_claims, fixture.witness, fixture.interaction);
    defer metadata.deinit();
    try metadata.require(fixture.policy);
    _ = try metadata.identity();
}
test "capacity fused capture: every owned claim inventory allocation failure releases unpublished custody" {
    for ([_]bool{ false, true }) |rw| {
        var fixture: Fixture = undefined;
        try fixture.init(std.testing.allocator, rw);
        defer fixture.deinit();
        try std.testing.checkAllAllocationFailures(std.testing.allocator, copyFailure, .{&fixture});
    }
}
test "capacity fused capture: metadata owns claims counts and four geometry lists after source destruction" {
    for ([_]bool{ false, true }) |rw| {
        var fixture: Fixture = undefined;
        try fixture.init(std.testing.allocator, rw);
        var owns = true;
        defer if (owns) fixture.deinit();
        var metadata = try Fused.CaptureMetadata.init(std.testing.allocator, fixture.policy, fixture.claims, fixture.access_claims, fixture.witness, fixture.interaction);
        defer metadata.deinit();
        const before = try metadata.identity();
        try std.testing.expect(metadata.claims.ptr != fixture.claims.ptr);
        try std.testing.expect(metadata.projections.ptr != fixture.policy.projections.ptr);
        fixture.claims[0].sum = core.fields.qm31.QM31.one();
        try std.testing.expectEqualDeep(before, try metadata.identity());
        fixture.deinit();
        owns = false;
        try std.testing.expectEqualDeep(before, try metadata.identity());
        metadata.claims[0].sum = core.fields.qm31.QM31.one();
        try std.testing.expect(!std.meta.eql(before, try metadata.identity()));
    }
}
test "capacity fused capture: copied policy rejects changed mode native instance frame roots logs and selector origin" {
    var fixture: Fixture = undefined;
    try fixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var metadata = try Fused.CaptureMetadata.init(std.testing.allocator, fixture.policy, fixture.claims, fixture.access_claims, fixture.witness, fixture.interaction);
    defer metadata.deinit();
    const before = try metadata.identity();
    metadata.native.instance_id[0] ^= 1;
    try std.testing.expectError(error.InvalidCapacityFusedCapturePolicy, metadata.require(fixture.policy));
    metadata.native.instance_id[0] ^= 1;
    metadata.frame.global_first_cycle += 1;
    try std.testing.expectError(error.InvalidCapacityFusedCapturePolicy, metadata.require(fixture.policy));
    metadata.frame.global_first_cycle -= 1;
    metadata.witness_root[0] ^= 1;
    try std.testing.expectError(error.InvalidCapacityFusedCapturePolicy, metadata.require(fixture.policy));
    metadata.witness_root[0] ^= 1;
    metadata.sealed.register_custody_mode = 0;
    try std.testing.expectError(error.InvalidCapacityFusedCapturePolicy, metadata.require(fixture.policy));
    metadata.sealed.register_custody_mode = 1;
    metadata.logs[1][0] += 1;
    try std.testing.expectError(error.InvalidCapacityFusedCapturePolicy, metadata.require(fixture.policy));
    metadata.logs[1][0] -= 1;
    metadata.slots[0].main_offset += 1;
    try std.testing.expectError(error.InvalidCapacityFusedCapturePolicy, metadata.require(fixture.policy));
    metadata.slots[0].main_offset -= 1;
    try metadata.require(fixture.policy);
    try std.testing.expectEqualDeep(before, try metadata.identity());
    metadata.memory_claims[0].range_claims[0] = core.fields.qm31.QM31.one();
    try std.testing.expect(!std.meta.eql(before, try metadata.identity()));
}
test "capacity fused capture: metadata byte cap rejects before copy and retains source" {
    var fixture: Fixture = undefined;
    try fixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var bounded = fixture.policy;
    bounded.limits.max_metadata_bytes = 1;
    try std.testing.expectError(error.CapacityFusedResourceLimit, Fused.CaptureMetadata.init(std.testing.allocator, bounded, fixture.claims, fixture.access_claims, fixture.witness, fixture.interaction));
    try std.testing.expect(fixture.claims[0].sum.isZero());
}

fn negativeBorrowed(a: std.mem.Allocator, fixture: *const Fixture, proof: *const Fused.Proof) !void {
    const p = fixture.policy;
    var captured = API.verifyCaptureBorrowed(a, proof, p.sealed, p.pins, p.entries, p.native, p.index, p.frame, p.projections, p.slots, p.fixed_logs, p.main_logs, p.witness_root, p.empty_entry, p.shape, p.external_retirements, p.limits) catch |err| {
        if (err != error.UntrustedCapacityFusedProtocol) return err;
        return;
    };
    captured.deinit();
    return error.UnexpectedLiteralCaptureAcceptance;
}
test "capacity fused capture: borrowed rejected source remains byte identical and owned rejection consumes all arrays" {
    const a = std.testing.allocator;
    var fixture: Fixture = undefined;
    try fixture.init(a, true);
    defer fixture.deinit();
    const expected = try Literal.expected(a, &fixture.shape);
    var source = try Literal.Fixture.init(a, expected);
    defer source.deinit();
    const original_bytes = try Codec.encode(a, &source.proof, expected, .{});
    defer a.free(original_bytes);
    source.proof.protocol_version = 2;
    const old_claim = source.proof.claims[0];
    try negativeBorrowed(a, &fixture, &source.proof);
    try std.testing.expectEqualDeep(old_claim, source.proof.claims[0]);
    source.proof.protocol_version = Fused.VERSION;
    const bytes = try Codec.encode(a, &source.proof, expected, .{});
    defer a.free(bytes);
    try std.testing.expectEqualSlices(u8, original_bytes, bytes);
    var owned = try Codec.decode(a, bytes, expected, .{});
    owned.protocol_version = 2;
    const p = fixture.policy;
    if (API.verifyCaptureOwned(a, owned, p.sealed, p.pins, p.entries, p.native, p.index, p.frame, p.projections, p.slots, p.fixed_logs, p.main_logs, p.witness_root, p.empty_entry, p.shape, p.external_retirements, p.limits)) |result| {
        var unexpected = result;
        unexpected.deinit();
        return error.UnexpectedLiteralCaptureAcceptance;
    } else |err| try std.testing.expectEqual(error.UntrustedCapacityFusedProtocol, err);
}
