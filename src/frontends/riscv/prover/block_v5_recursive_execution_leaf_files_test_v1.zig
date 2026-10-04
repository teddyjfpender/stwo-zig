//! Literal nonproof transport only: metadata round trips create no authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Files = @import("block_v5_recursive_execution_leaf_files_v1.zig");
const Original = @import("tests/block_v5_caller_capture_unit_test.zig").Fixture;
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Arithmetic = Files.ForFamily(.caller_arithmetic);
const Projection = Files.ForFamily(.caller_fused);
fn template(comptime T: type, prepared: *const T.Admission.Prepared, schedule: []const T.Bus.Wire) !T.Template {
    const geometry = Parent.Key{ .profile = .diagnostic_q8_pow0, .config = prepared.config, .context = .{ .child_key_id = prepared.template_id, .child_config = prepared.config, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try T.Protocol.Key.fromGeometry(geometry, schedule);
    return .{ .key = key, .key_id = try key.identity(), .schedule = schedule };
}
fn assemble(a: std.mem.Allocator, encoded: anytype) ![]u8 {
    const raw = try a.alloc(u8, encoded.total_bytes);
    var offset: usize = 0;
    for (encoded.parts()) |part| {
        @memcpy(raw[offset..][0..part.len], part);
        offset += part.len;
    }
    return raw;
}
fn roundTrip(comptime T: type, a: std.mem.Allocator, artifact: *const T.Stage.Artifact, policy: T.Policy) !void {
    var encoded = try T.encode(a, artifact, policy, .{});
    defer encoded.deinit();
    try std.testing.expect(encoded.proof.ptr == artifact.bytes.ptr);
    const raw = try assemble(a, &encoded);
    defer a.free(raw);
    var view = try T.decodeMetadata(a, raw, policy, .{});
    defer view.deinit();
    try std.testing.expect(view.proof.ptr == raw[Files.HEADER_BYTES + encoded.metadata.len ..].ptr);
    try std.testing.expectEqualDeep(policy.template.key_id, view.parsed.value.key_id);
}
const arithmetic_wires = [_]Arithmetic.Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .source = .open_sum, .coordinate = 0 }};
fn arithmeticArtifact(a: std.mem.Allocator, policy: Arithmetic.Policy) !Arithmetic.Stage.Artifact {
    const claims = try Arithmetic.Admission.Profile.ExtensionClaim.zeroForStatement(&policy.prepared.statement);
    const receipt = @import("block_v5_precompile_family_proof_v1.zig").OpenReceipt{ .binding = policy.prepared.binding, .open_sum = claims.componentSum() };
    const bytes = try a.dupe(u8, "literal nonproof recursive caller transport");
    errdefer a.free(bytes);
    const schedule = try a.dupe(Arithmetic.Bus.Wire, policy.template.schedule);
    errdefer a.free(schedule);
    return .{ .bytes = bytes, .key = policy.template.key, .expected_key_id = policy.template.key_id, .schedule = schedule, .native = receipt, .public_values = try Arithmetic.Bus.Values.fromCaller(policy.prepared, receipt, claims) };
}
fn arithmeticCase(a: std.mem.Allocator, artifact: *const Arithmetic.Stage.Artifact, policy: Arithmetic.Policy) !void {
    try roundTrip(Arithmetic, a, artifact, policy);
}
test "recursive execution files: arithmetic proposals roundtrip without copying proof and clean all allocation failures" {
    const a = std.testing.allocator;
    const fixture = try Original.init(a);
    var prepared = try Arithmetic.Admission.Prepared.init(a, fixture.statement, fixture.frame.cycle_count, fixture.binding, fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer prepared.deinit();
    const key = try template(Arithmetic, &prepared, &arithmetic_wires);
    const policy = Arithmetic.Policy{ .prepared = &prepared, .template = &key };
    var artifact = try arithmeticArtifact(a, policy);
    defer artifact.deinit(a);
    try arithmeticCase(a, &artifact, policy);
    try std.testing.checkAllAllocationFailures(a, arithmeticCase, .{ &artifact, policy });
}
test "recursive execution files: envelope family index extent key policy and trailing bytes are independently rejected" {
    const a = std.testing.allocator;
    const fixture = try Original.init(a);
    var prepared = try Arithmetic.Admission.Prepared.init(a, fixture.statement, fixture.frame.cycle_count, fixture.binding, fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer prepared.deinit();
    var key = try template(Arithmetic, &prepared, &arithmetic_wires);
    const policy = Arithmetic.Policy{ .prepared = &prepared, .template = &key };
    var artifact = try arithmeticArtifact(a, policy);
    defer artifact.deinit(a);
    var encoded = try Arithmetic.encode(a, &artifact, policy, .{});
    defer encoded.deinit();
    const raw = try assemble(a, &encoded);
    defer a.free(raw);
    for ([_]usize{ 0, 8, 12, 16 }) |offset| {
        raw[offset] ^= 1;
        try std.testing.expectError(error.InvalidRecursiveExecutionEnvelope, Arithmetic.decodeMetadata(a, raw, policy, .{}));
        raw[offset] ^= 1;
    }
    try std.testing.expectError(error.InvalidRecursiveExecutionEnvelope, Arithmetic.decodeMetadata(a, raw[0 .. raw.len - 1], policy, .{}));
    const appended = try a.alloc(u8, raw.len + 1);
    defer a.free(appended);
    @memcpy(appended[0..raw.len], raw);
    appended[raw.len] = 0;
    try std.testing.expectError(error.InvalidRecursiveExecutionEnvelope, Arithmetic.decodeMetadata(a, appended, policy, .{}));
    key.key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedRecursiveExecutionTemplate, Arithmetic.decodeMetadata(a, raw, policy, .{}));
    key.key_id[0] ^= 1;
    // Literal nonproof data cannot turn JSON/transport validity into an equation.
    var view = try Arithmetic.decodeMetadata(a, raw, policy, .{});
    defer view.deinit();
    if (view.verify(a, policy)) |received| {
        var unexpected = received;
        unexpected.deinit();
        return error.AcceptedLiteralNonproofLeaf;
    } else |_| {}
}
fn projectionClaims(a: std.mem.Allocator, prepared: *const Projection.Admission.Prepared) !Fused.ClaimFrames {
    const program = try a.alloc(@import("block_v5_program_extension_proof_v1.zig").Claim, prepared.schedule.program.len);
    errdefer a.free(program);
    const state = try a.alloc(@import("block_v5_program_extension_proof_v1.zig").Claim, prepared.schedule.program.len);
    errdefer a.free(state);
    for (program, state, prepared.schedule.program) |*p, *s, slot| {
        p.* = .{ .sum = Q.zero(), .fetch_count = slot.active_calls };
        s.* = p.*;
    }
    const tables = try a.alloc(@import("block_v5_precompile_lookup_algebra_v1.zig").Claim, prepared.schedule.tables.len);
    errdefer a.free(tables);
    for (tables, prepared.schedule.tables) |*claim, slot| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
    const memory = try a.alloc(@import("block_v5_external_memory_sidecar_proof_v1.zig").Claim, prepared.schedule.memory.len);
    for (memory, prepared.schedule.memory) |*claim, slot| claim.* = .{ .active_count = if (slot.kind == .sha) prepared.statement.sha.call_count else if (slot.kind == .keccak) prepared.statement.ethereum.counts.keccak_calls else prepared.statement.ethereum.counts.signer_calls, .transition_sum = Q.zero(), .universal_sum = Q.zero(), .range_claims = @splat(Q.zero()) };
    return .{ .program_claims = program, .state_claims = state, .table_claims = tables, .memory_claims = memory };
}
fn projectionCase(a: std.mem.Allocator, artifact: *const Projection.Stage.Artifact, policy: Projection.Policy) !void {
    try roundTrip(Projection, a, artifact, policy);
}
test "recursive execution files: fused claims preserve distinct owned public frames through every allocation failure" {
    const a = std.testing.allocator;
    const fixture = try Original.initWithKeccak(a, 1);
    var prepared = try Projection.Admission.Prepared.init(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer prepared.deinit();
    const wires = [_]Projection.Bus.Wire{.{ .circuit = Projection.Bus.PUBLIC_CIRCUIT, .wire = 0, .uses = 1, .source = .word, .coordinate = 0 }};
    const key = try template(Projection, &prepared, &wires);
    const policy = Projection.Policy{ .prepared = &prepared, .template = &key };
    var claims = try projectionClaims(a, &prepared);
    defer claims.deinit(a);
    var values = try Projection.Bus.Values.init(a, &prepared, claims);
    defer values.deinit();
    // Nonproof artifact borrowing test-owned fields. Native is never accessed
    // by the codec and is deliberately unavailable, not a fabricated receipt.
    var artifact = Projection.Stage.Artifact{ .bytes = @constCast("literal not a fused recursive proof"), .key = key.key, .expected_key_id = key.key_id, .schedule = @constCast(&wires), .native = undefined, .claims = claims, .public_values = values };
    try projectionCase(a, &artifact, policy);
    try std.testing.checkAllAllocationFailures(a, projectionCase, .{ &artifact, policy });
}
