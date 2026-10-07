//! Diagnostic parity: a real q193 child, no wrapper proof or key activation.
//!
//! The statement-admission callback runs before Fiat-Shamir and commitment
//! construction. This test compares it with fixture-pinned geometry/profile
//! and graph IDs; production still needs a separately versioned verifier key.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("recursive_segment_v3_native_test_fixture.zig");
const pin = frontend.recursion.vm_air_preleaf_graph_pin_v8;

const recursion = frontend.recursion;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const M31 = core.fields.m31.M31;
const known_q193_tree0 = [8]u32{
    2053578112, 2007969840, 1758814271, 1936034131,
    1603516961, 444025432,  32631551,   1362738667,
};
const known_statement_id = digestFromHex("96e162dc972c3d01c4183e8098b55506e328e35be852a279a4b9a1c2079daa2e");
const known_profile_id = digestFromHex("ace5e8c145321ed632a467b17a4a2274d6700fe38b6b2c31d29506e396971737");
const known_graph_id = digestFromHex("60fb2296f28f6bd654fd6291f23eac3fc57fe5dd71f4a9ad41f6bc2dec73b886");
const known_circuit_id = digestFromHex("cf442fc364989c66d7ee55c0966360d487ac9de95569d88a93f994f69a348663");

fn digestFromHex(comptime hex: []const u8) [32]u8 {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch @compileError("invalid pinned q193 digest");
    return bytes;
}

const Admission = struct {
    allocator: std.mem.Allocator,
    candidate: ?pin.Candidate = null,
    statement_id: [32]u8 = [_]u8{0} ** 32,
    profile_id: [32]u8 = [_]u8{0} ** 32,

    fn admit(context: *anyopaque, statement: *const frontend.air.statement_v2.RiscVStatementV2) anyerror!void {
        const self: *Admission = @ptrCast(@alignCast(context));
        if (self.candidate != null) return error.DuplicateStatementAdmission;
        try statement.validate();
        const manifest_mod = frontend.air.lookup_physical_manifest_v2;
        const profile_mod = recursion.vm_air_profile_v2;
        const geometry = recursion.vm_composition_base_geometry_v2;
        const manifest = manifest_mod.Manifest.native();
        const authenticated = try manifest_mod.AuthenticatedStatement.init(&statement.core, &manifest);
        const count = try geometry.expectedSampledValueCount(&statement.core, &manifest);
        var profile = try profile_mod.deriveAuthority(self.allocator, &statement.core, &manifest, &authenticated, count);
        defer profile.deinit();
        if (!std.mem.eql(u8, &authenticated.statement_identity, &known_statement_id) or
            !std.mem.eql(u8, &profile.identity_digest, &known_profile_id))
            return error.Q193FixtureAuthorityMismatch;
        self.statement_id = known_statement_id;
        self.profile_id = known_profile_id;
        const statement_hex = std.fmt.bytesToHex(self.statement_id, .lower);
        const profile_hex = std.fmt.bytesToHex(self.profile_id, .lower);
        std.debug.print("V8_Q193_ADMISSION_IDS statement={s} profile={s}\n", .{
            &statement_hex,
            &profile_hex,
        });
        // Fixture constants were selected before this proof transaction. This
        // diagnostic comparison still does not mint a production verifier key.
        self.candidate = try pin.Candidate.compile(self.allocator, .{
            .statement = &statement.core,
            .expected_statement_geometry_id = self.statement_id,
            .expected_profile_id = self.profile_id,
        });
        if (!std.mem.eql(u8, &self.candidate.?.graph_id, &known_graph_id) or
            !std.mem.eql(u8, &self.candidate.?.circuit_id, &known_circuit_id))
            return error.Q193FixtureVmGraphMismatch;
    }

    fn deinit(self: *Admission) void {
        if (self.candidate) |*candidate| candidate.deinit();
    }
};

test "diagnostic real q193 VM AIR graph matches pre-proof statement compiler" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(false, .self_loop);
    var session = try frontend.runner.Poseidon2ExecutionSession.init(allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left = try session.startSegment(1);
    defer left.deinit();
    var right = try session.resumeSegment(left.base.continuation.?, 16);
    defer right.deinit();
    const source = try fixture.rightGlobal(allocator, &left.base, &right.base);
    var projection = try recursion.segment_leaf_local_projection_v3.ProjectionV3.init(&source);
    const session_id = recursion.poseidon2_channel.hashBytes("native-local-v3-session", 0x4e56_3250);
    const local_source = try projection.sourceV2(&source, session_id);
    const words = try allocator.alloc(M31, try local_source.canonicalWordCount());
    defer allocator.free(words);
    _ = try local_source.encodeCanonical(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(words);

    var admission = Admission{ .allocator = allocator };
    defer admission.deinit();
    var channel = Engine.Channel{};
    var output = try frontend.prover_mod.proveRiscVSegmentV2WithEngineUsingChannelAndExecution(
        Engine,
        allocator,
        recursion.protocol.PCS_CONFIG,
        &projection.local_result,
        null,
        public_data,
        &channel,
        .{ .statement_admission = .{ .context = &admission, .admit_fn = Admission.admit } },
    );
    defer output.deinit(allocator);
    try std.testing.expect(admission.candidate != null);
    const selected = pin.Selected{
        .statement = &output.statement.core,
        .expected_statement_geometry_id = admission.statement_id,
        .expected_profile_id = admission.profile_id,
    };
    const candidate = &admission.candidate.?;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try postcard.serializeProof(Engine.Hasher, encoded.writer(allocator), output.proof);
    var stream = std.io.fixedBufferStream(encoded.items);
    var decoded = try postcard.deserializeProof(Engine.Hasher, allocator, stream.reader());
    var decoded_owned = true;
    defer if (decoded_owned) decoded.deinit(allocator);
    if (stream.pos != encoded.items.len) return error.InvalidProofShape;
    var capture: frontend.prover_mod.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
    var verify_channel = Engine.Channel{};
    decoded_owned = false;
    try frontend.prover_mod.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        recursion.protocol.PCS_CONFIG,
        output.statement,
        decoded,
        output.interaction_claim,
        &verify_channel,
        &capture,
    );
    defer capture.deinit(allocator);
    try std.testing.expectEqualDeep(known_q193_tree0, capture.proof.commitments[0]);
    var prepared = try recursion.vm_air_composition_prepared_v2.prepare(
        allocator,
        &capture,
        recursion.protocol.PCS_CONFIG,
    );
    defer prepared.deinit();
    try candidate.validateCapturedPrepared(allocator, selected, &prepared);
    const graph_hex = std.fmt.bytesToHex(candidate.graph_id, .lower);
    const circuit_hex = std.fmt.bytesToHex(candidate.circuit_id, .lower);
    std.debug.print("V8_Q193_VM_PIN_PARITY graph={s} circuit={s} nodes={d} status=diagnostic_only\n", .{
        &graph_hex,
        &circuit_hex,
        candidate.nodes.len,
    });
}
