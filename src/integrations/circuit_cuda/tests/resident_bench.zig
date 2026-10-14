//! GPU qualification harness for the complete circuit-recursion proof.
//! It checks the Rust R7 serialized verifier-proof digest after native
//! verification, then reports the per-stage device and host elapsed times.
//!
//! `<case> <profile> --last-layer <log_last_layer_degree_bound>
//! [--expect-sha256 <hex>]` proves under that last-layer bound instead, for
//! FRI shapes the Rust fixture lacks (a short last round of the four-fold
//! schedule), and checks the digest when one is given. This product forbids
//! CPU composition, so the expected digest comes from a CPU circuit build.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const cuda = @import("stwo_circuit_cuda_integration");
const cuda_backend = @import("stwo_cuda_backend");
const contexts = @import("circuit_testing").contexts;

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 3 or args.len > 7) return error.UsageResidentBenchCaseProfile;
    const which = std.meta.stringToEnum(contexts.TestContext, args[1]) orelse return error.UnknownCircuitCase;
    const profile = std.meta.stringToEnum(cuda.resident_prover.Profile, args[2]) orelse return error.UnknownCircuitProfile;
    const custom = args.len >= 5 and std.mem.eql(u8, args[3], "--last-layer");
    if (args.len >= 5 and !custom) return error.UsageResidentBenchCaseProfile;
    if (args.len == 6 or (args.len == 7 and !std.mem.eql(u8, args[5], "--expect-sha256"))) return error.UsageResidentBenchCaseProfile;
    const expected_fixture = if (args.len == 4) args[3] else "vectors/circuit/r7/prove_profiles.json";
    const log_last_layer: u32 = if (custom) try std.fmt.parseInt(u32, args[4], 10) else 0;
    const expected_sha256: ?[]const u8 = if (args.len == 7) args[6] else null;
    var total = try std.time.Timer.start();

    var ctx = try contexts.build(QM31, allocator, which);
    defer ctx.deinit();
    try ctx.finalize(false);
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.preprocessContext(QM31, allocator, &ctx);
    defer pp.deinit(allocator);
    if (!try ctx.isCircuitValid()) return error.InvalidCircuitFixture;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try cuda.air_aot.build(allocator, encoded);
    defer catalog.deinit();
    const layout = pp.layout();
    var air = try cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&layout), &layout);
    defer air.deinit();
    const config = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(26, log_last_layer, 1, 70, 4),
        pp.traceLogSize(),
    );
    const prepared_ns = total.read();
    var proving = try std.time.Timer.start();
    const input = cuda.resident_prover.Input{
        .values = ctx.values(),
        .preprocessed = &pp,
        .air = &air,
        .catalog = &catalog,
        .config = config,
        .profile = profile,
    };
    var result = try cuda.resident_prover.prove(allocator, input);
    defer result.deinit();
    const prove_ns = proving.read();
    var verifying = try std.time.Timer.start();
    var verified = try cuda.resident_verifier.verify(allocator, input, &result);
    defer verified.deinit();
    const verify_ns = verifying.read();

    const claim_words = result.terminal_proof.decoded.words[result.terminal_proof.decoded.layout.interaction_claim.start..result.terminal_proof.decoded.layout.interaction_claim.end];
    var claims: [circuit.common.component_list.N_COMPONENTS]QM31 = undefined;
    for (&claims, 0..) |*out, index| {
        const words = claim_words[index * 4 ..][0..4];
        out.* = QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
    }
    var recursive = try cpu.verifier_proof.fromVerifiedCapture(
        allocator,
        &result.stark,
        &verified.capture,
        try cpu.verifier_proof.proofConfig(pp.columns.len, config),
        &claims,
        result.terminal_proof.decoded.interactionNonce(),
        0,
    );
    defer recursive.deinit();
    const wire = try recursive.serialize(allocator);
    defer allocator.free(wire);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(wire, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (custom) {
        std.debug.print("case={s} profile={s} log_last_layer={} proof_bytes={} sha256={s}\n", .{
            @tagName(which), @tagName(profile), log_last_layer, wire.len, &hex,
        });
        if (expected_sha256) |sha| if (!std.mem.eql(u8, &hex, sha)) return error.CircuitProofDigestMismatch;
        return;
    }
    const expected = try fixtureDigest(allocator, expected_fixture, @tagName(which), @tagName(profile));
    if (!std.mem.eql(u8, &hex, &expected.sha256) or wire.len != expected.bytes) {
        std.debug.print("circuit CUDA proof mismatch case={s} profile={s} actual={s} expected={s} bytes={} expected_bytes={}\n", .{
            @tagName(which), @tagName(profile), &hex, &expected.sha256, wire.len, expected.bytes,
        });
        return error.RustCircuitProofMismatch;
    }
    std.debug.print("case={s} profile={s} prepared_ns={} prove_ns={} verify_ns={} total_ns={} arena_bytes={} peak_device_bytes={} proof_bytes={} resident={} rust_sha256={s}\n", .{
        @tagName(which),            @tagName(profile),                       prepared_ns, prove_ns,                    verify_ns, total.read(),
        result.planned_arena_bytes, result.verdict.counters.peak_live_bytes, wire.len,    result.verdict.isResident(), &hex,
    });
    for (cuda_backend.runtime.telemetry.all_stages) |stage| {
        const counters = result.verdict.counters.stages[stage.index()];
        std.debug.print("stage={s} device_ns={} launches={} h2d_bytes={} d2h_bytes={}\n", .{
            @tagName(stage),    counters.device_elapsed_ns, counters.kernel_launches,
            counters.h2d_bytes, counters.d2h_proof_bytes,
        });
    }
}

const Expected = struct { bytes: usize, sha256: [64]u8 };

fn fixtureDigest(allocator: std.mem.Allocator, path: []const u8, name: []const u8, profile: []const u8) !Expected {
    const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 16 << 20);
    defer allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    const body = parsed.value.object.get("body") orelse return error.InvalidCircuitFixture;
    const profiles = (body.object.get("profiles") orelse return error.InvalidCircuitFixture).array.items;
    for (profiles) |entry| {
        const lane = (entry.object.get("profile") orelse return error.InvalidCircuitFixture).string;
        if (!std.mem.eql(u8, lane, profile)) continue;
        const proofs = (entry.object.get("proofs") orelse return error.InvalidCircuitFixture).array.items;
        for (proofs) |proof| {
            const case_name = (proof.object.get("name") orelse return error.InvalidCircuitFixture).string;
            if (!std.mem.eql(u8, case_name, name)) continue;
            const serialized = proof.object.get("circuit_serialize") orelse return error.InvalidCircuitFixture;
            const sha = (serialized.object.get("sha256") orelse return error.InvalidCircuitFixture).string;
            if (sha.len != 64) return error.InvalidCircuitFixture;
            return .{
                .bytes = @intCast((serialized.object.get("bytes") orelse return error.InvalidCircuitFixture).integer),
                .sha256 = sha[0..64].*,
            };
        }
    }
    return error.MissingCircuitFixture;
}

test "resident CUDA fixture digest loader follows Rust profile names" {
    const result = try fixtureDigest(std.testing.allocator, "vectors/circuit/r7/prove_profiles.json", "fibonacci", "internal");
    try std.testing.expect(result.bytes > 1000);
}

comptime {
    std.debug.assert(@sizeOf(QM31) == 4 * @sizeOf(M31));
}
