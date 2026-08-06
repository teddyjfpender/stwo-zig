//! Closed protocol for the H-010 authenticated Poseidon layout benchmark.
//!
//! The benchmark is proposal evidence, not a proof-system surface.  Arm names,
//! representative selection, artifact identities, supported measurement sizes,
//! and negative capability labels are fixed here so a runner cannot silently
//! reinterpret an H-009 candidate or overstate what its timings measure.

const std = @import("std");
const frontier = @import("materialization_frontier_manifest.zig");

pub const schema = "stwo.typed-air.poseidon-layout-benchmark-sample-v1";
pub const schema_version: u16 = 1;
pub const benchmark_id = "h010-authenticated-poseidon-layout-cpu-v1";
pub const measurement_scope = "single-process-single-arm-cpu-candidate-evaluation-v1";
pub const call_schedule = "sha256-counter-poseidon-calls-v1";
pub const vector_format = "STWAIRB-v1";
pub const vector_magic = "STWAIRB\x00";
pub const vector_format_version: u16 = 1;
pub const vector_generator_id = "stwo.typed-air.benchmark.sha256-counter-v1";
pub const vector_value_domain =
    "stwo-zig/typed-air/h010/poseidon2-vector-value/v1\x00";
pub const call_digest_domain = "stwo-zig/typed-air/h010/call-schedule/v1";
pub const output_digest_domain = "stwo-zig/typed-air/h010/semantic-outputs/v1";
pub const trace_digest_domain = "stwo-zig/typed-air/h010/main-trace/v1";
pub const evaluator = "stwo.typed-air.poseidon2-retained-cpu-evaluator-v1";
pub const backend = "cpu-retained-scalar-m31";
pub const root_count: u32 = 430;
pub const materialization_count: u32 = 426;
pub const main_column_count: u32 = 445;
pub const padding_rows: u32 = 3;

pub const semantic_digest_hex =
    "9e8c3b5accdc2be31cf8ca128b5b27c87613f691ee8fd25e031f4286ceac81ed";
pub const identity_digest_hex =
    "d85aa12bb4de8b676d88e184558bf2ef047cf286fab2f6b7ee4e3825001faa68";
pub const fixed_program_digest_hex =
    "ef32024ba1d25b470c217ef96af95b52038948c67f6ac4ce1e14875bf68ea6a5";
pub const cost_model_digest_hex =
    "12670408a3c3020c62d279c997338d9c427d0755697aca2a954f6a1d88a9ba11";
pub const configuration_digest_hex =
    "32dc4c0b5e265c74b159a6e661d4f6f0b06f3b54d62efe286364b5dae92db8ed";
pub const result_digest_hex =
    "7948117553242d3154a8bd09ca1664c4bf6e5cbcc515a4ce80461cf544d39193";
pub const artifact_sha256_hex =
    "5ead00cfcb8cfd396836be9cc3a79ed80bfb0b8bc7913a1c6ab38dbcff879494";
pub const baseline_cut_digest_hex =
    "b10cb7f66e3519788ecec6edc4095541a24eaf642a3ed8877fbe87c85e8ba9c5";
pub const baseline_proposal_digest_hex =
    "7a585031ef8710d62adac55d1c2d8072c0b2a6ce82a562b4862d4329623a23ef";

pub const Arm = enum {
    compat_seed,
    removed_q0,
    removed_q50,
    removed_q100,

    pub fn id(self: Arm) []const u8 {
        return switch (self) {
            .compat_seed => "compat-seed",
            .removed_q0 => "removed-q0",
            .removed_q50 => "removed-q50",
            .removed_q100 => "removed-q100",
        };
    }

    pub fn parse(text: []const u8) ?Arm {
        inline for (std.meta.tags(Arm)) |arm| {
            if (std.mem.eql(u8, text, arm.id())) return arm;
        }
        return null;
    }

    pub fn frontierOrdinal(self: Arm) ?usize {
        return switch (self) {
            .compat_seed => null,
            .removed_q0 => 85,
            .removed_q50 => 92,
            .removed_q100 => 60,
        };
    }
};

pub const ArmPin = struct {
    arm: Arm,
    quantile_numerator: ?u8,
    frontier_ordinal: ?usize,
    removed_value_id: ?u32,
    added_value_id: ?u32,
    proposal_digest_hex: []const u8,
    cut_digest_hex: []const u8,
};

pub const arm_pins = [_]ArmPin{
    .{
        .arm = .compat_seed,
        .quantile_numerator = null,
        .frontier_ordinal = null,
        .removed_value_id = null,
        .added_value_id = null,
        .proposal_digest_hex = baseline_proposal_digest_hex,
        .cut_digest_hex = baseline_cut_digest_hex,
    },
    .{
        .arm = .removed_q0,
        .quantile_numerator = 0,
        .frontier_ordinal = 85,
        .removed_value_id = 266,
        .added_value_id = 240,
        .proposal_digest_hex = "997d7236203de34953b8479ea2773a0772737d6e7f81c08537f8bd744f5ccd44",
        .cut_digest_hex = "96f45498a15b2313ca83a9f5bc8a38f74c620f2712ca219bf440cb30dbe1e788",
    },
    .{
        .arm = .removed_q50,
        .quantile_numerator = 1,
        .frontier_ordinal = 92,
        .removed_value_id = 1_517,
        .added_value_id = 1_485,
        .proposal_digest_hex = "ae33d31eab62c10a8be6826a6e739c6e30dddf154eec22d10194e3583fa37e23",
        .cut_digest_hex = "0f339a827261aa19693617a6d782d8b02a49a6930fd75ea512c9bb62a59ea90e",
    },
    .{
        .arm = .removed_q100,
        .quantile_numerator = 2,
        .frontier_ordinal = 60,
        .removed_value_id = 2_039,
        .added_value_id = 2_007,
        .proposal_digest_hex = "662338db02cbb0e7e1e4eb7f486b2f6a05087e96f8d3597ca50dd667faa9ae6a",
        .cut_digest_hex = "a2b77acaaf4977012e6dfc17fed31856b906c1e221999d4d52932922cd425f20",
    },
};

pub const AuthenticationError = frontier.ManifestError || error{
    ArtifactDigestMismatch,
    ArtifactIdentityMismatch,
    ArmDerivationMismatch,
    ArmPinMismatch,
    BenchmarkGeometryMismatch,
    FixedProgramDigestMismatch,
};

pub const VectorAuthenticationError = error{
    UnsupportedVectorLog,
    VectorGeometryMismatch,
    VectorIdentityMismatch,
};

pub const RssError = error{ InvalidPeakRss, PeakRssOverflow };

pub const RssUnit = enum {
    bytes,
    kib,

    pub fn label(self: RssUnit) []const u8 {
        return switch (self) {
            .bytes => "bytes",
            .kib => "KiB",
        };
    }
};

pub const VectorIdentity = struct {
    log_size: u8,
    rows: u64,
    preimage_bytes: u64,
    artifact_bytes: u64,
    vector_seal: frontier.Digest,
    vector_artifact_sha256: frontier.Digest,
    call_digest: frontier.Digest,
    output_digest: frontier.Digest,
};

pub const VectorPin = struct {
    log_size: u8,
    rows: u64,
    preimage_bytes: u64,
    artifact_bytes: u64,
    vector_seal_hex: []const u8,
    vector_artifact_sha256_hex: []const u8,
    call_digest_hex: []const u8,
    output_digest_hex: []const u8,
    trace_digest_hex: [arm_pins.len][]const u8,
};

pub const vector_pins = [_]VectorPin{
    vectorPinValue(
        10,
        "27be0de8a88a36ac9cb686c40da6442abdd18950bc4cb45a93773f45de4fb113",
        "2d90fa647d55758f1fdf7be46de5232ee006ac3682ab0371ec1108c95c8f14ee",
        "c149cb04c9604a9702484f4cdc52712d8cbdd92e7ec5d5055b8066207f42826c",
        "08478c8bede13d09402a3ad5688d9581f3ee45e11455a46f23814387435c73ae",
        .{
            "972f3071150f299a9054363b8e27a63354bf2d18d93752476af546742fecab39",
            "c85fe25a7a9132c1d41fafb423252f4e62ff0a26f2e24f4012bbbda33a07c6ad",
            "c05bbe69456d010ec8a8318a5a0682f76326f774cab08a834d0ac011e6e5ed90",
            "669bae41567c5ef7be2bfe9be0e65c281b437f346d482c3907205cd6578b821d",
        },
    ),
    vectorPinValue(
        14,
        "b9ce7ca07edee474d0ca9da8e2a4dcdd24d300b6a99c1a1c5305a90da9a3c11d",
        "b2f84aa4ecc9f017932a2ca81fd89060d1fccb8bfaf90c9843ac9013cb6f83d8",
        "c1cbc8b1f135c6e2ac71f0a17fa545714a5adefadef52a993b19fd4b0416613a",
        "5b0a3a47bba89e6ffa0314b0d5a64ce9f0d8fe560cb63e1b2803c3011ebb2454",
        .{
            "9fa0b291e70bcbf637c4605d002e7fd6040bbf1b3803f8feba9b5c294b3827a7",
            "2e8a3424f62e33e908e69be3e0f04159e71e28953454fd090bb7d50ba9137ad2",
            "79511831f3a2b3a7bd09a95ce8614a2d4ca81b9186cb53d29b4ea2daa75fc332",
            "5a626e0a415caa06e2ee3e5a479b1c25061ccb5e61bb620a8e6d9243236ab4c2",
        },
    ),
    vectorPinValue(
        18,
        "026856cb253075be1cc3671cff75a9e974bf384bcff359e903bd1c2e4f357f08",
        "97c24095ff33d0150a69da5cc9e108065b3f68e204ea10d6f0a21d19dce604b4",
        "255b80dc74b2cd1cf528ab12d9240ff98247db8807a3bdefe624ae7a8f30ad97",
        "f687cc5b81a20b10a2200190dd0449271ac488ea5db9e581fb9fe463d811c1fa",
        .{
            "dba86497b97ae4213564822d6945b9fdb708173f73e7c0b921595e83392235a5",
            "6fca9b92fa3014f12596bc34e92180a0ba4dc5c7d62c9d1d1ebc00912b08179d",
            "601fdcd3af1202f6f7ee66881709215ae0309c238a1ef342cfcbd9cdfbac5095",
            "34085fd56f4732d1caf5ed9e32f884e5b81cb7f82a4c3a71961021a796d42db7",
        },
    ),
};

pub fn pin(arm: Arm) ArmPin {
    return arm_pins[@intFromEnum(arm)];
}

pub fn isMeasurementLog(log_size: u8) bool {
    return log_size == 10 or log_size == 14 or log_size == 18;
}

pub fn normalizePeakRss(native_value: u64, unit: RssUnit) RssError!u64 {
    if (native_value == 0) return error.InvalidPeakRss;
    return switch (unit) {
        .bytes => native_value,
        .kib => std.math.mul(u64, native_value, 1024) catch
            return error.PeakRssOverflow,
    };
}

pub fn authenticateFixedProgramDigest(
    actual: frontier.Digest,
    artifact: frontier.Digest,
) AuthenticationError!void {
    try expectDigest(
        actual,
        fixed_program_digest_hex,
        error.FixedProgramDigestMismatch,
    );
    if (!std.mem.eql(u8, &actual, &artifact))
        return error.FixedProgramDigestMismatch;
}

pub fn authenticateVector(identity: VectorIdentity) VectorAuthenticationError!void {
    const expected = vectorPin(identity.log_size) orelse
        return error.UnsupportedVectorLog;
    if (identity.rows != expected.rows or
        identity.preimage_bytes != expected.preimage_bytes or
        identity.artifact_bytes != expected.artifact_bytes)
    {
        return error.VectorGeometryMismatch;
    }
    try expectVectorDigest(identity.vector_seal, expected.vector_seal_hex);
    try expectVectorDigest(
        identity.vector_artifact_sha256,
        expected.vector_artifact_sha256_hex,
    );
    try expectVectorDigest(identity.call_digest, expected.call_digest_hex);
    try expectVectorDigest(identity.output_digest, expected.output_digest_hex);
}

pub fn authenticateTrace(
    arm: Arm,
    log_size: u8,
    digest: frontier.Digest,
) VectorAuthenticationError!void {
    const expected = vectorPin(log_size) orelse return error.UnsupportedVectorLog;
    try expectVectorDigest(
        digest,
        expected.trace_digest_hex[@intFromEnum(arm)],
    );
}

pub fn vectorPin(log_size: u8) ?VectorPin {
    for (vector_pins) |value| if (value.log_size == log_size) return value;
    return null;
}

/// Authenticates the reviewed bytes and derives q0/q50/q100 by ranking every
/// retained proposal's removed semantic `ValueId`.  For the even 126-member
/// frontier q50 deliberately uses the lower median: floor((n - 1) / 2).
pub fn authenticateArtifact(
    bytes: []const u8,
    manifest: frontier.Manifest,
) AuthenticationError!void {
    var raw_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &raw_digest, .{});
    try expectDigest(raw_digest, artifact_sha256_hex, error.ArtifactDigestMismatch);
    try frontier.validateCanonical(manifest);
    try expectDigest(
        manifest.identity.semantic_digest,
        semantic_digest_hex,
        error.ArtifactIdentityMismatch,
    );
    try expectDigest(
        manifest.identity.identity_digest,
        identity_digest_hex,
        error.ArtifactIdentityMismatch,
    );
    try expectDigest(
        manifest.cost_model.fixed_program_digest,
        fixed_program_digest_hex,
        error.ArtifactIdentityMismatch,
    );
    try expectDigest(
        manifest.cost_model.cost_model_digest,
        cost_model_digest_hex,
        error.ArtifactIdentityMismatch,
    );
    try expectDigest(
        manifest.search.configuration_digest,
        configuration_digest_hex,
        error.ArtifactIdentityMismatch,
    );
    try expectDigest(
        manifest.run.result_digest,
        result_digest_hex,
        error.ArtifactIdentityMismatch,
    );
    try expectDigest(
        manifest.baseline.cut_digest,
        baseline_cut_digest_hex,
        error.ArmPinMismatch,
    );
    try expectDigest(
        manifest.baseline.proposal_digest,
        baseline_proposal_digest_hex,
        error.ArmPinMismatch,
    );
    if (manifest.frontier.len != 126 or
        manifest.run.frontier_truncated or manifest.run.budget_exhausted or
        manifest.geometry.base_main_columns != 19 or
        manifest.geometry.interaction_columns != 8 or
        manifest.baseline.cost.materialization_count != materialization_count or
        manifest.baseline.cost.candidate_main_columns != main_column_count or
        manifest.baseline.cost.direct_roots != root_count or
        manifest.baseline.cost.interaction_columns != 8 or
        manifest.baseline.cost.canonical_direct_nodes != 3_460 or
        manifest.baseline.cost.canonical_direct_additions != 1_346 or
        manifest.baseline.cost.canonical_direct_subtractions != 429 or
        manifest.baseline.cost.canonical_direct_negations != 0 or
        manifest.baseline.cost.canonical_direct_multiplications != 1_080 or
        manifest.baseline.cost.unique_committed_column_reads != 445 or
        manifest.baseline.cost.canonical_streaming_peak_live_nodes != 39 or
        manifest.baseline.cost.semantic_witness_nodes != 2_171)
    {
        return error.BenchmarkGeometryMismatch;
    }

    for (arm_pins[1..]) |arm_pin| {
        const derived = try deriveQuantile(manifest, arm_pin.quantile_numerator.?);
        if (derived.ordinal != arm_pin.frontier_ordinal.?)
            return error.ArmDerivationMismatch;
        const proposal = manifest.frontier[derived.ordinal];
        if (proposal.provenance.removed != arm_pin.removed_value_id or
            proposal.provenance.added != arm_pin.added_value_id or
            proposal.selected_values.len != materialization_count)
        {
            return error.ArmPinMismatch;
        }
        try expectDigest(
            proposal.proposal_digest,
            arm_pin.proposal_digest_hex,
            error.ArmPinMismatch,
        );
        try expectDigest(
            proposal.cut_digest,
            arm_pin.cut_digest_hex,
            error.ArmPinMismatch,
        );
        try expectDigest(
            proposal.provenance.parent_cut_digest,
            baseline_cut_digest_hex,
            error.ArmPinMismatch,
        );
        if (proposal.provenance.kind != .swap or proposal.provenance.pass != 1)
            return error.ArmPinMismatch;
    }
    for (manifest.frontier) |proposal| {
        if (!std.meta.eql(manifest.baseline.cost, proposal.cost) or
            proposal.scenario_costs.len != manifest.baseline.scenario_costs.len)
        {
            return error.BenchmarkGeometryMismatch;
        }
        for (proposal.scenario_costs, manifest.baseline.scenario_costs) |lhs, rhs| {
            if (!std.meta.eql(lhs, rhs)) return error.BenchmarkGeometryMismatch;
        }
    }
}

const Derived = struct { ordinal: usize, removed: u32 };

fn deriveQuantile(manifest: frontier.Manifest, numerator: u8) !Derived {
    if (manifest.frontier.len == 0 or numerator > 2)
        return error.ArmDerivationMismatch;
    const rank = (manifest.frontier.len - 1) * @as(usize, numerator) / 2;
    for (manifest.frontier, 0..) |proposal, ordinal| {
        const removed = proposal.provenance.removed orelse
            return error.ArmDerivationMismatch;
        var below: usize = 0;
        for (manifest.frontier, 0..) |other, other_ordinal| {
            const candidate = other.provenance.removed orelse
                return error.ArmDerivationMismatch;
            if (candidate < removed or (candidate == removed and
                std.mem.order(
                    u8,
                    &other.proposal_digest,
                    &proposal.proposal_digest,
                ) == .lt))
            {
                below += 1;
            }
            if (other_ordinal != ordinal and
                std.mem.eql(u8, &other.proposal_digest, &proposal.proposal_digest))
            {
                return error.ArmDerivationMismatch;
            }
        }
        if (below == rank) return .{ .ordinal = ordinal, .removed = removed };
    }
    return error.ArmDerivationMismatch;
}

fn expectDigest(
    actual: frontier.Digest,
    expected_hex: []const u8,
    mismatch: AuthenticationError,
) AuthenticationError!void {
    const actual_hex = std.fmt.bytesToHex(actual, .lower);
    if (!std.mem.eql(u8, &actual_hex, expected_hex)) return mismatch;
}

fn expectVectorDigest(
    actual: frontier.Digest,
    expected_hex: []const u8,
) VectorAuthenticationError!void {
    const actual_hex = std.fmt.bytesToHex(actual, .lower);
    if (!std.mem.eql(u8, &actual_hex, expected_hex))
        return error.VectorIdentityMismatch;
}

fn vectorPinValue(
    comptime log_size: u8,
    vector_seal_hex: []const u8,
    vector_artifact_sha256_hex: []const u8,
    call_digest_hex: []const u8,
    output_digest_hex: []const u8,
    trace_digest_hex: [arm_pins.len][]const u8,
) VectorPin {
    const rows = @as(u64, 1) << log_size;
    const preimage_bytes = vector_magic.len + @sizeOf(u16) + @sizeOf(u16) +
        vector_generator_id.len + 32 + @sizeOf(u32) + @sizeOf(u64) + rows * 140;
    return .{
        .log_size = log_size,
        .rows = rows,
        .preimage_bytes = preimage_bytes,
        .artifact_bytes = preimage_bytes + 32,
        .vector_seal_hex = vector_seal_hex,
        .vector_artifact_sha256_hex = vector_artifact_sha256_hex,
        .call_digest_hex = call_digest_hex,
        .output_digest_hex = output_digest_hex,
        .trace_digest_hex = trace_digest_hex,
    };
}

test "H-010 arm spelling and measurement logs are closed" {
    for (arm_pins) |arm_pin| {
        try std.testing.expectEqual(arm_pin.arm, Arm.parse(arm_pin.arm.id()).?);
        try std.testing.expectEqual(
            arm_pin.frontier_ordinal,
            arm_pin.arm.frontierOrdinal(),
        );
    }
    try std.testing.expect(isMeasurementLog(10));
    try std.testing.expect(isMeasurementLog(14));
    try std.testing.expect(isMeasurementLog(18));
    try std.testing.expect(!isMeasurementLog(6));
}

test "H-010 RSS normalization is explicit and overflow checked" {
    try std.testing.expectEqual(@as(u64, 7), try normalizePeakRss(7, .bytes));
    try std.testing.expectEqual(@as(u64, 7 * 1024), try normalizePeakRss(7, .kib));
    try std.testing.expectError(error.InvalidPeakRss, normalizePeakRss(0, .bytes));
    try std.testing.expectError(
        error.PeakRssOverflow,
        normalizePeakRss(std.math.maxInt(u64), .kib),
    );
}
