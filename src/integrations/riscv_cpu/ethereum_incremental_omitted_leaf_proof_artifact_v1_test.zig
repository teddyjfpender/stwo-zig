//! Focused gates for the `STWIOL01` omitted-leaf envelope.
//!
//! What is reachable here, and what is not:
//!
//!   * The framing (magic, versions, shard count, lengths, seal) is fully
//!     reachable with synthetic section bytes, so every tamper case runs
//!     against the real encoder and decoder.
//!   * The omission section is fully reachable: a real plan, a real validated
//!     call authority, a real Stage-A manifest and a real relation context are
//!     minted from a 33-call fixture (three log-4 shards); only the projection
//!     is a stand-in, because `validateAgainst` reads exactly six of its fields
//!     and minting a genuine one needs a full leaf statement.
//!   * The typed envelope decoder runs up to the statement section on a
//!     synthetic envelope: the omission section and the header shard count are
//!     checked before any statement byte is opened, so both of those refusals
//!     are pinned here. A full typed round trip needs a proved leaf and is
//!     `test-riscv-ethereum-incremental-omitted-leaf-proof-v1` (Step 10).
//!   * `encodeAlloc` and `Decoded.decodeClaims` are instantiated against the
//!     q193 CPU engine on their first refusal, so their bodies are analysed at
//!     this cheap root rather than in a ten-minute product build.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const envelope =
    @import("ethereum_incremental_omitted_leaf_proof_artifact_v1.zig");
const stwief04 = @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const statement_mod = frontend.air.statement;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const prover = frontend.prover_mod;
const incremental_bridge = prover.incremental_bridge_external_v3;
const omission = prover.guest_precompile.native_provider_omit_v1;
const protocol = prover.ethereum_native_provider_omit_protocol_v1;
const route = prover.guest_precompile.incremental_ethereum_omit_protocol_v4;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const orchestration =
    frontend.testing.incremental_ethereum_omit_orchestration_v4_internal;
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const Manifest = protocol.ProviderStageAManifestV1(Engine);
const Shared = protocol.SharedRelationAuthorityV1(Engine);
const Frame = route.IncrementalOmissionFrameV4;
const LeafOmission = route.LeafOmissionAuthorityV4;
const Section = envelope.OmissionSectionV1;
const Record = envelope.OmissionShardRecordV1;

const call_count = 33;
const test_shard_log = 4;
const limits = envelope.Limits{};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn digest(marker: u8) provider_authority.Digest {
    return [_]u8{marker} ** 32;
}

fn authorityId(marker: u32) route.AuthorityId {
    return [_]u32{marker} ** 8;
}

fn callsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]poseidon2_air.Call {
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    for (calls, 0..) |*call, index| {
        call.* = poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    }
    return calls;
}

/// Same shape as the route's pins with a test shard log, so the fixture plans
/// three shards instead of one 2^18 shard.
fn request(count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(count),
        .column_count = provider_authority.main_column_count,
        .min_shard_log_size = test_shard_log,
        .max_shard_log_size = test_shard_log,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}

fn rootValue(seed: u32) Engine.Hasher.Hash {
    var value: Engine.Hasher.Hash = undefined;
    const words = std.mem.bytesAsSlice(u32, std.mem.asBytes(&value));
    var state: u32 = seed *% 0x9e37_79b9 +% 1;
    for (words) |*word| {
        state = state *% 1_664_525 +% 1_013_904_223;
        word.* = state & 0x3fff_ffff;
    }
    return value;
}

fn rootsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]harness.StageACommitment(Engine) {
    const roots = try allocator.alloc(harness.StageACommitment(Engine), count);
    for (roots, 0..) |*value, index| {
        value.* = .{
            .preprocessed_root = rootValue(@intCast(0x5100 + index)),
            .main_root = rootValue(@intCast(0xa200 + index)),
        };
    }
    return roots;
}

const GeometryFixture = struct {
    full: incremental_bridge.GeometryV3,
    projected_prefix: incremental_bridge.PrefixColumnsV3,
    projected: incremental_bridge.GeometryV3,

    fn init() !GeometryFixture {
        const projected_prefix = incremental_bridge.PrefixColumnsV3{
            .preprocessed = 24,
            .main = 610,
            .interaction = 96,
        };
        const full_prefix = incremental_bridge.PrefixColumnsV3{
            .preprocessed = projected_prefix.preprocessed +
                route.omitted_preprocessed_columns,
            .main = projected_prefix.main + route.omitted_main_columns,
            .interaction = projected_prefix.interaction +
                route.omitted_interaction_columns,
        };
        const n_rows: u32 = 1024;
        const full = try incremental_bridge.GeometryV3.canonicalAfterPrefix(
            n_rows,
            full_prefix,
        );
        const projected = try orchestration.projectedRouteGeometryFromPrefix(
            &full,
            projected_prefix,
        );
        return .{
            .full = full,
            .projected_prefix = projected_prefix,
            .projected = projected.bridge,
        };
    }
};

/// Everything `OmissionSectionV1.canonical` and `validateAgainst` read, with
/// no proof anywhere. Initialised in place: the validated call authority and
/// the Stage-A manifest close over `&self.plan` by pointer.
const LeafFixture = struct {
    allocator: std.mem.Allocator,
    calls: []poseidon2_air.Call,
    plan: provider_authority.ProviderShardPlanV1,
    roots: []harness.StageACommitment(Engine),
    token: provider_authority.OwnedValidatedPlanCallAuthorityV1,
    manifest: protocol.OwnedProviderStageAManifestV1(Engine),
    geometry: GeometryFixture,
    projection: omission.ProjectionV1,
    frame: Frame,
    leaf_omission: LeafOmission,
    shared: Shared,
    air_program_identity: provider_authority.Digest,
    execution_profile_identity: provider_authority.Digest,

    fn init(self: *LeafFixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.calls = try callsFixture(allocator, call_count);
        errdefer allocator.free(self.calls);
        self.plan = try provider_authority.ProviderShardPlanV1.create(
            allocator,
            digest(0xa7),
            self.calls,
            request(self.calls.len),
        );
        errdefer self.plan.deinit(allocator);
        self.roots = try rootsFixture(allocator, self.plan.shards.len);
        errdefer allocator.free(self.roots);
        self.token = try provider_authority.OwnedValidatedPlanCallAuthorityV1
            .init(allocator, &self.plan, self.calls);
        errdefer self.token.deinit();
        self.manifest = try Manifest.createFromRootsValidated(
            allocator,
            &self.plan,
            self.calls,
            &self.token,
            self.roots,
        );
        errdefer self.manifest.deinit(allocator);
        self.geometry = try GeometryFixture.init();

        // Projection stand-in: only the six fields `validateAgainst` reads.
        self.projection = undefined;
        self.projection.identity = digest(0x42);
        self.projection.omitted_infra_index = 3;
        self.projection.omitted_descriptor = .{
            .kind = .poseidon2,
            .log_size = 6,
            .n_rows = call_count,
            .n_columns = route.omitted_main_columns,
        };
        self.projection.projected_native.authority_id = authorityId(0x64);
        self.projection.provider_plan_identity = self.plan.identity;
        self.projection.call_list_commitment = self.plan.call_list_commitment;

        self.frame = try Frame.canonicalFromGeometry(
            self.projection.identity,
            self.geometry.projected,
        );
        self.shared = .{
            .format = 1,
            .plan_identity = self.plan.identity,
            .manifest_identity = self.manifest.manifest.identity,
            .projection_identity = self.projection.identity,
            .tree0_root = rootValue(0x7000),
            .tree1_root = rootValue(0x7001),
            .interaction_pow_bits = 16,
            .interaction_pow = 0x0123_4567_89ab_cdef,
            .relation_context = try provider_authority
                .PoseidonRelationContextV1.canonical(
                self.plan.session,
                QM31.fromU32Unchecked(11, 12, 13, 14),
                QM31.fromU32Unchecked(21, 22, 23, 24),
            ),
            .identity = digest(0x53),
        };
        self.leaf_omission = try LeafOmission.canonical(
            digest(0x31),
            self.frame.identity,
            self.shared.identity,
            authorityId(0x64),
        );
        self.air_program_identity = digest(0xd5);
        self.execution_profile_identity = digest(0xe5);
    }

    fn deinit(self: *LeafFixture) void {
        self.manifest.deinit(self.allocator);
        self.token.deinit();
        self.allocator.free(self.roots);
        self.plan.deinit(self.allocator);
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    fn section(self: *const LeafFixture, allocator: std.mem.Allocator) !Section {
        return Section.canonical(
            Engine,
            allocator,
            &self.projection,
            &self.plan,
            &self.manifest.manifest,
            self.shared,
            &self.geometry.projected,
            &self.frame,
            &self.leaf_omission,
            self.air_program_identity,
            self.execution_profile_identity,
        );
    }

    fn readmit(self: *const LeafFixture, value: *const Section) !void {
        try value.validateAgainst(
            &self.projection,
            &self.plan,
            &self.manifest.manifest,
            self.shared,
            &self.geometry.projected,
            &self.frame,
            &self.leaf_omission,
        );
        try value.validateDegree5Program(
            self.air_program_identity,
            self.execution_profile_identity,
        );
    }
};

fn encodeSection(
    allocator: std.mem.Allocator,
    value: *const Section,
) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try value.encode(bytes.writer(allocator));
    return bytes.toOwnedSlice(allocator);
}

fn expectSectionsEqual(expected: *const Section, actual: *const Section) !void {
    try std.testing.expectEqual(expected.shards.len, actual.shards.len);
    for (expected.shards, actual.shards) |left, right|
        try std.testing.expect(std.meta.eql(left, right));
    var left = expected.*;
    var right = actual.*;
    left.shards = &.{};
    right.shards = &.{};
    try std.testing.expect(std.meta.eql(left, right));
}

/// Seven synthetic fixed sections and three synthetic shard artifacts.
const FramingFixture = struct {
    fixed: [envelope.FIXED_SECTION_COUNT][]const u8,
    shards: [3][]const u8,

    fn init() FramingFixture {
        return .{
            .fixed = .{
                "statement-section",
                "public",
                "extension-bytes",
                "profile",
                "omission",
                "claims!",
                "core-proof-postcard",
            },
            .shards = .{ "shard-0", "shard-1-longer", "s2" },
        };
    }
};

fn eqlBytes(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, left, right);
}

fn isError(result: anytype) bool {
    if (result) |_| return false else |_| return true;
}

// ---------------------------------------------------------------------------
// 1. Framing
// ---------------------------------------------------------------------------

test "STWIOL01 envelope: framing round-trips fixed sections and shard artifacts" {
    const allocator = std.testing.allocator;
    const fixture = FramingFixture.init();
    const bytes = try envelope.encodeFramedAlloc(
        allocator,
        fixture.fixed,
        &fixture.shards,
        limits,
    );
    defer allocator.free(bytes);

    // Header layout: magic, format, schema, shard count, total length.
    try std.testing.expect(eqlBytes(bytes[0..8], &envelope.MAGIC));
    try std.testing.expectEqual(
        envelope.FORMAT_VERSION,
        std.mem.readInt(u16, bytes[8..10], .little),
    );
    try std.testing.expectEqual(
        envelope.SCHEMA_VERSION,
        std.mem.readInt(u16, bytes[10..12], .little),
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        std.mem.readInt(u32, bytes[12..16], .little),
    );
    try std.testing.expectEqual(
        @as(u64, bytes.len),
        std.mem.readInt(u64, bytes[16..24], .little),
    );
    try std.testing.expectEqual(
        @as(usize, 16 + (1 + 7 + 3) * 8),
        try envelope.headerBytes(3),
    );

    var framed = try envelope.decodeFramedAlloc(allocator, bytes, limits);
    defer framed.deinit(allocator);
    for (framed.fixed, fixture.fixed) |actual, expected|
        try std.testing.expect(eqlBytes(actual, expected));
    try std.testing.expectEqual(@as(usize, 3), framed.shards.len);
    for (framed.shards, fixture.shards) |actual, expected|
        try std.testing.expect(eqlBytes(actual, expected));

    // Zero shards and empty shard artifacts are refused at encode time.
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.encodeFramedAlloc(allocator, fixture.fixed, &.{}, limits),
    );
    try std.testing.expectError(
        error.IncrementalOmittedLeafShardArtifactSizeV1,
        envelope.encodeFramedAlloc(
            allocator,
            fixture.fixed,
            &.{ "shard-0", "" },
            limits,
        ),
    );
}

test "STWIOL01 envelope: seal, length and magic tampering are refused" {
    const allocator = std.testing.allocator;
    const fixture = FramingFixture.init();
    const bytes = try envelope.encodeFramedAlloc(
        allocator,
        fixture.fixed,
        &fixture.shards,
        limits,
    );
    defer allocator.free(bytes);
    const copy = try allocator.dupe(u8, bytes);
    defer allocator.free(copy);

    // Magic.
    copy[7] ^= 0x01;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[7] ^= 0x01;
    // Format / schema.
    copy[9] ^= 0x01;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[9] ^= 0x01;
    copy[11] ^= 0x01;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[11] ^= 0x01;
    // Declared total length.
    copy[16] ^= 0x01;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[16] ^= 0x01;
    // Header shard count (the section-length arithmetic no longer closes).
    copy[12] ^= 0x01;
    try std.testing.expect(isError(
        envelope.decodeFramedAlloc(allocator, copy, limits),
    ));
    copy[12] ^= 0x01;
    // Truncation and extension.
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeFramedAlloc(allocator, copy[0 .. copy.len - 1], limits),
    );
    const extended = try allocator.alloc(u8, copy.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..copy.len], copy);
    extended[copy.len] = 0;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeFramedAlloc(allocator, extended, limits),
    );
    // Content under the seal: a section byte, a shard byte, a length word.
    const header = try envelope.headerBytes(3);
    copy[header] ^= 0x01;
    try std.testing.expectError(
        error.IncrementalOmittedLeafProofArtifactContentMismatchV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[header] ^= 0x01;
    copy[copy.len - 33] ^= 0x01;
    try std.testing.expectError(
        error.IncrementalOmittedLeafProofArtifactContentMismatchV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[copy.len - 33] ^= 0x01;
    // Seal byte.
    copy[copy.len - 1] ^= 0x01;
    try std.testing.expectError(
        error.IncrementalOmittedLeafProofArtifactContentMismatchV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[copy.len - 1] ^= 0x01;
    // Moving bytes between two adjacent sections keeps the total but breaks
    // the seal (the lengths are sealed too).
    const first_len_at = 24;
    const second_len_at = 32;
    copy[first_len_at] += 1;
    copy[second_len_at] -= 1;
    try std.testing.expectError(
        error.IncrementalOmittedLeafProofArtifactContentMismatchV1,
        envelope.decodeFramedAlloc(allocator, copy, limits),
    );
    copy[first_len_at] -= 1;
    copy[second_len_at] += 1;
    // The untouched copy still decodes.
    var framed = try envelope.decodeFramedAlloc(allocator, copy, limits);
    framed.deinit(allocator);
}

test "STWIOL01 envelope: STWIEF04 and STWIOL01 decoders reject each other" {
    const allocator = std.testing.allocator;
    const fixture = FramingFixture.init();
    const stwiol01 = try envelope.encodeFramedAlloc(
        allocator,
        fixture.fixed,
        &fixture.shards,
        limits,
    );
    defer allocator.free(stwiol01);
    try std.testing.expectError(
        error.InvalidIncrementalFullLeafProofArtifactV4,
        stwief04.decodeAlloc(Engine, allocator, stwiol01, limits),
    );
    try std.testing.expectError(
        error.InvalidIncrementalFullLeafProofArtifactV4,
        stwief04.decodeAlloc(Engine, allocator, stwiol01, stwief04.Limits{}),
    );

    // A structurally plausible STWIEF04 header: magic, format 4, schema 2,
    // reserved 0, total length, six zero section lengths, 32 seal bytes.
    var fake = std.mem.zeroes([72 + 32]u8);
    @memcpy(fake[0..8], &stwief04.MAGIC);
    std.mem.writeInt(u16, fake[8..10], stwief04.FORMAT_VERSION, .little);
    std.mem.writeInt(u16, fake[10..12], stwief04.SCHEMA_VERSION, .little);
    std.mem.writeInt(u64, fake[16..24], fake.len, .little);
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeFramedAlloc(allocator, &fake, limits),
    );
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeAlloc(Engine, allocator, &fake, limits),
    );
    try std.testing.expect(!std.mem.eql(u8, &envelope.MAGIC, &stwief04.MAGIC));
}

// ---------------------------------------------------------------------------
// 2. Omission section
// ---------------------------------------------------------------------------

test "STWIOL01 envelope: omission section round-trips and readmits every field" {
    const allocator = std.testing.allocator;
    var fixture: LeafFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    try std.testing.expectEqual(@as(usize, 3), fixture.plan.shards.len);

    var section = try fixture.section(allocator);
    defer section.deinit(allocator);
    try section.validate();
    try fixture.readmit(&section);
    try std.testing.expectEqual(@as(u32, 3), section.shard_count);
    try std.testing.expectEqual(
        @as(u64, call_count),
        section.total_call_count,
    );
    try std.testing.expect(std.meta.eql(
        section.pins,
        envelope.OmissionPinsV1.pinned(),
    ));
    try std.testing.expect(std.mem.eql(
        u8,
        &section.pins_identity,
        &route.ProviderOmissionPinsV1.identity(),
    ));
    for (section.shards, fixture.roots) |record, roots| {
        try std.testing.expect(std.mem.eql(
            u8,
            &record.preprocessed_root,
            &envelope.rootBytes(roots.preprocessed_root),
        ));
        try std.testing.expect(std.mem.eql(
            u8,
            &record.main_root,
            &envelope.rootBytes(roots.main_root),
        ));
    }

    const bytes = try encodeSection(allocator, &section);
    defer allocator.free(bytes);
    try std.testing.expectEqual(
        try Section.encodedSize(section.shards.len),
        bytes.len,
    );
    try std.testing.expectEqual(
        Section.fixed_encoded_size + 3 * Record.encoded_size,
        bytes.len,
    );
    var decoded = try Section.decodeAlloc(allocator, bytes);
    defer decoded.deinit(allocator);
    try expectSectionsEqual(&section, &decoded);
    try fixture.readmit(&decoded);

    // The verifier-side projection carries exactly the readmitted digests.
    const projected = decoded.toDecodedOmission();
    try projected.validate();
    try projected.validateAgainst(
        &fixture.projection,
        &fixture.plan,
        &fixture.manifest.manifest,
        fixture.shared,
        &fixture.geometry.projected,
        &fixture.frame,
        &fixture.leaf_omission,
    );
    try std.testing.expect(std.meta.eql(
        projected.projected_bridge_geometry,
        fixture.geometry.projected,
    ));

    // Determinism: a second mint encodes to the same bytes.
    var again = try fixture.section(allocator);
    defer again.deinit(allocator);
    const again_bytes = try encodeSection(allocator, &again);
    defer allocator.free(again_bytes);
    try std.testing.expect(eqlBytes(bytes, again_bytes));

    // Truncated and extended section bytes are refused before any allocation
    // survives.
    try std.testing.expect(isError(
        Section.decodeAlloc(allocator, bytes[0 .. bytes.len - 1]),
    ));
    const extended = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..bytes.len], bytes);
    extended[bytes.len] = 0;
    try std.testing.expect(isError(Section.decodeAlloc(allocator, extended)));
}

const Mutation = enum {
    format,
    pin_shard_log_size,
    pin_requested_parallel_shards,
    pin_log_blowup_factor,
    pin_retention_policy,
    pin_host_byte_budget,
    pin_reserved_host_bytes,
    pin_column_count,
    pin_execution_owners,
    pin_engine_workers_per_owner,
    pin_non_column_reserve_per_owner,
    pins_identity,
    projection_identity,
    omitted_infra_index,
    descriptor_kind,
    descriptor_log_size,
    descriptor_n_rows,
    descriptor_n_columns,
    projected_authority_id,
    plan_identity,
    session,
    call_list_commitment,
    total_call_count,
    shard_count,
    shard_descriptor_identity,
    shard_first_call,
    shard_call_count,
    shard_expected_log_size,
    shard_preprocessed_root,
    shard_main_root,
    shards_swapped,
    manifest_identity,
    interaction_pow,
    relation_context_identity,
    relation_z,
    relation_alpha,
    shared_identity,
    bridge_n_rows,
    bridge_log_size,
    bridge_is_first,
    bridge_is_active,
    bridge_main_offset,
    bridge_interaction_offset,
    bridge_total_preprocessed,
    bridge_total_main,
    bridge_total_interaction,
    bridge_identity,
    frame_identity,
    leaf_omission_identity,
    air_program_identity,
    execution_profile_identity,

    fn isDegree5Program(self: Mutation) bool {
        return self == .air_program_identity or
            self == .execution_profile_identity;
    }
};

fn applyMutation(section: *Section, shards: []Record, mutation: Mutation) void {
    switch (mutation) {
        .format => section.format += 1,
        .pin_shard_log_size => section.pins.shard_log_size += 1,
        .pin_requested_parallel_shards => section.pins
            .requested_parallel_shards += 1,
        .pin_log_blowup_factor => section.pins.log_blowup_factor += 1,
        .pin_retention_policy => section.pins.retention_policy += 1,
        .pin_host_byte_budget => section.pins.host_byte_budget += 1,
        .pin_reserved_host_bytes => section.pins.reserved_host_bytes += 1,
        .pin_column_count => section.pins.column_count += 1,
        .pin_execution_owners => section.pins.execution_owners += 1,
        .pin_engine_workers_per_owner => section.pins
            .engine_workers_per_owner += 1,
        .pin_non_column_reserve_per_owner => section.pins
            .non_column_reserve_per_owner += 1,
        .pins_identity => section.pins_identity[0] ^= 0x01,
        .projection_identity => section.projection_identity[0] ^= 0x01,
        .omitted_infra_index => section.omitted_infra_index += 1,
        .descriptor_kind => section.omitted_descriptor.kind = .merkle,
        .descriptor_log_size => section.omitted_descriptor.log_size += 1,
        .descriptor_n_rows => section.omitted_descriptor.n_rows += 1,
        .descriptor_n_columns => section.omitted_descriptor.n_columns += 1,
        .projected_authority_id => section.projected_authority_id[7] ^= 1,
        .plan_identity => section.plan_identity[31] ^= 0x01,
        .session => section.session[0] ^= 0x01,
        .call_list_commitment => section.call_list_commitment[0] ^= 0x01,
        .total_call_count => section.total_call_count += 1,
        .shard_count => section.shard_count -= 1,
        .shard_descriptor_identity => shards[1].descriptor_identity[0] ^= 1,
        .shard_first_call => shards[1].first_call += 1,
        .shard_call_count => shards[2].call_count += 1,
        .shard_expected_log_size => shards[0].expected_log_size += 1,
        .shard_preprocessed_root => shards[0].preprocessed_root[0] ^= 0x01,
        .shard_main_root => shards[2].main_root[31] ^= 0x01,
        .shards_swapped => std.mem.swap(Record, &shards[0], &shards[1]),
        .manifest_identity => section.manifest_identity[0] ^= 0x01,
        .interaction_pow => section.interaction_pow += 1,
        .relation_context_identity => section.relation_context_identity[0] ^= 1,
        .relation_z => section.relation_z = section.relation_z.add(QM31.one()),
        .relation_alpha => section.relation_alpha = section.relation_alpha
            .add(QM31.one()),
        .shared_identity => section.shared_identity[0] ^= 0x01,
        .bridge_n_rows => section.projected_bridge_geometry.n_rows += 1,
        .bridge_log_size => section.projected_bridge_geometry.log_size += 1,
        .bridge_is_first => section.projected_bridge_geometry.placement
            .is_first_col_idx += 1,
        .bridge_is_active => section.projected_bridge_geometry.placement
            .is_active_col_idx += 1,
        .bridge_main_offset => section.projected_bridge_geometry.placement
            .main_col_offset += 1,
        .bridge_interaction_offset => section.projected_bridge_geometry
            .placement.interaction_col_offset += 1,
        .bridge_total_preprocessed => section.projected_bridge_geometry
            .total_preprocessed_columns += 1,
        .bridge_total_main => section.projected_bridge_geometry
            .total_main_columns += 1,
        .bridge_total_interaction => section.projected_bridge_geometry
            .total_interaction_columns += 1,
        .bridge_identity => section.projected_bridge_geometry
            .identity_sha256[0] ^= 0x01,
        .frame_identity => section.frame_identity[0] ^= 0x01,
        .leaf_omission_identity => section.leaf_omission_identity[0] ^= 0x01,
        .air_program_identity => section.air_program_identity[0] ^= 0x01,
        .execution_profile_identity => section
            .execution_profile_identity[0] ^= 0x01,
    }
}

test "STWIOL01 envelope: every mutated omission field is rejected" {
    const allocator = std.testing.allocator;
    var fixture: LeafFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    var canonical = try fixture.section(allocator);
    defer canonical.deinit(allocator);
    try fixture.readmit(&canonical);

    for (std.enums.values(Mutation)) |mutation| {
        const shards = try allocator.dupe(Record, canonical.shards);
        defer allocator.free(shards);
        var mutated = canonical;
        mutated.shards = shards;
        applyMutation(&mutated, shards, mutation);

        // Live readmission refuses the mutated value.
        if (mutation.isDegree5Program()) {
            try std.testing.expectError(
                error.IncrementalOmittedLeafOmissionProgramMismatchV1,
                mutated.validateDegree5Program(
                    fixture.air_program_identity,
                    fixture.execution_profile_identity,
                ),
            );
        } else {
            const result = mutated.validateAgainst(
                &fixture.projection,
                &fixture.plan,
                &fixture.manifest.manifest,
                fixture.shared,
                &fixture.geometry.projected,
                &fixture.frame,
                &fixture.leaf_omission,
            );
            if (!isError(result)) {
                std.debug.print(
                    "mutation {s} was accepted by validateAgainst\n",
                    .{@tagName(mutation)},
                );
                return error.TestUnexpectedResult;
            }
        }

        // The byte path refuses it too: either the section no longer encodes
        // or decodes, or the decoded copy is refused by readmission.
        const bytes = encodeSection(allocator, &mutated) catch continue;
        defer allocator.free(bytes);
        var decoded = Section.decodeAlloc(allocator, bytes) catch continue;
        defer decoded.deinit(allocator);
        try expectSectionsEqual(&mutated, &decoded);
        if (!isError(fixture.readmit(&decoded))) {
            std.debug.print(
                "mutation {s} survived encode/decode readmission\n",
                .{@tagName(mutation)},
            );
            return error.TestUnexpectedResult;
        }
    }

    // Pin drift names its own error whichever knob moved.
    var drifted = canonical;
    drifted.pins.host_byte_budget += 1;
    try std.testing.expectError(
        error.ProviderOmissionPinDriftV4,
        drifted.validate(),
    );

    // The canonical value is still accepted after the sweep.
    try fixture.readmit(&canonical);
}

// ---------------------------------------------------------------------------
// 3. Typed envelope on the q193 CPU engine
// ---------------------------------------------------------------------------

/// A framed envelope whose omission section is genuine and whose other fixed
/// sections are placeholders: exactly enough for the typed decoder to reach
/// the statement section.
fn syntheticEnvelope(
    allocator: std.mem.Allocator,
    section: *const Section,
    shards: []const []const u8,
) ![]u8 {
    const omission_bytes = try encodeSection(allocator, section);
    defer allocator.free(omission_bytes);
    const extension_bytes = try allocator.alloc(
        u8,
        prover.guest_precompile.ethereum_proof_artifact_wire
            .extension_encoded_size,
    );
    defer allocator.free(extension_bytes);
    @memset(extension_bytes, 0xee);
    return envelope.encodeFramedAlloc(
        allocator,
        .{
            "not-a-statement",
            "public",
            extension_bytes,
            "profile",
            omission_bytes,
            "claims-are-opened-in-phase-two",
            "core-proof",
        },
        shards,
        limits,
    );
}

test "STWIOL01 envelope: header shard count must match the omission section" {
    const allocator = std.testing.allocator;
    var fixture: LeafFixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit();
    var section = try fixture.section(allocator);
    defer section.deinit(allocator);

    // Three shards in the header, three in the section: the decoder gets past
    // both checks and fails on the placeholder statement instead.
    const matching = try syntheticEnvelope(
        allocator,
        &section,
        &.{ "shard-0", "shard-1", "shard-2" },
    );
    defer allocator.free(matching);
    const result = envelope.decodeAlloc(Engine, allocator, matching, limits);
    try std.testing.expect(isError(result));
    if (result) |_| unreachable else |err| {
        try std.testing.expect(
            err != error.IncrementalOmittedLeafProofArtifactShardCountMismatchV1,
        );
        try std.testing.expect(
            err != error.IncrementalOmittedLeafProofArtifactContentMismatchV1,
        );
        try std.testing.expect(
            err != error.InvalidIncrementalOmittedLeafProofArtifactV1,
        );
        try std.testing.expect(
            err != error.InvalidIncrementalOmittedLeafOmissionSectionV1,
        );
    }

    // Two shards in the header, three in the section.
    const fewer = try syntheticEnvelope(
        allocator,
        &section,
        &.{ "shard-0", "shard-1" },
    );
    defer allocator.free(fewer);
    try std.testing.expectError(
        error.IncrementalOmittedLeafProofArtifactShardCountMismatchV1,
        envelope.decodeAlloc(Engine, allocator, fewer, limits),
    );

    // Four shards in the header, three in the section.
    const more = try syntheticEnvelope(
        allocator,
        &section,
        &.{ "shard-0", "shard-1", "shard-2", "shard-3" },
    );
    defer allocator.free(more);
    try std.testing.expectError(
        error.IncrementalOmittedLeafProofArtifactShardCountMismatchV1,
        envelope.decodeAlloc(Engine, allocator, more, limits),
    );

    // A tampered omission section is refused by the section's own validation
    // before the statement is opened, even though the seal was re-minted.
    var drifted = section;
    const shards = try allocator.dupe(Record, section.shards);
    defer allocator.free(shards);
    drifted.shards = shards;
    drifted.pins.execution_owners += 1;
    const drifted_bytes = try syntheticEnvelope(
        allocator,
        &drifted,
        &.{ "shard-0", "shard-1", "shard-2" },
    );
    defer allocator.free(drifted_bytes);
    try std.testing.expectError(
        error.ProviderOmissionPinDriftV4,
        envelope.decodeAlloc(Engine, allocator, drifted_bytes, limits),
    );

    // A wrong-size extension section is refused before the omission section.
    const omission_bytes = try encodeSection(allocator, &section);
    defer allocator.free(omission_bytes);
    const short_extension = try envelope.encodeFramedAlloc(
        allocator,
        .{ "s", "p", "ext", "prof", omission_bytes, "claims", "proof" },
        &.{ "shard-0", "shard-1", "shard-2" },
        limits,
    );
    defer allocator.free(short_extension);
    try std.testing.expectError(
        error.ProofResourceLimitExceeded,
        envelope.decodeAlloc(Engine, allocator, short_extension, limits),
    );

    // Seal tampering on the typed path.
    const copy = try allocator.dupe(u8, matching);
    defer allocator.free(copy);
    copy[copy.len - 40] ^= 0x01;
    try std.testing.expectError(
        error.IncrementalOmittedLeafProofArtifactContentMismatchV1,
        envelope.decodeAlloc(Engine, allocator, copy, limits),
    );
}

test "STWIOL01 envelope: typed encoder and decoders instantiate on the q193 CPU engine" {
    const allocator = std.testing.allocator;

    // `encodeAlloc` validates the limits before touching any input, so an
    // undefined input never gets read; the call still instantiates and
    // analyses the whole encoder body against the concrete engine.
    const input: envelope.EncodeInput(Engine) = undefined;
    try std.testing.expectError(
        error.InvalidResourceLimits,
        envelope.encodeAlloc(
            Engine,
            allocator,
            input,
            .{ .max_artifact_bytes = 0 },
        ),
    );

    // The retained-lease decoder shares the framing refusal with the plain
    // decoder.
    const retained: frontend.air.public_data_v2.PublicDataV2
        .RetainedSnapshots = undefined;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        envelope.decodeAllocWithRetainedLease(
            Engine,
            allocator,
            "STWIOL01-not-an-envelope",
            limits,
            retained,
            null,
        ),
    );

    // Phase two refuses a claim section too short to hold the bridge claim
    // before any claim byte is interpreted.
    var decoded: envelope.Decoded(Engine) = undefined;
    decoded.claim_bytes = "short";
    var core = std.mem.zeroes(statement_mod.RiscVStatement);
    core.initializeDescriptorStorage();
    const extension: ethereum_statement.Statement = undefined;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedLeafProofArtifactV1,
        decoded.decodeClaims(allocator, &core, &extension),
    );

    // Activation guards.
    try std.testing.expect(!envelope.PRODUCTION_ACTIVE);
    try std.testing.expect(!envelope.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(envelope.RESEARCH_ONLY);
}
