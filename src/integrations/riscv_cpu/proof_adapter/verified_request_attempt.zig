//! Owned binding between one successfully verified request and its flat task profile.

const std = @import("std");
const stwo = @import("stwo");

const stage_profile = stwo.prover.stage_profile;
const task_profile = stwo.prover.task_profile;
const work_profile = stwo.prover.work_profile;
const proof_phase_meter = stwo.frontends.riscv.prover_mod.proof_phase_meter;

pub const SCHEMA = "riscv_verified_request_attempt_v2";
pub const EXACT_WORK_SCHEMA = "riscv_verified_request_attempt_v3";
pub const PROFILED_BENCHMARK_SCHEMA = "riscv_profiled_proof_v3";
pub const EXACT_WORK_PROFILED_BENCHMARK_SCHEMA = "riscv_profiled_proof_v4";
pub const WORK_COUNTER_SEMANTICS =
    "scalar_lane_completed_algorithm_boundaries_v1";
pub const TIMING_PARTITION =
    "protocol_complete:guest_execution+witness_materialization+proving+" ++
    "native_verification;proof_serialization_excluded";

/// Declares which duration is authoritative in the additive profiled benchmark
/// schema. Legacy seconds-valued aggregates remain present for compatibility,
/// but must not be substituted for the per-attempt monotonic integers.
pub const BenchmarkTimingAuthority = struct {
    clock: []const u8 = "monotonic",
    unit: []const u8 = "nanoseconds",
    partition: []const u8 = "protocol_complete",
    protocol_partition_complete: bool = true,
    witness_materialization_regions: u64 = proof_phase_meter.REGION_COUNT,
    authoritative_samples: []const u8 =
        "verified_request_attempts[*].verified_request_ns",
    legacy_outer_samples: []const u8 =
        "sample_seconds_and_median_seconds_are_non_authoritative_compatibility_fields",
};

/// JSON-facing projection of the stronger prover-API work profile. The digest
/// is recomputed from the fixed source record before this projection is
/// accepted or emitted; its owned hexadecimal storage is cold receipt state.
pub const WorkProfileReport = struct {
    schema: []const u8 = work_profile.SCHEMA,
    schema_version: u16 = work_profile.SCHEMA_VERSION,
    counter_semantics: []const u8 = WORK_COUNTER_SEMANTICS,
    authority: work_profile.Authority,
    source_mask: u8,
    record_count: u64,
    producer_ledger_schema_version: u16,
    expected_producer_counts: work_profile.ProducerCounts,
    completed_producer_counts: work_profile.ProducerCounts,
    producer_coverage_terminal_sealed: bool,
    field_additions: u64,
    field_multiplications: u64,
    field_inversions: u64,
    fft_butterflies: u64,
    fri_folds: u64,
    merkle_compressions: u64,
    profile_sha256: []const u8,

    pub fn initAlloc(
        allocator: std.mem.Allocator,
        profile: *const work_profile.Profile,
    ) !WorkProfileReport {
        try profile.validate();
        if (!profile.completeExact()) return error.IncompleteExactWorkProfile;
        const digest_hex = std.fmt.bytesToHex(profile.profile_digest, .lower);
        return .{
            .authority = profile.authority,
            .source_mask = profile.source_mask.bits,
            .record_count = profile.record_count,
            .producer_ledger_schema_version = profile.producer_ledger.schema_version,
            .expected_producer_counts = profile.producer_ledger.expected,
            .completed_producer_counts = profile.producer_ledger.completed,
            .producer_coverage_terminal_sealed = profile.producer_ledger.terminal_sealed,
            .field_additions = profile.counters.field_additions,
            .field_multiplications = profile.counters.field_multiplications,
            .field_inversions = profile.counters.field_inversions,
            .fft_butterflies = profile.counters.fft_butterflies,
            .fri_folds = profile.counters.fri_folds,
            .merkle_compressions = profile.counters.merkle_compressions,
            .profile_sha256 = try allocator.dupe(u8, &digest_hex),
        };
    }

    pub fn validate(self: *const WorkProfileReport) !void {
        if (!std.mem.eql(u8, self.schema, work_profile.SCHEMA) or
            self.schema_version != work_profile.SCHEMA_VERSION or
            !std.mem.eql(u8, self.counter_semantics, WORK_COUNTER_SEMANTICS) or
            self.authority != .instrumented_exact or
            self.source_mask != work_profile.ALL_SOURCE_BITS or
            self.record_count == 0 or
            self.producer_ledger_schema_version !=
                work_profile.PRODUCER_LEDGER_SCHEMA_VERSION or
            !self.producer_coverage_terminal_sealed or
            self.profile_sha256.len != @sizeOf(work_profile.Digest) * 2)
        {
            return error.InvalidExactWorkProfile;
        }
        var digest: work_profile.Digest = undefined;
        _ = std.fmt.hexToBytes(&digest, self.profile_sha256) catch
            return error.InvalidExactWorkProfile;
        const canonical_hex = std.fmt.bytesToHex(digest, .lower);
        if (!std.mem.eql(u8, self.profile_sha256, &canonical_hex))
            return error.InvalidExactWorkProfile;
        const profile = work_profile.Profile{
            .authority = self.authority,
            .source_mask = .{ .bits = self.source_mask },
            .producer_ledger = .{
                .schema_version = self.producer_ledger_schema_version,
                .expected = self.expected_producer_counts,
                .completed = self.completed_producer_counts,
                .terminal_sealed = self.producer_coverage_terminal_sealed,
            },
            .counters = .{
                .field_additions = self.field_additions,
                .field_multiplications = self.field_multiplications,
                .field_inversions = self.field_inversions,
                .fft_butterflies = self.fft_butterflies,
                .fri_folds = self.fri_folds,
                .merkle_compressions = self.merkle_compressions,
            },
            .record_count = self.record_count,
            .profile_digest = digest,
        };
        profile.validate() catch return error.InvalidExactWorkProfile;
        if (!profile.completeExact()) return error.InvalidExactWorkProfile;
    }

    fn deinit(self: *WorkProfileReport, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.profile_sha256));
        self.* = undefined;
    }
};

/// A profile is present only for explicitly profiled attempts. The duration is
/// always a raw monotonic integer and is sampled before this owned snapshot is
/// allocated, so profile copying and report rendering are outside the request.
pub const Attempt = struct {
    schema: []const u8,
    status: Status,
    sample_index: u64,
    timing_partition: []const u8,
    protocol_partition_complete: bool,
    witness_materialization_regions: u64,
    guest_execution_ns: u64,
    witness_materialization_ns: u64,
    proving_ns: u64,
    proving_including_witness_ns: u64,
    native_verification_ns: u64,
    verified_request_ns: u64,
    task_profile: ?task_profile.TaskProfile,
    work_profile: ?WorkProfileReport = null,

    pub const Status = enum { verified };

    pub fn capture(
        allocator: std.mem.Allocator,
        sample_index: usize,
        guest_execution_ns: u64,
        witness_materialization_ns: u64,
        proving_ns: u64,
        native_verification_ns: u64,
        recorder: ?*stage_profile.Recorder,
    ) !Attempt {
        const encoded_sample_index = std.math.cast(u64, sample_index) orelse
            return error.ProfileSampleIndexOverflow;
        const proving_including_witness_ns = try std.math.add(
            u64,
            witness_materialization_ns,
            proving_ns,
        );
        const proving_boundary_ns = try std.math.add(
            u64,
            guest_execution_ns,
            proving_including_witness_ns,
        );
        const verified_request_ns = try std.math.add(
            u64,
            proving_boundary_ns,
            native_verification_ns,
        );
        var profile: ?task_profile.TaskProfile = if (recorder) |active|
            try active.taskSnapshot(allocator)
        else
            null;
        errdefer if (profile) |*owned| owned.deinit(allocator);
        if (recorder) |active| if (active.workCaptureRecorder()) |work| {
            _ = try work.finalizePlannedProducerCoverage();
        };
        var work_report: ?WorkProfileReport = if (recorder) |active| work: {
            const snapshot = try active.workSnapshot();
            break :work if (snapshot.completeExact())
                try WorkProfileReport.initAlloc(allocator, &snapshot)
            else
                null;
        } else null;
        errdefer if (work_report) |*owned| owned.deinit(allocator);
        var attempt = Attempt{
            .schema = if (work_report != null) EXACT_WORK_SCHEMA else SCHEMA,
            .status = .verified,
            .sample_index = encoded_sample_index,
            .timing_partition = TIMING_PARTITION,
            .protocol_partition_complete = true,
            .witness_materialization_regions = proof_phase_meter.REGION_COUNT,
            .guest_execution_ns = guest_execution_ns,
            .witness_materialization_ns = witness_materialization_ns,
            .proving_ns = proving_ns,
            .proving_including_witness_ns = proving_including_witness_ns,
            .native_verification_ns = native_verification_ns,
            .verified_request_ns = verified_request_ns,
            .task_profile = profile,
            .work_profile = work_report,
        };
        try attempt.validate();
        return attempt;
    }

    pub fn validate(self: *const Attempt) !void {
        if ((self.work_profile == null and !std.mem.eql(u8, self.schema, SCHEMA)) or
            (self.work_profile != null and
                !std.mem.eql(u8, self.schema, EXACT_WORK_SCHEMA)))
        {
            return error.InvalidVerifiedRequestSchema;
        }
        if (!self.protocol_partition_complete)
            return error.IncompleteProtocolPartition;
        if (self.witness_materialization_regions != proof_phase_meter.REGION_COUNT)
            return error.InvalidWitnessMaterializationRegionCount;
        const expected_proving_boundary_ns = try std.math.add(
            u64,
            self.witness_materialization_ns,
            self.proving_ns,
        );
        if (self.proving_including_witness_ns != expected_proving_boundary_ns)
            return error.ProvingPartitionMismatch;
        const proving_boundary_ns = try std.math.add(
            u64,
            self.guest_execution_ns,
            self.proving_including_witness_ns,
        );
        const expected_request_ns = try std.math.add(
            u64,
            proving_boundary_ns,
            self.native_verification_ns,
        );
        if (expected_request_ns == 0) return error.EmptyVerifiedRequestDuration;
        if (self.verified_request_ns != expected_request_ns) {
            return error.VerifiedRequestPartitionMismatch;
        }
        if (self.task_profile) |owned| {
            if (owned.schema_version != task_profile.TASK_PROFILE_SCHEMA_VERSION) {
                return error.UnsupportedTaskProfileSchema;
            }
            for (owned.graphs) |graph| {
                if (graph.summary.graph_elapsed_ns > self.proving_including_witness_ns) {
                    return error.TaskGraphElapsedExceedsProofBoundary;
                }
                if (graph.summary.admitted_workers == 1 and
                    graph.summary.parallel_eligible_ns > self.proving_including_witness_ns)
                {
                    return error.SingleWorkerParallelEligibleExceedsProofBoundary;
                }
            }
        }
        if (self.work_profile) |*work| try work.validate();
    }

    pub fn deinit(self: *Attempt, allocator: std.mem.Allocator) void {
        if (self.task_profile) |*profile| profile.deinit(allocator);
        if (self.work_profile) |*work| work.deinit(allocator);
        self.* = undefined;
    }
};

pub fn requireProfiled(attempt: ?*const Attempt, sample_index: usize) !void {
    const bound = attempt orelse return error.MissingProfiledVerifiedRequestAttempt;
    const encoded_sample_index = std.math.cast(u64, sample_index) orelse
        return error.InvalidProfiledVerifiedRequestAttempt;
    if ((!std.mem.eql(u8, bound.schema, SCHEMA) and
        !std.mem.eql(u8, bound.schema, EXACT_WORK_SCHEMA)) or
        !std.mem.eql(u8, bound.timing_partition, TIMING_PARTITION) or
        bound.sample_index != encoded_sample_index or
        bound.task_profile == null)
    {
        return error.InvalidProfiledVerifiedRequestAttempt;
    }
    bound.validate() catch return error.InvalidProfiledVerifiedRequestAttempt;
}

test "profiled benchmark timing authority is protocol complete" {
    const authority = BenchmarkTimingAuthority{};
    try std.testing.expectEqualStrings("monotonic", authority.clock);
    try std.testing.expectEqualStrings("nanoseconds", authority.unit);
    try std.testing.expectEqualStrings("protocol_complete", authority.partition);
    try std.testing.expect(authority.protocol_partition_complete);
    try std.testing.expectEqual(
        proof_phase_meter.REGION_COUNT,
        authority.witness_materialization_regions,
    );
}

test "verified request attempt: disabled capture allocates no task profile" {
    var empty: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&empty);
    var attempt = try Attempt.capture(fixed.allocator(), 3, 5, 2, 5, 5, null);
    defer attempt.deinit(fixed.allocator());

    try std.testing.expectEqual(@as(u64, 3), attempt.sample_index);
    try std.testing.expectEqual(@as(u64, 17), attempt.verified_request_ns);
    try std.testing.expect(attempt.task_profile == null);
}

test "verified request attempt: schema binds duration beside task profile" {
    var no_graphs: [0]task_profile.GraphRecord = .{};
    const attempt = Attempt{
        .schema = SCHEMA,
        .status = .verified,
        .sample_index = 4,
        .timing_partition = TIMING_PARTITION,
        .protocol_partition_complete = true,
        .witness_materialization_regions = proof_phase_meter.REGION_COUNT,
        .guest_execution_ns = 3,
        .witness_materialization_ns = 4,
        .proving_ns = 7,
        .proving_including_witness_ns = 11,
        .native_verification_ns = 9,
        .verified_request_ns = 23,
        .task_profile = .{
            .runtime = "ReleaseFast",
            .example = "riscv",
            .graphs = &no_graphs,
        },
    };
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, attempt, .{
        .emit_null_optional_fields = false,
    });
    defer std.testing.allocator.free(encoded);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings(SCHEMA, object.get("schema").?.string);
    try std.testing.expectEqualStrings("verified", object.get("status").?.string);
    try std.testing.expectEqual(@as(i64, 4), object.get("sample_index").?.integer);
    try std.testing.expect(object.get("protocol_partition_complete").?.bool);
    try std.testing.expectEqual(
        @as(i64, proof_phase_meter.REGION_COUNT),
        object.get("witness_materialization_regions").?.integer,
    );
    try std.testing.expectEqualStrings(
        TIMING_PARTITION,
        object.get("timing_partition").?.string,
    );
    try std.testing.expectEqual(@as(i64, 3), object.get("guest_execution_ns").?.integer);
    try std.testing.expectEqual(
        @as(i64, 4),
        object.get("witness_materialization_ns").?.integer,
    );
    try std.testing.expectEqual(@as(i64, 7), object.get("proving_ns").?.integer);
    try std.testing.expectEqual(
        @as(i64, 11),
        object.get("proving_including_witness_ns").?.integer,
    );
    try std.testing.expectEqual(
        @as(i64, 9),
        object.get("native_verification_ns").?.integer,
    );
    try std.testing.expectEqual(@as(i64, 23), object.get("verified_request_ns").?.integer);
    try std.testing.expect(object.get("task_profile").? == .object);
    try std.testing.expect(!object.contains("work_profile"));
    try requireProfiled(&attempt, 4);
    try std.testing.expectError(
        error.InvalidProfiledVerifiedRequestAttempt,
        requireProfiled(&attempt, 5),
    );
    var wrong_task_schema = attempt;
    wrong_task_schema.task_profile.?.schema_version += 1;
    try std.testing.expectError(
        error.InvalidProfiledVerifiedRequestAttempt,
        requireProfiled(&wrong_task_schema, 4),
    );
    try std.testing.expectError(
        error.MissingProfiledVerifiedRequestAttempt,
        requireProfiled(null, 4),
    );
}

test "verified request attempt: complete exact work promotes v3 transactionally" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.initWithOptions(
        allocator,
        "ReleaseFast",
        "riscv",
        .{ .capture_tasks = true, .capture_work = true },
    );
    defer recorder.deinit();
    const work = recorder.workCaptureRecorder() orelse unreachable;
    try work.expectProducer(.main_witness_field);
    try work.recordCompletedDelta(.{
        .site = .main_witness_field,
        .producer = .field_operations,
        .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
            work_profile.SourceMask.one(.field_multiplications).bits |
            work_profile.SourceMask.one(.field_inversions).bits },
        .counters = .{
            .field_additions = 10_001,
            .field_multiplications = 8_003,
            .field_inversions = 17,
        },
    });
    try work.expectProducer(.fri_protocol);
    try work.recordCompletedDelta(.{
        .site = .fri_protocol,
        .producer = .fri_protocol,
        .source_mask = .{ .bits = work_profile.SourceMask.one(.fft_butterflies).bits |
            work_profile.SourceMask.one(.fri_folds).bits |
            work_profile.SourceMask.one(.merkle_compressions).bits },
        .counters = .{
            .fft_butterflies = 4_096,
            .fri_folds = 2_048,
            .merkle_compressions = 1_023,
        },
    });
    try work.finalizeFieldCoverage();

    var attempt = try Attempt.capture(allocator, 0, 8, 5, 8, 8, &recorder);
    defer attempt.deinit(allocator);
    try std.testing.expectEqualStrings(EXACT_WORK_SCHEMA, attempt.schema);
    const exact = &attempt.work_profile.?;
    try exact.validate();
    try std.testing.expectEqual(work_profile.ALL_SOURCE_BITS, exact.source_mask);
    try std.testing.expectEqual(@as(u64, 4_096), exact.fft_butterflies);
    try requireProfiled(&attempt, 0);

    const encoded = try std.json.Stringify.valueAlloc(allocator, attempt, .{
        .emit_null_optional_fields = false,
    });
    defer allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings(
        EXACT_WORK_SCHEMA,
        object.get("schema").?.string,
    );
    const work_object = object.get("work_profile").?.object;
    try std.testing.expectEqualStrings(
        work_profile.SCHEMA,
        work_object.get("schema").?.string,
    );
    try std.testing.expectEqual(
        @as(i64, work_profile.ALL_SOURCE_BITS),
        work_object.get("source_mask").?.integer,
    );

    var malformed = attempt;
    var wrong_digest = [_]u8{'0'} ** (@sizeOf(work_profile.Digest) * 2);
    malformed.work_profile.?.profile_sha256 = &wrong_digest;
    try std.testing.expectError(error.InvalidExactWorkProfile, malformed.validate());
}

test "verified request attempt: profiled capture cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseProfiledCapture,
        .{},
    );
}

fn exerciseProfiledCapture(allocator: std.mem.Allocator) !void {
    var recorder = stage_profile.Recorder.init(allocator, "ReleaseFast", "riscv");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraph(1, 1);
    defer pending.deinit();
    pending.events[0] = .{
        .stage_id = "composition",
        .component_kind = "opcode",
        .terminal_status = .completed,
    };
    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "composition" },
        .{ .planned_tasks = 1 },
    );

    var attempt = try Attempt.capture(allocator, 0, 8, 5, 8, 8, &recorder);
    defer attempt.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), attempt.task_profile.?.graphs.len);
}

test "verified request attempt: snapshot ownership outlives recorder storage" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "ReleaseFast", "riscv");
    var pending = try recorder.reserveTaskGraph(1, 1);
    pending.events[0] = .{
        .stage_id = "composition",
        .component_kind = "opcode",
        .terminal_status = .completed,
    };
    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "composition" },
        .{ .planned_tasks = 1 },
    );

    var attempt = try Attempt.capture(allocator, 0, 9, 5, 9, 8, &recorder);
    recorder.deinit();
    defer attempt.deinit(allocator);

    const profile = attempt.task_profile.?;
    try std.testing.expectEqualStrings("ReleaseFast", profile.runtime);
    try std.testing.expectEqualStrings("riscv", profile.example);
    try std.testing.expectEqualStrings("composition", profile.graphs[0].graph_id);
    try std.testing.expectEqualStrings(
        "opcode",
        profile.graphs[0].events[0].component_kind,
    );
}

test "verified request attempt: graph elapsed time cannot exceed proof boundary" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "ReleaseFast", "riscv");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraph(0, 0);
    defer pending.deinit();
    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "composition" },
        .{ .graph_elapsed_ns = 18 },
    );

    try std.testing.expectError(
        error.TaskGraphElapsedExceedsProofBoundary,
        Attempt.capture(allocator, 0, 5, 2, 5, 5, &recorder),
    );
}

test "verified request attempt: single-worker eligibility is request bounded" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "ReleaseFast", "riscv");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraph(0, 0);
    defer pending.deinit();
    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "composition" },
        .{
            .admitted_workers = 1,
            .graph_elapsed_ns = 6,
            .parallel_eligible_ns = 18,
        },
    );

    try std.testing.expectError(
        error.SingleWorkerParallelEligibleExceedsProofBoundary,
        Attempt.capture(allocator, 0, 5, 2, 5, 5, &recorder),
    );
}

test "verified request attempt: raw phase sum is checked exactly" {
    const seed = Attempt{
        .schema = SCHEMA,
        .status = .verified,
        .sample_index = 0,
        .timing_partition = TIMING_PARTITION,
        .protocol_partition_complete = true,
        .witness_materialization_regions = proof_phase_meter.REGION_COUNT,
        .guest_execution_ns = 3,
        .witness_materialization_ns = 2,
        .proving_ns = 3,
        .proving_including_witness_ns = 5,
        .native_verification_ns = 7,
        .verified_request_ns = 14,
        .task_profile = null,
    };
    var malformed = seed;
    try std.testing.expectError(
        error.VerifiedRequestPartitionMismatch,
        malformed.validate(),
    );
    malformed = seed;
    malformed.verified_request_ns = 15;
    malformed.proving_including_witness_ns = 4;
    try std.testing.expectError(
        error.ProvingPartitionMismatch,
        malformed.validate(),
    );
    malformed = seed;
    malformed.verified_request_ns = 15;
    malformed.protocol_partition_complete = false;
    try std.testing.expectError(
        error.IncompleteProtocolPartition,
        malformed.validate(),
    );
    malformed = seed;
    malformed.verified_request_ns = 15;
    malformed.witness_materialization_regions -= 1;
    try std.testing.expectError(
        error.InvalidWitnessMaterializationRegionCount,
        malformed.validate(),
    );
    try std.testing.expectError(
        error.Overflow,
        Attempt.capture(
            std.testing.allocator,
            0,
            std.math.maxInt(u64),
            1,
            1,
            1,
            null,
        ),
    );
}
