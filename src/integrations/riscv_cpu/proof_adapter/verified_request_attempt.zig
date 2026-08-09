//! Owned binding between one successfully verified request and its flat task profile.

const std = @import("std");
const stwo = @import("stwo");

const stage_profile = stwo.prover.stage_profile;
const task_profile = stwo.prover.task_profile;

pub const SCHEMA = "riscv_verified_request_attempt_v1";
pub const PROFILED_BENCHMARK_SCHEMA = "riscv_profiled_proof_v1";
pub const TIMING_PARTITION =
    "development_coarse:guest_execution+proving_including_witness+" ++
    "native_verification;proof_serialization_excluded";

/// Declares which duration is authoritative in the additive profiled benchmark
/// schema. Legacy seconds-valued aggregates remain present for compatibility,
/// but must not be substituted for the per-attempt monotonic integers.
pub const BenchmarkTimingAuthority = struct {
    clock: []const u8 = "monotonic",
    unit: []const u8 = "nanoseconds",
    partition: []const u8 = "development_coarse",
    protocol_partition_complete: bool = false,
    authoritative_samples: []const u8 =
        "verified_request_attempts[*].verified_request_ns",
    legacy_outer_samples: []const u8 =
        "sample_seconds_and_median_seconds_are_non_authoritative_compatibility_fields",
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
    guest_execution_ns: u64,
    proving_including_witness_ns: u64,
    native_verification_ns: u64,
    verified_request_ns: u64,
    task_profile: ?task_profile.TaskProfile,

    pub const Status = enum { verified };

    pub fn capture(
        allocator: std.mem.Allocator,
        sample_index: usize,
        guest_execution_ns: u64,
        proving_including_witness_ns: u64,
        native_verification_ns: u64,
        recorder: ?*const stage_profile.Recorder,
    ) !Attempt {
        const encoded_sample_index = std.math.cast(u64, sample_index) orelse
            return error.ProfileSampleIndexOverflow;
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
        var attempt = Attempt{
            .schema = SCHEMA,
            .status = .verified,
            .sample_index = encoded_sample_index,
            .timing_partition = TIMING_PARTITION,
            .protocol_partition_complete = false,
            .guest_execution_ns = guest_execution_ns,
            .proving_including_witness_ns = proving_including_witness_ns,
            .native_verification_ns = native_verification_ns,
            .verified_request_ns = verified_request_ns,
            .task_profile = profile,
        };
        try attempt.validate();
        return attempt;
    }

    pub fn validate(self: *const Attempt) !void {
        if (self.protocol_partition_complete) {
            return error.UnexpectedCompleteProtocolPartition;
        }
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
                if (graph.summary.graph_elapsed_ns > self.verified_request_ns) {
                    return error.TaskGraphElapsedExceedsVerifiedRequest;
                }
                if (graph.summary.admitted_workers == 1 and
                    graph.summary.parallel_eligible_ns > self.verified_request_ns)
                {
                    return error.SingleWorkerParallelEligibleExceedsVerifiedRequest;
                }
            }
        }
    }

    pub fn deinit(self: *Attempt, allocator: std.mem.Allocator) void {
        if (self.task_profile) |*profile| profile.deinit(allocator);
        self.* = undefined;
    }
};

pub fn requireProfiled(attempt: ?*const Attempt, sample_index: usize) !void {
    const bound = attempt orelse return error.MissingProfiledVerifiedRequestAttempt;
    const encoded_sample_index = std.math.cast(u64, sample_index) orelse
        return error.InvalidProfiledVerifiedRequestAttempt;
    if (!std.mem.eql(u8, bound.schema, SCHEMA) or
        !std.mem.eql(u8, bound.timing_partition, TIMING_PARTITION) or
        bound.sample_index != encoded_sample_index or
        bound.task_profile == null)
    {
        return error.InvalidProfiledVerifiedRequestAttempt;
    }
    bound.validate() catch return error.InvalidProfiledVerifiedRequestAttempt;
}

test "profiled benchmark timing authority stays explicitly development coarse" {
    const authority = BenchmarkTimingAuthority{};
    try std.testing.expectEqualStrings("monotonic", authority.clock);
    try std.testing.expectEqualStrings("nanoseconds", authority.unit);
    try std.testing.expectEqualStrings("development_coarse", authority.partition);
    try std.testing.expect(!authority.protocol_partition_complete);
}

test "verified request attempt: disabled capture allocates no task profile" {
    var empty: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&empty);
    var attempt = try Attempt.capture(fixed.allocator(), 3, 5, 7, 5, null);
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
        .protocol_partition_complete = false,
        .guest_execution_ns = 3,
        .proving_including_witness_ns = 11,
        .native_verification_ns = 9,
        .verified_request_ns = 23,
        .task_profile = .{
            .runtime = "ReleaseFast",
            .example = "riscv",
            .graphs = &no_graphs,
        },
    };
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, attempt, .{});
    defer std.testing.allocator.free(encoded);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings(SCHEMA, object.get("schema").?.string);
    try std.testing.expectEqualStrings("verified", object.get("status").?.string);
    try std.testing.expectEqual(@as(i64, 4), object.get("sample_index").?.integer);
    try std.testing.expect(!object.get("protocol_partition_complete").?.bool);
    try std.testing.expectEqualStrings(
        TIMING_PARTITION,
        object.get("timing_partition").?.string,
    );
    try std.testing.expectEqual(@as(i64, 3), object.get("guest_execution_ns").?.integer);
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
    var pending = try recorder.reserveTaskGraph(1, 0);
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

    var attempt = try Attempt.capture(allocator, 0, 8, 13, 8, &recorder);
    defer attempt.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), attempt.task_profile.?.graphs.len);
}

test "verified request attempt: snapshot ownership outlives recorder storage" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "ReleaseFast", "riscv");
    var pending = try recorder.reserveTaskGraph(1, 0);
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

    var attempt = try Attempt.capture(allocator, 0, 9, 14, 8, &recorder);
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

test "verified request attempt: graph elapsed time cannot exceed request" {
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
        error.TaskGraphElapsedExceedsVerifiedRequest,
        Attempt.capture(allocator, 0, 5, 7, 5, &recorder),
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
            .graph_elapsed_ns = 16,
            .parallel_eligible_ns = 18,
        },
    );

    try std.testing.expectError(
        error.SingleWorkerParallelEligibleExceedsVerifiedRequest,
        Attempt.capture(allocator, 0, 5, 7, 5, &recorder),
    );
}

test "verified request attempt: raw phase sum is checked exactly" {
    const malformed = Attempt{
        .schema = SCHEMA,
        .status = .verified,
        .sample_index = 0,
        .timing_partition = TIMING_PARTITION,
        .protocol_partition_complete = false,
        .guest_execution_ns = 3,
        .proving_including_witness_ns = 5,
        .native_verification_ns = 7,
        .verified_request_ns = 14,
        .task_profile = null,
    };
    try std.testing.expectError(
        error.VerifiedRequestPartitionMismatch,
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
            null,
        ),
    );
}
