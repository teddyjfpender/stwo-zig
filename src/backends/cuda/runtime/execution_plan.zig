//! CUDA compilation of a backend-neutral proof program.

const std = @import("std");
const arena = @import("arena.zig");
const execution_provider = @import("provider.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");
const proof_ir = @import("stwo_backend_contracts").proof_program;

pub const schedule_version: u32 = 2;
pub const graph_schema_version: u32 = 1;

pub const CompileOptions = struct {
    provider: execution_provider.Kind = .nvidia_cuda,
    sm: u32,
    device_uuid: [16]u8,
    driver_version: u32,
    runtime_version: u32,
    toolkit_version: u32,
    runtime_build_identity: proof_ir.Digest,
    host_toolchain_identity: proof_ir.Digest,
    kernel_pack_identity: proof_ir.Digest,
    lane_streams: u8,
    enable_graphs: bool,
    schedule_schema_version: u32 = schedule_version,
    graph_schema_version: u32 = graph_schema_version,

    pub fn validate(self: CompileOptions) Error!void {
        if (self.sm < 50 or
            std.mem.allEqual(u8, &self.device_uuid, 0) or
            self.driver_version == 0 or
            self.runtime_version == 0 or
            self.toolkit_version == 0 or
            digestEmpty(self.runtime_build_identity) or
            digestEmpty(self.host_toolchain_identity) or
            digestEmpty(self.kernel_pack_identity) or
            self.lane_streams > max_lane_streams or
            self.schedule_schema_version == 0 or
            self.graph_schema_version == 0)
        {
            return error.InvalidCompileTarget;
        }
    }
};

// Production currently owns only the coordination stream. Keep lane admission
// closed until the executor has real stream handles, dependency events, and
// hardware evidence for overlap. A planned lane index that is ignored at
// execution time is a false performance claim.
pub const max_lane_streams: u8 = 0;

pub const ScheduledNode = struct {
    node_id: u32,
    kind: proof_ir.OperationKind,
    stage: telemetry.Stage,
    stream_index: u8,
    graph_region: u32,
    graph_candidate: bool,
    dependency_count: u32,
};

pub const Prediction = struct {
    request_bytes: u64,
    persistent_bytes: u64,
    bytes_read: u64,
    bytes_written: u64,
    field_operations: u64,
    hash_compressions: u64,
    minimum_launches: u64,
    transcript_barriers: u32,
    request_buffers: u32,
    persistent_buffers: u32,
};

pub const Error = error{
    EmptyRequestArena,
    InvalidCompileTarget,
    SizeOverflow,
};

pub const CudaPlan = struct {
    program_digest: proof_ir.Digest,
    cache_key: proof_ir.Digest,
    target: CompileOptions,
    schedule: []ScheduledNode,
    arena_plan: arena.Plan,
    prediction: Prediction,

    pub fn compile(
        allocator: std.mem.Allocator,
        program: proof_ir.ProofProgram,
        options: CompileOptions,
    ) (std.mem.Allocator.Error || proof_ir.Error || runtime_error.Error || Error)!CudaPlan {
        return compileDiagnosed(allocator, program, options, null);
    }

    /// Only pure backend-owned program admission supplies a diagnostic. Device,
    /// compile-target, planner and allocation errors remain outside that origin.
    pub fn compileDiagnosed(
        allocator: std.mem.Allocator,
        program: proof_ir.ProofProgram,
        options: CompileOptions,
        failure: ?*?@import("stwo_core").error_codes.Entry,
    ) (std.mem.Allocator.Error || proof_ir.Error || runtime_error.Error || Error)!CudaPlan {
        try program.validateDiagnosed(failure);
        try options.validate();

        var requirements: std.ArrayList(arena.Requirement) = .empty;
        defer requirements.deinit(allocator);
        var prediction = Prediction{
            .request_bytes = 0,
            .persistent_bytes = 0,
            .bytes_read = 0,
            .bytes_written = 0,
            .field_operations = 0,
            .hash_compressions = 0,
            .minimum_launches = 0,
            .transcript_barriers = @intCast(program.transcript.len),
            .request_buffers = 0,
            .persistent_buffers = 0,
        };
        for (program.buffers) |buffer| {
            const bytes = std.math.mul(u64, buffer.words, @sizeOf(u32)) catch
                return error.SizeOverflow;
            switch (buffer.storage) {
                .request_local => {
                    const words = std.math.cast(usize, buffer.words) orelse
                        return error.SizeOverflow;
                    try requirements.append(allocator, .{
                        .id = buffer.id,
                        .words = words,
                        .alignment_words = buffer.alignment_words,
                        .live_from = stage(buffer.live_from),
                        .live_through = stage(buffer.live_through),
                    });
                    prediction.request_buffers += 1;
                },
                .process_cache => {
                    prediction.persistent_bytes = add(
                        prediction.persistent_bytes,
                        bytes,
                    ) catch return error.SizeOverflow;
                    prediction.persistent_buffers += 1;
                },
            }
        }
        if (requirements.items.len == 0) return error.EmptyRequestArena;

        var arena_plan = try arena.Plan.init(allocator, requirements.items);
        errdefer arena_plan.deinit(allocator);
        prediction.request_bytes = std.math.mul(
            u64,
            arena_plan.total_words,
            @sizeOf(u32),
        ) catch return error.SizeOverflow;

        const schedule = try allocator.alloc(ScheduledNode, program.nodes.len);
        errdefer allocator.free(schedule);
        var graph_region: u32 = 0;
        for (program.nodes, 0..) |node, index| {
            schedule[index] = .{
                .node_id = node.id,
                .kind = node.kind,
                .stage = stage(node.stage),
                .stream_index = streamFor(node, options.lane_streams),
                .graph_region = graph_region,
                .graph_candidate = options.enable_graphs and
                    node.graph_candidate,
                .dependency_count = node.dependencies.count,
            };
            prediction.bytes_read = add(
                prediction.bytes_read,
                node.work.bytes_read,
            ) catch return error.SizeOverflow;
            prediction.bytes_written = add(
                prediction.bytes_written,
                node.work.bytes_written,
            ) catch return error.SizeOverflow;
            prediction.field_operations = add(
                prediction.field_operations,
                node.work.field_operations,
            ) catch return error.SizeOverflow;
            prediction.hash_compressions = add(
                prediction.hash_compressions,
                node.work.hash_compressions,
            ) catch return error.SizeOverflow;
            prediction.minimum_launches = add(
                prediction.minimum_launches,
                node.work.minimum_launches,
            ) catch return error.SizeOverflow;
            if (hasBarrierAt(program.transcript, node.id)) {
                graph_region = std.math.add(u32, graph_region, 1) catch
                    return error.SizeOverflow;
            }
        }

        return .{
            .program_digest = program.program_digest,
            .cache_key = cacheKey(program.program_digest, options),
            .target = options,
            .schedule = schedule,
            .arena_plan = arena_plan,
            .prediction = prediction,
        };
    }

    pub fn deinit(
        self: *CudaPlan,
        allocator: std.mem.Allocator,
    ) void {
        self.arena_plan.deinit(allocator);
        allocator.free(self.schedule);
        self.* = undefined;
    }

    pub fn instantiateArenaPlan(
        self: *const CudaPlan,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!arena.Plan {
        return self.arena_plan.clone(allocator);
    }
};

pub fn cacheKey(
    program_digest: proof_ir.Digest,
    options: CompileOptions,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-cuda-plan-v2");
    hash.update(&program_digest);
    hashInt(&hash, u8, @intFromEnum(options.provider));
    hash.update(&options.device_uuid);
    hash.update(&options.runtime_build_identity);
    hash.update(&options.host_toolchain_identity);
    hash.update(&options.kernel_pack_identity);
    hashInt(&hash, u32, options.sm);
    hashInt(&hash, u32, options.driver_version);
    hashInt(&hash, u32, options.runtime_version);
    hashInt(&hash, u32, options.toolkit_version);
    hashInt(&hash, u8, options.lane_streams);
    hashInt(&hash, u8, @intFromBool(options.enable_graphs));
    hashInt(&hash, u32, options.schedule_schema_version);
    hashInt(&hash, u32, options.graph_schema_version);
    var digest: proof_ir.Digest = undefined;
    hash.final(&digest);
    return digest;
}

fn streamFor(node: proof_ir.Node, lane_streams: u8) u8 {
    _ = node;
    std.debug.assert(lane_streams == 0);
    return 0;
}

fn hasBarrierAt(
    barriers: []const proof_ir.TranscriptBarrier,
    node_id: u32,
) bool {
    for (barriers) |barrier| {
        if (barrier.node == node_id) return true;
    }
    return false;
}

fn stage(value: proof_ir.Stage) telemetry.Stage {
    return switch (value) {
        .ingress => .ingress,
        .trace_generation => .trace_generation,
        .trace_commit => .trace_commit,
        .constraint_evaluation => .constraint_evaluation,
        .oods => .oods,
        .quotient => .quotient,
        .fri_commit => .fri_commit,
        .pow => .pow,
        .decommit => .decommit,
        .proof_assembly => .proof_assembly,
    };
}

fn digestEmpty(digest: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &digest, 0);
}

fn add(left: u64, right: anytype) error{Overflow}!u64 {
    const rhs = std.math.cast(u64, right) orelse return error.Overflow;
    return std.math.add(u64, left, rhs) catch error.Overflow;
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "CUDA planning binds target identity and rejects unimplemented lanes" {
    const allocator = std.testing.allocator;
    var program = try testProgram(allocator);
    defer program.deinit(allocator);
    const identity = proof_ir.identityDigest("runtime");
    const options = CompileOptions{
        .sm = 89,
        .device_uuid = [_]u8{0x42} ** 16,
        .driver_version = 12080,
        .runtime_version = 12080,
        .toolkit_version = 12080,
        .runtime_build_identity = identity,
        .host_toolchain_identity = proof_ir.identityDigest("zig-0.15.2"),
        .kernel_pack_identity = proof_ir.identityDigest("pack"),
        .lane_streams = 0,
        .enable_graphs = true,
    };
    var plan = try CudaPlan.compile(allocator, program, options);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), plan.schedule.len);
    try std.testing.expectEqual(@as(u8, 0), plan.schedule[0].stream_index);
    try std.testing.expectEqual(@as(u8, 0), plan.schedule[1].stream_index);
    try std.testing.expectEqual(@as(u64, 256), plan.prediction.request_bytes);
    try std.testing.expectEqual(@as(u64, 2), plan.prediction.minimum_launches);
    try std.testing.expectEqual(@as(u32, 1), plan.prediction.transcript_barriers);

    var unsupported_lanes = options;
    unsupported_lanes.lane_streams = 1;
    try std.testing.expectError(
        error.InvalidCompileTarget,
        CudaPlan.compile(allocator, program, unsupported_lanes),
    );

    var changed = options;
    changed.sm = 90;
    try std.testing.expect(!std.mem.eql(
        u8,
        &plan.cache_key,
        &cacheKey(program.program_digest, changed),
    ));
    const identity_variants = [_]CompileOptions{
        changedOptions(options, .provider),
        changedOptions(options, .device_uuid),
        changedOptions(options, .driver_version),
        changedOptions(options, .runtime_version),
        changedOptions(options, .toolkit_version),
        changedOptions(options, .runtime_build),
        changedOptions(options, .host_toolchain),
        changedOptions(options, .kernel_pack),
        changedOptions(options, .schedule_schema),
        changedOptions(options, .graph_schema),
    };
    for (identity_variants) |identity_changed| {
        try std.testing.expect(!std.mem.eql(
            u8,
            &plan.cache_key,
            &cacheKey(program.program_digest, identity_changed),
        ));
    }

    var resource_changed = try testProgramWithGraph(
        allocator,
        .native,
        false,
    );
    defer resource_changed.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &program.semantic_digest,
        &resource_changed.semantic_digest,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &plan.cache_key,
        &cacheKey(resource_changed.program_digest, options),
    ));
}

const ChangedIdentity = enum {
    provider,
    device_uuid,
    driver_version,
    runtime_version,
    toolkit_version,
    runtime_build,
    host_toolchain,
    kernel_pack,
    schedule_schema,
    graph_schema,
};

fn changedOptions(
    options: CompileOptions,
    field: ChangedIdentity,
) CompileOptions {
    var changed = options;
    switch (field) {
        .provider => changed.provider = .cumetal,
        .device_uuid => changed.device_uuid[0] ^= 0xff,
        .driver_version => changed.driver_version += 1,
        .runtime_version => changed.runtime_version += 1,
        .toolkit_version => changed.toolkit_version += 1,
        .runtime_build => changed.runtime_build_identity[0] ^= 0xff,
        .host_toolchain => changed.host_toolchain_identity[0] ^= 0xff,
        .kernel_pack => changed.kernel_pack_identity[0] ^= 0xff,
        .schedule_schema => changed.schedule_schema_version += 1,
        .graph_schema => changed.graph_schema_version += 1,
    }
    return changed;
}

fn testProgram(allocator: std.mem.Allocator) !proof_ir.ProofProgram {
    return testProgramWithGraph(allocator, .native, true);
}

fn testProgramWithGraph(
    allocator: std.mem.Allocator,
    frontend: proof_ir.Frontend,
    graph_candidate: bool,
) !proof_ir.ProofProgram {
    const nodes = [_]proof_ir.Node{
        .{
            .id = 0,
            .kind = .trace_generation,
            .stage = .trace_generation,
            .dependencies = .{ .first = 0, .count = 0 },
            .parallelism = .component,
            .graph_candidate = graph_candidate,
            .work = .{
                .bytes_read = 0,
                .bytes_written = 256,
                .field_operations = 64,
                .hash_compressions = 0,
                .minimum_launches = 1,
            },
        },
        .{
            .id = 1,
            .kind = .commitment,
            .stage = .trace_commit,
            .dependencies = .{ .first = 0, .count = 1 },
            .parallelism = .merkle_subtree,
            .graph_candidate = graph_candidate,
            .work = .{
                .bytes_read = 256,
                .bytes_written = 0,
                .field_operations = 0,
                .hash_compressions = 32,
                .minimum_launches = 1,
            },
        },
    };
    return proof_ir.ProofProgram.init(allocator, .{
        .identity = .{
            .frontend = frontend,
            .air = proof_ir.identityDigest("air"),
            .statement = proof_ir.identityDigest("statement"),
            .protocol = proof_ir.identityDigest("protocol"),
        },
        .trace_columns = &.{.{
            .id = 0,
            .component = 0,
            .ordinal = 0,
            .log_rows = 8,
            .role = .main,
        }},
        .constraints = &.{.{
            .id = 0,
            .component = 0,
            .expression = proof_ir.identityDigest("constraint"),
            .constraint_count = 1,
            .max_degree_log = 1,
        }},
        .commitments = &.{.{
            .id = 0,
            .role = .main,
            .first_column = 0,
            .column_count = 1,
            .evaluation_log_rows = 9,
            .log_rows_per_leaf = 9,
            .retain_openings = true,
        }},
        .transcript = &.{.{
            .ordinal = 0,
            .node = 1,
            .phase = 0,
            .kind = .challenge,
            .value_count = 1,
        }},
        .quotient = .{
            .term_count = 1,
            .group_count = 1,
            .evaluation_log_rows = 9,
            .composition_degree_log = 1,
        },
        .fri_layers = &.{.{
            .tree_id = 0,
            .evaluation_log_rows = 9,
            .fold_step = 1,
            .cumulative_fold = 0,
            .log_rows_per_leaf = 9,
        }},
        .buffers = &.{.{
            .id = 1,
            .words = 64,
            .alignment_words = 1,
            .live_from = .trace_generation,
            .live_through = .decommit,
            .storage = .request_local,
            .immutable = false,
        }},
        .nodes = &nodes,
        .dependency_ids = &.{0},
    });
}

/// Deterministic fixtures shared by backend integration-contract tests.
pub const testing = struct {
    pub fn program(
        allocator: std.mem.Allocator,
        frontend: proof_ir.Frontend,
    ) !proof_ir.ProofProgram {
        return testProgramWithGraph(allocator, frontend, true);
    }

    pub fn target(kind: execution_provider.Kind) CompileOptions {
        const identity = proof_ir.identityDigest("runtime");
        return .{
            .provider = kind,
            .sm = 80,
            .device_uuid = [_]u8{0x42} ** 16,
            .driver_version = 12080,
            .runtime_version = 12080,
            .toolkit_version = 12080,
            .runtime_build_identity = identity,
            .host_toolchain_identity = proof_ir.identityDigest("toolchain"),
            .kernel_pack_identity = proof_ir.identityDigest("pack"),
            .lane_streams = 0,
            .enable_graphs = false,
        };
    }
};

test "CUDA host program admission retains legacy plans and foreign allocation failures unmapped" {
    const a = std.testing.allocator;
    const codes = @import("stwo_backend_contracts").error_codes;
    var program = try testing.program(a, .native);
    defer program.deinit(a);
    const options = testing.target(.nvidia_cuda);
    var legacy = try CudaPlan.compile(a, program, options);
    defer legacy.deinit(a);
    var failure: ?@import("stwo_core").error_codes.Entry = codes.fromProofProgram(error.EmptyTrace);
    var diagnosed = try CudaPlan.compileDiagnosed(a, program, options, &failure);
    defer diagnosed.deinit(a);
    try std.testing.expect(failure == null);
    try std.testing.expectEqualSlices(u8, &legacy.cache_key, &diagnosed.cache_key);
    try std.testing.expectEqualDeep(legacy.schedule, diagnosed.schedule);
    try std.testing.expectEqualDeep(legacy.prediction, diagnosed.prediction);
    try std.testing.expectEqual(legacy.arena_plan.total_words, diagnosed.arena_plan.total_words);
    var target = options;
    target.sm = 0;
    failure = codes.fromProofProgram(error.EmptyTrace);
    try std.testing.expectError(error.InvalidCompileTarget, CudaPlan.compileDiagnosed(a, program, target, &failure));
    try std.testing.expect(failure == null);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, admitted: proof_ir.ProofProgram, selected: CompileOptions) !void {
            var detail: ?@import("stwo_core").error_codes.Entry = null;
            var result = CudaPlan.compileDiagnosed(allocator, admitted, selected, &detail) catch |err| {
                try std.testing.expect(detail == null);
                return err;
            };
            defer result.deinit(allocator);
            try std.testing.expect(detail == null);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{ program, options });
}

test "CUDA host compiler rejects physical malformed program origins with stable codes" {
    const a = std.testing.allocator;
    var program = try testing.program(a, .native);
    defer program.deinit(a);
    const options = testing.target(.nvidia_cuda);
    const errors = [_]proof_ir.Error{ error.DuplicateBuffer, error.DuplicateColumn, error.EmptyCommitmentSet, error.EmptyConstraintSet, error.EmptyExecutionGraph, error.EmptyIdentity, error.EmptyTrace, error.InvalidBuffer, error.InvalidCommitment, error.InvalidConstraint, error.InvalidDependency, error.InvalidFriSchedule, error.InvalidNode, error.InvalidNativeAir, error.InvalidQuotientSchedule, error.InvalidTranscript };
    for (errors, 0..) |expected, index| {
        var bad = program;
        var buffers = [_]proof_ir.Buffer{program.buffers[0]} ** 2;
        var columns = [_]proof_ir.TraceColumn{program.trace_columns[0]} ** 2;
        var commitments = [_]proof_ir.CommitmentTree{program.commitments[0]};
        var constraints = [_]proof_ir.ConstraintProgram{program.constraints[0]};
        var nodes = [_]proof_ir.Node{ program.nodes[0], program.nodes[1] };
        var layers = [_]proof_ir.FriLayer{program.fri_layers[0]};
        var transcript = [_]proof_ir.TranscriptBarrier{program.transcript[0]};
        switch (expected) {
            error.DuplicateBuffer => bad.buffers = &buffers,
            error.DuplicateColumn => {
                columns[1].id = 1;
                bad.trace_columns = &columns;
            },
            error.EmptyCommitmentSet => bad.commitments = &.{},
            error.EmptyConstraintSet => bad.constraints = &.{},
            error.EmptyExecutionGraph => bad.nodes = &.{},
            error.EmptyIdentity => bad.identity.air = @splat(0),
            error.EmptyTrace => bad.trace_columns = &.{},
            error.InvalidBuffer => {
                buffers[0].words = 0;
                bad.buffers = buffers[0..1];
            },
            error.InvalidCommitment => {
                commitments[0].evaluation_log_rows = 0;
                bad.commitments = &commitments;
            },
            error.InvalidConstraint => {
                constraints[0].constraint_count = 0;
                bad.constraints = &constraints;
            },
            error.InvalidDependency => {
                nodes[1].dependencies.count = 2;
                bad.nodes = &nodes;
            },
            error.InvalidFriSchedule => {
                layers[0].fold_step = 0;
                bad.fri_layers = &layers;
            },
            error.InvalidNode => {
                nodes[0].id = 99;
                bad.nodes = &nodes;
            },
            error.InvalidNativeAir => bad.native_air_contract = nativeFixture(),
            error.InvalidQuotientSchedule => bad.quotient.term_count = 0,
            error.InvalidTranscript => {
                transcript[0].value_count = 0;
                bad.transcript = &transcript;
            },
        }
        var failure: ?@import("stwo_core").error_codes.Entry = null;
        try std.testing.expectError(expected, CudaPlan.compile(a, bad, options));
        try std.testing.expectError(expected, CudaPlan.compileDiagnosed(a, bad, options, &failure));
        try std.testing.expectEqual(@as(u16, @intCast(0x2201 + index)), failure.?.code);
    }
}

fn nativeFixture() proof_ir.NativeAirContract {
    return .{
        .geometry = .{ .component = 7, .log_rows = 8, .preprocessed_columns = 0, .main_columns = 2, .interaction_columns = 1 },
        .ingress = .{ .recipe_identity = @splat(1), .layout_abi_identity = @splat(2), .element_count = 768 },
        .statement = .{ .transcript_recipe_identity = @splat(3), .public_input_abi_identity = @splat(4), .public_input_words = 1 },
        .sampling = .{ .recipe_identity = @splat(5), .mask_layout_identity = @splat(6), .mask_point_count = 1 },
        .constraint_parameters = .{ .identity = @splat(7), .statement_words = 1, .challenge_words = 1, .parameter_words = 1 },
    };
}

test "CUDA host admission preserves all six native AIR sub-contract origins" {
    const a = std.testing.allocator;
    var program = try testing.program(a, .native);
    defer program.deinit(a);
    const NativeError = @typeInfo(@typeInfo(@TypeOf(proof_ir.NativeAirContract.validate)).@"fn".return_type.?).error_union.error_set;
    const errors = [_]NativeError{ error.EmptyIdentity, error.GeometryOverflow, error.InvalidGeometry, error.InvalidIngress, error.InvalidSampling, error.UnsupportedVersion };
    for (errors, 0..) |expected, index| {
        var contract = nativeFixture();
        switch (expected) {
            error.EmptyIdentity => contract.ingress.recipe_identity = @splat(0),
            error.GeometryOverflow => {
                contract.geometry.log_rows = 62;
                contract.geometry.main_columns = 8;
            },
            error.InvalidGeometry => contract.geometry.log_rows = 0,
            error.InvalidIngress => contract.ingress.element_count = 0,
            error.InvalidSampling => contract.sampling.mask_point_count = 0,
            error.UnsupportedVersion => contract.version = 0,
        }
        try std.testing.expectError(expected, contract.validate());
        var bad = program;
        bad.native_air_contract = contract;
        var failure: ?@import("stwo_core").error_codes.Entry = null;
        try std.testing.expectError(error.InvalidNativeAir, CudaPlan.compileDiagnosed(a, bad, testing.target(.nvidia_cuda), &failure));
        try std.testing.expectEqual(@as(u16, @intCast(0x2301 + index)), failure.?.code);
        try std.testing.expectEqualStrings(@errorName(expected), failure.?.tag);
    }
}
