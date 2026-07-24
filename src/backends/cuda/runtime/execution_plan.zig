//! CUDA compilation of a backend-neutral proof program.

const std = @import("std");
const arena = @import("arena.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");
const proof_ir = @import("stwo_backend_contracts").proof_program;

pub const schedule_version: u32 = 1;

pub const CompileOptions = struct {
    sm: u32,
    runtime_build_identity: proof_ir.Digest,
    toolchain_identity: proof_ir.Digest,
    kernel_pack_identity: proof_ir.Digest,
    lane_streams: u8,
    enable_graphs: bool,
    version: u32 = schedule_version,

    pub fn validate(self: CompileOptions) Error!void {
        if (self.sm < 50 or
            digestEmpty(self.runtime_build_identity) or
            digestEmpty(self.toolchain_identity) or
            digestEmpty(self.kernel_pack_identity) or
            self.lane_streams > max_lane_streams or
            self.version == 0)
        {
            return error.InvalidCompileTarget;
        }
    }
};

pub const max_lane_streams: u8 = 8;

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
        try program.validate();
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
    hash.update("stwo-zig-cuda-plan-v1");
    hash.update(&program_digest);
    hash.update(&options.runtime_build_identity);
    hash.update(&options.toolchain_identity);
    hash.update(&options.kernel_pack_identity);
    hashInt(&hash, u32, options.sm);
    hashInt(&hash, u8, options.lane_streams);
    hashInt(&hash, u8, @intFromBool(options.enable_graphs));
    hashInt(&hash, u32, options.version);
    var digest: proof_ir.Digest = undefined;
    hash.final(&digest);
    return digest;
}

fn streamFor(node: proof_ir.Node, lane_streams: u8) u8 {
    if (lane_streams == 0) return 0;
    return switch (node.parallelism) {
        .coordination, .fri_round => 0,
        .component, .merkle_subtree, .quotient_chunk => 1 + @as(u8, @intCast(node.id % lane_streams)),
    };
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

test "CUDA planning binds target identity and derives independent lanes" {
    const allocator = std.testing.allocator;
    var program = try testProgram(allocator);
    defer program.deinit(allocator);
    const identity = proof_ir.identityDigest("runtime");
    const options = CompileOptions{
        .sm = 89,
        .runtime_build_identity = identity,
        .toolchain_identity = proof_ir.identityDigest("cuda-12.8"),
        .kernel_pack_identity = proof_ir.identityDigest("pack"),
        .lane_streams = 2,
        .enable_graphs = true,
    };
    var plan = try CudaPlan.compile(allocator, program, options);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), plan.schedule.len);
    try std.testing.expectEqual(@as(u8, 1), plan.schedule[0].stream_index);
    try std.testing.expectEqual(@as(u8, 2), plan.schedule[1].stream_index);
    try std.testing.expectEqual(@as(u64, 256), plan.prediction.request_bytes);
    try std.testing.expectEqual(@as(u64, 2), plan.prediction.minimum_launches);
    try std.testing.expectEqual(@as(u32, 1), plan.prediction.transcript_barriers);

    var changed = options;
    changed.sm = 90;
    try std.testing.expect(!std.mem.eql(
        u8,
        &plan.cache_key,
        &cacheKey(program.program_digest, changed),
    ));

    var resource_changed = try testProgramWithGraph(allocator, false);
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

fn testProgram(allocator: std.mem.Allocator) !proof_ir.ProofProgram {
    return testProgramWithGraph(allocator, true);
}

fn testProgramWithGraph(
    allocator: std.mem.Allocator,
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
            .frontend = .native,
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
