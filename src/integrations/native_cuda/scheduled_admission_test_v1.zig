//! Host-only admission fixtures. No native ABI, device operation or proof runs.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const pipeline = @import("wide_fibonacci/executor/pipeline.zig");
const request = @import("wide_fibonacci/request.zig");
const Session = cuda.runtime.NativeSession;

pub const behavioral_test_count = 4;

// Only fields read by the actual guard are initialized. The host sentinel is
// never dereferenced as a native context or used to produce a receipt/proof.
fn guardedSession(sentinel: *u8) Session {
    var result: Session = undefined;
    result.owner_thread_id = std.Thread.getCurrentId();
    result.state = .open;
    result.context.handle = sentinel;
    result.context.lane_count = 1;
    result.context.owner_thread_id = std.Thread.getCurrentId();
    result.context.active_stage = .pow;
    return result;
}

test "CUDA scheduled admission: actual session rejects absent or unsupported lanes" {
    var sentinel: u8 = 0;
    var session = guardedSession(&sentinel);
    try session.admitScheduledNode(.pow, 0);
    try std.testing.expectError(error.InvalidExecutionLaneCount, session.admitScheduledNode(.pow, 1));
    session.context.lane_count = 0;
    try std.testing.expectError(error.InvalidExecutionLaneCount, session.admitScheduledNode(.pow, 0));
    session.context.lane_count = 2;
    try std.testing.expectError(error.InvalidExecutionLaneCount, session.admitScheduledNode(.pow, 0));
    session.context.lane_count = 1;
    session.context.handle = null;
    try std.testing.expectError(error.ContextClosed, session.admitScheduledNode(.pow, 0));
}

test "CUDA scheduled admission: actual session enforces thread state and active stage" {
    var sentinel: u8 = 0;
    var session = guardedSession(&sentinel);
    session.owner_thread_id ^= 1;
    try std.testing.expectError(error.ThreadOwnershipViolation, session.admitScheduledNode(.pow, 0));
    session.owner_thread_id = std.Thread.getCurrentId();
    session.state = .idle;
    try std.testing.expectError(error.InvalidState, session.admitScheduledNode(.pow, 0));
    session.state = .open;
    session.context.active_stage = null;
    try std.testing.expectError(error.StageOrderViolation, session.admitScheduledNode(.pow, 0));
    session.context.active_stage = .oods;
    try std.testing.expectError(error.StageOrderViolation, session.admitScheduledNode(.pow, 0));
}

fn smallRequest() request.Request {
    return .{
        .statement = .{ .log_n_rows = 3, .sequence_len = 3 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
}

fn prepare() !pipeline.PreparedPlan {
    const ir = @import("stwo_backend_contracts").proof_program;
    return pipeline.prepare(std.testing.allocator, try request.admit(smallRequest()), .{
        .sm = 89,
        .device_uuid = [_]u8{0x42} ** 16,
        .driver_version = 12080,
        .runtime_version = 12080,
        .toolkit_version = 12080,
        .runtime_build_identity = ir.identityDigest("scheduled-admission-test-runtime"),
        .host_toolchain_identity = ir.identityDigest("scheduled-admission-test-toolchain"),
        .kernel_pack_identity = ir.identityDigest("scheduled-admission-test-pack"),
        .lane_streams = 0,
        .enable_graphs = true,
    });
}

const GuardTransaction = struct {
    session: *Session,
    pub fn proofSession(self: *@This()) *Session {
        return self.session;
    }
};

test "CUDA scheduled admission: original compiled plan rejects tuple drift before session" {
    var prepared = try prepare();
    defer prepared.deinit(std.testing.allocator);
    const geometry = try request.admit(smallRequest());
    var sentinel: u8 = 0;
    var session = guardedSession(&sentinel);
    // Invalid session deliberately proves metadata checks run first.
    session.context.handle = null;
    var transaction = GuardTransaction{ .session = &session };
    const original = prepared.schedule()[0];
    for (0..7) |field| {
        var changed = original;
        switch (field) {
            0 => changed.node_id = std.math.maxInt(u32),
            1 => changed.kind = if (original.kind == .pow) .oods else .pow,
            2 => changed.stage = if (original.stage == .pow) .oods else .pow,
            3 => changed.stream_index = 1,
            4 => changed.dependency_count +%= 1,
            5 => changed.graph_candidate = !original.graph_candidate,
            6 => changed.graph_region +%= 1,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidKernelDescriptor, pipeline.admitNode(&transaction, &prepared, geometry, changed));
    }
    var changed_geometry = geometry;
    changed_geometry.trace_rows += 1;
    try std.testing.expectError(error.InvalidKernelDescriptor, pipeline.admitNode(&transaction, &prepared, changed_geometry, original));
    // Valid metadata still cannot confer native session custody.
    try std.testing.expectError(error.ContextClosed, pipeline.admitNode(&transaction, &prepared, geometry, original));
}

test "CUDA scheduled admission: original plan guards current schedule mutation and graph target" {
    var prepared = try prepare();
    defer prepared.deinit(std.testing.allocator);
    const geometry = try request.admit(smallRequest());
    var sentinel: u8 = 0;
    var session = guardedSession(&sentinel);
    var transaction = GuardTransaction{ .session = &session };
    const original = prepared.schedule()[0];
    session.context.active_stage = original.stage;
    try pipeline.admitNode(&transaction, &prepared, geometry, original);
    for (0..2) |field| {
        prepared.structural.cuda_plan.schedule[0] = original;
        switch (field) {
            0 => prepared.structural.cuda_plan.schedule[0].stream_index = 1,
            1 => prepared.structural.cuda_plan.schedule[0].dependency_count +%= 1,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidKernelDescriptor, pipeline.admitNode(&transaction, &prepared, geometry, prepared.schedule()[0]));
    }
    prepared.structural.cuda_plan.schedule[0] = original;
    prepared.structural.cuda_plan.target.lane_streams = 1;
    try std.testing.expectError(error.InvalidCompileTarget, pipeline.admitNode(&transaction, &prepared, geometry, original));
    prepared.structural.cuda_plan.target.lane_streams = 0;
    if (original.graph_candidate) {
        prepared.structural.cuda_plan.target.enable_graphs = false;
        try std.testing.expectError(error.InvalidKernelDescriptor, pipeline.admitNode(&transaction, &prepared, geometry, original));
    } else {
        prepared.structural.cuda_plan.schedule[0].graph_candidate = true;
        try std.testing.expectError(error.InvalidKernelDescriptor, pipeline.admitNode(&transaction, &prepared, geometry, prepared.schedule()[0]));
    }
}
