//! Executable type and policy checks for every resident proof-stage wrapper.

const std = @import("std");
const field = @import("../../abi/field.zig");
const column = @import("../column.zig");
const telemetry = @import("../telemetry.zig");
const commitment = @import("commitment.zig").Native;
const decommit = @import("decommit.zig");
const fri = @import("fri.zig").Native;
const oods_module = @import("oods.zig");
const oods = oods_module.Native;
const quotient = @import("quotient.zig");
const quotient_abi = @import("../../abi/stages/quotient.zig");
const trace = @import("trace.zig").Native;
const transcript = @import("transcript.zig");
const transform_module = @import("transform.zig");
const transform = transform_module.Native;

const owner: usize = 7;

const FakeContext = struct {
    stream_storage: u8 = 0,
    stream: *anyopaque = undefined,
    active_stage: ?telemetry.Stage = null,

    fn init(stage: telemetry.Stage) FakeContext {
        var result = FakeContext{};
        result.stream = &result.stream_storage;
        result.active_stage = stage;
        return result;
    }

    pub fn deviceSlicePointer(
        self: *@This(),
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) ![*]F {
        _ = self;
        if (slice.owner != owner or slice.len < minimum or
            slice.address == 0 or slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }

    pub fn requireStage(self: *@This(), expected: telemetry.Stage) !void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn uploadSlice(
        self: *@This(),
        comptime F: type,
        destination: anytype,
        source: []const F,
    ) !void {
        try self.requireStage(.ingress);
        _ = try self.deviceSlicePointer(F, destination, source.len);
    }
};

const FakeSession = struct {
    context: FakeContext,
    launches: usize = 0,

    fn init(stage: telemetry.Stage) FakeSession {
        return .{ .context = FakeContext.init(stage) };
    }

    pub fn recordOrdinaryKernel(
        self: *@This(),
        stage: telemetry.Stage,
        status: c_int,
    ) !void {
        try self.recordOrdinaryKernels(stage, status, 1);
    }

    pub fn recordOrdinaryKernels(
        self: *@This(),
        stage: telemetry.Stage,
        status: c_int,
        count: u64,
    ) !void {
        if (status != 0) return error.CudaFailure;
        try self.context.requireStage(stage);
        self.launches += @intCast(count);
    }
};

fn view(comptime F: type, len: usize) column.DeviceSlice(F) {
    return .{ .address = 0x1000, .len = len, .owner = owner };
}

fn viewAt(
    comptime F: type,
    address: usize,
    len: usize,
) column.DeviceSlice(F) {
    return .{ .address = address, .len = len, .owner = owner };
}

fn words(len: usize) column.DeviceSlice(u32) {
    return view(u32, len);
}

fn pointers(len: usize) column.DeviceSlice(usize) {
    return view(usize, len);
}

fn wordMatrix(
    address: usize,
    column_count: usize,
    stride_words: usize,
) transform_module.WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = column_count * stride_words,
            .owner = owner,
        },
        .column_stride_words = stride_words,
    };
}

fn secure(len: usize) column.DeviceSlice(field.SecureField) {
    return view(field.SecureField, len);
}

fn circles(len: usize) column.DeviceSlice(field.CirclePointBaseField) {
    return view(field.CirclePointBaseField, len);
}

fn secureCircles(len: usize) column.DeviceSlice(field.SecureCirclePoint) {
    return view(field.SecureCirclePoint, len);
}

fn preparedTerms(len: usize) quotient.PreparedTermDescriptors {
    return view(quotient_abi.PreparedTermDescriptor, len);
}

fn batchTerms(len: usize) quotient.BatchTermDescriptors {
    return view(quotient_abi.BatchTermDescriptor, len);
}

fn hashes(len: usize) column.DeviceSlice(field.Blake2sHash) {
    return view(field.Blake2sHash, len);
}

fn states(len: usize) column.DeviceSlice(field.ProgressiveBlake2sState) {
    return view(field.ProgressiveBlake2sState, len);
}

test "Native trace construction is exact, resident, and stage bound" {
    var session = FakeSession.init(.trace_generation);
    try trace.wideFibonacci(&session, words(8 * 37), 8, 37, 3);
    try std.testing.expectEqual(@as(usize, 1), session.launches);
    try std.testing.expectError(
        error.SizeOverflow,
        trace.wideFibonacci(&session, words(8 * 37 - 1), 8, 37, 3),
    );
    session.context.active_stage = .trace_commit;
    try std.testing.expectError(
        error.StageOrderViolation,
        trace.wideFibonacci(&session, words(8 * 37), 8, 37, 3),
    );
}

test "transform, commitment, and transcript wrappers bind the session stream" {
    var session = FakeSession.init(.trace_commit);
    try transform.inverseToRetained(
        &session,
        .trace_commit,
        wordMatrix(0x10000, 4, 256),
        wordMatrix(0x20000, 4, 512),
        8,
        words(256),
    );
    try transform.forwardInPlace(
        &session,
        .trace_commit,
        wordMatrix(0x30000, 4, 256),
        8,
        words(256),
    );
    try transform.extend(
        &session,
        .trace_commit,
        wordMatrix(0x40000, 4, 128),
        words(4),
        wordMatrix(0x50000, 4, 256),
        8,
        words(256),
        false,
    );
    try transform.extend(
        &session,
        .trace_commit,
        wordMatrix(0x40000, 4, 128),
        words(4),
        wordMatrix(0x50000, 4, 256),
        8,
        words(256),
        true,
    );
    try commitment.progressiveInit(&session, .trace_commit, states(16));
    try commitment.progressiveAbsorb(
        &session,
        .trace_commit,
        16,
        0,
        pointers(4),
        states(16),
    );
    try commitment.progressiveFinalize(
        &session,
        .trace_commit,
        4,
        states(16),
        hashes(16),
    );
    try commitment.layer(&session, .trace_commit, hashes(32), hashes(16), false);
    try commitment.layer(&session, .trace_commit, hashes(256), hashes(16), true);

    session.context.active_stage = .fri_commit;
    try commitment.friLeaves(&session, pointers(4), 256, 0, hashes(256));
    const boundary = transcript.Boundary{
        .expected_step = 1,
        .expected_chain = 2,
        .next_chain = 3,
        .snapshot = words(16),
    };
    try transcript.Native.initialize(
        &session,
        .fri_commit,
        words(16),
        words(9),
        words(9),
        1,
    );
    try transcript.Native.initialize(
        &session,
        .fri_commit,
        words(16),
        null,
        null,
        1,
    );
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        transcript.Native.initialize(
            &session,
            .fri_commit,
            words(16),
            words(8),
            words(9),
            1,
        ),
    );
    try transcript.Native.mixWords(
        &session,
        .fri_commit,
        words(16),
        boundary,
        words(8),
        true,
        words(8),
    );
    try transcript.Native.drawWords(
        &session,
        .fri_commit,
        words(16),
        boundary,
        words(8),
        words(8),
    );
    try transcript.Native.drawSecure(
        &session,
        .fri_commit,
        words(16),
        boundary,
        4,
        16,
        secure(4),
        secure(4),
    );
    session.context.active_stage = .pow;
    try transcript.Native.absorbPow(
        &session,
        words(16),
        boundary,
        words(2),
        10,
        words(2),
    );
    session.context.active_stage = .decommit;
    try transcript.Native.drawQueries(
        &session,
        words(16),
        boundary,
        8,
        words(16),
        words(16),
    );
    try std.testing.expectEqual(@as(usize, 46), session.launches);
}

test "transform rejects unsafe ranges before launching CUDA" {
    var session = FakeSession.init(.trace_commit);
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        transform.inverseToRetained(
            &session,
            .trace_commit,
            wordMatrix(0x10000, 1, 256),
            wordMatrix(0x10004, 1, 512),
            8,
            words(256),
        ),
    );

    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        transform.forwardInPlace(
            &session,
            .trace_commit,
            wordMatrix(0x30000, 2, 128),
            8,
            words(256),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), session.launches);
}

test "OODS and quotient wrappers type-check every copied resident ABI" {
    var session = FakeSession.init(.ingress);
    const indices = try oods_module.prepareIndexMap(
        &session,
        &.{ 0, 1, 2, 3 },
        viewAt(u32, 0x60000, 4),
        4,
    );
    const samples = try oods_module.prepareSampleMap(
        &session,
        &.{ 0, 1, 2, 3 },
        &.{ 1, 2, 3, 4 },
        viewAt(u32, 0x61000, 4),
        viewAt(u32, 0x62000, 4),
        4,
    );
    session.context.active_stage = .oods;
    try oods.derivePoints(
        &session,
        viewAt(field.SecureField, 0x70000, 1),
        viewAt(field.CirclePointBaseField, 0x71000, 4),
        samples,
        4,
        viewAt(field.SecureCirclePoint, 0x72000, 4),
        viewAt(field.SecureCirclePoint, 0x73000, 4),
        viewAt(field.SecureField, 0x74000, 16),
    );
    try oods.evaluateFirst(
        &session,
        .{
            .storage = viewAt(u32, 0x80000, 4 * 16),
            .column_stride_words = 16,
        },
        16,
        viewAt(field.SecureField, 0x81000, 16),
        viewAt(field.SecureField, 0x82000, 4),
    );
    try oods.reduce(
        &session,
        viewAt(field.SecureField, 0x83000, 4 * 16),
        16,
        16,
        3,
        4,
        viewAt(field.SecureField, 0x84000, 16),
        viewAt(field.SecureField, 0x85000, 4),
    );
    try oods.storeResults(
        &session,
        viewAt(field.SecureField, 0x86000, 4),
        1,
        indices,
        viewAt(field.SecureField, 0x87000, 4),
    );
    try oods.barycentricWeights(
        &session,
        1,
        2,
        4,
        viewAt(field.SecureCirclePoint, 0x88000, 1),
        .{ .a = 1, .b = 2, .c = 3, .d = 4 },
        .{ .x = 1, .y = 2 },
        viewAt(field.SecureField, 0x89000, 16),
        viewAt(field.SecureField, 0x8a000, 16),
        viewAt(field.SecureField, 0x8b000, 2),
    );
    try oods.barycentricEvaluate(
        &session,
        .{
            .storage = viewAt(u32, 0x8c000, 4 * 16),
            .column_stride_words = 16,
        },
        viewAt(field.SecureField, 0x8d000, 16),
        viewAt(field.SecureField, 0x8e000, 32),
        8,
        indices,
        viewAt(field.SecureField, 0x8f000, 4),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        oods.reduce(
            &session,
            viewAt(field.SecureField, 0x83000, 4 * 16),
            16,
            16,
            0,
            4,
            viewAt(field.SecureField, 0x84000, 16),
            viewAt(field.SecureField, 0x85000, 4),
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        oods.barycentricWeights(
            &session,
            1,
            2,
            8,
            viewAt(field.SecureCirclePoint, 0x88000, 1),
            .{ .a = 1, .b = 2, .c = 3, .d = 4 },
            .{ .x = 1, .y = 2 },
            viewAt(field.SecureField, 0x89000, 16),
            viewAt(field.SecureField, 0x8a000, 16),
            viewAt(field.SecureField, 0x8b000, 2),
        ),
    );
    try std.testing.expectEqual(@as(usize, 10), session.launches);

    session.context.active_stage = .quotient;
    const tables = quotient.CoordinateTables{
        .c0 = pointers(4),
        .c1 = pointers(4),
        .c2 = pointers(4),
        .c3 = pointers(4),
    };
    try quotient.Native.prepareTerms(
        &session,
        preparedTerms(4),
        secureCircles(4),
        secure(4),
        secure(1),
        secureCircles(4),
        secure(12),
    );
    try quotient.Native.finalizeGroups(
        &session,
        words(5),
        words(4),
        secureCircles(4),
        secure(12),
        secureCircles(4),
        secure(4),
    );
    try quotient.Native.zeroOutputs(&session, words(4), 256, tables);
    try quotient.Native.accumulate(
        &session,
        words(5),
        batchTerms(4),
        256,
        pointers(4),
        secure(12),
        words(4),
        tables,
    );
    try quotient.Native.combine(
        &session,
        1,
        2,
        8,
        secureCircles(2),
        secure(4),
        words(4),
        tables,
        .{
            .c0 = words(256),
            .c1 = words(256),
            .c2 = words(256),
            .c3 = words(256),
        },
    );
    try std.testing.expectEqual(@as(usize, 15), session.launches);
}

test "FRI, PoW, and decommit wrappers type-check every copied resident ABI" {
    var session = FakeSession.init(.fri_commit);
    try fri.fold(
        &session,
        true,
        words(256),
        0,
        256,
        pointers(4),
        secure(1),
        0,
        pointers(4),
    );
    try fri.fold(
        &session,
        false,
        words(256),
        0,
        256,
        pointers(4),
        secure(1),
        0,
        pointers(4),
    );
    try fri.foldThree(
        &session,
        words(256),
        .{ 0, 1, 2 },
        256,
        true,
        pointers(4),
        secure(1),
        pointers(4),
    );
    try fri.lastLayer(
        &session,
        words(1024),
        256,
        8,
        words(256),
        4,
        words(1024),
        words(1),
        words(64),
    );
    session.context.active_stage = .pow;
    try fri.grindPow(
        &session,
        words(16),
        10,
        words(8),
        view(u64, 1),
        words(1),
        words(2),
    );

    session.context.active_stage = .decommit;
    try decommit.Native.normalizeQueries(
        &session,
        words(16),
        8,
        4,
        words(16),
        words(1),
        words(256),
    );
    const trace_queries = decommit.TraceQueries{
        .mapped = words(16),
        .mapped_count = words(1),
        .walk = words(16),
        .walk_count = words(1),
        .leaf_indices = words(16),
        .leaf_count = words(1),
    };
    try decommit.Native.prepareTraceQueries(
        &session,
        words(16),
        words(1),
        8,
        8,
        1,
        0,
        trace_queries,
    );
    try decommit.Native.packTraceGroup(
        &session,
        0,
        4,
        0,
        pointers(4),
        words(4),
        8,
        words(16),
        words(1),
        words(256),
    );
    try decommit.Native.sparseParents(
        &session,
        words(16),
        hashes(16),
        words(1),
        words(8),
        hashes(8),
        words(1),
    );
    const fri_queries = decommit.FriQueries{
        .tree = words(16),
        .tree_count = words(1),
        .expanded = words(32),
        .expanded_count = words(1),
        .walk = words(32),
        .walk_count = words(1),
    };
    try decommit.Native.prepareFriQueries(
        &session,
        words(16),
        words(1),
        0,
        1,
        1,
        fri_queries,
    );
    try decommit.Native.assembleTrace(
        &session,
        0,
        0,
        1,
        1,
        4,
        16,
        .{
            .mapped_count = words(1),
            .walk_queries = words(16),
            .walk_scratch = words(16),
            .walk_count = words(1),
            .retained_layers = pointers(8),
            .sparse_indices = words(16),
            .sparse_hashes = hashes(16),
            .sparse_level_offsets = words(4),
            .sparse_level_counts = words(4),
            .assembly = words(256),
        },
    );
    try decommit.Native.assembleFri(&session, 0, 1, .{
        .tree_queries = words(16),
        .tree_query_count = words(1),
        .expanded_positions = words(16),
        .expanded_count = words(1),
        .coordinate_columns = pointers(4),
        .walk_queries = words(16),
        .walk_scratch = words(16),
        .walk_count = words(1),
        .retained_layers = pointers(8),
        .assembly = words(256),
    });
    try std.testing.expectEqual(@as(usize, 12), session.launches);
}
