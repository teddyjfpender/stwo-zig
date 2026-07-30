//! Executable type and policy checks for every resident proof-stage wrapper.

const std = @import("std");
const field = @import("../../abi/field.zig");
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
const support = @import("contract_test_support.zig");
const FakeSession = support.FakeSession;
const view = support.view;
const viewAt = support.viewAt;
const words = support.words;
const wordMatrix = support.wordMatrix;
const secure = support.secure;
const circles = support.circles;
const secureCircles = support.secureCircles;
const hashes = support.hashes;
const states = support.states;

test "Native trace construction is exact, resident, and stage bound" {
    var session = FakeSession.init(.trace_generation);
    try trace.wideFibonacci(&session, wordMatrix(0x1000, 37, 16), 8, 3);
    try std.testing.expectEqual(@as(usize, 1), session.launches);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        trace.wideFibonacci(
            &session,
            .{
                .storage = words(16 * 37 - 1),
                .column_stride_words = 16,
            },
            8,
            3,
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        trace.wideFibonacci(&session, wordMatrix(0x1000, 37, 7), 8, 3),
    );
    session.context.active_stage = .trace_commit;
    try std.testing.expectError(
        error.StageOrderViolation,
        trace.wideFibonacci(&session, wordMatrix(0x1000, 37, 16), 8, 3),
    );
}

test "retained trace layout admits exact in-place B2N expansion" {
    var session = FakeSession.init(.trace_commit);
    try transform.inverseToRetained(
        &session,
        .trace_commit,
        wordMatrix(0x22000, 4, 512),
        wordMatrix(0x22000, 4, 512),
        8,
        words(256),
    );
    try std.testing.expectEqual(@as(usize, 8), session.launches);
}

test "transform telemetry uses the launch count returned by the CUDA ABI" {
    const CountingApi = struct {
        pub fn stwo_ntt_n2b_columns_on(
            _: [*]u32,
            _: usize,
            _: u32,
            _: u32,
            _: [*]const u32,
            _: u32,
            _: u32,
            _: *anyopaque,
            launches_out: *u32,
        ) c_int {
            launches_out.* = 3;
            return 0;
        }
    };
    var session = FakeSession.init(.trace_commit);
    try transform_module.OpsFor(CountingApi).forwardInPlace(
        &session,
        .trace_commit,
        wordMatrix(0x30000, 37, 8192),
        13,
        words(4096),
    );
    try std.testing.expectEqual(@as(usize, 3), session.launches);
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
        wordMatrix(0x60000, 4, 16),
        states(16),
    );
    try commitment.progressiveFinalize(
        &session,
        .trace_commit,
        4,
        states(16),
        viewAt(field.Blake2sHash, 0x68000, 16),
    );
    try commitment.layer(
        &session,
        .trace_commit,
        viewAt(field.Blake2sHash, 0x90000, 32),
        viewAt(field.Blake2sHash, 0x91000, 16),
        false,
    );
    try commitment.layer(
        &session,
        .trace_commit,
        viewAt(field.Blake2sHash, 0xa0000, 256),
        viewAt(field.Blake2sHash, 0xa2000, 16),
        true,
    );
    const interaction_boundary = transcript.Boundary{
        .expected_step = 4,
        .expected_chain = 5,
        .next_chain = 6,
        .snapshot = words(16),
    };
    try fri.grindPowAtStage(
        &session,
        .trace_commit,
        words(16),
        24,
        1 << 16,
        words(8),
        view(u64, 1),
        words(1),
        words(2),
    );
    try transcript.Native.absorbPowAtStage(
        &session,
        .trace_commit,
        words(16),
        interaction_boundary,
        words(2),
        24,
        words(2),
    );

    session.context.active_stage = .fri_commit;
    try commitment.friLeaves(
        &session,
        wordMatrix(0x70000, 4, 256),
        256,
        0,
        viewAt(field.Blake2sHash, 0x80000, 256),
    );
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
    try std.testing.expectEqual(@as(usize, 50), session.launches);
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

    session.context.active_stage = .ingress;
    const host_prepared_terms = [_]quotient_abi.PreparedTermDescriptor{
        .{
            .sample_index = 0,
            .exponent = 0,
            .periodic = 0,
            .period_x = 0,
            .period_y = 0,
        },
        .{
            .sample_index = 1,
            .exponent = 1,
            .periodic = 0,
            .period_x = 0,
            .period_y = 0,
        },
        .{
            .sample_index = 2,
            .exponent = 2,
            .periodic = 0,
            .period_x = 0,
            .period_y = 0,
        },
        .{
            .sample_index = 3,
            .exponent = 3,
            .periodic = 0,
            .period_x = 0,
            .period_y = 0,
        },
    };
    const group_offsets = [_]u32{ 0, 1, 2, 3, 4 };
    const term_indices = [_]u32{ 0, 1, 2, 3 };
    const prepared = try quotient.prepareGroups(
        std.testing.allocator,
        &session,
        &host_prepared_terms,
        &group_offsets,
        &term_indices,
        viewAt(quotient_abi.PreparedTermDescriptor, 0x90000, 4),
        viewAt(u32, 0x91000, 5),
        viewAt(u32, 0x92000, 4),
        4,
    );
    var invalid_prepared_terms = host_prepared_terms;
    invalid_prepared_terms[2].exponent = 9;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        quotient.prepareGroups(
            std.testing.allocator,
            &session,
            &invalid_prepared_terms,
            &group_offsets,
            &term_indices,
            viewAt(quotient_abi.PreparedTermDescriptor, 0x90000, 4),
            viewAt(u32, 0x91000, 5),
            viewAt(u32, 0x92000, 4),
            4,
        ),
    );
    const host_batch_terms = [_]quotient_abi.BatchTermDescriptor{
        .{ .source_index = 0, .term_index = 0, .source_log_size = 8 },
        .{ .source_index = 1, .term_index = 1, .source_log_size = 8 },
        .{ .source_index = 2, .term_index = 2, .source_log_size = 8 },
        .{ .source_index = 3, .term_index = 3, .source_log_size = 8 },
    };
    const group_logs = [_]u32{ 8, 8, 8, 8 };
    const numerator_topology = try quotient.prepareNumeratorTopology(
        &session,
        &group_offsets,
        &host_batch_terms,
        &group_logs,
        viewAt(u32, 0x93000, 5),
        viewAt(quotient_abi.BatchTermDescriptor, 0x94000, 4),
        viewAt(u32, 0x95000, 4),
        256,
        4,
        256,
        4,
    );
    const partial_logs = [_]u32{ 8, 8 };
    const combine_topology = try quotient.prepareCombineTopology(
        &session,
        &partial_logs,
        viewAt(u32, 0x96000, 2),
        8,
        256,
    );
    const outputs = quotient.CoordinateSlabs{
        .c0 = wordMatrix(0xa0000, 4, 256),
        .c1 = wordMatrix(0xb0000, 4, 256),
        .c2 = wordMatrix(0xc0000, 4, 256),
        .c3 = wordMatrix(0xd0000, 4, 256),
    };
    session.context.active_stage = .quotient;
    try quotient.Native.prepareTerms(
        &session,
        prepared,
        viewAt(field.SecureCirclePoint, 0xe0000, 4),
        viewAt(field.SecureField, 0xe1000, 4),
        viewAt(field.SecureField, 0xe2000, 1),
        viewAt(field.SecureCirclePoint, 0xe3000, 4),
        viewAt(field.SecureField, 0xe4000, 12),
    );
    try quotient.Native.finalizeGroups(
        &session,
        prepared,
        viewAt(field.SecureCirclePoint, 0xe3000, 4),
        viewAt(field.SecureField, 0xe4000, 12),
        viewAt(field.SecureCirclePoint, 0xe5000, 4),
        viewAt(field.SecureField, 0xe6000, 4),
    );
    try quotient.Native.zeroOutputs(&session, numerator_topology, outputs);
    try quotient.Native.accumulate(
        &session,
        numerator_topology,
        wordMatrix(0xf0000, 4, 256),
        viewAt(field.SecureField, 0xe4000, 12),
        outputs,
    );
    try quotient.Native.combine(
        &session,
        1,
        2,
        combine_topology,
        viewAt(field.SecureCirclePoint, 0x110000, 2),
        viewAt(field.SecureField, 0x111000, 2),
        .{
            .c0 = wordMatrix(0x120000, 2, 256),
            .c1 = wordMatrix(0x130000, 2, 256),
            .c2 = wordMatrix(0x140000, 2, 256),
            .c3 = wordMatrix(0x150000, 2, 256),
        },
        .{
            .c0 = viewAt(u32, 0x160000, 256),
            .c1 = viewAt(u32, 0x170000, 256),
            .c2 = viewAt(u32, 0x180000, 256),
            .c3 = viewAt(u32, 0x190000, 256),
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
        .{
            .storage = words(1024),
            .column_stride_words = 256,
        },
        secure(1),
        0,
        .{
            .storage = words(512),
            .column_stride_words = 128,
        },
    );
    try fri.fold(
        &session,
        false,
        words(256),
        0,
        256,
        .{
            .storage = words(1024),
            .column_stride_words = 256,
        },
        secure(1),
        0,
        .{
            .storage = words(512),
            .column_stride_words = 128,
        },
    );
    try fri.foldThree(
        &session,
        words(256),
        .{ 0, 1, 2 },
        256,
        true,
        .{
            .storage = words(1024),
            .column_stride_words = 256,
        },
        secure(1),
        .{
            .storage = words(128),
            .column_stride_words = 32,
        },
    );
    try fri.foldTwo(
        &session,
        words(256),
        .{ 0, 1 },
        256,
        true,
        .{
            .storage = words(1024),
            .column_stride_words = 256,
        },
        secure(1),
        .{
            .storage = words(256),
            .column_stride_words = 64,
        },
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
        1 << 16,
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
        .{
            .storage = words(1024),
            .column_stride_words = 256,
        },
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
            .retained = .{
                .hashes = hashes(8),
                .layers = view(field.MerkleLayerDescriptor, 2),
            },
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
        .coordinates = .{
            .storage = words(64),
            .column_stride_words = 16,
        },
        .walk_queries = words(16),
        .walk_scratch = words(16),
        .walk_count = words(1),
        .retained = .{
            .hashes = hashes(8),
            .layers = view(field.MerkleLayerDescriptor, 2),
        },
        .assembly = words(256),
    });
    try std.testing.expectEqual(@as(usize, 27), session.launches);
}

test "decommit query planning rejects work outside the protocol bound" {
    var session = FakeSession.init(.decommit);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        decommit.Native.normalizeQueries(
            &session,
            words(decommit.max_protocol_queries + 1),
            8,
            1,
            words(decommit.max_protocol_queries + 1),
            words(1),
            words(1024),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), session.launches);
}
