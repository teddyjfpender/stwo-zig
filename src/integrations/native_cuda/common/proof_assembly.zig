//! AIR-neutral device-to-device capture into a resident SWPC proof bundle.
//!
//! The bundle is zeroed and receives its immutable header during ingress.
//! These helpers only fill dynamic sections; the transaction's one terminal
//! read and host-side Stark bundle decoding remain outside this module.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const runtime_error = @import("../../../backends/cuda/runtime/error.zig");
const stark_bundle = @import(
    "../../../backends/cuda/runtime/proof_assembly/stark_bundle.zig",
);
const proof_bundle = @import("proof_bundle.zig");
const resident_views = @import("resident_views.zig");

pub fn captureTraceRoot(
    session: anytype,
    views: anytype,
    commitment_index: usize,
    root: common.Hashes,
) runtime_error.Error!void {
    if (root.len != 1) return error.InvalidKernelDescriptor;
    const destination = try rootDestination(
        views.proof.trace_commitments,
        commitment_index,
    );
    try copyWords(session, destination, try root.cast(u32));
}

pub fn captureStaticTraceRoot(
    session: anytype,
    views: anytype,
    commitment_index: usize,
    root_words: common.Words,
) runtime_error.Error!void {
    if (root_words.len != stark_bundle.hash_words)
        return error.InvalidKernelDescriptor;
    const destination = try rootDestination(
        views.proof.trace_commitments,
        commitment_index,
    );
    try copyWords(session, destination, root_words);
}

pub fn captureSampledValues(
    session: anytype,
    views: anytype,
) runtime_error.Error!void {
    try copyWords(
        session,
        views.proof.sampled_values,
        try views.oods.sampled_values.cast(u32),
    );
}

pub fn captureFriRoot(
    session: anytype,
    views: anytype,
    layer_index: usize,
    root: common.Hashes,
) runtime_error.Error!void {
    if (root.len != 1) return error.InvalidKernelDescriptor;
    const destination = try rootDestination(
        views.proof.fri_commitments,
        layer_index,
    );
    try copyWords(session, destination, try root.cast(u32));
}

pub fn captureLastLayer(
    session: anytype,
    views: anytype,
) runtime_error.Error!void {
    try copyWords(
        session,
        views.proof.fri_last_layer,
        try views.fri.last_transcript.cast(u32),
    );
    try copyWords(
        session,
        views.proof.degree_verdict,
        views.fri.last_degree_error,
    );
}

pub fn capturePowNonce(
    session: anytype,
    views: anytype,
) runtime_error.Error!void {
    try copyWords(
        session,
        views.proof.pow_nonce,
        views.pow.transcript_nonce,
    );
}

pub fn validateLayout(
    prepared: anytype,
    views: anytype,
) runtime_error.Error!void {
    const proof = views.proof;
    if (proof.bundle.len != prepared.proof.total_words or
        proof.degree_verdict.len != 1 or
        proof.trace_commitments.len !=
            prepared.proof.section(.trace_commitments).words or
        proof.sampled_values.len !=
            prepared.proof.section(.sampled_values).words or
        proof.fri_commitments.len !=
            prepared.proof.section(.fri_commitments).words or
        proof.fri_last_layer.len !=
            prepared.proof.section(.fri_last_layer).words or
        proof.pow_nonce.len !=
            prepared.proof.section(.proof_of_work).words or
        proof.decommitment.len !=
            prepared.proof.section(.decommitment).words)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn rootDestination(
    section: common.Words,
    index: usize,
) runtime_error.Error!common.Words {
    const first = std.math.mul(
        usize,
        index,
        stark_bundle.hash_words,
    ) catch return error.SizeOverflow;
    return section.sub(first, stark_bundle.hash_words);
}

fn copyWords(
    session: anytype,
    destination: common.Words,
    source: common.Words,
) runtime_error.Error!void {
    if (destination.len == 0 or destination.len != source.len)
        return error.SizeOverflow;
    try session.context.copyDeviceSlice(u32, destination, source);
}

comptime {
    if (proof_bundle.magic != stark_bundle.magic or
        proof_bundle.version != stark_bundle.version or
        proof_bundle.fixed_header_words != stark_bundle.fixed_header_words or
        proof_bundle.section_record_words != stark_bundle.section_record_words or
        proof_bundle.header_words != stark_bundle.header_words or
        @sizeOf(field.Blake2sHash) / @sizeOf(u32) != stark_bundle.hash_words or
        @sizeOf(field.SecureField) / @sizeOf(u32) != stark_bundle.secure_words)
    {
        @compileError("resident SWPC producer and terminal decoder diverged");
    }
}

test "capture helpers issue only exact typed device copies" {
    const FakeContext = struct {
        const Copy = struct {
            destination: usize,
            source: usize,
            count: usize,
        };

        copies: [4]Copy = undefined,
        count: usize = 0,

        pub fn copyDeviceSlice(
            self: *@This(),
            comptime F: type,
            destination: anytype,
            source: anytype,
        ) runtime_error.Error!void {
            try std.testing.expectEqual(u32, F);
            self.copies[self.count] = .{
                .destination = destination.address,
                .source = source.address,
                .count = source.len,
            };
            self.count += 1;
        }
    };
    const FakeSession = struct { context: FakeContext = .{} };
    var session = FakeSession{};

    const proof = testViews();
    try captureFriRoot(
        &session,
        &proof,
        2,
        .{ .address = 0x9000, .len = 1, .owner = 1 },
    );
    try captureLastLayer(&session, &proof);
    try capturePowNonce(&session, &proof);

    try std.testing.expectEqual(@as(usize, 4), session.context.count);
    try std.testing.expectEqual(
        @as(usize, 0x3000 + 2 * stark_bundle.hash_words * 4),
        session.context.copies[0].destination,
    );
    try std.testing.expectEqual(@as(usize, 0x9000), session.context.copies[0].source);
    try std.testing.expectEqual(
        stark_bundle.hash_words,
        session.context.copies[0].count,
    );
    try std.testing.expectEqual(@as(usize, 0x4000), session.context.copies[1].destination);
    try std.testing.expectEqual(@as(usize, 0x7100), session.context.copies[1].source);
    try std.testing.expectEqual(@as(usize, 0x4010), session.context.copies[2].destination);
    try std.testing.expectEqual(@as(usize, 0x7200), session.context.copies[2].source);
    try std.testing.expectEqual(@as(usize, 0x5000), session.context.copies[3].destination);
    try std.testing.expectEqual(@as(usize, 0x7300), session.context.copies[3].source);
}

test "root capture rejects a non-root and an out-of-range section index" {
    const FakeContext = struct {
        pub fn copyDeviceSlice(
            _: *@This(),
            comptime F: type,
            _: anytype,
            _: anytype,
        ) runtime_error.Error!void {
            _ = F;
        }
    };
    const FakeSession = struct { context: FakeContext = .{} };
    var session = FakeSession{};
    const views = testViews();

    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        captureFriRoot(
            &session,
            &views,
            0,
            .{ .address = 0x9000, .len = 2, .owner = 1 },
        ),
    );
    try std.testing.expectError(
        error.SizeOverflow,
        captureFriRoot(
            &session,
            &views,
            4,
            .{ .address = 0x9000, .len = 1, .owner = 1 },
        ),
    );
}

fn testViews() resident_views.Views {
    const words = struct {
        fn at(address: usize, len: usize) common.Words {
            return .{ .address = address, .len = len, .owner = 1 };
        }
    }.at;
    const secure = struct {
        fn at(address: usize, len: usize) common.SecureFields {
            return .{ .address = address, .len = len, .owner = 1 };
        }
    }.at;
    return .{
        .trace = undefined,
        .transcript = undefined,
        .constraint = undefined,
        .oods = .{
            .parameter = undefined,
            .offset_points = undefined,
            .fold_counts = undefined,
            .output_indices = undefined,
            .sample_points = undefined,
            .evaluation_points = undefined,
            .folding_factors = undefined,
            .reduce_a = undefined,
            .reduce_b = undefined,
            .sampled_values = secure(0x6000, 8),
        },
        .quotient = undefined,
        .fri = .{
            .alpha = undefined,
            .layers = undefined,
            .layer_count = 0,
            .last_evaluation = undefined,
            .last_coefficients = undefined,
            .last_degree_error = words(0x7200, 1),
            .last_transcript = secure(0x7100, 1),
        },
        .pow = .{
            .prefix_digest = undefined,
            .best_nonce = undefined,
            .completed_blocks = undefined,
            .transcript_nonce = words(0x7300, 2),
        },
        .decommit = undefined,
        .proof = .{
            .bundle = words(0x1000, 512),
            .degree_verdict = words(0x4010, 1),
            .trace_commitments = words(0x2000, 24),
            .sampled_values = words(0x2800, 8 * 4),
            .fri_commitments = words(0x3000, 4 * 8),
            .fri_last_layer = words(0x4000, 4),
            .pow_nonce = words(0x5000, 2),
            .decommitment = words(0x5100, 64),
        },
    };
}
