//! CP-08 tracing through the live RISC-V prover and verifier orchestration.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const pcs_core = @import("stwo_core").pcs;
const qm31 = @import("stwo_core").fields.qm31;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover = @import("stwo_riscv_frontend").prover_mod;
const relation_challenges = @import("stwo_riscv_frontend").air.relation_challenges;
const runner = @import("stwo_riscv_frontend").runner;
const postcard = @import("../../interop/postcard.zig");
const prover_engine = @import("stwo_prover_impl").engine;

const QM31 = qm31.QM31;
const BaseChannel = channel_blake2s.Blake2sChannel;
const BaseMerkleChannel = blake2_merkle.Blake2sMerkleChannel;

const TEST_PCS_CONFIG = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

const TraceTag = enum(u8) {
    mix_u32s,
    mix_u64,
    mix_felts,
    draw_secure_felt,
    draw_secure_felts,
    draw_u32s,
    pow,
    relation_pair,
    commitment_root,
};

const TranscriptRecorder = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    len: usize = 0,
    tags: []TraceTag,
    event_ends: []usize,
    event_count: usize = 0,

    fn init(allocator: std.mem.Allocator) !TranscriptRecorder {
        const bytes = try allocator.alloc(u8, 2 * 1024 * 1024);
        errdefer allocator.free(bytes);
        const tags = try allocator.alloc(TraceTag, 4096);
        errdefer allocator.free(tags);
        return .{
            .allocator = allocator,
            .bytes = bytes,
            .tags = tags,
            .event_ends = try allocator.alloc(usize, tags.len),
        };
    }

    fn deinit(self: *TranscriptRecorder) void {
        self.allocator.free(self.event_ends);
        self.allocator.free(self.tags);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    fn begin(self: *TranscriptRecorder, tag: TraceTag, payload_len: usize) void {
        std.debug.assert(self.event_count < self.tags.len);
        self.tags[self.event_count] = tag;
        self.appendByte(@intFromEnum(tag));
        self.appendU64(@intCast(payload_len));
    }

    fn finish(self: *TranscriptRecorder, channel: BaseChannel) void {
        self.appendBytes(&channel.digestBytes());
        self.appendU32(channel.n_draws);
        self.event_ends[self.event_count] = self.len;
        self.event_count += 1;
    }

    fn appendFelt(self: *TranscriptRecorder, value: QM31) void {
        for (value.toM31Array()) |limb| self.appendU32(limb.toU32());
    }

    fn appendU64(self: *TranscriptRecorder, value: u64) void {
        self.appendU32(@truncate(value));
        self.appendU32(@truncate(value >> 32));
    }

    fn appendU32(self: *TranscriptRecorder, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        self.appendBytes(&bytes);
    }

    fn appendByte(self: *TranscriptRecorder, value: u8) void {
        std.debug.assert(self.len < self.bytes.len);
        self.bytes[self.len] = value;
        self.len += 1;
    }

    fn appendBytes(self: *TranscriptRecorder, values: []const u8) void {
        std.debug.assert(self.len + values.len <= self.bytes.len);
        @memcpy(self.bytes[self.len..][0..values.len], values);
        self.len += values.len;
    }

    fn count(self: TranscriptRecorder, tag: TraceTag) usize {
        var result: usize = 0;
        for (self.tags[0..self.event_count]) |actual| result += @intFromBool(actual == tag);
        return result;
    }

    fn eventBytes(self: TranscriptRecorder, event_index: usize) []const u8 {
        const start = if (event_index == 0) 0 else self.event_ends[event_index - 1];
        return self.bytes[start..self.event_ends[event_index]];
    }

    fn nthEvent(self: TranscriptRecorder, tag: TraceTag, ordinal: usize) ?usize {
        var seen: usize = 0;
        for (self.tags[0..self.event_count], 0..) |actual, event_index| {
            if (actual != tag) continue;
            if (seen == ordinal) return event_index;
            seen += 1;
        }
        return null;
    }
};

const Mutation = union(enum) {
    none,
    relation_pair: usize,
};

/// Compile-time channel substitution used only by this test engine. The
/// production channel remains unchanged when tracing is disabled.
const TraceChannel = struct {
    inner: BaseChannel = .{},
    recorder: ?*TranscriptRecorder = null,
    mutation: Mutation = .none,
    relation_pair_index: usize = 0,

    pub fn digestBytes(self: TraceChannel) [32]u8 {
        return self.inner.digestBytes();
    }

    pub fn mixU32s(self: *TraceChannel, values: []const u32) void {
        self.inner.mixU32s(values);
        if (self.recorder) |recorder| {
            recorder.begin(.mix_u32s, values.len * @sizeOf(u32));
            for (values) |value| recorder.appendU32(value);
            recorder.finish(self.inner);
        }
    }

    pub fn mixU64(self: *TraceChannel, value: u64) void {
        self.inner.mixU64(value);
        if (self.recorder) |recorder| {
            recorder.begin(.mix_u64, @sizeOf(u64));
            recorder.appendU64(value);
            recorder.finish(self.inner);
        }
    }

    pub fn mixFelts(self: *TraceChannel, values: []const QM31) void {
        self.inner.mixFelts(values);
        if (self.recorder) |recorder| {
            recorder.begin(.mix_felts, values.len * 4 * @sizeOf(u32));
            for (values) |value| recorder.appendFelt(value);
            recorder.finish(self.inner);
        }
    }

    pub fn drawSecureFelt(self: *TraceChannel) QM31 {
        const value = self.inner.drawSecureFelt();
        if (self.recorder) |recorder| {
            recorder.begin(.draw_secure_felt, 4 * @sizeOf(u32));
            recorder.appendFelt(value);
            recorder.finish(self.inner);
        }
        return value;
    }

    pub fn drawSecureFelts(
        self: *TraceChannel,
        allocator: std.mem.Allocator,
        n_felts: usize,
    ) ![]QM31 {
        if (n_felts == 2 * relation_challenges.RELATION_COUNT and
            self.relation_pair_index == 0)
        {
            return self.drawRelationPairs(allocator);
        }
        const values = try self.inner.drawSecureFelts(allocator, n_felts);
        if (self.recorder) |recorder| {
            recorder.begin(.draw_secure_felts, values.len * 4 * @sizeOf(u32));
            for (values) |value| recorder.appendFelt(value);
            recorder.finish(self.inner);
        }
        return values;
    }

    fn drawRelationPairs(self: *TraceChannel, allocator: std.mem.Allocator) ![]QM31 {
        const values = try allocator.alloc(QM31, 2 * relation_challenges.RELATION_COUNT);
        errdefer allocator.free(values);
        while (self.relation_pair_index < relation_challenges.RELATION_COUNT) {
            const pair = try self.inner.drawSecureFelts(allocator, 2);
            defer allocator.free(pair);
            const pair_index = self.relation_pair_index;
            values[2 * pair_index] = pair[0];
            values[2 * pair_index + 1] = pair[1];
            switch (self.mutation) {
                .none => {},
                .relation_pair => |target| {
                    if (target == pair_index) {
                        values[2 * pair_index] = values[2 * pair_index].add(QM31.one());
                    }
                },
            }
            self.relation_pair_index += 1;
            if (self.recorder) |recorder| {
                recorder.begin(.relation_pair, 2 * 4 * @sizeOf(u32));
                recorder.appendFelt(values[2 * pair_index]);
                recorder.appendFelt(values[2 * pair_index + 1]);
                recorder.finish(self.inner);
            }
        }
        return values;
    }

    pub fn drawU32s(self: *TraceChannel) [8]u32 {
        const values = self.inner.drawU32s();
        if (self.recorder) |recorder| {
            recorder.begin(.draw_u32s, values.len * @sizeOf(u32));
            for (values) |value| recorder.appendU32(value);
            recorder.finish(self.inner);
        }
        return values;
    }

    pub fn grind(self: *TraceChannel, bits: u32) u64 {
        const nonce = self.inner.grind(bits);
        self.recordPow(bits, nonce);
        return nonce;
    }

    pub fn verifyPowNonce(self: *TraceChannel, bits: u32, nonce: u64) bool {
        const valid = self.inner.verifyPowNonce(bits, nonce);
        self.recordPow(bits, nonce);
        return valid;
    }

    fn recordRoot(self: *TraceChannel, root: [32]u8) void {
        if (self.recorder) |recorder| {
            recorder.begin(.commitment_root, root.len);
            recorder.appendBytes(&root);
            recorder.finish(self.inner);
        }
    }

    fn recordPow(self: *TraceChannel, bits: u32, nonce: u64) void {
        if (self.recorder) |recorder| {
            recorder.begin(.pow, @sizeOf(u32) + @sizeOf(u64));
            recorder.appendU32(bits);
            recorder.appendU64(nonce);
            recorder.finish(self.inner);
        }
    }
};

const TraceMerkleChannel = struct {
    pub fn mixRoot(channel: *TraceChannel, root: [32]u8) void {
        BaseMerkleChannel.mixRoot(&channel.inner, root);
        channel.recordRoot(root);
    }
};

const TraceEngine = prover_engine.ProverEngine(
    CpuBackend,
    prover.Hasher,
    TraceMerkleChannel,
    TraceChannel,
);

fn cloneProof(allocator: std.mem.Allocator, bytes: []const u8) !prover.Proof {
    var stream = std.io.fixedBufferStream(bytes);
    return postcard.deserializeProof(prover.Hasher, allocator, stream.reader());
}

fn expectEqualTrace(expected: TranscriptRecorder, actual: TranscriptRecorder) !void {
    try std.testing.expectEqual(expected.event_count, actual.event_count);
    try std.testing.expectEqualSlices(
        TraceTag,
        expected.tags[0..expected.event_count],
        actual.tags[0..actual.event_count],
    );
    try std.testing.expectEqualSlices(
        usize,
        expected.event_ends[0..expected.event_count],
        actual.event_ends[0..actual.event_count],
    );
    try std.testing.expectEqualSlices(u8, expected.bytes[0..expected.len], actual.bytes[0..actual.len]);
}

test "riscv transcript: production prover and verifier are byte-symmetric end to end" {
    const allocator = std.testing.allocator;
    const elf = runner.trace_dump.buildTestElf(5, .{
        0x00100093, // ADDI x1, x0, 1
        0x00100093,
        0x00100093,
        0x00100093,
        0x0000006f, // JAL x0, 0: completion sentinel, not a retirement
    });
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    var prover_trace = try TranscriptRecorder.init(allocator);
    defer prover_trace.deinit();
    var prover_channel = TraceChannel{ .recorder = &prover_trace };
    var output = try prover.proveRiscVWithEngineUsingChannel(
        TraceEngine,
        allocator,
        TEST_PCS_CONFIG,
        &run.execution_trace,
        null,
        null,
        null,
        &prover_channel,
    );
    defer output.deinit(allocator);

    var proof_bytes: std.ArrayList(u8) = .{};
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(prover.Hasher, proof_bytes.writer(allocator), output.proof);

    var verifier_trace = try TranscriptRecorder.init(allocator);
    defer verifier_trace.deinit();
    var verifier_channel = TraceChannel{ .recorder = &verifier_trace };
    try prover.verifyRiscVWithEngineUsingChannel(
        TraceEngine,
        allocator,
        TEST_PCS_CONFIG,
        output.statement,
        try cloneProof(allocator, proof_bytes.items),
        output.interaction_claim,
        &verifier_channel,
    );
    try expectEqualTrace(prover_trace, verifier_trace);

    try std.testing.expectEqual(
        relation_challenges.RELATION_COUNT,
        prover_trace.count(.relation_pair),
    );
    try std.testing.expect(prover_trace.count(.commitment_root) >= 4);
    try std.testing.expect(prover_trace.count(.pow) >= 2);

    var roots: [3]usize = undefined;
    var n_roots: usize = 0;
    for (prover_trace.tags[0..prover_trace.event_count], 0..) |tag, event_index| {
        if (tag == .commitment_root and n_roots < roots.len) {
            roots[n_roots] = event_index;
            n_roots += 1;
        }
    }
    try std.testing.expectEqual(roots.len, n_roots);
    var pairs_between_main_and_interaction: usize = 0;
    var claim_mix_seen = false;
    for (prover_trace.tags[roots[1] + 1 .. roots[2]]) |tag| {
        pairs_between_main_and_interaction += @intFromBool(tag == .relation_pair);
        claim_mix_seen = claim_mix_seen or tag == .mix_felts;
    }
    try std.testing.expectEqual(relation_challenges.RELATION_COUNT, pairs_between_main_and_interaction);
    try std.testing.expect(claim_mix_seen);
    try std.testing.expect(roots[2] + 1 < prover_trace.event_count);

    var root_mutation_trace = try TranscriptRecorder.init(allocator);
    defer root_mutation_trace.deinit();
    var root_mutation_channel = TraceChannel{ .recorder = &root_mutation_trace };
    var root_mutation_proof = try cloneProof(allocator, proof_bytes.items);
    root_mutation_proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
    try std.testing.expectError(
        error.InvalidInteractionProofOfWork,
        prover.verifyRiscVWithEngineUsingChannel(
            TraceEngine,
            allocator,
            TEST_PCS_CONFIG,
            output.statement,
            root_mutation_proof,
            output.interaction_claim,
            &root_mutation_channel,
        ),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        verifier_trace.eventBytes(roots[1]),
        root_mutation_trace.eventBytes(roots[1]),
    ));

    var draw_mutation_trace = try TranscriptRecorder.init(allocator);
    defer draw_mutation_trace.deinit();
    var draw_mutation_channel = TraceChannel{
        .recorder = &draw_mutation_trace,
        .mutation = .{ .relation_pair = 4 },
    };
    try std.testing.expectError(
        error.OodsNotMatching,
        prover.verifyRiscVWithEngineUsingChannel(
            TraceEngine,
            allocator,
            TEST_PCS_CONFIG,
            output.statement,
            try cloneProof(allocator, proof_bytes.items),
            output.interaction_claim,
            &draw_mutation_channel,
        ),
    );
    const mutated_draw_event = verifier_trace.nthEvent(.relation_pair, 4) orelse
        return error.MissingRelationDrawEvent;
    try std.testing.expect(!std.mem.eql(
        u8,
        verifier_trace.eventBytes(mutated_draw_event),
        draw_mutation_trace.eventBytes(mutated_draw_event),
    ));

    var reverted_trace = try TranscriptRecorder.init(allocator);
    defer reverted_trace.deinit();
    var reverted_channel = TraceChannel{ .recorder = &reverted_trace };
    try prover.verifyRiscVWithEngineUsingChannel(
        TraceEngine,
        allocator,
        TEST_PCS_CONFIG,
        output.statement,
        try cloneProof(allocator, proof_bytes.items),
        output.interaction_claim,
        &reverted_channel,
    );
    try expectEqualTrace(verifier_trace, reverted_trace);

    // The byte-symmetric proof transcript above is now attributed to the
    // pinned architectural model on the exact runner trace it committed.
    // Keep this last so an absent oracle skips only the sampled Sail leg.
    try runner.sail_oracle.requireAgreement(
        allocator,
        "transcript-path four-ADDI runner guest",
        &elf,
        &run.execution_trace,
        run.cpu_final,
        &.{},
    );
}
