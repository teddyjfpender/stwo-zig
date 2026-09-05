//! Owned recording adapter for the ordinary Poseidon2-M31 channel.
//!
//! The adapter preserves the native channel ABI and transcript bytes while
//! retaining the exact sponge frames consumed by the recursive transcript
//! AIR.  A successful PoW check is recorded as the same virtual draw used by
//! the verifier circuit, but does not mutate the live transcript state.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const permutation = @import("../air/memory_commitment/poseidon2.zig");
const native_channel = @import("poseidon2_channel.zig");
const transcript = @import("transcript_program_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const RATE: usize = native_channel.RATE;
pub const WIDTH: usize = permutation.WIDTH;
pub const TranscriptTrace = transcript.TranscriptTrace;
pub const PoseidonCall = transcript.PoseidonCall;
pub const HashFrame = transcript.HashFrame;
pub const HashPurpose = transcript.HashPurpose;
pub const Check = transcript.Check;
pub const Digest = native_channel.Digest;

const IDENTITY_DOMAIN =
    "stwo-zig/recording-poseidon-channel/v4\x00";

pub const Error = std.mem.Allocator.Error || transcript.Error || error{
    ArithmeticOverflow,
    BitsMismatch,
    BitsOutOfRange,
    DrawFrameMissing,
    IncompleteRecording,
    InvalidContextTag,
    InvalidRecording,
    NativeTranscriptMismatch,
    PendingProofOfWork,
    PowCheckCountMismatch,
    ProofOfWorkMismatch,
    SchemaMismatch,
};

pub const Effect = enum(u8) {
    mix = 1,
    draw = 2,
    pow = 3,
};

/// One native channel operation.  `context_tag` is supplied by the typed
/// caller and is included in the execution identity; it never changes the
/// native transcript payload.
pub const OperationV4 = struct {
    context_tag: u32,
    effect: Effect,
    first_hash_id: u32,
    hash_count: u32,
    first_call_id: u32,
    call_count: u32,
    pow_check_index: ?u32,
};

const FrameMeta = struct {
    word_offset: u32,
    word_count: u32,
    output: [WIDTH]M31,
    purpose: HashPurpose,
    first_call_id: u32,
    call_count: u32,
};

const PendingPow = struct {
    bits: u32,
    nonce: u64,
};

const OperationStart = struct {
    frame: usize,
    call: usize,
};

/// Exact owned raw sponge evidence.  This type is transport-neutral evidence,
/// not a verifier lease or cryptographic admission capability.
pub const ExecutionV4 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    poseidon_calls: []PoseidonCall,
    hash_frames: []HashFrame,
    pow_checks: []Check,
    word_storage: []M31,
    operations: []OperationV4,
    final_digest: Digest,
    final_draw_count: u32,
    identity_sha256: [32]u8,

    pub fn deinit(self: *ExecutionV4) void {
        self.allocator.free(self.operations);
        self.allocator.free(self.word_storage);
        self.allocator.free(self.pow_checks);
        self.allocator.free(self.hash_frames);
        self.allocator.free(self.poseidon_calls);
        self.* = undefined;
    }

    pub fn trace(self: *const ExecutionV4) TranscriptTrace {
        return .{
            .poseidon_calls = self.poseidon_calls,
            .hash_frames = self.hash_frames,
            .pow_checks = self.pow_checks,
        };
    }

    pub fn validate(self: *const ExecutionV4) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.operations.len == 0 or
            self.hash_frames.len == 0 or
            self.poseidon_calls.len == 0)
        {
            return error.InvalidRecording;
        }
        try self.trace().validate();
        try validateWordOwnership(self);
        try replay(self);
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &executionIdentity(self),
        )) return error.InvalidRecording;
    }
};

/// Recording channel with the same public calls used by the generic STWO
/// verifier.  Void-returning channel calls retain their first allocation or
/// protocol failure and make `finish` fail closed.
pub const Channel = struct {
    allocator: std.mem.Allocator,
    inner: native_channel.Channel = .{},
    context_tag: u32 = 0,
    first_fault: ?anyerror = null,
    pending_pow: ?PendingPow = null,
    calls: std.ArrayList(PoseidonCall) = .empty,
    frames: std.ArrayList(FrameMeta) = .empty,
    checks: std.ArrayList(Check) = .empty,
    words: std.ArrayList(M31) = .empty,
    operations: std.ArrayList(OperationV4) = .empty,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Channel {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        self.operations.deinit(self.allocator);
        self.words.deinit(self.allocator);
        self.checks.deinit(self.allocator);
        self.frames.deinit(self.allocator);
        self.calls.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn setContextTag(self: *Self, value: u32) void {
        if (value >= m31.Modulus) {
            self.recordFault(error.InvalidContextTag);
            return;
        }
        self.context_tag = value;
    }

    pub fn digestWords(self: Self) Digest {
        return self.inner.digestWords();
    }

    pub fn digestBytes(self: Self) [RATE * @sizeOf(u32)]u8 {
        return self.inner.digestBytes();
    }

    pub fn mixCanonicalM31Words(self: *Self, values: []const M31) void {
        self.mixCanonicalM31Slices(&.{values});
    }

    pub fn mixCanonicalM31Slices(
        self: *Self,
        values: []const []const M31,
    ) void {
        self.ensureNoPendingPow() catch |err| {
            self.recordFault(err);
            return;
        };
        const start = self.startFrame() catch |err| {
            self.recordFault(err);
            return;
        };
        for (values) |slice| self.words.appendSlice(
            self.allocator,
            slice,
        ) catch |err| {
            self.recordFault(err);
            return;
        };
        const operation_start = self.operationStart();
        const output = self.finishFrame(start, .mix) catch |err| {
            self.recordFault(err);
            return;
        };
        self.inner.mixCanonicalM31Slices(values);
        if (!digestEqlFelts(self.inner.digestWords(), output[0..RATE].*)) {
            self.recordFault(error.NativeTranscriptMismatch);
            return;
        }
        self.finishOperation(operation_start, .mix, null) catch |err|
            self.recordFault(err);
    }

    pub fn mixU32s(self: *Self, values: []const u32) void {
        self.ensureNoPendingPow() catch |err| {
            self.recordFault(err);
            return;
        };
        const operation_start = self.operationStart();
        const start = self.startFrame() catch |err| {
            self.recordFault(err);
            return;
        };
        for (values) |value| {
            self.words.append(self.allocator, M31.fromCanonical(
                value & 0xffff,
            )) catch |err| {
                self.recordFault(err);
                return;
            };
            self.words.append(self.allocator, M31.fromCanonical(
                value >> 16,
            )) catch |err| {
                self.recordFault(err);
                return;
            };
        }
        const output = self.finishFrame(start, .mix) catch |err| {
            self.recordFault(err);
            return;
        };
        self.inner.mixU32s(values);
        if (!digestEqlFelts(self.inner.digestWords(), output[0..RATE].*)) {
            self.recordFault(error.NativeTranscriptMismatch);
            return;
        }
        self.finishOperation(operation_start, .mix, null) catch |err|
            self.recordFault(err);
    }

    pub fn mixU64(self: *Self, value: u64) void {
        const pending = self.pending_pow;
        if (pending) |pow| {
            if (pow.nonce != value) {
                self.recordFault(error.ProofOfWorkMismatch);
                return;
            }
        }
        const operation_start = self.operationStart();
        const start = self.startFrame() catch |err| {
            self.recordFault(err);
            return;
        };
        const low: u32 = @truncate(value);
        const high: u32 = @truncate(value >> 32);
        for ([_]u32{ low, high }) |word| {
            self.words.append(self.allocator, M31.fromCanonical(
                word & 0xffff,
            )) catch |err| {
                self.recordFault(err);
                return;
            };
            self.words.append(self.allocator, M31.fromCanonical(
                word >> 16,
            )) catch |err| {
                self.recordFault(err);
                return;
            };
        }
        const output = self.finishFrame(start, .mix) catch |err| {
            self.recordFault(err);
            return;
        };
        self.inner.mixU64(value);
        if (!digestEqlFelts(self.inner.digestWords(), output[0..RATE].*)) {
            self.recordFault(error.NativeTranscriptMismatch);
            return;
        }
        if (pending) |pow| {
            const draw_start = self.startFrame() catch |err| {
                self.recordFault(err);
                return;
            };
            self.words.append(self.allocator, M31.fromCanonical(0)) catch |err|
                {
                    self.recordFault(err);
                    return;
                };
            self.words.append(
                self.allocator,
                M31.fromCanonical(native_channel.DRAW_TAG),
            ) catch |err| {
                self.recordFault(err);
                return;
            };
            const drawn = self.finishFrame(draw_start, .draw) catch |err| {
                self.recordFault(err);
                return;
            };
            var candidate = self.inner;
            const native_draw = candidate.drawU32s();
            if (!digestEqlFelts(native_draw, drawn[0..RATE].*)) {
                self.recordFault(error.NativeTranscriptMismatch);
                return;
            }
            const check_index = std.math.cast(u32, self.checks.items.len) orelse {
                self.recordFault(error.ArithmeticOverflow);
                return;
            };
            const call_id = std.math.cast(u32, self.calls.items.len - 1) orelse {
                self.recordFault(error.ArithmeticOverflow);
                return;
            };
            self.checks.append(self.allocator, .{
                .call_id = call_id,
                .nonce = pow.nonce,
                .bits = pow.bits,
                .word = drawn[0],
            }) catch |err| {
                self.recordFault(err);
                return;
            };
            self.pending_pow = null;
            self.finishOperation(operation_start, .pow, check_index) catch |err|
                self.recordFault(err);
        } else {
            self.finishOperation(operation_start, .mix, null) catch |err|
                self.recordFault(err);
        }
    }

    pub fn mixFelts(self: *Self, values: []const QM31) void {
        self.ensureNoPendingPow() catch |err| {
            self.recordFault(err);
            return;
        };
        const operation_start = self.operationStart();
        const start = self.startFrame() catch |err| {
            self.recordFault(err);
            return;
        };
        for (values) |value| {
            const coordinates = value.toM31Array();
            self.words.appendSlice(
                self.allocator,
                &coordinates,
            ) catch |err| {
                self.recordFault(err);
                return;
            };
        }
        const output = self.finishFrame(start, .mix) catch |err| {
            self.recordFault(err);
            return;
        };
        self.inner.mixFelts(values);
        if (!digestEqlFelts(self.inner.digestWords(), output[0..RATE].*)) {
            self.recordFault(error.NativeTranscriptMismatch);
            return;
        }
        self.finishOperation(operation_start, .mix, null) catch |err|
            self.recordFault(err);
    }

    pub fn drawU32s(self: *Self) Digest {
        self.ensureNoPendingPow() catch |err| {
            self.recordFault(err);
            return .{0} ** RATE;
        };
        const operation_start = self.operationStart();
        const start = self.startFrame() catch |err| {
            self.recordFault(err);
            return .{0} ** RATE;
        };
        self.words.append(
            self.allocator,
            M31.fromCanonical(self.inner.n_draws),
        ) catch |err| {
            self.recordFault(err);
            return .{0} ** RATE;
        };
        self.words.append(
            self.allocator,
            M31.fromCanonical(native_channel.DRAW_TAG),
        ) catch |err| {
            self.recordFault(err);
            return .{0} ** RATE;
        };
        const output = self.finishFrame(start, .draw) catch |err| {
            self.recordFault(err);
            return .{0} ** RATE;
        };
        const result = self.inner.drawU32s();
        if (!digestEqlFelts(result, output[0..RATE].*)) {
            self.recordFault(error.NativeTranscriptMismatch);
            return .{0} ** RATE;
        }
        self.finishOperation(operation_start, .draw, null) catch |err|
            self.recordFault(err);
        return result;
    }

    pub fn drawSecureFelt(self: *Self) QM31 {
        const words = self.drawU32s();
        return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
    }

    pub fn drawSecureFelts(
        self: *Self,
        allocator: std.mem.Allocator,
        count: usize,
    ) ![]QM31 {
        const result = try allocator.alloc(QM31, count);
        errdefer allocator.free(result);
        var produced: usize = 0;
        while (produced < count) {
            const words = self.drawU32s();
            var at: usize = 0;
            while (at + 4 <= RATE and produced < count) : (at += 4) {
                result[produced] = QM31.fromU32Unchecked(
                    words[at],
                    words[at + 1],
                    words[at + 2],
                    words[at + 3],
                );
                produced += 1;
            }
        }
        if (self.first_fault != null) return error.IncompleteRecording;
        return result;
    }

    pub fn verifyPowNonce(self: *Self, bits: u32, nonce: u64) bool {
        if (self.first_fault != null or self.pending_pow != null) {
            self.recordFault(error.PendingProofOfWork);
            return false;
        }
        if (!self.inner.verifyPowNonce(bits, nonce)) return false;
        self.pending_pow = .{ .bits = bits, .nonce = nonce };
        return true;
    }

    pub fn grind(self: *Self, bits: u32) u64 {
        if (self.first_fault != null or self.pending_pow != null) {
            self.recordFault(error.PendingProofOfWork);
            return 0;
        }
        const nonce = self.inner.grind(bits);
        self.pending_pow = .{ .bits = bits, .nonce = nonce };
        return nonce;
    }

    pub fn finish(self: *Self) Error!ExecutionV4 {
        if (self.first_fault != null) return error.IncompleteRecording;
        try self.ensureNoPendingPow();
        if (self.calls.items.len >= m31.Modulus or
            self.frames.items.len >= m31.Modulus or
            self.operations.items.len >= m31.Modulus)
        {
            return error.ArithmeticOverflow;
        }
        const calls = try self.calls.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(calls);
        const checks = try self.checks.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(checks);
        const words = try self.words.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(words);
        const operations = try self.operations.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(operations);
        const metas = try self.frames.toOwnedSlice(self.allocator);
        defer self.allocator.free(metas);
        const frames = try self.allocator.alloc(HashFrame, metas.len);
        errdefer self.allocator.free(frames);
        for (frames, metas, 0..) |*destination, meta, index| {
            const start: usize = @intCast(meta.word_offset);
            const end = std.math.add(usize, start, meta.word_count) catch
                return error.ArithmeticOverflow;
            if (end > words.len) return error.InvalidRecording;
            destination.* = .{
                .hash_id = @intCast(index),
                .first_call_id = meta.first_call_id,
                .call_count = meta.call_count,
                .purpose = meta.purpose,
                .words = words[start..end],
                .output = meta.output,
            };
        }
        var result = ExecutionV4{
            .allocator = self.allocator,
            .poseidon_calls = calls,
            .hash_frames = frames,
            .pow_checks = checks,
            .word_storage = words,
            .operations = operations,
            .final_digest = self.inner.digestWords(),
            .final_draw_count = self.inner.n_draws,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = executionIdentity(&result);
        try result.validate();
        return result;
    }

    fn ensureNoPendingPow(self: *const Self) Error!void {
        if (self.first_fault != null) return error.IncompleteRecording;
        if (self.pending_pow != null) return error.PendingProofOfWork;
    }

    fn operationStart(self: *const Self) OperationStart {
        return .{ .frame = self.frames.items.len, .call = self.calls.items.len };
    }

    fn finishOperation(
        self: *Self,
        start: OperationStart,
        effect: Effect,
        check_index: ?u32,
    ) Error!void {
        const frame_count = std.math.sub(
            usize,
            self.frames.items.len,
            start.frame,
        ) catch return error.ArithmeticOverflow;
        const call_count = std.math.sub(
            usize,
            self.calls.items.len,
            start.call,
        ) catch return error.ArithmeticOverflow;
        if (frame_count != @as(usize, if (effect == .pow) 2 else 1) or
            call_count == 0)
            return error.InvalidRecording;
        try self.operations.append(self.allocator, .{
            .context_tag = self.context_tag,
            .effect = effect,
            .first_hash_id = @intCast(start.frame),
            .hash_count = @intCast(frame_count),
            .first_call_id = @intCast(start.call),
            .call_count = @intCast(call_count),
            .pow_check_index = check_index,
        });
    }

    fn startFrame(self: *Self) Error!usize {
        if (self.first_fault != null) return error.IncompleteRecording;
        const start = self.words.items.len;
        for (self.inner.digestWords()) |word| try self.words.append(
            self.allocator,
            M31.fromCanonical(word),
        );
        return start;
    }

    fn finishFrame(
        self: *Self,
        start: usize,
        purpose: HashPurpose,
    ) Error![WIDTH]M31 {
        const word_count = std.math.sub(
            usize,
            self.words.items.len,
            start,
        ) catch return error.ArithmeticOverflow;
        const call_count = try frameCallCount(word_count);
        const first_call = self.calls.items.len;
        var state = [_]M31{M31.zero()} ** WIDTH;
        const frame_words = self.words.items[start..];
        for (0..call_count) |step| {
            const input = addChunk(state, frame_words, step);
            var output = input;
            permutation.permute(&output);
            try self.calls.append(self.allocator, .{
                .id = .{
                    .call_id = @intCast(self.calls.items.len),
                    .hash_id = @intCast(self.frames.items.len),
                    .step = @intCast(step),
                },
                .input = input,
                .output = output,
            });
            state = output;
        }
        try self.frames.append(self.allocator, .{
            .word_offset = @intCast(start),
            .word_count = @intCast(word_count),
            .output = state,
            .purpose = purpose,
            .first_call_id = @intCast(first_call),
            .call_count = @intCast(call_count),
        });
        return state;
    }

    fn recordFault(self: *Self, err: anyerror) void {
        if (self.first_fault == null) self.first_fault = err;
    }
};

pub const MerkleChannel = struct {
    pub fn mixRoot(channel: *Channel, root: Digest) void {
        var words: [RATE]M31 = undefined;
        for (&words, root) |*destination, word| {
            if (word >= m31.Modulus) {
                channel.recordFault(error.NativeTranscriptMismatch);
                return;
            }
            destination.* = M31.fromCanonical(word);
        }
        channel.mixCanonicalM31Words(&words);
    }
};

fn validateWordOwnership(value: *const ExecutionV4) Error!void {
    var cursor: usize = 0;
    for (value.hash_frames) |frame| {
        const end = std.math.add(usize, cursor, frame.words.len) catch
            return error.ArithmeticOverflow;
        if (end > value.word_storage.len or
            frame.words.ptr != value.word_storage[cursor..end].ptr)
        {
            return error.InvalidRecording;
        }
        cursor = end;
    }
    if (cursor != value.word_storage.len) return error.InvalidRecording;
}

fn replay(value: *const ExecutionV4) Error!void {
    var native = native_channel.Channel{};
    var frame_at: usize = 0;
    var call_at: usize = 0;
    var check_at: usize = 0;
    for (value.operations) |operation| {
        if (operation.context_tag >= m31.Modulus or
            operation.first_hash_id != frame_at or
            operation.first_call_id != call_at or
            operation.hash_count !=
                @as(u32, if (operation.effect == .pow) 2 else 1))
        {
            return error.InvalidRecording;
        }
        const frame_end = std.math.add(
            usize,
            frame_at,
            operation.hash_count,
        ) catch return error.ArithmeticOverflow;
        if (frame_end > value.hash_frames.len)
            return error.InvalidRecording;
        var operation_calls: usize = 0;
        for (value.hash_frames[frame_at..frame_end]) |frame|
            operation_calls = std.math.add(
                usize,
                operation_calls,
                frame.call_count,
            ) catch return error.ArithmeticOverflow;
        if (operation.call_count != operation_calls)
            return error.InvalidRecording;
        const first = value.hash_frames[frame_at];
        try expectDigestPrefix(native.digestWords(), first.words);
        switch (operation.effect) {
            .mix => {
                if (operation.pow_check_index != null or
                    first.purpose != .mix)
                {
                    return error.InvalidRecording;
                }
                native.mixCanonicalM31Words(first.words[RATE..]);
                try expectDigest(native.digestWords(), first.output);
            },
            .draw => {
                if (operation.pow_check_index != null or
                    first.purpose != .draw)
                {
                    return error.InvalidRecording;
                }
                try expectDigest(native.drawU32s(), first.output);
            },
            .pow => {
                const expected_check_index = std.math.cast(
                    u32,
                    check_at,
                ) orelse return error.ArithmeticOverflow;
                if (operation.pow_check_index !=
                    @as(?u32, expected_check_index) or
                    check_at >= value.pow_checks.len or
                    first.purpose != .mix)
                {
                    return error.InvalidRecording;
                }
                const check = value.pow_checks[check_at];
                if (!powPayloadEql(first.words[RATE..], check.nonce) or
                    !native.verifyPowNonce(check.bits, check.nonce))
                {
                    return error.ProofOfWorkMismatch;
                }
                native.mixCanonicalM31Words(first.words[RATE..]);
                try expectDigest(native.digestWords(), first.output);
                const drawn = value.hash_frames[frame_at + 1];
                if (drawn.purpose != .draw)
                    return error.InvalidRecording;
                try expectDigestPrefix(native.digestWords(), drawn.words);
                var candidate = native;
                const actual = candidate.drawU32s();
                try expectDigest(actual, drawn.output);
                const final_call = drawn.finalCallId() orelse
                    return error.InvalidRecording;
                if (check.call_id != final_call or
                    !check.word.eql(drawn.output[0]))
                {
                    return error.InvalidRecording;
                }
                check_at += 1;
            },
        }
        frame_at = frame_end;
        call_at += operation_calls;
    }
    if (frame_at != value.hash_frames.len or
        call_at != value.poseidon_calls.len or
        check_at != value.pow_checks.len or
        native.n_draws != value.final_draw_count or
        !digestEql(native.digestWords(), value.final_digest))
    {
        return error.InvalidRecording;
    }
}

fn executionIdentity(value: *const ExecutionV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    const receipt = value.trace().receiptDigest();
    hash.update(&receipt);
    hashInt(&hash, u32, @as(u32, @intCast(value.operations.len)));
    for (value.operations) |operation| {
        hashInt(&hash, u32, operation.context_tag);
        hashInt(&hash, u8, @intFromEnum(operation.effect));
        hashInt(&hash, u32, operation.first_hash_id);
        hashInt(&hash, u32, operation.hash_count);
        hashInt(&hash, u32, operation.first_call_id);
        hashInt(&hash, u32, operation.call_count);
        hashInt(&hash, u8, @intFromBool(operation.pow_check_index != null));
        hashInt(&hash, u32, operation.pow_check_index orelse 0);
    }
    for (value.final_digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, value.final_draw_count);
    return hash.finalResult();
}

fn frameCallCount(words: usize) Error!usize {
    const with_marker = std.math.add(usize, words, 1) catch
        return error.ArithmeticOverflow;
    return std.math.divCeil(usize, with_marker, RATE) catch
        return error.ArithmeticOverflow;
}

fn addChunk(
    previous: [WIDTH]M31,
    words: []const M31,
    step: usize,
) [WIDTH]M31 {
    var input = previous;
    for (0..RATE) |lane| {
        const index = step * RATE + lane;
        const word = if (index < words.len)
            words[index]
        else if (index == words.len)
            M31.one()
        else
            M31.zero();
        input[lane] = input[lane].add(word);
    }
    return input;
}

fn expectDigestPrefix(actual: Digest, words: []const M31) Error!void {
    if (words.len < RATE) return error.InvalidRecording;
    for (actual, words[0..RATE]) |left, right|
        if (left != right.toU32()) return error.NativeTranscriptMismatch;
}

fn expectDigest(actual: Digest, expected: [WIDTH]M31) Error!void {
    if (!digestEqlFelts(actual, expected[0..RATE].*))
        return error.NativeTranscriptMismatch;
}

fn digestEql(left: Digest, right: Digest) bool {
    return std.mem.eql(u32, &left, &right);
}

fn digestEqlFelts(left: Digest, right: [RATE]M31) bool {
    for (left, right) |actual, expected|
        if (actual != expected.toU32()) return false;
    return true;
}

fn powPayloadEql(words: []const M31, nonce: u64) bool {
    if (words.len != 4) return false;
    const low: u32 = @truncate(nonce);
    const high: u32 = @truncate(nonce >> 32);
    return words[0].toU32() == (low & 0xffff) and
        words[1].toU32() == (low >> 16) and
        words[2].toU32() == (high & 0xffff) and
        words[3].toU32() == (high >> 16);
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or RATE != 8 or
        WIDTH != 16)
    {
        @compileError("recording Poseidon channel V4 drifted");
    }
}
