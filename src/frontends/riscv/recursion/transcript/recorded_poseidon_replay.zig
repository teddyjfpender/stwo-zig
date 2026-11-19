//! Independent native-transcript replay and identity derivation over owned recording frames.

const Root = @import("recording_poseidon_channel.zig");
const std = @import("std");
const native_channel = @import("stwo_riscv_memory").recursion.poseidon2_channel;
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const RATE = Root.RATE;
const WIDTH = Root.WIDTH;
const Digest = Root.Digest;
const IDENTITY_DOMAIN = "stwo-zig/recording-poseidon-channel/v4\x00";
const Error = Root.Error;
const ExecutionV4 = Root.ExecutionV4;

pub fn validateWordOwnership(value: *const ExecutionV4) Error!void {
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

pub fn replay(value: *const ExecutionV4) Error!void {
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

pub fn executionIdentity(value: *const ExecutionV4) [32]u8 {
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

pub fn frameCallCount(words: usize) Error!usize {
    const with_marker = std.math.add(usize, words, 1) catch
        return error.ArithmeticOverflow;
    return std.math.divCeil(usize, with_marker, RATE) catch
        return error.ArithmeticOverflow;
}

pub fn addChunk(
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

pub fn expectDigestPrefix(actual: Digest, words: []const M31) Error!void {
    if (words.len < RATE) return error.InvalidRecording;
    for (actual, words[0..RATE]) |left, right|
        if (left != right.toU32()) return error.NativeTranscriptMismatch;
}

pub fn expectDigest(actual: Digest, expected: [WIDTH]M31) Error!void {
    if (!digestEqlFelts(actual, expected[0..RATE].*))
        return error.NativeTranscriptMismatch;
}

pub fn digestEql(left: Digest, right: Digest) bool {
    return std.mem.eql(u32, &left, &right);
}

pub fn digestEqlFelts(left: Digest, right: [RATE]M31) bool {
    for (left, right) |actual, expected|
        if (actual != expected.toU32()) return false;
    return true;
}

pub fn powPayloadEql(words: []const M31, nonce: u64) bool {
    if (words.len != 4) return false;
    const low: u32 = @truncate(nonce);
    const high: u32 = @truncate(nonce >> 32);
    return words[0].toU32() == (low & 0xffff) and
        words[1].toU32() == (low >> 16) and
        words[2].toU32() == (high & 0xffff) and
        words[3].toU32() == (high >> 16);
}

pub fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
