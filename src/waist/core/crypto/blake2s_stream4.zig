//! Four-message continuation helpers for independent BLAKE2s streams.

const std = @import("std");
const builtin = @import("builtin");

fn gatherStates(comptime State: type, comptime V4: type, hashers: *const [4]State) [8]V4 {
    var states: [8]V4 = undefined;
    for (0..8) |word_index| {
        states[word_index] = .{
            hashers[0].h[word_index],
            hashers[1].h[word_index],
            hashers[2].h[word_index],
            hashers[3].h[word_index],
        };
    }
    return states;
}

fn scatterStates(
    comptime State: type,
    comptime V4: type,
    hashers: *[4]State,
    states: *const [8]V4,
    t0: u32,
    t1: u32,
    buf_len: usize,
) void {
    for (0..4) |lane| {
        for (0..8) |word_index| hashers[lane].h[word_index] = states[word_index][lane];
        hashers[lane].t0 = t0;
        hashers[lane].t1 = t1;
        hashers[lane].buf_len = buf_len;
    }
}

fn addBlockCounter(t0: *u32, t1: *u32) void {
    const sum = @as(u64, t0.*) + 64;
    t0.* = @truncate(sum);
    t1.* +%= @intCast(sum >> 32);
}

fn assertCompatible(comptime State: type, hashers: *const [4]State) void {
    for (0..4) |lane| {
        std.debug.assert(!hashers[lane].finalized);
        std.debug.assert(hashers[lane].buf_len == hashers[0].buf_len);
        std.debug.assert(hashers[lane].t0 == hashers[0].t0);
        std.debug.assert(hashers[lane].t1 == hashers[0].t1);
        std.debug.assert(hashers[lane].selection.effective == hashers[0].selection.effective);
    }
}

pub fn finalizeEqualTail4(
    comptime State: type,
    comptime V4: type,
    comptime Hash: type,
    hashers: *const [4]State,
    tails: *const [4][]const u8,
    comptime loadParallelBlock4: fn (*const [4][64]u8, *[16]V4) void,
    comptime compressParallel4: fn (*[8]V4, *const [16]V4, u32, u32, u32) void,
    comptime statesToDigests: fn (*const [8]V4) [4]Hash,
) [4]Hash {
    assertCompatible(State, hashers);
    const tail_len = tails[0].len;
    for (0..4) |lane| {
        std.debug.assert(tails[lane].len == tail_len);
        std.debug.assert(tail_len <= 64 - hashers[lane].buf_len);
    }
    if (hashers[0].selection.effective == .scalar) {
        var out: [4]Hash = undefined;
        for (&out, 0..) |*digest, lane| {
            var hasher = hashers[lane];
            hasher.update(tails[lane]);
            digest.* = hasher.finalize();
        }
        return out;
    }

    var blocks = [_][64]u8{[_]u8{0} ** 64} ** 4;
    for (0..4) |lane| {
        const buffered = hashers[lane].buf_len;
        @memcpy(blocks[lane][0..buffered], hashers[lane].buf[0..buffered]);
        @memcpy(blocks[lane][buffered .. buffered + tail_len], tails[lane]);
    }
    var messages: [16]V4 = undefined;
    loadParallelBlock4(&blocks, &messages);
    var states = gatherStates(State, V4, hashers);
    const increment = hashers[0].buf_len + tail_len;
    const counter_sum = @as(u64, hashers[0].t0) + @as(u64, @intCast(increment));
    const t0: u32 = @truncate(counter_sum);
    const t1 = hashers[0].t1 +% @as(u32, @intCast(counter_sum >> 32));
    compressParallel4(&states, &messages, t0, t1, 0xFFFF_FFFF);
    return statesToDigests(&states);
}

pub fn updateEqual4(
    comptime State: type,
    comptime V4: type,
    hashers: *[4]State,
    data: *const [4][]const u8,
    comptime loadParallelBlock4: fn (*const [4][64]u8, *[16]V4) void,
    comptime compressParallel4: fn (*[8]V4, *const [16]V4, u32, u32, u32) void,
) void {
    assertCompatible(State, hashers);
    const data_len = data[0].len;
    for (data) |message| std.debug.assert(message.len == data_len);
    if (data_len == 0) return;
    if (hashers[0].selection.effective == .scalar) {
        for (0..4) |lane| hashers[lane].update(data[lane]);
        return;
    }

    var states = gatherStates(State, V4, hashers);
    var t0 = hashers[0].t0;
    var t1 = hashers[0].t1;
    var buf_len = hashers[0].buf_len;
    var at: usize = 0;
    if (buf_len > 0 or data_len <= 64) {
        const copy_len = @min(64 - buf_len, data_len);
        for (0..4) |lane| {
            @memcpy(hashers[lane].buf[buf_len .. buf_len + copy_len], data[lane][0..copy_len]);
        }
        buf_len += copy_len;
        at += copy_len;
        if (buf_len < 64 or at == data_len) {
            for (0..4) |lane| hashers[lane].buf_len = buf_len;
            return;
        }
        addBlockCounter(&t0, &t1);
        var blocks: [4][64]u8 = undefined;
        for (0..4) |lane| blocks[lane] = hashers[lane].buf;
        var messages: [16]V4 = undefined;
        loadParallelBlock4(&blocks, &messages);
        compressParallel4(&states, &messages, t0, t1, 0);
        buf_len = 0;
    }
    while (at + 64 < data_len) : (at += 64) {
        var blocks: [4][64]u8 = undefined;
        for (0..4) |lane| @memcpy(blocks[lane][0..], data[lane][at .. at + 64]);
        var messages: [16]V4 = undefined;
        loadParallelBlock4(&blocks, &messages);
        addBlockCounter(&t0, &t1);
        compressParallel4(&states, &messages, t0, t1, 0);
    }
    const remaining = data_len - at;
    for (0..4) |lane| @memcpy(hashers[lane].buf[0..remaining], data[lane][at..]);
    scatterStates(State, V4, hashers, &states, t0, t1, remaining);
}

pub fn updateM31Columns4(
    comptime State: type,
    comptime V4: type,
    hashers: *[4]State,
    columns: anytype,
    position: usize,
    comptime loadParallelBlock4: fn (*const [4][64]u8, *[16]V4) void,
    comptime compressParallel4: fn (*[8]V4, *const [16]V4, u32, u32, u32) void,
) void {
    assertCompatible(State, hashers);
    for (columns) |column| std.debug.assert(position + 4 <= column.values.len);
    if (columns.len == 0) return;
    if (hashers[0].selection.effective == .scalar or
        comptime builtin.cpu.arch.endian() != .little)
    {
        for (0..4) |lane| {
            for (columns) |column| {
                var encoded: [4]u8 = undefined;
                std.mem.writeInt(u32, &encoded, column.values[position + lane].v, .little);
                hashers[lane].update(&encoded);
            }
        }
        return;
    }

    std.debug.assert((hashers[0].buf_len & 3) == 0);
    var states = gatherStates(State, V4, hashers);
    var t0 = hashers[0].t0;
    var t1 = hashers[0].t1;
    var buffered_words = hashers[0].buf_len / @sizeOf(u32);
    var word_at: usize = 0;
    if (buffered_words > 0 or columns.len <= 16) {
        const copy_words = @min(16 - buffered_words, columns.len);
        for (0..copy_words) |word| {
            for (0..4) |lane| {
                var encoded: [4]u8 = undefined;
                std.mem.writeInt(u32, &encoded, columns[word].values[position + lane].v, .little);
                const byte_start = (buffered_words + word) * @sizeOf(u32);
                @memcpy(hashers[lane].buf[byte_start .. byte_start + 4], encoded[0..]);
            }
        }
        buffered_words += copy_words;
        word_at += copy_words;
        if (buffered_words < 16 or word_at == columns.len) {
            for (0..4) |lane| hashers[lane].buf_len = buffered_words * @sizeOf(u32);
            return;
        }
        addBlockCounter(&t0, &t1);
        var blocks: [4][64]u8 = undefined;
        for (0..4) |lane| blocks[lane] = hashers[lane].buf;
        var messages: [16]V4 = undefined;
        loadParallelBlock4(&blocks, &messages);
        compressParallel4(&states, &messages, t0, t1, 0);
        buffered_words = 0;
    }
    while (word_at + 16 < columns.len) : (word_at += 16) {
        var messages: [16]V4 = undefined;
        inline for (0..16) |word| {
            const values: *const [4]u32 = @ptrCast(columns[word_at + word].values.ptr + position);
            messages[word] = values.*;
        }
        addBlockCounter(&t0, &t1);
        compressParallel4(&states, &messages, t0, t1, 0);
    }
    const remaining_words = columns.len - word_at;
    for (0..remaining_words) |word| {
        for (0..4) |lane| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, columns[word_at + word].values[position + lane].v, .little);
            const byte_start = word * @sizeOf(u32);
            @memcpy(hashers[lane].buf[byte_start .. byte_start + 4], encoded[0..]);
        }
    }
    scatterStates(
        State,
        V4,
        hashers,
        &states,
        t0,
        t1,
        remaining_words * @sizeOf(u32),
    );
}
