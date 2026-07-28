//! Canonical public-memory data derived for Cairo statement inputs.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const memory_mod = @import("../common/memory.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const Blake2sMerkleHasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;

pub const Digest = [std.crypto.hash.sha2.Sha256.digest_length]u8;

pub const Error = error{
    ClaimLengthOverflow,
    InvalidClaimWord,
    InvalidMemoryId,
    InvalidOutputSegment,
    InvalidProgramRange,
    InvalidPublicSegmentContext,
    InvalidSafeCall,
    MemoryAddressMissing,
    SegmentPointerOverflow,
};

pub const PublicStatement = struct {
    program_len: u32,
    output_len: u32,
    public_claim: []u32,
    public_claim_word_count: usize,
    public_claim_sha256: Digest,
    public_claim_padded_sha256: Digest,
    output_claim_word_count: usize,
    output_claim_sha256: Digest,
    program_claim_word_count: usize,
    program_claim_sha256: Digest,
    output_root: [8]u32,
    program_root: [8]u32,
};

pub const MemoryEntry = struct {
    id: u32,
    value: memory_mod.MemoryValue,
};

pub const SmallPointer = struct {
    id: u32,
    value: u32,
};

pub const SegmentRange = struct {
    start: SmallPointer,
    stop: SmallPointer,
};

pub fn validateClaimWord(word: u32) Error!void {
    if (word >= M31_MODULUS) return Error.InvalidClaimWord;
}

pub fn allocPadded(
    allocator: std.mem.Allocator,
    len: usize,
) (Error || std.mem.Allocator.Error)![]u32 {
    const with_padding = std.math.add(usize, len, 3) catch return Error.ClaimLengthOverflow;
    const words = try allocator.alloc(u32, with_padding & ~@as(usize, 3));
    @memset(words, 0);
    return words;
}

pub fn derive(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
) (Error || std.mem.Allocator.Error)!PublicStatement {
    const initial = input.state_transitions.initial_state;
    const final = input.state_transitions.final_state;
    const initial_pc = initial.pc.toU32();
    const initial_ap = initial.ap.toU32();
    if (initial_ap < 2) return Error.InvalidProgramRange;
    const program_stop = initial_ap - 2;
    if (program_stop < initial_pc) return Error.InvalidProgramRange;
    const program_len_u32 = program_stop - initial_pc;
    const program_len: usize = program_len_u32;

    const segments = try extractPublicSegments(input);
    const output = segments[0] orelse return Error.InvalidPublicSegmentContext;
    if (output.stop.value < output.start.value) return Error.InvalidOutputSegment;
    const output_len_u32 = output.stop.value - output.start.value;
    const output_len: usize = output_len_u32;

    const fixed_len: usize = 6 + adapter.N_PUBLIC_SEGMENTS * 4 + 2;
    const with_program = std.math.add(usize, fixed_len, program_len) catch return Error.ClaimLengthOverflow;
    const unpadded_len = std.math.add(usize, with_program, output_len) catch return Error.ClaimLengthOverflow;
    var public_claim = try allocPadded(allocator, unpadded_len);
    errdefer allocator.free(public_claim);

    var cursor: usize = 0;
    for ([_]u32{
        initial.pc.toU32(), initial.ap.toU32(), initial.fp.toU32(),
        final.pc.toU32(),   final.ap.toU32(),   final.fp.toU32(),
    }) |word| {
        public_claim[cursor] = word;
        cursor += 1;
    }
    for (segments) |segment| {
        if (segment) |range| {
            for ([_]u32{ range.start.id, range.start.value, range.stop.id, range.stop.value }) |word| {
                public_claim[cursor] = word;
                cursor += 1;
            }
        } else {
            cursor += 4;
        }
    }

    const safe0 = try memoryEntryAt(input.memory, initial_ap - 2);
    const safe1 = try memoryEntryAt(input.memory, initial_ap - 1);
    if (!memoryValueEqualsU32(safe0.value, initial_ap) or !memoryValueIsZero(safe1.value))
        return Error.InvalidSafeCall;
    public_claim[cursor] = safe0.id;
    public_claim[cursor + 1] = safe1.id;
    cursor += 2;

    var output_hasher = Blake2sMerkleHasher.defaultWithInitialState();
    var output_digest = std.crypto.hash.sha2.Sha256.init(.{});
    for (0..output_len) |offset| {
        const address = std.math.add(u32, output.start.value, @as(u32, @intCast(offset))) catch
            return Error.SegmentPointerOverflow;
        const entry = try memoryEntryAt(input.memory, address);
        public_claim[cursor] = entry.id;
        cursor += 1;
        hashMemoryValue(&output_hasher, &output_digest, entry.value);
    }

    var program_hasher = Blake2sMerkleHasher.defaultWithInitialState();
    var program_digest = std.crypto.hash.sha2.Sha256.init(.{});
    for (0..program_len) |offset| {
        const address = std.math.add(u32, initial_pc, @as(u32, @intCast(offset))) catch
            return Error.SegmentPointerOverflow;
        const entry = try memoryEntryAt(input.memory, address);
        public_claim[cursor] = entry.id;
        cursor += 1;
        hashMemoryValue(&program_hasher, &program_digest, entry.value);
    }
    std.debug.assert(cursor == unpadded_len);
    const output_claim_word_count = std.math.mul(usize, output_len, 28) catch
        return Error.ClaimLengthOverflow;
    const program_claim_word_count = std.math.mul(usize, program_len, 28) catch
        return Error.ClaimLengthOverflow;

    return .{
        .program_len = program_len_u32,
        .output_len = output_len_u32,
        .public_claim = public_claim,
        .public_claim_word_count = unpadded_len,
        .public_claim_sha256 = digestWords(public_claim[0..unpadded_len]),
        .public_claim_padded_sha256 = digestWords(public_claim),
        .output_claim_word_count = output_claim_word_count,
        .output_claim_sha256 = finishDigest(&output_digest),
        .program_claim_word_count = program_claim_word_count,
        .program_claim_sha256 = finishDigest(&program_digest),
        .output_root = hashWords(output_hasher.finalize()),
        .program_root = hashWords(program_hasher.finalize()),
    };
}

pub fn extractPublicSegments(input: *const adapter.ProverInput) Error![adapter.N_PUBLIC_SEGMENTS]?SegmentRange {
    var present_count: u32 = 0;
    for (input.public_segment_context) |present| present_count += @intFromBool(present);
    if (present_count == 0 or !input.public_segment_context[0])
        return Error.InvalidPublicSegmentContext;

    const initial_ap = input.state_transitions.initial_state.ap.toU32();
    const final_ap = input.state_transitions.final_state.ap.toU32();
    _ = std.math.add(u32, initial_ap, present_count) catch return Error.SegmentPointerOverflow;
    if (final_ap < present_count) return Error.SegmentPointerOverflow;
    const stop_base = final_ap - present_count;

    var result: [adapter.N_PUBLIC_SEGMENTS]?SegmentRange = .{null} ** adapter.N_PUBLIC_SEGMENTS;
    var packed_index: u32 = 0;
    for (input.public_segment_context, 0..) |present, segment_index| {
        if (!present) continue;
        const start_address = std.math.add(u32, initial_ap, packed_index) catch
            return Error.SegmentPointerOverflow;
        const stop_address = std.math.add(u32, stop_base, packed_index) catch
            return Error.SegmentPointerOverflow;
        result[segment_index] = .{
            .start = try memorySmallPointerAt(input.memory, start_address),
            .stop = try memorySmallPointerAt(input.memory, stop_address),
        };
        packed_index += 1;
    }
    return result;
}

pub fn memoryEntryAt(memory: memory_mod.Memory, address: u32) Error!MemoryEntry {
    if (address >= memory.address_to_id.len) return Error.MemoryAddressMissing;
    const encoded = memory.address_to_id[address];
    if (encoded.isEmpty()) return Error.MemoryAddressMissing;
    if (encoded.isSmall()) {
        if (encoded.index() >= memory.small_values.len) return Error.InvalidMemoryId;
        return .{ .id = encoded.raw, .value = .{ .small = memory.small_values[encoded.index()] } };
    }
    if (encoded.index() >= memory.f252_values.len) return Error.InvalidMemoryId;
    return .{ .id = encoded.raw, .value = .{ .f252 = memory.f252_values[encoded.index()] } };
}

fn memorySmallPointerAt(memory: memory_mod.Memory, address: u32) Error!SmallPointer {
    const entry = try memoryEntryAt(memory, address);
    const value = switch (entry.value) {
        .small => |small| std.math.cast(u32, small) orelse return Error.SegmentPointerOverflow,
        .f252 => |words| blk: {
            if (words[1] != 0 or words[2] != 0 or words[3] != 0 or
                words[4] != 0 or words[5] != 0 or words[6] != 0 or words[7] != 0)
                return Error.SegmentPointerOverflow;
            break :blk words[0];
        },
    };
    try validateClaimWord(value);
    return .{ .id = entry.id, .value = value };
}

pub fn memoryValueWords(value: memory_mod.MemoryValue) [8]u32 {
    return switch (value) {
        .small => |small| .{
            @truncate(small),
            @truncate(small >> 32),
            @truncate(small >> 64),
            @truncate(small >> 96),
            0,
            0,
            0,
            0,
        },
        .f252 => |words| words,
    };
}

pub fn memoryValueEqualsU32(value: memory_mod.MemoryValue, expected: u32) bool {
    const words = memoryValueWords(value);
    return words[0] == expected and memoryValueTailIsZero(words);
}

pub fn memoryValueIsZero(value: memory_mod.MemoryValue) bool {
    const words = memoryValueWords(value);
    for (words) |word| if (word != 0) return false;
    return true;
}

fn memoryValueTailIsZero(words: [8]u32) bool {
    for (words[1..]) |word| if (word != 0) return false;
    return true;
}

fn hashMemoryValue(
    hasher: *Blake2sMerkleHasher,
    digest: *std.crypto.hash.sha2.Sha256,
    value: memory_mod.MemoryValue,
) void {
    const dense = memoryValueWords(value);
    var split: [28]M31 = undefined;
    for (&split, 0..) |*word, index| {
        const bit_offset = index * 9;
        const limb = bit_offset / 32;
        const shift: u5 = @intCast(bit_offset % 32);
        var raw = dense[limb] >> shift;
        if (shift > 23 and limb + 1 < dense.len) {
            raw |= dense[limb + 1] << @intCast(32 - @as(u6, shift));
        }
        const canonical = raw & 0x1ff;
        word.* = M31.fromCanonical(canonical);
        updateDigestWord(digest, canonical);
    }
    hasher.updateLeaf(&split);
}

fn digestWords(words: []const u32) Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (words) |word| updateDigestWord(&hasher, word);
    return finishDigest(&hasher);
}

fn updateDigestWord(hasher: *std.crypto.hash.sha2.Sha256, word: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, word, .little);
    hasher.update(&encoded);
}

fn finishDigest(hasher: *std.crypto.hash.sha2.Sha256) Digest {
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

fn hashWords(hash: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        const start = index * 4;
        word.* = std.mem.readInt(u32, hash[start..][0..4], .little);
    }
    return result;
}
