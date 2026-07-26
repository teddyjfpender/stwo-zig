//! Public statement data for RV32IM proofs.
//!
//! The field model and transcript order mirror Stark-V's `PublicData` at the
//! pinned RISC-V oracle revision. PC and clock bind through registers-state,
//! registers and I/O close through memory-access, and roots are checked against
//! the committed program and RW-memory trees before entering the transcript.

const std = @import("std");
const profile = @import("../isa/profile.zig");

pub const ValidationError = error{
    InputAddressOverflow,
    InputWordCountMismatch,
    InvalidCompletionAddress,
    InvalidCompletionClock,
    InvalidCompletionValue,
    MisalignedFinalPc,
    MisalignedInitialPc,
    MissingCompletion,
    MisalignedOutputDataAddress,
    MisalignedOutputLengthAddress,
    MissingProgramRoot,
    NonCanonicalInputPadding,
    NonZeroFinalX0,
    NonZeroInitialX0,
    OutputAddressOverflow,
    OutputClockOutOfRange,
    OutputLengthWordMismatch,
    OutputWordAddressMismatch,
    OutputWordCountMismatch,
    OverlappingOutputRegions,
    RegisterClockOutOfRange,
    UnsupportedCompletion,
};

/// Proof-bearing environment event that ended the execution.
pub const CompletionKind = enum(u32) {
    /// A nonzero final word at the linker-declared halt flag.
    halt_flag = 1,
    /// The canonical `jal x0, 0` at `final_pc`, observed but not retired.
    unretired_self_loop = 2,
};

pub const CANONICAL_SELF_LOOP_WORD: u32 = 0x0000_006f;

pub const Completion = struct {
    kind: CompletionKind,
    address: u32,
    value: u32,
    clock: u32,

    pub fn canonicalSelfLoop(pc: u32) Completion {
        return .{
            .kind = .unretired_self_loop,
            .address = pc,
            .value = CANONICAL_SELF_LOOP_WORD,
            .clock = 0,
        };
    }
};

pub fn completionFromRun(run_result: anytype) ValidationError!Completion {
    return switch (run_result.completion_reason) {
        .halt_flag => .{
            .kind = .halt_flag,
            .address = run_result.completion_address,
            .value = run_result.completion_value,
            .clock = run_result.completion_clock,
        },
        .self_loop => blk: {
            if (run_result.completion_value != CANONICAL_SELF_LOOP_WORD)
                return error.InvalidCompletionValue;
            break :blk Completion.canonicalSelfLoop(run_result.completion_address);
        },
        else => error.UnsupportedCompletion,
    };
}

/// A final public output word and the clock of its last memory access.
pub const OutputWord = struct {
    addr: u32,
    value: u32,
    clock: u32,
};

/// Public input and output memory entries.
pub const IoEntries = struct {
    /// Input region start address.
    input_start: u32,
    /// Input length in bytes.
    input_len: u32,
    /// Little-endian input words, contiguous from `input_start`.
    input_words: []const u32,
    /// Output length in bytes.
    output_len: u32,
    /// Address of the output length word.
    output_len_addr: u32,
    /// Address of the first output data byte.
    output_data_addr: u32,
    /// Output length word followed by the output data words.
    output_words: []const OutputWord,

    /// Derive the address of an input word without the wrapping arithmetic used
    /// by the pinned Rust implementation. Valid statements occupy the shared
    /// non-wrapping subset of both implementations.
    pub fn inputWordAddress(self: IoEntries, index: usize) ValidationError!u32 {
        const word_index = std.math.cast(u32, index) orelse
            return error.InputAddressOverflow;
        const offset = std.math.mul(u32, word_index, 4) catch
            return error.InputAddressOverflow;
        return std.math.add(u32, self.input_start, offset) catch
            return error.InputAddressOverflow;
    }

    fn outputDataWordAddress(self: IoEntries, index: usize) ValidationError!u32 {
        const word_index = std.math.cast(u32, index) orelse
            return error.OutputAddressOverflow;
        const offset = std.math.mul(u32, word_index, 4) catch
            return error.OutputAddressOverflow;
        return std.math.add(u32, self.output_data_addr & ~@as(u32, 3), offset) catch
            return error.OutputAddressOverflow;
    }

    fn outputDataWordCount(self: IoEntries) ValidationError!usize {
        if (self.output_len == 0) return 0;
        const end = std.math.add(u32, self.output_data_addr, self.output_len) catch
            return error.OutputAddressOverflow;
        const start_aligned = self.output_data_addr & ~@as(u32, 3);
        const end_aligned = (@as(u64, end) + 3) & ~@as(u64, 3);
        return std.math.cast(usize, (end_aligned - start_aligned) / 4) orelse
            return error.OutputAddressOverflow;
    }
};

/// Public execution state carried by an RV32IM proof.
pub const PublicData = struct {
    initial_pc: u32,
    final_pc: u32,
    /// Total executed cycles in the Stark-V public-data clock model.
    clock: u32,
    initial_regs: [32]u32,
    final_regs: [32]u32,
    /// Last access clock for every register, or zero if never accessed.
    reg_last_clock: [32]u32,
    program_root: ?u32,
    initial_rw_root: ?u32,
    final_rw_root: ?u32,
    /// Mandatory in every produced proof. `null` is accepted only as an input
    /// convenience for synthetic traces and is resolved before commitment.
    completion: ?Completion = null,
    io_entries: IoEntries,

    /// Validate the statement shape that is derivable from public data alone.
    ///
    /// The released CLI accepts one complete, unsegmented execution, so every
    /// public output word is present. Output words expose complete memory words;
    /// unused bytes of the final output word are intentionally not required to
    /// be zero.
    pub fn validate(self: *const PublicData) ValidationError!void {
        if (!profile.isInstructionAligned(self.initial_pc))
            return error.MisalignedInitialPc;
        if (!profile.isInstructionAligned(self.final_pc))
            return error.MisalignedFinalPc;
        if (self.program_root == null) return error.MissingProgramRoot;
        if (self.initial_regs[0] != 0) return error.NonZeroInitialX0;
        if (self.final_regs[0] != 0) return error.NonZeroFinalX0;
        try self.validateCompletion();
        for (self.reg_last_clock) |clock| {
            if (clock > self.clock) return error.RegisterClockOutOfRange;
        }
        try self.validateInput();
        try self.validateOutput();
    }

    fn validateCompletion(self: *const PublicData) ValidationError!void {
        const completion = self.completion orelse return error.MissingCompletion;
        switch (completion.kind) {
            .halt_flag => {
                if ((completion.address & 3) != 0 or completion.address >= 0x7fff_fffc)
                    return error.InvalidCompletionAddress;
                if (completion.value == 0) return error.InvalidCompletionValue;
                if (completion.clock == 0 or completion.clock > self.clock)
                    return error.InvalidCompletionClock;
            },
            .unretired_self_loop => {
                if (completion.address != self.final_pc)
                    return error.InvalidCompletionAddress;
                profile.requireProgramWordAddress(completion.address) catch
                    return error.InvalidCompletionAddress;
                if (completion.value != CANONICAL_SELF_LOOP_WORD)
                    return error.InvalidCompletionValue;
                if (completion.clock != 0) return error.InvalidCompletionClock;
            },
        }
    }

    fn validateInput(self: *const PublicData) ValidationError!void {
        const io = self.io_entries;
        const expected_words_u32 = std.math.divCeil(u32, io.input_len, 4) catch unreachable;
        const expected_words = std.math.cast(usize, expected_words_u32) orelse
            return error.InputWordCountMismatch;
        if (io.input_words.len != expected_words) return error.InputWordCountMismatch;

        _ = std.math.add(u32, io.input_start, io.input_len) catch
            return error.InputAddressOverflow;
        if (io.input_words.len != 0) {
            _ = try io.inputWordAddress(io.input_words.len - 1);
        }

        const used_bytes = io.input_len & 3;
        if (used_bytes != 0) {
            const used_bits: u5 = @intCast(used_bytes * 8);
            const used_mask = (@as(u32, 1) << used_bits) - 1;
            if ((io.input_words[io.input_words.len - 1] & ~used_mask) != 0)
                return error.NonCanonicalInputPadding;
        }
    }

    fn validateOutput(self: *const PublicData) ValidationError!void {
        const io = self.io_entries;
        // The pinned runner permits an unaligned symbol, but publishes only the
        // containing aligned word. Without adjacent words the four-byte length
        // cannot be reconstructed uniquely, so the proof profile fails closed
        // to the aligned subset rather than leaving `output_len` transcript-only.
        if ((io.output_len_addr & 3) != 0) return error.MisalignedOutputLengthAddress;
        // The memory relation carries aligned word addresses, not the byte
        // offset within a word. Restricting the data symbol to word alignment
        // makes `output_data_addr` uniquely derivable from non-empty output.
        if ((io.output_data_addr & 3) != 0) return error.MisalignedOutputDataAddress;
        if (io.output_words.len == 0) {
            if (io.output_len != 0) return error.OutputWordCountMismatch;
            return;
        }

        const data_word_count = try io.outputDataWordCount();
        const expected_count = std.math.add(usize, data_word_count, 1) catch
            return error.OutputWordCountMismatch;
        if (io.output_words.len != expected_count) return error.OutputWordCountMismatch;

        const length_word_addr = io.output_len_addr & ~@as(u32, 3);
        const length_word = io.output_words[0];
        if (length_word.addr != length_word_addr) return error.OutputWordAddressMismatch;
        if (length_word.value != io.output_len) return error.OutputLengthWordMismatch;
        try validateOutputClock(length_word.clock, self.clock);

        for (io.output_words[1..], 0..) |word, index| {
            const expected_addr = try io.outputDataWordAddress(index);
            if (expected_addr == length_word_addr) return error.OverlappingOutputRegions;
            if (word.addr != expected_addr) return error.OutputWordAddressMismatch;
            try validateOutputClock(word.clock, self.clock);
        }
    }

    /// Mix fields in the exact order used by pinned Stark-V `PublicData`.
    pub fn mixInto(self: *const PublicData, channel: anytype) void {
        channel.mixU32s(&.{ self.initial_pc, self.final_pc, self.clock });
        channel.mixU32s(&self.initial_regs);
        channel.mixU32s(&self.final_regs);
        channel.mixU32s(&self.reg_last_clock);

        channel.mixU32s(&.{
            @intFromBool(self.program_root != null),
            @intFromBool(self.initial_rw_root != null),
            @intFromBool(self.final_rw_root != null),
        });
        channel.mixU32s(&.{
            self.program_root orelse 0,
            self.initial_rw_root orelse 0,
            self.final_rw_root orelse 0,
        });

        const completion = self.completion;
        channel.mixU32s(&.{
            @intFromBool(completion != null),
            if (completion) |value| @intFromEnum(value.kind) else 0,
            if (completion) |value| value.address else 0,
            if (completion) |value| value.value else 0,
            if (completion) |value| value.clock else 0,
        });

        channel.mixU32s(&.{
            self.io_entries.input_start,
            self.io_entries.input_len,
            self.io_entries.output_len_addr,
            self.io_entries.output_data_addr,
            self.io_entries.output_len,
            @intCast(self.io_entries.output_words.len),
        });
        channel.mixU32s(self.io_entries.input_words);
        for (self.io_entries.output_words) |word| {
            channel.mixU32s(&.{ word.addr, word.value, word.clock });
        }
    }
};

fn validateOutputClock(clock: u32, final_clock: u32) ValidationError!void {
    if (clock == 0 or clock > final_clock) return error.OutputClockOutOfRange;
}

/// Pack public input bytes into Stark-V's contiguous little-endian words.
/// The unused high bytes of the final word are zero.
pub fn packInputWords(allocator: std.mem.Allocator, bytes: []const u8) ![]u32 {
    const words = try allocator.alloc(u32, std.math.divCeil(usize, bytes.len, 4) catch unreachable);
    errdefer allocator.free(words);
    for (words, 0..) |*word, word_index| {
        var buf = [_]u8{0} ** 4;
        const start = word_index * 4;
        const end = @min(start + 4, bytes.len);
        @memcpy(buf[0 .. end - start], bytes[start..end]);
        word.* = std.mem.readInt(u32, &buf, .little);
    }
    return words;
}

const RecordingChannel = struct {
    words: [256]u32 = undefined,
    words_len: usize = 0,
    call_lengths: [32]usize = undefined,
    calls_len: usize = 0,

    fn mixU32s(self: *RecordingChannel, values: []const u32) void {
        std.debug.assert(self.calls_len < self.call_lengths.len);
        std.debug.assert(self.words_len + values.len <= self.words.len);
        self.call_lengths[self.calls_len] = values.len;
        self.calls_len += 1;
        @memcpy(self.words[self.words_len..][0..values.len], values);
        self.words_len += values.len;
    }
};

fn sequence(comptime n: usize, start: u32) [n]u32 {
    var result: [n]u32 = undefined;
    for (&result, 0..) |*value, i| value.* = start + @as(u32, @intCast(i));
    return result;
}

test "public data: transcript mix order matches pinned Stark-V" {
    const initial_regs = sequence(32, 100);
    const final_regs = sequence(32, 200);
    const reg_last_clock = sequence(32, 300);
    const input_words = [_]u32{ 0x0403_0201, 0x0000_0605 };
    const output_words = [_]OutputWord{
        .{ .addr = 0x0010_0004, .value = 5, .clock = 40 },
        .{ .addr = 0x0010_0008, .value = 0x4443_4241, .clock = 41 },
    };
    const public_data = PublicData{
        .initial_pc = 11,
        .final_pc = 22,
        .clock = 33,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 44,
        .initial_rw_root = null,
        .final_rw_root = 66,
        .completion = Completion.canonicalSelfLoop(22),
        .io_entries = .{
            .input_start = 0x0018_0000,
            .input_len = 6,
            .input_words = &input_words,
            .output_len = 5,
            .output_len_addr = 0x0010_0004,
            .output_data_addr = 0x0010_0008,
            .output_words = &output_words,
        },
    };

    var channel = RecordingChannel{};
    public_data.mixInto(&channel);

    const expected_call_lengths = [_]usize{ 3, 32, 32, 32, 3, 3, 5, 6, 2, 3, 3 };
    try std.testing.expectEqualSlices(
        usize,
        &expected_call_lengths,
        channel.call_lengths[0..channel.calls_len],
    );

    var expected: [124]u32 = undefined;
    var cursor: usize = 0;
    const append = struct {
        fn values(dst: []u32, at: *usize, src: []const u32) void {
            @memcpy(dst[at.*..][0..src.len], src);
            at.* += src.len;
        }
    }.values;
    append(&expected, &cursor, &.{ 11, 22, 33 });
    append(&expected, &cursor, &initial_regs);
    append(&expected, &cursor, &final_regs);
    append(&expected, &cursor, &reg_last_clock);
    append(&expected, &cursor, &.{ 1, 0, 1 });
    append(&expected, &cursor, &.{ 44, 0, 66 });
    append(&expected, &cursor, &.{ 1, 2, 22, CANONICAL_SELF_LOOP_WORD, 0 });
    append(&expected, &cursor, &.{ 0x0018_0000, 6, 0x0010_0004, 0x0010_0008, 5, 2 });
    append(&expected, &cursor, &input_words);
    append(&expected, &cursor, &.{ 0x0010_0004, 5, 40 });
    append(&expected, &cursor, &.{ 0x0010_0008, 0x4443_4241, 41 });
    try std.testing.expectEqual(expected.len, cursor);
    try std.testing.expectEqualSlices(u32, &expected, channel.words[0..channel.words_len]);
}

test "public data: absent roots and empty input preserve upstream mix calls" {
    const public_data = PublicData{
        .initial_pc = 1,
        .final_pc = 2,
        .clock = 3,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = Completion.canonicalSelfLoop(2),
        .io_entries = .{
            .input_start = 4,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 5,
            .output_data_addr = 6,
            .output_words = &.{},
        },
    };

    var channel = RecordingChannel{};
    public_data.mixInto(&channel);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 3, 32, 32, 32, 3, 3, 5, 6, 0 },
        channel.call_lengths[0..channel.calls_len],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0, 0, 0, 1, 2, 2, CANONICAL_SELF_LOOP_WORD, 0 },
        channel.words[102..110],
    );
}

test "public data: pack input words is little endian with zero padding" {
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6 };
    const words = try packInputWords(std.testing.allocator, &bytes);
    defer std.testing.allocator.free(words);
    try std.testing.expectEqualSlices(u32, &.{ 0x0403_0201, 0x0000_0605 }, words);

    const empty = try packInputWords(std.testing.allocator, &.{});
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

fn validPublicData(input_words: []const u32, output_words: []const OutputWord) PublicData {
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1010,
        .clock = 10,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = 1,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = Completion.canonicalSelfLoop(0x1010),
        .io_entries = .{
            .input_start = 0x2000,
            .input_len = 6,
            .input_words = input_words,
            .output_len = 5,
            .output_len_addr = 0x3004,
            .output_data_addr = 0x3008,
            .output_words = output_words,
        },
    };
}

test "public data: validator accepts the pinned input and output shape" {
    const input_words = [_]u32{ 0x0403_0201, 0x0000_0605 };
    const output_words = [_]OutputWord{
        .{ .addr = 0x3004, .value = 5, .clock = 8 },
        .{ .addr = 0x3008, .value = 0x4443_4241, .clock = 9 },
        // Stark-V publishes the complete final memory word. Bytes above the
        // five-byte logical output are public but are not required to be zero.
        .{ .addr = 0x300c, .value = 0xaabb_cc45, .clock = 10 },
    };
    const data = validPublicData(&input_words, &output_words);
    try data.validate();
}

test "public data: validator rejects missing root and malformed input" {
    const output_words = [_]OutputWord{
        .{ .addr = 0x3004, .value = 5, .clock = 8 },
        .{ .addr = 0x3008, .value = 11, .clock = 9 },
        .{ .addr = 0x300c, .value = 12, .clock = 10 },
    };
    const canonical_input = [_]u32{ 0x0403_0201, 0x0000_0605 };

    var data = validPublicData(&canonical_input, &output_words);
    data.initial_pc += 2;
    try std.testing.expectError(error.MisalignedInitialPc, data.validate());

    data = validPublicData(&canonical_input, &output_words);
    data.final_pc += 2;
    try std.testing.expectError(error.MisalignedFinalPc, data.validate());

    data = validPublicData(&canonical_input, &output_words);
    data.program_root = null;
    try std.testing.expectError(error.MissingProgramRoot, data.validate());

    data = validPublicData(&canonical_input, &output_words);
    data.initial_regs[0] = 42;
    try std.testing.expectError(error.NonZeroInitialX0, data.validate());

    data = validPublicData(&canonical_input, &output_words);
    data.final_regs[0] = 42;
    try std.testing.expectError(error.NonZeroFinalX0, data.validate());

    data = validPublicData(&canonical_input, &output_words);
    data.reg_last_clock[31] = data.clock + 1;
    try std.testing.expectError(error.RegisterClockOutOfRange, data.validate());

    data = validPublicData(canonical_input[0..1], &output_words);
    try std.testing.expectError(error.InputWordCountMismatch, data.validate());

    const noncanonical_input = [_]u32{ 0x0403_0201, 0x0100_0605 };
    data = validPublicData(&noncanonical_input, &output_words);
    try std.testing.expectError(error.NonCanonicalInputPadding, data.validate());

    const one_byte_input = [_]u32{1};
    data = validPublicData(&one_byte_input, &output_words);
    data.io_entries.input_start = std.math.maxInt(u32);
    data.io_entries.input_len = 1;
    try std.testing.expectError(error.InputAddressOverflow, data.validate());
}

test "public data: validator rejects malformed output structure" {
    const input_words = [_]u32{ 0x0403_0201, 0x0000_0605 };
    var output_words = [_]OutputWord{
        .{ .addr = 0x3004, .value = 5, .clock = 8 },
        .{ .addr = 0x3008, .value = 11, .clock = 9 },
        .{ .addr = 0x300c, .value = 12, .clock = 10 },
    };
    var data = validPublicData(&input_words, output_words[0..2]);
    try std.testing.expectError(error.OutputWordCountMismatch, data.validate());

    data = validPublicData(&input_words, &output_words);
    output_words[0].value = 4;
    try std.testing.expectError(error.OutputLengthWordMismatch, data.validate());
    output_words[0].value = 5;

    output_words[1].addr += 4;
    try std.testing.expectError(error.OutputWordAddressMismatch, data.validate());
    output_words[1].addr -= 4;

    output_words[1].clock = 0;
    try std.testing.expectError(error.OutputClockOutOfRange, data.validate());
    output_words[1].clock = 11;
    try std.testing.expectError(error.OutputClockOutOfRange, data.validate());
}

test "public data: empty output forms retain the pinned segment distinction" {
    const input_words = [_]u32{ 0x0403_0201, 0x0000_0605 };
    var data = validPublicData(&input_words, &.{});
    data.io_entries.output_len = 0;
    try data.validate();

    const final_segment_words = [_]OutputWord{.{
        .addr = 0x3004,
        .value = 0,
        .clock = 8,
    }};
    data.io_entries.output_words = &final_segment_words;
    try data.validate();

    data.io_entries.output_len = 1;
    try std.testing.expectError(error.OutputWordCountMismatch, data.validate());
}

test "public data: output regions use checked, non-overlapping addresses" {
    const input_words = [_]u32{ 0x0403_0201, 0x0000_0605 };
    const overflow_words = [_]OutputWord{
        .{ .addr = 0x3004, .value = 2, .clock = 8 },
        .{ .addr = 0xffff_fffc, .value = 1, .clock = 9 },
    };
    var data = validPublicData(&input_words, &overflow_words);
    data.io_entries.output_len = 4;
    data.io_entries.output_data_addr = 0xffff_fffc;
    try std.testing.expectError(error.OutputAddressOverflow, data.validate());

    const overlap_words = [_]OutputWord{
        .{ .addr = 0x3008, .value = 4, .clock = 8 },
        .{ .addr = 0x3008, .value = 1, .clock = 9 },
    };
    data = validPublicData(&input_words, &overlap_words);
    data.io_entries.output_len = 4;
    data.io_entries.output_len_addr = 0x3008;
    try std.testing.expectError(error.OverlappingOutputRegions, data.validate());
}

test "public data: unaligned output length is outside the supported proof profile" {
    const input_words = [_]u32{ 0x0403_0201, 0x0000_0605 };
    const output_words = [_]OutputWord{
        .{ .addr = 0x3004, .value = 5, .clock = 8 },
        .{ .addr = 0x3008, .value = 11, .clock = 9 },
        .{ .addr = 0x300c, .value = 12, .clock = 10 },
    };
    var data = validPublicData(&input_words, &output_words);
    data.io_entries.output_len_addr += 1;
    try std.testing.expectError(error.MisalignedOutputLengthAddress, data.validate());

    data = validPublicData(&input_words, &output_words);
    data.io_entries.output_data_addr += 1;
    try std.testing.expectError(error.MisalignedOutputDataAddress, data.validate());
}
