//! Fixed canonical VM public claim for a recursive segment leaf.
//!
//! The layout is the exact Stark-V V1 claim geometry consumed by recursion
//! rows 12--17.  This implementation admits the local frontend's canonical
//! unretired self-loop completion only: in that profile completion is uniquely
//! derived from `final_pc`, so omitting a second completion encoding cannot
//! weaken the recursively exposed statement.  Halt-flag executions require a
//! versioned claim-layout extension and fail closed here.

const std = @import("std");
const stwo_core = @import("stwo_core");
const public_data_mod = @import("../air/public_data.zig");
const channel = @import("poseidon2_channel.zig");
const claim_witness = @import("air/vm_public_claim_input_witness.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;

pub const VM_PUBLIC_CLAIM_HASH_DOMAIN: u32 = 0x5643;
pub const PUBLIC_INPUT_HASH_DOMAIN: u32 = 0x5649;
pub const PUBLIC_OUTPUT_HASH_DOMAIN: u32 = 0x564f;
pub const FIXED_CLAIM_WORDS: usize = claim_witness.FIXED_CLAIM_WORDS;
pub const INPUT_SLOT_WORDS: usize = claim_witness.INPUT_SLOT_WORDS;
pub const OUTPUT_SLOT_WORDS: usize = claim_witness.OUTPUT_SLOT_WORDS;
pub const DEFAULT_MAX_INPUT_WORDS: u32 = 1024;
pub const DEFAULT_MAX_OUTPUT_WORDS: u32 = 1025;

pub const Shape = claim_witness.Shape;
pub const Digest = channel.Digest;

/// Application-visible public input, without unrelated VM execution state.
pub const PublicInputProjection = struct {
    start: u32,
    len: u32,
    words: []const u32,
};

/// One application-visible public output word. Access clocks are deliberately
/// absent: the public-output digest never commits proof-only predecessor clocks.
pub const PublicOutputValue = struct {
    addr: u32,
    value: u32,
};

/// Application-visible public output, without unrelated VM execution state.
pub const PublicOutputProjection = struct {
    len_addr: u32,
    data_addr: u32,
    len: u32,
    words: []const PublicOutputValue,
};

pub const Error = public_data_mod.ValidationError || claim_witness.Error ||
    std.mem.Allocator.Error || error{
    HaltFlagCompletionRequiresClaimV2,
    CompletionMismatch,
    LengthOutOfRange,
    MissingCompletion,
    NonCanonicalRoot,
    VectorExceedsShape,
    WordCountMismatch,
    DigestMismatch,
};

pub const Tag = enum(u32) {
    claim = 1,
    initial_pc = 2,
    final_pc = 3,
    clock = 4,
    initial_registers = 5,
    final_registers = 6,
    register_last_clocks = 7,
    program_root = 8,
    initial_rw_root = 9,
    final_rw_root = 10,
    io_header = 11,
    input_words = 12,
    output_words = 13,
    shape = 14,
    public_input = 20,
    public_output = 21,
};

pub const canonical_layout = struct {
    pub const claim_tag: usize = 0;
    pub const shape_tag: usize = 1;
    pub const max_input_words_start: usize = 2;
    pub const max_output_words_start: usize = 4;
    pub const initial_pc_tag: usize = 6;
    pub const initial_pc_start: usize = 7;
    pub const final_pc_tag: usize = 9;
    pub const final_pc_start: usize = 10;
    pub const clock_tag: usize = 12;
    pub const clock_start: usize = 13;
    pub const initial_registers_tag: usize = 15;
    pub const initial_registers_start: usize = 16;
    pub const final_registers_tag: usize = 80;
    pub const final_registers_start: usize = 81;
    pub const register_last_clocks_tag: usize = 145;
    pub const register_last_clocks_start: usize = 146;
    pub const program_root_tag: usize = 210;
    pub const program_root_present: usize = 211;
    pub const program_root_start: usize = 212;
    pub const initial_rw_root_tag: usize = 220;
    pub const initial_rw_root_present: usize = 221;
    pub const initial_rw_root_start: usize = 222;
    pub const final_rw_root_tag: usize = 230;
    pub const final_rw_root_present: usize = 231;
    pub const final_rw_root_start: usize = 232;
    pub const io_header_tag: usize = 240;
    pub const input_start_start: usize = 241;
    pub const input_length_start: usize = 243;
    pub const output_length_address_start: usize = 245;
    pub const output_data_address_start: usize = 247;
    pub const output_length_start: usize = 249;
    pub const header_output_word_count_start: usize = 251;
    pub const input_words_tag: usize = 253;
    pub const input_word_count_start: usize = 254;
    pub const input_slots_start: usize = 256;

    pub fn inputSlotPresent(index: usize) usize {
        return input_slots_start + index * INPUT_SLOT_WORDS;
    }

    pub fn outputWordsTag(shape: Shape) usize {
        return input_slots_start + @as(usize, shape.max_input_words) * INPUT_SLOT_WORDS;
    }

    pub fn outputWordCountStart(shape: Shape) usize {
        return outputWordsTag(shape) + 1;
    }

    pub fn outputSlotsStart(shape: Shape) usize {
        return outputWordsTag(shape) + 3;
    }

    pub fn outputSlotPresent(shape: Shape, index: usize) usize {
        return outputSlotsStart(shape) + index * OUTPUT_SLOT_WORDS;
    }
};

pub const Encoded = struct {
    allocator: std.mem.Allocator,
    shape: Shape,
    words: []M31,
    digest: Digest,
    public_input_digest: Digest,
    public_output_digest: Digest,

    pub fn deinit(self: *Encoded) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Encoded, data: *const public_data_mod.PublicData) Error!void {
        try validateProfile(data);
        try self.validatePayload();
    }

    /// Versioned validation for a claim whose completion is constrained by a
    /// separate authenticated V4 public-semantics row.  The claim bytes and
    /// hash domain remain the frozen V1 values; no completion is relabelled or
    /// silently omitted.
    pub fn validateAgainstBoundCompletionV4(
        self: *const Encoded,
        data: *const public_data_mod.PublicData,
        completion: public_data_mod.Completion,
    ) Error!void {
        try validateBoundCompletionV4(data, completion);
        try self.validatePayload();
    }

    fn validatePayload(self: *const Encoded) Error!void {
        if (self.words.len != try self.shape.wordCount())
            return error.WordCountMismatch;
        const actual_digest = channel.hashCanonicalWords(self.words, VM_PUBLIC_CLAIM_HASH_DOMAIN);
        if (!std.meta.eql(actual_digest, self.digest)) return error.DigestMismatch;
        const input = try publicInputDigestFromClaim(self.words, self.shape);
        const output = try publicOutputDigestFromClaim(self.words, self.shape);
        if (!std.meta.eql(input, self.public_input_digest) or
            !std.meta.eql(output, self.public_output_digest))
        {
            return error.DigestMismatch;
        }
    }
};

pub fn encode(
    allocator: std.mem.Allocator,
    data: *const public_data_mod.PublicData,
    shape: Shape,
) Error!Encoded {
    try validateProfile(data);
    return encodeValidated(allocator, data, shape);
}

/// Frozen claim codec with a separately authenticated V4 completion.  This
/// intentionally emits byte-for-byte the same claim/hash as `encode`; the
/// extra argument only prevents the legacy self-loop profile guard from
/// misrepresenting a real kind-3 completion.
pub fn encodeWithBoundCompletionV4(
    allocator: std.mem.Allocator,
    data: *const public_data_mod.PublicData,
    shape: Shape,
    completion: public_data_mod.Completion,
) Error!Encoded {
    try validateBoundCompletionV4(data, completion);
    var result = try encodeValidated(allocator, data, shape);
    errdefer result.deinit();
    try result.validateAgainstBoundCompletionV4(data, completion);
    return result;
}

fn encodeValidated(
    allocator: std.mem.Allocator,
    data: *const public_data_mod.PublicData,
    shape: Shape,
) Error!Encoded {
    try validateCapacity(data, shape);
    const count = try shape.wordCount();
    const words = try allocator.alloc(M31, count);
    errdefer allocator.free(words);
    var writer = Writer{ .words = words };
    writer.tag(.claim);
    writer.tag(.shape);
    writer.u32Value(shape.max_input_words);
    writer.u32Value(shape.max_output_words);
    writer.taggedU32(.initial_pc, data.initial_pc);
    writer.taggedU32(.final_pc, data.final_pc);
    writer.taggedU32(.clock, data.clock);
    writer.taggedU32s(.initial_registers, &data.initial_regs);
    writer.taggedU32s(.final_registers, &data.final_regs);
    writer.taggedU32s(.register_last_clocks, &data.reg_last_clock);
    writer.optionalRoot(.program_root, data.program_root);
    writer.optionalRoot(.initial_rw_root, data.initial_rw_root);
    writer.optionalRoot(.final_rw_root, data.final_rw_root);
    writer.tag(.io_header);
    writer.u32Value(data.io_entries.input_start);
    writer.u32Value(data.io_entries.input_len);
    writer.u32Value(data.io_entries.output_len_addr);
    writer.u32Value(data.io_entries.output_data_addr);
    writer.u32Value(data.io_entries.output_len);
    try writer.length(data.io_entries.output_words.len);
    writer.tag(.input_words);
    try writer.length(data.io_entries.input_words.len);
    for (0..shape.max_input_words) |index| {
        const value = if (index < data.io_entries.input_words.len)
            data.io_entries.input_words[index]
        else
            null;
        writer.boolean(value != null);
        writer.u32Value(value orelse 0);
    }
    writer.tag(.output_words);
    try writer.length(data.io_entries.output_words.len);
    for (0..shape.max_output_words) |index| {
        const value = if (index < data.io_entries.output_words.len)
            data.io_entries.output_words[index]
        else
            null;
        writer.boolean(value != null);
        writer.u32Value(if (value) |item| item.addr else 0);
        writer.u32Value(if (value) |item| item.value else 0);
        writer.u32Value(if (value) |item| item.clock else 0);
    }
    if (writer.at != words.len) return error.WordCountMismatch;
    const result = Encoded{
        .allocator = allocator,
        .shape = shape,
        .words = words,
        .digest = channel.hashCanonicalWords(words, VM_PUBLIC_CLAIM_HASH_DOMAIN),
        .public_input_digest = try publicInputDigestFromClaim(words, shape),
        .public_output_digest = try publicOutputDigestFromClaim(words, shape),
    };
    try result.validatePayload();
    return result;
}

pub fn defaultShape() Error!Shape {
    return Shape.init(DEFAULT_MAX_INPUT_WORDS, DEFAULT_MAX_OUTPUT_WORDS);
}

/// Commits application-visible input directly from the fixed claim.  The
/// selected ranges match Stark-V V1 exactly and avoid rebuilding an auxiliary
/// vector on this hot leaf-ingestion path.
pub fn publicInputDigestFromClaim(words: []const M31, shape: Shape) Error!Digest {
    try validateClaimWordCount(words, shape);
    var hasher = channel.CanonicalWordHasher.init(PUBLIC_INPUT_HASH_DOMAIN);
    const tag = [_]M31{M31.fromCanonical(@intFromEnum(Tag.public_input))};
    hasher.update(&tag);
    hasher.update(words[canonical_layout.max_input_words_start..][0..2]);
    hasher.update(words[canonical_layout.input_start_start..][0..2]);
    hasher.update(words[canonical_layout.input_length_start..][0..2]);
    hasher.update(words[canonical_layout.input_word_count_start..][0..2]);
    hasher.update(words[canonical_layout.input_slots_start..canonical_layout.outputWordsTag(shape)]);
    return hasher.finalize();
}

/// Commits application-visible output directly from the fixed claim while
/// deliberately excluding proof-only access clocks.
pub fn publicOutputDigestFromClaim(words: []const M31, shape: Shape) Error!Digest {
    try validateClaimWordCount(words, shape);
    var hasher = channel.CanonicalWordHasher.init(PUBLIC_OUTPUT_HASH_DOMAIN);
    const tag = [_]M31{M31.fromCanonical(@intFromEnum(Tag.public_output))};
    hasher.update(&tag);
    hasher.update(words[canonical_layout.max_output_words_start..][0..2]);
    hasher.update(words[canonical_layout.output_length_address_start..][0..2]);
    hasher.update(words[canonical_layout.output_data_address_start..][0..2]);
    hasher.update(words[canonical_layout.output_length_start..][0..2]);
    hasher.update(words[canonical_layout.outputWordCountStart(shape)..][0..2]);
    const output_slots = canonical_layout.outputSlotsStart(shape);
    for (0..@as(usize, shape.max_output_words)) |index| {
        const slot = output_slots + index * OUTPUT_SLOT_WORDS;
        hasher.update(words[slot..][0..5]);
    }
    return hasher.finalize();
}

/// Hashes the canonical public-input projection directly from validated VM
/// data. This is exactly the input portion of the immutable V1 claim layout,
/// but it does not inherit that envelope's self-loop-only completion policy.
/// Versioned segmented jobs can therefore bind a real halt-flag transport
/// without constructing or pretending to admit a V1 claim.
pub fn publicInputDigestFromData(
    data: *const public_data_mod.PublicData,
    shape: Shape,
) Error!Digest {
    try validateTransportDigestSource(data, shape);
    return publicInputDigestFromProjection(.{
        .start = data.io_entries.input_start,
        .len = data.io_entries.input_len,
        .words = data.io_entries.input_words,
    }, shape);
}

/// Hashes and validates exactly the clock-free public-input projection. This
/// is the canonical helper for segmented materialization, where no fictitious
/// whole-execution register or access-clock state may be constructed merely to
/// derive an application transport digest.
pub fn publicInputDigestFromProjection(
    input: PublicInputProjection,
    shape: Shape,
) Error!Digest {
    try validateInputProjection(input, shape);
    var hasher = channel.CanonicalWordHasher.init(PUBLIC_INPUT_HASH_DOMAIN);
    hashScalar(&hasher, @intFromEnum(Tag.public_input));
    hashU32(&hasher, shape.max_input_words);
    hashU32(&hasher, input.start);
    hashU32(&hasher, input.len);
    hashLength(&hasher, input.words.len) catch
        return error.LengthOutOfRange;
    for (0..shape.max_input_words) |index| {
        const present = index < input.words.len;
        hashScalar(&hasher, @intFromBool(present));
        hashU32(&hasher, if (present) input.words[index] else 0);
    }
    return hasher.finalize();
}

/// Hashes the canonical public-output projection directly from validated VM
/// data. Proof-only predecessor clocks remain deliberately excluded, exactly
/// as in `publicOutputDigestFromClaim`.
pub fn publicOutputDigestFromData(
    data: *const public_data_mod.PublicData,
    shape: Shape,
) Error!Digest {
    try validateTransportDigestSource(data, shape);
    return publicOutputDigestFromParts(
        data.io_entries.output_len_addr,
        data.io_entries.output_data_addr,
        data.io_entries.output_len,
        data.io_entries.output_words,
        shape,
    );
}

/// Hashes and validates exactly the clock-free public-output projection.
pub fn publicOutputDigestFromProjection(
    output: PublicOutputProjection,
    shape: Shape,
) Error!Digest {
    try validateOutputProjection(output, shape);
    return publicOutputDigestFromParts(
        output.len_addr,
        output.data_addr,
        output.len,
        output.words,
        shape,
    );
}

fn publicOutputDigestFromParts(
    len_addr: u32,
    data_addr: u32,
    len: u32,
    words: anytype,
    shape: Shape,
) Error!Digest {
    var hasher = channel.CanonicalWordHasher.init(PUBLIC_OUTPUT_HASH_DOMAIN);
    hashScalar(&hasher, @intFromEnum(Tag.public_output));
    hashU32(&hasher, shape.max_output_words);
    hashU32(&hasher, len_addr);
    hashU32(&hasher, data_addr);
    hashU32(&hasher, len);
    hashLength(&hasher, words.len) catch
        return error.LengthOutOfRange;
    for (0..shape.max_output_words) |index| {
        const present = index < words.len;
        hashScalar(&hasher, @intFromBool(present));
        hashU32(&hasher, if (present) words[index].addr else 0);
        hashU32(&hasher, if (present) words[index].value else 0);
    }
    return hasher.finalize();
}

fn validateInputProjection(input: PublicInputProjection, shape: Shape) Error!void {
    _ = try shape.wordCount();
    if (input.words.len > shape.max_input_words)
        return error.VectorExceedsShape;
    const expected_words_u32 = std.math.divCeil(u32, input.len, 4) catch unreachable;
    const expected_words = std.math.cast(usize, expected_words_u32) orelse
        return error.InputWordCountMismatch;
    if (input.words.len != expected_words)
        return error.InputWordCountMismatch;
    _ = std.math.add(u32, input.start, input.len) catch
        return error.InputAddressOverflow;
    if (input.words.len != 0) {
        const last_index = std.math.cast(u32, input.words.len - 1) orelse
            return error.InputAddressOverflow;
        const last_offset = std.math.mul(u32, last_index, 4) catch
            return error.InputAddressOverflow;
        _ = std.math.add(u32, input.start, last_offset) catch
            return error.InputAddressOverflow;
    }
    const used_bytes = input.len & 3;
    if (used_bytes != 0) {
        const used_bits: u5 = @intCast(used_bytes * 8);
        const used_mask = (@as(u32, 1) << used_bits) - 1;
        if ((input.words[input.words.len - 1] & ~used_mask) != 0)
            return error.NonCanonicalInputPadding;
    }
}

fn validateOutputProjection(output: PublicOutputProjection, shape: Shape) Error!void {
    _ = try shape.wordCount();
    if (output.words.len > shape.max_output_words)
        return error.VectorExceedsShape;
    if ((output.len_addr & 3) != 0)
        return error.MisalignedOutputLengthAddress;
    if ((output.data_addr & 3) != 0)
        return error.MisalignedOutputDataAddress;
    if (output.words.len == 0) {
        if (output.len != 0) return error.OutputWordCountMismatch;
        return;
    }

    const data_word_count = if (output.len == 0) 0 else blk: {
        const end = std.math.add(u32, output.data_addr, output.len) catch
            return error.OutputAddressOverflow;
        const end_aligned = (@as(u64, end) + 3) & ~@as(u64, 3);
        break :blk std.math.cast(
            usize,
            (end_aligned - output.data_addr) / 4,
        ) orelse return error.OutputAddressOverflow;
    };
    const expected_count = std.math.add(usize, data_word_count, 1) catch
        return error.OutputWordCountMismatch;
    if (output.words.len != expected_count)
        return error.OutputWordCountMismatch;
    const length_word = output.words[0];
    if (length_word.addr != output.len_addr)
        return error.OutputWordAddressMismatch;
    if (length_word.value != output.len)
        return error.OutputLengthWordMismatch;
    for (output.words[1..], 0..) |word, index| {
        const word_index = std.math.cast(u32, index) orelse
            return error.OutputAddressOverflow;
        const offset = std.math.mul(u32, word_index, 4) catch
            return error.OutputAddressOverflow;
        const expected_addr = std.math.add(u32, output.data_addr, offset) catch
            return error.OutputAddressOverflow;
        if (expected_addr == output.len_addr)
            return error.OverlappingOutputRegions;
        if (word.addr != expected_addr)
            return error.OutputWordAddressMismatch;
    }
}

fn validateTransportDigestSource(
    data: *const public_data_mod.PublicData,
    shape: Shape,
) Error!void {
    try data.validate();
    for ([_]?u32{ data.program_root, data.initial_rw_root, data.final_rw_root }) |root| {
        if (root) |value| if (value >= m31.Modulus) return error.NonCanonicalRoot;
    }
    try validateCapacity(data, shape);
}

fn hashScalar(hasher: *channel.CanonicalWordHasher, value: u32) void {
    const word = [_]M31{M31.fromCanonical(value)};
    hasher.update(&word);
}

fn hashU32(hasher: *channel.CanonicalWordHasher, value: u32) void {
    const words = [_]M31{
        M31.fromCanonical(value & 0xffff),
        M31.fromCanonical(value >> 16),
    };
    hasher.update(&words);
}

fn hashLength(
    hasher: *channel.CanonicalWordHasher,
    value: usize,
) error{LengthOutOfRange}!void {
    hashU32(
        hasher,
        std.math.cast(u32, value) orelse return error.LengthOutOfRange,
    );
}

fn validateProfile(data: *const public_data_mod.PublicData) Error!void {
    try data.validate();
    for ([_]?u32{ data.program_root, data.initial_rw_root, data.final_rw_root }) |root| {
        if (root) |value| if (value >= m31.Modulus) return error.NonCanonicalRoot;
    }
    const completion = data.completion orelse return error.MissingCompletion;
    if (completion.kind != .unretired_self_loop)
        return error.HaltFlagCompletionRequiresClaimV2;
}

fn validateBoundCompletionV4(
    data: *const public_data_mod.PublicData,
    completion: public_data_mod.Completion,
) Error!void {
    try data.validate();
    for ([_]?u32{ data.program_root, data.initial_rw_root, data.final_rw_root }) |root| {
        if (root) |value| if (value >= m31.Modulus) return error.NonCanonicalRoot;
    }
    const retained = data.completion orelse return error.MissingCompletion;
    if (!std.meta.eql(retained, completion)) return error.CompletionMismatch;
}

fn validateCapacity(data: *const public_data_mod.PublicData, shape: Shape) Error!void {
    _ = try shape.wordCount();
    if (data.io_entries.input_words.len > shape.max_input_words or
        data.io_entries.output_words.len > shape.max_output_words)
    {
        return error.VectorExceedsShape;
    }
}

fn validateClaimWordCount(words: []const M31, shape: Shape) Error!void {
    if (words.len != try shape.wordCount()) return error.WordCountMismatch;
}

const Writer = struct {
    words: []M31,
    at: usize = 0,

    fn put(self: *Writer, value: u32) void {
        std.debug.assert(self.at < self.words.len and value < m31.Modulus);
        self.words[self.at] = M31.fromCanonical(value);
        self.at += 1;
    }

    fn tag(self: *Writer, value: Tag) void {
        self.put(@intFromEnum(value));
    }

    fn boolean(self: *Writer, value: bool) void {
        self.put(@intFromBool(value));
    }

    fn u32Value(self: *Writer, value: u32) void {
        self.put(value & 0xffff);
        self.put(value >> 16);
    }

    fn length(self: *Writer, value: usize) Error!void {
        self.u32Value(std.math.cast(u32, value) orelse return error.LengthOutOfRange);
    }

    fn taggedU32(self: *Writer, tag_value: Tag, value: u32) void {
        self.tag(tag_value);
        self.u32Value(value);
    }

    fn taggedU32s(self: *Writer, tag_value: Tag, values: []const u32) void {
        self.tag(tag_value);
        for (values) |value| self.u32Value(value);
    }

    fn optionalRoot(self: *Writer, tag_value: Tag, value: ?u32) void {
        self.tag(tag_value);
        self.boolean(value != null);
        self.put(value orelse 0);
        for (1..channel.RATE) |_| self.put(0);
    }
};

comptime {
    if (FIXED_CLAIM_WORDS != 259 or INPUT_SLOT_WORDS != 3 or OUTPUT_SLOT_WORDS != 7)
        @compileError("VM public-claim V1 layout drifted from typed row 12");
}
