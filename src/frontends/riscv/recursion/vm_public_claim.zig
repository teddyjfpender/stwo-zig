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

pub const Error = public_data_mod.ValidationError || claim_witness.Error ||
    std.mem.Allocator.Error || error{
    HaltFlagCompletionRequiresClaimV2,
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
    try result.validateAgainst(data);
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

fn validateProfile(data: *const public_data_mod.PublicData) Error!void {
    try data.validate();
    for ([_]?u32{ data.program_root, data.initial_rw_root, data.final_rw_root }) |root| {
        if (root) |value| if (value >= m31.Modulus) return error.NonCanonicalRoot;
    }
    const completion = data.completion orelse return error.MissingCompletion;
    if (completion.kind != .unretired_self_loop)
        return error.HaltFlagCompletionRequiresClaimV2;
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
