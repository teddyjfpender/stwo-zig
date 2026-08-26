//! Internal vm public io hash witness authority shard; use vm_public_io_hash_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
pub const poseidon_executor = @import("../../air/lang/typed_poseidon2_witness.zig");
pub const types = @import("../../air/lang/types.zig");
pub const component = @import("vm_public_io_hash.zig");
pub const claim_input = @import("vm_public_claim_input_witness.zig");
pub const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const STATE_WIDTH = component.STATE_WIDTH;
pub const RATE = component.RATE;
pub const Shape = claim_input.Shape;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const PoseidonCall = poseidon_executor.Call;
pub const POSEIDON_MAIN_COLUMN_COUNT = poseidon_executor.N_MAIN_COLUMNS;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-io-hash-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "c599f19b8b391cde283d779c19b5dc1bc6cfb343479facf319d353c26f2ccb17";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion VM public-I/O hash witness-binding digest",
);
pub const PREPROCESSING_FORMAT_VERSION: u16 = 1;
pub const PREPROCESSING_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-io-hash-preprocessing/v1\x00";
pub const WITNESS_FORMAT_VERSION: u16 = 1;
pub const WITNESS_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-io-hash-main/v1\x00";

pub const Error = direct.Error || component.ValidationError || claim_input.Error ||
    poseidon_executor.ExecutionError || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    BindingMismatch,
    DigestMismatch,
    InactiveClaimProvided,
    InvalidFieldElement,
    InvalidPreprocessedRow,
    InvalidWitnessRow,
    LogSizeOutOfRange,
    SegmentClaimMissing,
    ShapeMismatch,
    WordCountMismatch,
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    source_authority_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]types.ValueId,
    preprocessed: [PREPROCESSED_COLUMN_COUNT]types.ValueId,
    parameters: [component.PARAMETER_COUNT]types.ValueId,

    pub fn canonical(definition: *const component.Definition) !Binding {
        try definition.validate();
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .source_authority_digest = component.SOURCE_AUTHORITY_DIGEST,
            .main = definition.main.physical(),
            .preprocessed = definition.preprocessed.physical(),
            .parameters = definition.parameters.physical(),
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hash.update(&self.source_authority_digest);
        for (self.main) |value| hashInt(&hash, u32, @intFromEnum(value));
        for (self.preprocessed) |value| hashInt(&hash, u32, @intFromEnum(value));
        for (self.parameters) |value| hashInt(&hash, u32, @intFromEnum(value));
        return hash.finalResult();
    }
};

pub const Chunk = struct {
    source_mask: u32,
    word_index: u32,
    constant: u32,
};

pub const PreprocessedRow = struct {
    row_mask: u32,
    io_kind: u32,
    step: u32,
    first: u32,
    last: u32,
    hash_domain: u32,
    chunks: [RATE]Chunk,

    pub fn values(self: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
        var result: [PREPROCESSED_COLUMN_COUNT]M31 = undefined;
        result[0..6].* = .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.io_kind),
            M31.fromCanonical(self.step),
            M31.fromCanonical(self.first),
            M31.fromCanonical(self.last),
            M31.fromCanonical(self.hash_domain),
        };
        for (self.chunks, 0..) |chunk, index| result[6 + 3 * index ..][0..3].* = .{
            M31.fromCanonical(chunk.source_mask),
            M31.fromCanonical(chunk.word_index),
            M31.fromCanonical(chunk.constant),
        };
        return result;
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    shape: Shape,
    claim_word_count: usize,
    input_word_count: usize,
    output_word_count: usize,
    input_row_count: usize,
    output_row_count: usize,
    log_size: u32,
    rows: []PreprocessedRow,
    claim_input_authority_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        claim_preprocessing: *const claim_input.Preprocessed,
    ) Error!Preprocessed {
        try component.SourceAuthority.pinned().validate();
        try claim_preprocessing.validate();
        const word_count = try claim_preprocessing.shape.wordCount();
        if (word_count != claim_preprocessing.rows.len)
            return error.ShapeMismatch;
        const input_words = try inputWordCount(claim_preprocessing.shape);
        const output_words = try outputWordCount(claim_preprocessing.shape);
        const input_rows = try laneRowCount(input_words);
        const output_rows = try laneRowCount(output_words);
        const row_count = std.math.add(usize, input_rows, output_rows) catch
            return error.ArithmeticOverflow;
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(PreprocessedRow, row_count);
        errdefer allocator.free(rows);
        for (rows, 0..) |*row, row_index| row.* = try expectedRow(
            claim_preprocessing.shape,
            input_words,
            output_words,
            input_rows,
            output_rows,
            row_index,
        );
        const authority_digest = preprocessingDigest(
            claim_preprocessing.shape,
            word_count,
            log_size,
            claim_preprocessing.authority_digest,
            rows,
        );
        return .{
            .allocator = allocator,
            .shape = claim_preprocessing.shape,
            .claim_word_count = word_count,
            .input_word_count = input_words,
            .output_word_count = output_words,
            .input_row_count = input_rows,
            .output_row_count = output_rows,
            .log_size = log_size,
            .rows = rows,
            .claim_input_authority_digest = claim_preprocessing.authority_digest,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    /// Complete allocation-free schedule validation.
    pub fn validate(self: *const Preprocessed) Error!void {
        const word_count = try self.shape.wordCount();
        const input_words = try inputWordCount(self.shape);
        const output_words = try outputWordCount(self.shape);
        const input_rows = try laneRowCount(input_words);
        const output_rows = try laneRowCount(output_words);
        const row_count = std.math.add(usize, input_rows, output_rows) catch
            return error.ArithmeticOverflow;
        if (word_count != self.claim_word_count or self.rows.len != row_count or
            input_words != self.input_word_count or output_words != self.output_word_count or
            input_rows != self.input_row_count or output_rows != self.output_row_count or
            self.log_size != try traceLogSize(row_count))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows, 0..) |row, row_index| {
            try validatePreprocessedRow(row);
            if (!std.meta.eql(row, try expectedRow(
                self.shape,
                input_words,
                output_words,
                input_rows,
                output_rows,
                row_index,
            )))
                return error.AuthorityMismatch;
        }
        const actual = preprocessingDigest(
            self.shape,
            self.claim_word_count,
            self.log_size,
            self.claim_input_authority_digest,
            self.rows,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        claim_preprocessing: *const claim_input.Preprocessed,
    ) Error!void {
        try self.validate();
        try claim_preprocessing.validate();
        if (!std.meta.eql(self.shape, claim_preprocessing.shape) or
            self.claim_word_count != claim_preprocessing.rows.len or
            !std.mem.eql(
                u8,
                &self.claim_input_authority_digest,
                &claim_preprocessing.authority_digest,
            ))
        {
            return error.AuthorityMismatch;
        }
    }
};

pub const Source = union(ProofKind) {
    segment_leaf: []const M31,
    binary_node: void,
    empty_leaf: void,

    pub fn proofKind(self: Source) ProofKind {
        return std.meta.activeTag(self);
    }
};

pub const MainRow = struct {
    enabler: u32,
    previous: [STATE_WIDTH]M31,
    chunks: [RATE]M31,
    output: [STATE_WIDTH]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{M31.fromCanonical(self.enabler)} ++
            self.previous ++ self.chunks ++ self.output;
    }
};

pub fn inputWordCount(shape: Shape) Error!usize {
    const dynamic = std.math.mul(usize, shape.max_input_words, 3) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, 9, dynamic) catch error.ArithmeticOverflow;
}

pub fn outputWordCount(shape: Shape) Error!usize {
    const dynamic = std.math.mul(usize, shape.max_output_words, 5) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, 11, dynamic) catch error.ArithmeticOverflow;
}

pub fn laneRowCount(word_count: usize) Error!usize {
    const with_marker = std.math.add(usize, word_count, 1) catch
        return error.ArithmeticOverflow;
    return std.math.divCeil(usize, with_marker, RATE) catch
        return error.ArithmeticOverflow;
}

pub fn expectedRow(
    shape: Shape,
    input_words: usize,
    output_words: usize,
    input_rows: usize,
    output_rows: usize,
    row_index: usize,
) Error!PreprocessedRow {
    const total_rows = std.math.add(usize, input_rows, output_rows) catch
        return error.ArithmeticOverflow;
    if (row_index >= total_rows) return error.InvalidPreprocessedRow;
    const is_output = row_index >= input_rows;
    const io_kind: u32 = if (is_output)
        component.VM_PUBLIC_OUTPUT_KIND
    else
        component.VM_PUBLIC_INPUT_KIND;
    const step = if (is_output) row_index - input_rows else row_index;
    const row_count = if (is_output) output_rows else input_rows;
    const word_count = if (is_output) output_words else input_words;
    const capacity = if (is_output) shape.max_output_words else shape.max_input_words;
    if (step >= row_count or step >= m31.Modulus)
        return error.InvalidPreprocessedRow;
    var chunks = [_]Chunk{.{
        .source_mask = 0,
        .word_index = 0,
        .constant = 0,
    }} ** RATE;
    for (&chunks, 0..) |*chunk, slot| {
        const index = std.math.add(
            usize,
            std.math.mul(usize, step, RATE) catch return error.ArithmeticOverflow,
            slot,
        ) catch return error.ArithmeticOverflow;
        if (index == 0) {
            chunk.constant = if (is_output)
                component.PUBLIC_OUTPUT_TAG
            else
                component.PUBLIC_INPUT_TAG;
        } else if (index == 1) {
            chunk.constant = capacity & 0xffff;
        } else if (index == 2) {
            chunk.constant = capacity >> 16;
        } else if (index < word_count) {
            if (index >= m31.Modulus) return error.InvalidPreprocessedRow;
            chunk.* = .{
                .source_mask = 1,
                .word_index = @intCast(index),
                .constant = 0,
            };
        } else if (index == word_count) {
            chunk.constant = 1;
        }
    }
    return .{
        .row_mask = 1,
        .io_kind = io_kind,
        .step = @intCast(step),
        .first = @intFromBool(step == 0),
        .last = @intFromBool(step + 1 == row_count),
        .hash_domain = if (is_output)
            component.PUBLIC_OUTPUT_HASH_DOMAIN
        else
            component.PUBLIC_INPUT_HASH_DOMAIN,
        .chunks = chunks,
    };
}

pub fn materialize(
    shape: Shape,
    metadata: PreprocessedRow,
    words: []const M31,
    previous: [STATE_WIDTH]M31,
) MainRow {
    var chunks: [RATE]M31 = undefined;
    for (&chunks, metadata.chunks) |*target, chunk| target.* = if (chunk.source_mask == 1)
        words[sourceClaimIndex(shape, metadata.io_kind, chunk.word_index).?]
    else
        M31.fromCanonical(chunk.constant);
    var output = previous;
    for (chunks, 0..) |word, index| output[index] = output[index].add(word);
    poseidon2.permute(&output);
    return .{
        .enabler = 1,
        .previous = previous,
        .chunks = chunks,
        .output = output,
    };
}

/// Inverts row 12's two public-I/O projection schedules without allocating an
/// intermediate stream. This is also a precise executable statement of the
/// cross-component lookup boundary.
pub fn sourceClaimIndex(shape: Shape, io_kind: u32, io_index: u32) ?usize {
    const index: usize = io_index;
    if (io_kind == component.VM_PUBLIC_INPUT_KIND) {
        if (index >= 3 and index < 7) return 241 + index - 3;
        if (index >= 7 and index < 9) return 254 + index - 7;
        const input_words = inputWordCount(shape) catch return null;
        if (index >= 9 and index < input_words) return 256 + index - 9;
        return null;
    }
    if (io_kind != component.VM_PUBLIC_OUTPUT_KIND) return null;
    if (index >= 3 and index < 9) return 245 + index - 3;
    const output_tag = std.math.add(
        usize,
        256,
        std.math.mul(usize, shape.max_input_words, 3) catch return null,
    ) catch return null;
    if (index >= 9 and index < 11) return output_tag + 1 + index - 9;
    const output_words = outputWordCount(shape) catch return null;
    if (index < 11 or index >= output_words) return null;
    const offset = index - 11;
    return output_tag + 3 + (offset / 5) * 7 + offset % 5;
}

pub fn zeroMainRow() MainRow {
    return .{
        .enabler = 0,
        .previous = .{M31.zero()} ** STATE_WIDTH,
        .chunks = .{M31.zero()} ** RATE,
        .output = .{M31.zero()} ** STATE_WIDTH,
    };
}

pub fn permutationInput(row: MainRow) [STATE_WIDTH]M31 {
    var result = row.previous;
    for (row.chunks, 0..) |word, index| result[index] = result[index].add(word);
    return result;
}

pub fn callFor(row: MainRow) PoseidonCall {
    var input: [STATE_WIDTH]u32 = undefined;
    for (&input, permutationInput(row)) |*target, word| target.* = word.toU32();
    return .{
        .input = input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
}

pub fn validatePreprocessedRow(row: PreprocessedRow) Error!void {
    if (row.row_mask != 1 or
        (row.io_kind != component.VM_PUBLIC_INPUT_KIND and
            row.io_kind != component.VM_PUBLIC_OUTPUT_KIND) or
        row.step >= m31.Modulus or row.first > 1 or row.last > 1 or
        row.hash_domain >= m31.Modulus)
    {
        return error.InvalidPreprocessedRow;
    }
    for (row.chunks) |chunk| if (chunk.source_mask > 1 or
        chunk.word_index >= m31.Modulus or chunk.constant >= m31.Modulus)
    {
        return error.InvalidPreprocessedRow;
    };
}

pub fn validateMainRowFor(
    row: MainRow,
    metadata: PreprocessedRow,
    proof_kind: ProofKind,
) Error!void {
    if (row.enabler != @intFromBool(proof_kind == .segment_leaf))
        return error.InvalidWitnessRow;
    for (row.previous) |word| if (word.toU32() >= m31.Modulus or
        (proof_kind != .segment_leaf and !word.isZero()))
    {
        return error.InvalidWitnessRow;
    };
    for (row.output) |word| if (word.toU32() >= m31.Modulus or
        (proof_kind != .segment_leaf and !word.isZero()))
    {
        return error.InvalidWitnessRow;
    };
    for (row.chunks, metadata.chunks) |word, chunk| {
        if (word.toU32() >= m31.Modulus or
            (proof_kind != .segment_leaf and !word.isZero()) or
            (proof_kind == .segment_leaf and chunk.source_mask == 0 and
                word.toU32() != chunk.constant))
        {
            return error.InvalidWitnessRow;
        }
    }
    if (proof_kind == .segment_leaf and metadata.first == 1) {
        for (row.previous[0 .. STATE_WIDTH - 1]) |word| if (!word.isZero())
            return error.InvalidWitnessRow;
        if (row.previous[STATE_WIDTH - 1].toU32() != metadata.hash_domain) {
            return error.InvalidWitnessRow;
        }
    }
}

pub fn traceLogSize(row_count: usize) Error!u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.ArithmeticOverflow;
    const log_size: u32 = @max(MIN_LOG_SIZE, std.math.log2_int(usize, padded));
    if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return log_size;
}

pub fn preprocessingDigest(
    shape: Shape,
    word_count: usize,
    log_size: u32,
    claim_input_digest: digest.Digest,
    rows: []const PreprocessedRow,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPROCESSING_DOMAIN);
    hashInt(&hash, u16, PREPROCESSING_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u32, shape.max_input_words);
    hashInt(&hash, u32, shape.max_output_words);
    hashInt(&hash, u64, word_count);
    hashInt(&hash, u32, log_size);
    hash.update(&claim_input_digest);
    hashInt(&hash, u64, rows.len);
    for (rows) |row| hashPreprocessedRow(&hash, row);
    return hash.finalResult();
}

pub fn witnessDigest(
    proof_kind: ProofKind,
    preprocessing_digest: digest.Digest,
    claim_words_digest: digest.Digest,
    output_digests: [2][RATE]u32,
    rows: []const MainRow,
    calls: []const PoseidonCall,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(WITNESS_DOMAIN);
    hashInt(&hash, u16, WITNESS_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u8, @intFromEnum(proof_kind));
    hash.update(&preprocessing_digest);
    hash.update(&claim_words_digest);
    for (output_digests) |output_digest|
        for (output_digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u64, rows.len);
    for (rows) |row| hashMainRow(&hash, row);
    hashInt(&hash, u64, calls.len);
    for (calls) |call| hashCall(&hash, call);
    return hash.finalResult();
}

pub fn wordsDigest(words: []const M31) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-vm-public-io-hash-words/v1\x00");
    hashInt(&hash, u64, words.len);
    for (words) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

pub fn hashPreprocessedRow(hash: anytype, row: PreprocessedRow) void {
    hashInt(hash, u32, row.row_mask);
    hashInt(hash, u32, row.io_kind);
    hashInt(hash, u32, row.step);
    hashInt(hash, u32, row.first);
    hashInt(hash, u32, row.last);
    hashInt(hash, u32, row.hash_domain);
    for (row.chunks) |chunk| {
        hashInt(hash, u32, chunk.source_mask);
        hashInt(hash, u32, chunk.word_index);
        hashInt(hash, u32, chunk.constant);
    }
}

pub fn hashMainRow(hash: anytype, row: MainRow) void {
    hashInt(hash, u32, row.enabler);
    for (row.previous) |word| hashInt(hash, u32, word.toU32());
    for (row.chunks) |word| hashInt(hash, u32, word.toU32());
    for (row.output) |word| hashInt(hash, u32, word.toU32());
}

pub fn hashCall(hash: anytype, call: PoseidonCall) void {
    for (call.input) |word| hashInt(hash, u32, word);
    hashInt(hash, u8, @intFromBool(call.wide));
    hashInt(hash, u8, @intFromBool(call.io));
    hashInt(hash, u8, @intFromBool(call.narrow_output != null));
    if (call.narrow_output) |word| hashInt(hash, u32, word);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
