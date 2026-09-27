//! Canonical O(n) profile admission and direct SoA witness for row 16.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const air = @import("vm_public_logup_input.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-logup-reference/v1\x00";
pub const CHALLENGE_WORD_COUNT: u32 = 8;
pub const QM31_LIMB_COUNT: u32 = 4;
/// Native public LogUp relation order: registers-state, memory-access,
/// program-access, then Merkle.  The program relation is mandatory for the
/// V1 self-loop completion term and may not be omitted from row 16.
pub const CHALLENGES = [_]u32{ 0, 1, 2, 3 };
pub const MAIN_COLUMN_COUNT = air.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = air.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    CircuitIdNotCanonical,
    InputCountMismatch,
    InputLayoutMismatch,
    InvalidWitnessValue,
    LogSizeOutOfRange,
    NodeIdNotCanonical,
    NodeOrderNotCanonical,
    ReferenceDigestMismatch,
    SourceOrderMismatch,
    UseCountNotCanonical,
};

pub const ClaimKind = enum(u8) {
    constant = 0,
    boolean = 1,
    u16 = 2,
    field = 3,
};

pub const Source = union(enum) {
    claim_word: u32,
    claim_byte: struct { word_index: u32, byte_index: u32 },
    relation_challenge_word: struct { challenge: u32, word_index: u32 },
    claimed_sum_word: struct { item_index: u32, limb_index: u32 },
    segment_selector,
};

pub const Binding = struct {
    node_id: u32,
    use_count: u32,
    source: Source,
};

/// The canonical source sequence is validated in one linear pass: selector;
/// claim words with adjacent bytes for U16 words; challenges 0 through 3;
/// then every claimed-sum limb. No hash set or quadratic duplicate scan is on
/// this cold path.
pub const Reference = struct {
    circuit_id: u32,
    claim_kinds: []const ClaimKind,
    claimed_sum_count: u32,
    bindings: []const Binding,
    authority_digest: digest.Digest,

    pub fn seal(
        circuit_id: u32,
        claim_kinds: []const ClaimKind,
        claimed_sum_count: u32,
        bindings: []const Binding,
    ) Error!Reference {
        try validateLayout(circuit_id, claim_kinds, claimed_sum_count, bindings);
        return .{
            .circuit_id = circuit_id,
            .claim_kinds = claim_kinds,
            .claimed_sum_count = claimed_sum_count,
            .bindings = bindings,
            .authority_digest = computeReferenceDigest(
                circuit_id,
                claim_kinds,
                claimed_sum_count,
                bindings,
            ),
        };
    }

    pub fn validate(self: Reference) Error!void {
        try validateLayout(
            self.circuit_id,
            self.claim_kinds,
            self.claimed_sum_count,
            self.bindings,
        );
        const actual = computeReferenceDigest(
            self.circuit_id,
            self.claim_kinds,
            self.claimed_sum_count,
            self.bindings,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.ReferenceDigestMismatch;
    }
};

pub const PreprocessedRow = struct {
    source: Source,
    circuit_id: u32,
    node_id: u32,
    use_count: u32,
    source_index_0: u32,
    source_index_1: u32,

    pub fn values(self: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.one(),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.source) == .claim_word)),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.source) == .claim_byte)),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.source) == .relation_challenge_word)),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.source) == .claimed_sum_word)),
            M31.fromU64(@intFromBool(std.meta.activeTag(self.source) == .segment_selector)),
            M31.fromU64(self.circuit_id),
            M31.fromU64(self.node_id),
            M31.fromU64(self.use_count),
            M31.fromU64(self.source_index_0),
            M31.fromU64(self.source_index_1),
        };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []PreprocessedRow,
    reference_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        reference: Reference,
    ) Error!Preprocessed {
        try reference.validate();
        const log_size = try traceLogSize(reference.bindings.len);
        const rows = try allocator.alloc(PreprocessedRow, reference.bindings.len);
        errdefer allocator.free(rows);
        for (rows, reference.bindings) |*row, binding| {
            const indices = sourceIndices(binding.source);
            row.* = .{
                .source = binding.source,
                .circuit_id = reference.circuit_id,
                .node_id = binding.node_id,
                .use_count = binding.use_count,
                .source_index_0 = indices[0],
                .source_index_1 = indices[1],
            };
        }
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .reference_digest = reference.authority_digest,
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Preprocessed, reference: Reference) Error!void {
        try reference.validate();
        if (!std.mem.eql(
            u8,
            &self.reference_digest,
            &reference.authority_digest,
        ) or self.rows.len != reference.bindings.len or
            self.log_size != try traceLogSize(reference.bindings.len))
        {
            return error.InputLayoutMismatch;
        }
        for (self.rows, reference.bindings) |row, binding| {
            const indices = sourceIndices(binding.source);
            if (!std.meta.eql(row, PreprocessedRow{
                .source = binding.source,
                .circuit_id = reference.circuit_id,
                .node_id = binding.node_id,
                .use_count = binding.use_count,
                .source_index_0 = indices[0],
                .source_index_1 = indices[1],
            })) return error.InputLayoutMismatch;
        }
    }

    pub fn generateInto(
        self: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        reference: Reference,
    ) Error!void {
        try self.validateAgainst(reference);
        return direct.generateMainInto(
            M31,
            PreprocessedRow,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            self,
            validatePreprocessedRow,
            writePreprocessedRow,
        );
    }
};

pub const MainRow = struct {
    value: M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ M31.one(), self.value };
    }
};

pub const MainWitness = struct {
    allocator: std.mem.Allocator,
    rows: []MainRow,
    proof_kind: ProofKind,
    reference_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        reference: Reference,
        values: []const M31,
        proof_kind: ProofKind,
    ) Error!MainWitness {
        try preprocessing.validateAgainst(reference);
        if (values.len != preprocessing.rows.len)
            return error.InputCountMismatch;
        const rows = try allocator.alloc(MainRow, values.len);
        errdefer allocator.free(rows);
        for (rows, values, preprocessing.rows) |*row, value, metadata| {
            try validateValue(metadata.source, value, proof_kind);
            row.* = .{ .value = value };
        }
        return .{
            .allocator = allocator,
            .rows = rows,
            .proof_kind = proof_kind,
            .reference_digest = preprocessing.reference_digest,
        };
    }

    pub fn deinit(self: *MainWitness) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
    ) Error!void {
        if (!std.mem.eql(
            u8,
            &self.reference_digest,
            &preprocessing.reference_digest,
        ) or self.rows.len != preprocessing.rows.len) {
            return error.InputLayoutMismatch;
        }
        for (self.rows, preprocessing.rows) |row, metadata|
            try validateValue(metadata.source, row.value, self.proof_kind);
    }

    pub fn generateInto(
        self: *const MainWitness,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        preprocessing: *const Preprocessed,
    ) Error!void {
        try self.validateAgainst(preprocessing);
        return direct.generateMainInto(
            M31,
            MainRow,
            MAIN_COLUMN_COUNT,
            columns,
            self.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validateMainRow,
            writeMainRow,
        );
    }
};

pub fn logicalInputs(
    main: MainRow,
    preprocessing: PreprocessedRow,
    kind: ProofKind,
    claim_scope: M31,
    verifier_id: M31,
    challenge_scope: M31,
    claimed_sum_kind: M31,
) [air.LOGICAL_INPUT_COUNT]M31 {
    const selectors = kind.selectors();
    return main.values() ++ preprocessing.values() ++ .{
        selectors[0],
        claim_scope,
        verifier_id,
        challenge_scope,
        claimed_sum_kind,
    };
}

pub fn computeReferenceDigest(
    circuit_id: u32,
    claim_kinds: []const ClaimKind,
    claimed_sum_count: u32,
    bindings: []const Binding,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashInt(&hash, u32, circuit_id);
    hashInt(&hash, u32, claim_kinds.len);
    for (claim_kinds) |kind| hashInt(&hash, u8, @intFromEnum(kind));
    hashInt(&hash, u32, claimed_sum_count);
    hashInt(&hash, u32, bindings.len);
    for (bindings) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashInt(&hash, u32, binding.use_count);
        hashSource(&hash, binding.source);
    }
    return hash.finalResult();
}

fn validateLayout(
    circuit_id: u32,
    claim_kinds: []const ClaimKind,
    claimed_sum_count: u32,
    bindings: []const Binding,
) Error!void {
    if (circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
    const expected_count = try expectedInputCount(claim_kinds, claimed_sum_count);
    if (bindings.len != expected_count) return error.InputCountMismatch;
    var cursor: usize = 0;
    try expectSource(bindings, &cursor, .segment_selector);
    for (claim_kinds, 0..) |kind, word_index| {
        const index: u32 = @intCast(word_index);
        try expectSource(bindings, &cursor, .{ .claim_word = index });
        if (kind == .u16) {
            try expectSource(bindings, &cursor, .{ .claim_byte = .{
                .word_index = index,
                .byte_index = 0,
            } });
            try expectSource(bindings, &cursor, .{ .claim_byte = .{
                .word_index = index,
                .byte_index = 1,
            } });
        }
    }
    for (CHALLENGES) |challenge| for (0..CHALLENGE_WORD_COUNT) |word_index|
        try expectSource(bindings, &cursor, .{ .relation_challenge_word = .{
            .challenge = challenge,
            .word_index = @intCast(word_index),
        } });
    for (0..claimed_sum_count) |item_index| for (0..QM31_LIMB_COUNT) |limb_index|
        try expectSource(bindings, &cursor, .{ .claimed_sum_word = .{
            .item_index = @intCast(item_index),
            .limb_index = @intCast(limb_index),
        } });
    std.debug.assert(cursor == bindings.len);

    var previous_node: ?u32 = null;
    for (bindings) |binding| {
        if (binding.node_id >= m31.Modulus) return error.NodeIdNotCanonical;
        if (binding.use_count >= m31.Modulus) return error.UseCountNotCanonical;
        if (previous_node) |previous| if (binding.node_id <= previous)
            return error.NodeOrderNotCanonical;
        previous_node = binding.node_id;
    }
}

fn expectedInputCount(
    claim_kinds: []const ClaimKind,
    claimed_sum_count: u32,
) Error!usize {
    var count: usize = 1;
    for (claim_kinds) |kind| count = std.math.add(
        usize,
        count,
        if (kind == .u16) 3 else 1,
    ) catch return error.ArithmeticOverflow;
    count = std.math.add(
        usize,
        count,
        CHALLENGES.len * CHALLENGE_WORD_COUNT,
    ) catch return error.ArithmeticOverflow;
    count = std.math.add(
        usize,
        count,
        std.math.mul(usize, claimed_sum_count, QM31_LIMB_COUNT) catch
            return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
    return count;
}

fn expectSource(
    bindings: []const Binding,
    cursor: *usize,
    expected: Source,
) Error!void {
    if (cursor.* >= bindings.len or
        !std.meta.eql(bindings[cursor.*].source, expected))
    {
        return error.SourceOrderMismatch;
    }
    cursor.* += 1;
}

fn sourceIndices(source_value: Source) [2]u32 {
    return switch (source_value) {
        .claim_word => |index| .{ index, 0 },
        .claim_byte => |item| .{ item.word_index, item.byte_index },
        .relation_challenge_word => |item| .{ item.challenge, item.word_index },
        .claimed_sum_word => |item| .{ item.item_index, item.limb_index },
        .segment_selector => .{ 0, 0 },
    };
}

fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, row_count))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn validateValue(source_value: Source, value: M31, kind: ProofKind) Error!void {
    const active = kind == .segment_leaf;
    switch (source_value) {
        .segment_selector => if (value.toU32() != @intFromBool(active))
            return error.InvalidWitnessValue,
        else => if (!active and !value.isZero()) return error.InvalidWitnessValue,
    }
}

fn validatePreprocessedRow(row: PreprocessedRow) direct.Error!void {
    if (row.circuit_id >= m31.Modulus or row.node_id >= m31.Modulus or
        row.use_count >= m31.Modulus or row.source_index_0 >= m31.Modulus or
        row.source_index_1 >= m31.Modulus or
        !std.meta.eql(sourceIndices(row.source), .{
            row.source_index_0,
            row.source_index_1,
        }))
    {
        return error.InvalidTraceRow;
    }
}

fn validateMainRow(_: MainRow) direct.Error!void {}

fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: PreprocessedRow,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: MainRow,
) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

fn hashSource(hash: anytype, source_value: Source) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source_value)));
    const indices = sourceIndices(source_value);
    hashInt(hash, u32, indices[0]);
    hashInt(hash, u32, indices[1]);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
