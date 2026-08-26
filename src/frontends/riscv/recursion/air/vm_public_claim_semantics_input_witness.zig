//! Authenticated profile and direct SoA witness for authority-spine row 15.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const air = @import("vm_public_claim_semantics_input.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-claim-semantics-reference/v1\x00";
pub const ProofKind = proof_kind_mod.ProofKind;
pub const MAIN_COLUMN_COUNT = air.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = air.PREPROCESSED_COLUMN_COUNT;

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    CircuitIdNotCanonical,
    InputCountMismatch,
    InputLayoutMismatch,
    InvalidBinding,
    InvalidWitnessValue,
    IoDigestLimbOutOfRange,
    LogSizeOutOfRange,
    NodeIdNotCanonical,
    NodeOrderNotCanonical,
    ReferenceDigestMismatch,
    UnknownIoKind,
    UseCountNotCanonical,
    WordIndexNotCanonical,
};

pub const Source = enum(u8) {
    claim = 0,
    statement = 1,
    selector = 2,
    private = 3,
    io_digest = 4,
};

pub const Binding = struct {
    source: Source,
    node_id: u32,
    use_count: u32,
    word_index: u32 = 0,
    io_kind: u32 = 0,
};

/// AIR-owned reference metadata.  Its digest is intended to be admitted by a
/// fixed circuit profile; proof data supplies values only, never bindings.
pub const Reference = struct {
    circuit_id: u32,
    bindings: []const Binding,
    authority_digest: digest.Digest,

    pub fn seal(circuit_id: u32, bindings: []const Binding) Error!Reference {
        try validateBindings(circuit_id, bindings);
        return .{
            .circuit_id = circuit_id,
            .bindings = bindings,
            .authority_digest = computeReferenceDigest(circuit_id, bindings),
        };
    }

    pub fn validate(self: Reference) Error!void {
        try validateBindings(self.circuit_id, self.bindings);
        const actual = computeReferenceDigest(self.circuit_id, self.bindings);
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.ReferenceDigestMismatch;
    }
};

pub const PreprocessedRow = struct {
    source: Source,
    circuit_id: u32,
    node_id: u32,
    use_count: u32,
    word_index: u32,
    io_kind: u32,

    pub fn values(self: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.one(),
            M31.fromU64(@intFromBool(self.source == .claim)),
            M31.fromU64(@intFromBool(self.source == .statement)),
            M31.fromU64(@intFromBool(self.source == .selector)),
            M31.fromU64(@intFromBool(self.source == .private)),
            M31.fromU64(@intFromBool(self.source == .io_digest)),
            M31.fromU64(self.io_kind),
            M31.fromU64(self.circuit_id),
            M31.fromU64(self.node_id),
            M31.fromU64(self.use_count),
            M31.fromU64(self.word_index),
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
        for (rows, reference.bindings) |*row, binding| row.* = .{
            .source = binding.source,
            .circuit_id = reference.circuit_id,
            .node_id = binding.node_id,
            .use_count = binding.use_count,
            .word_index = binding.word_index,
            .io_kind = binding.io_kind,
        };
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

    pub fn validateAgainst(
        self: *const Preprocessed,
        reference: Reference,
    ) Error!void {
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
            if (!std.meta.eql(row, PreprocessedRow{
                .source = binding.source,
                .circuit_id = reference.circuit_id,
                .node_id = binding.node_id,
                .use_count = binding.use_count,
                .word_index = binding.word_index,
                .io_kind = binding.io_kind,
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

/// Prepared values own their copy so profile checks cannot be invalidated by a
/// caller mutating the borrowed value slice after admission.
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
    statement_scope: M31,
) [air.LOGICAL_INPUT_COUNT]M31 {
    const selectors = kind.selectors();
    return main.values() ++ preprocessing.values() ++ .{
        selectors[0],
        claim_scope,
        statement_scope,
    };
}

pub fn computeReferenceDigest(
    circuit_id: u32,
    bindings: []const Binding,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashInt(&hash, u32, circuit_id);
    hashInt(&hash, u32, bindings.len);
    for (bindings) |binding| {
        hashInt(&hash, u8, @intFromEnum(binding.source));
        hashInt(&hash, u32, binding.node_id);
        hashInt(&hash, u32, binding.use_count);
        hashInt(&hash, u32, binding.word_index);
        hashInt(&hash, u32, binding.io_kind);
    }
    return hash.finalResult();
}

fn validateBindings(circuit_id: u32, bindings: []const Binding) Error!void {
    if (circuit_id >= m31.Modulus) return error.CircuitIdNotCanonical;
    if (bindings.len == 0) return error.InputCountMismatch;
    var previous_node: ?u32 = null;
    for (bindings) |binding| {
        if (binding.node_id >= m31.Modulus) return error.NodeIdNotCanonical;
        if (binding.use_count >= m31.Modulus) return error.UseCountNotCanonical;
        if (binding.word_index >= m31.Modulus) return error.WordIndexNotCanonical;
        if (previous_node) |previous| {
            if (binding.node_id <= previous) return error.NodeOrderNotCanonical;
        }
        previous_node = binding.node_id;
        switch (binding.source) {
            .claim, .statement => if (binding.io_kind != 0)
                return error.InvalidBinding,
            .selector, .private => if (binding.word_index != 0 or binding.io_kind != 0)
                return error.InvalidBinding,
            .io_digest => {
                if (binding.io_kind > 1) return error.UnknownIoKind;
                if (binding.word_index >= 8) return error.IoDigestLimbOutOfRange;
            },
        }
    }
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
        .selector => if (value.toU32() != @intFromBool(active))
            return error.InvalidWitnessValue,
        .claim, .statement, .private, .io_digest => if (!active and !value.isZero())
            return error.InvalidWitnessValue,
    }
}

fn validatePreprocessedRow(row: PreprocessedRow) direct.Error!void {
    if (row.circuit_id >= m31.Modulus or row.node_id >= m31.Modulus or
        row.use_count >= m31.Modulus or row.word_index >= m31.Modulus)
    {
        return error.InvalidTraceRow;
    }
    switch (row.source) {
        .claim, .statement => if (row.io_kind != 0) return error.InvalidTraceRow,
        .selector, .private => if (row.word_index != 0 or row.io_kind != 0)
            return error.InvalidTraceRow,
        .io_digest => if (row.io_kind > 1 or row.word_index >= 8)
            return error.InvalidTraceRow,
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

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
