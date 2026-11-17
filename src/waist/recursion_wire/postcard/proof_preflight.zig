//! Allocation-free structural preflight for the postcard `StarkProof` wire.
//!
//! The ordinary decoder allocates each length-prefixed sequence as it is read.
//! External proof bytes must pass this exact-shape walk first so an attacker
//! cannot turn a small payload into a large allocation request.

const std = @import("std");

const TREE_COUNT: usize = 4;
// These are allocation-safety limits, not an AIR mask declaration. Exact mask
// widths are reconstructed from the production components by the verifier.
pub const DEFAULT_SAMPLE_WIDTH_LIMITS = [TREE_COUNT]u32{ 2, 2, 2, 1 };

pub const Config = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    n_queries: u64,
    log_last_layer_degree_bound: u32,
    fold_step: u32,
    lifting_log_size: ?u32,
};

/// Postcard representation of one Merkle hash.
///
/// Blake-family hashes are fixed byte arrays and therefore occupy exactly
/// `hash_size` bytes.  Poseidon hashes are arrays of M31 words; postcard
/// serializes each word as a canonical varint, so their encoded size is not
/// fixed and every word must be parsed rather than skipped.
pub const HashEncoding = enum {
    raw_bytes,
    canonical_m31_words,
};

/// Shape known before proof decoding from an independently validated statement.
pub const Shape = struct {
    config: Config,
    /// Preprocessed, main, interaction, and composition column counts.
    tree_columns: [TREE_COUNT]u32,
    /// Fixed-only provider proofs may commit an empty main tree. Other tree
    /// counts remain nonzero, and the parser still checks exact zero vectors.
    allow_empty_main_tree: bool = false,
    /// Maximum column log size after composition splitting and before FRI.
    max_column_log_size: u32,
    /// Optional larger Merkle-path bound for reused native fixed/main trees.
    /// Zero keeps the original four-tree admission behavior.
    max_merkle_column_log_size: u32 = 0,
    /// A same-root adapter may open only selected native source columns.
    /// The AIR verifier, not this allocation guard, checks exact masks.
    allow_zero_samples: bool = false,
    /// Allocation-safety bounds for sampled values per column in each tree.
    ///
    /// The default preserves the released V1 proof-artifact admission policy.
    /// Profiles whose statically authenticated AIR masks are wider must opt in
    /// through their statement-derived shape rather than artifact bytes.
    sample_width_limits: [TREE_COUNT]u32 = DEFAULT_SAMPLE_WIDTH_LIMITS,
    /// In-memory hash width.  For `canonical_m31_words` this must be a
    /// non-zero multiple of four and determines the number of M31 words.
    hash_size: u32,
    hash_encoding: HashEncoding = .raw_bytes,
    max_wire_bytes: usize,
};

/// Block-v2 same-root execution sidecars commit native fixed/main, sidecar
/// witness/interaction, then composition: five trees in one STARK.
pub const Shape5 = struct {
    config: Config,
    tree_columns: [5]u32,
    allow_empty_main_tree: bool = false,
    /// FRI layers follow the last (composition) commitment's lifting log.
    max_column_log_size: u32,
    /// Replayed native fixed/main columns may have larger logs but need only
    /// Merkle-path resource bounds when sampled by the sidecar.
    max_merkle_column_log_size: u32,
    allow_zero_samples: bool = true,
    sample_width_limits: [5]u32 = .{ 1, 1, 1, 2, 1 },
    hash_size: u32,
    hash_encoding: HashEncoding = .raw_bytes,
    max_wire_bytes: usize,
};

/// Independent multi-tree component inventories. N is a compile-time protocol
/// choice, never a length decoded from an untrusted artifact. Existing four-
/// and five-tree APIs retain their released behavior and default masks.
pub const MAX_TYPED_TREES: usize = 16;
pub fn ShapeFor(comptime N: usize) type {
    if (N < 2 or N > MAX_TYPED_TREES) @compileError("unsupported typed proof tree count");
    return struct {
        config: Config,
        tree_columns: [N]u32,
        allow_empty_main_tree: bool = false,
        max_column_log_size: u32,
        max_merkle_column_log_size: u32 = 0,
        allow_zero_samples: bool = false,
        // Mandatory independent allocation bounds; no inferred/default masks.
        sample_width_limits: [N]u32,
        hash_size: u32,
        hash_encoding: HashEncoding = .raw_bytes,
        max_wire_bytes: usize,
    };
}
pub fn validateFor(comptime N: usize, raw: []const u8, shape: ShapeFor(N)) Error!void {
    // Large width envelopes must not be accidentally selected as mask policy.
    // Actual point masks remain independently checked by the AIR receiver.
    for (shape.sample_width_limits) |width| if (width == 0 or width > 16) return error.InvalidPreflightShape;
    return validateInternal(raw, shape, null);
}

pub const Error = error{
    EndOfStream,
    InvalidOptionTag,
    InvalidProofConfig,
    InvalidProofShape,
    InvalidPreflightShape,
    NonCanonicalM31,
    NonCanonicalVarint,
    ProofResourceLimitExceeded,
    TrailingProofBytes,
    VarintOverflow,
};

/// Typed, allocation-free localization for the first proof-shape mismatch.
///
/// This is diagnostic telemetry only.  `validateWithDiagnostic` executes the
/// same admission parser and returns the same error set as `validate`.
pub const DiagnosticStage = enum {
    commitment_tree_count,
    sampled_tree_count,
    sampled_column_count,
    sampled_width,
    decommitment_tree_count,
    queried_tree_count,
    queried_column_count,
    fri_inner_layer_count,
    fri_last_coefficient_count,
};

pub const Diagnostic = struct {
    stage: DiagnosticStage,
    tree: ?u32,
    index: ?u32,
    offset: usize,
    actual: usize,
    expected: usize,
};

/// Validate every length prefix and scalar without allocating.
pub fn validate(raw: []const u8, shape: Shape) Error!void {
    return validateInternal(raw, shape, null);
}

pub fn validateFive(raw: []const u8, shape: Shape5) Error!void {
    return validateInternal(raw, shape, null);
}

/// Run the canonical preflight while retaining only its first exact mismatch.
pub fn validateWithDiagnostic(
    raw: []const u8,
    shape: Shape,
    diagnostic: *?Diagnostic,
) Error!void {
    diagnostic.* = null;
    return validateInternal(raw, shape, diagnostic);
}

fn validateInternal(
    raw: []const u8,
    shape: anytype,
    diagnostic: ?*?Diagnostic,
) Error!void {
    const bounds = try Bounds.init(shape);
    if (raw.len > shape.max_wire_bytes) return error.ProofResourceLimitExceeded;

    var cursor = Cursor{ .bytes = raw };
    try expectConfig(&cursor, shape.config);

    try expectCountAt(
        &cursor,
        shape.tree_columns.len,
        diagnostic,
        .commitment_tree_count,
        null,
        null,
    );
    for (0..shape.tree_columns.len) |_| try skipHash(&cursor, bounds);

    try expectCountAt(
        &cursor,
        shape.tree_columns.len,
        diagnostic,
        .sampled_tree_count,
        null,
        null,
    );
    for (shape.tree_columns, shape.sample_width_limits, 0..) |
        column_count,
        sample_width_limit,
        tree_index,
    | {
        try expectCountAt(
            &cursor,
            column_count,
            diagnostic,
            .sampled_column_count,
            @intCast(tree_index),
            null,
        );
        for (0..column_count) |column_index| {
            const sample_width_offset = cursor.position;
            const sample_width = try cursor.readUsize();
            if (sample_width == 0 and !(if (@hasField(@TypeOf(shape), "allow_zero_samples")) shape.allow_zero_samples else false)) {
                recordMismatch(
                    diagnostic,
                    .sampled_width,
                    @intCast(tree_index),
                    @intCast(column_index),
                    sample_width_offset,
                    sample_width,
                    1,
                );
                return error.InvalidProofShape;
            }
            if (sample_width > sample_width_limit)
                return error.ProofResourceLimitExceeded;
            for (0..sample_width) |_| try cursor.readQm31();
        }
    }

    try expectCountAt(
        &cursor,
        shape.tree_columns.len,
        diagnostic,
        .decommitment_tree_count,
        null,
        null,
    );
    for (0..shape.tree_columns.len) |_| try skipHashWitness(&cursor, bounds);

    try expectCountAt(
        &cursor,
        shape.tree_columns.len,
        diagnostic,
        .queried_tree_count,
        null,
        null,
    );
    for (shape.tree_columns, 0..) |column_count, tree_index| {
        try expectCountAt(
            &cursor,
            column_count,
            diagnostic,
            .queried_column_count,
            @intCast(tree_index),
            null,
        );
        for (0..column_count) |_| {
            const value_count = try cursor.readUsize();
            if (value_count > bounds.n_queries) return error.ProofResourceLimitExceeded;
            for (0..value_count) |_| try cursor.readM31();
        }
    }

    _ = try cursor.readVarint(); // proof of work
    try readFriLayer(&cursor, bounds);

    try expectCountAt(
        &cursor,
        bounds.inner_layer_count,
        diagnostic,
        .fri_inner_layer_count,
        null,
        null,
    );
    for (0..bounds.inner_layer_count) |_| try readFriLayer(&cursor, bounds);

    try expectCountAt(
        &cursor,
        bounds.last_layer_coefficients,
        diagnostic,
        .fri_last_coefficient_count,
        null,
        null,
    );
    for (0..bounds.last_layer_coefficients) |_| try cursor.readQm31();

    if (cursor.position != raw.len) return error.TrailingProofBytes;
}

const Bounds = struct {
    n_queries: usize,
    hash_size: usize,
    max_hash_witnesses: usize,
    max_fri_witnesses: usize,
    inner_layer_count: usize,
    last_layer_coefficients: usize,
    hash_encoding: HashEncoding,
    hash_word_count: usize,

    fn init(shape: anytype) Error!Bounds {
        const config = shape.config;
        if (shape.max_wire_bytes == 0 or shape.hash_size == 0 or
            config.n_queries == 0 or config.n_queries > std.math.maxInt(usize) or
            config.fold_step == 0 or config.fold_step > 16 or
            config.log_blowup_factor > 16 or
            config.log_last_layer_degree_bound > 30 or
            shape.max_column_log_size > 30 or
            shape.max_column_log_size < config.log_last_layer_degree_bound)
            return error.InvalidPreflightShape;
        for (shape.tree_columns, 0..) |count, index| {
            if (count == 0 and !(shape.allow_empty_main_tree and index == 1))
                return error.InvalidPreflightShape;
        }
        for (shape.sample_width_limits) |limit| {
            if (limit == 0) return error.InvalidPreflightShape;
        }
        const hash_word_count: usize = switch (shape.hash_encoding) {
            .raw_bytes => 0,
            .canonical_m31_words => blk: {
                if (shape.hash_size % @sizeOf(u32) != 0)
                    return error.InvalidPreflightShape;
                break :blk @intCast(shape.hash_size / @sizeOf(u32));
            },
        };

        const n_queries: usize = @intCast(config.n_queries);
        const merkle_log = if (shape.max_merkle_column_log_size != 0)
            shape.max_merkle_column_log_size
        else
            shape.max_column_log_size;
        if (merkle_log > 30) return error.InvalidPreflightShape;
        const merkle_depth_u32 = std.math.add(
            u32,
            merkle_log,
            config.log_blowup_factor + 1,
        ) catch return error.InvalidPreflightShape;
        const merkle_depth: usize = @intCast(merkle_depth_u32);
        const max_hash_witnesses = multiply(n_queries, merkle_depth) catch
            return error.InvalidPreflightShape;

        const subset_size = @as(usize, 1) << @intCast(config.fold_step);
        const max_fri_witnesses = multiply(n_queries, subset_size - 1) catch
            return error.InvalidPreflightShape;
        const inner_layer_count = try expectedInnerLayers(
            shape.max_column_log_size,
            config.log_last_layer_degree_bound,
            config.fold_step,
        );
        const last_layer_coefficients = @as(usize, 1) <<
            @intCast(config.log_last_layer_degree_bound);

        return .{
            .n_queries = n_queries,
            .hash_size = shape.hash_size,
            .max_hash_witnesses = max_hash_witnesses,
            .max_fri_witnesses = max_fri_witnesses,
            .inner_layer_count = inner_layer_count,
            .last_layer_coefficients = last_layer_coefficients,
            .hash_encoding = shape.hash_encoding,
            .hash_word_count = hash_word_count,
        };
    }
};

fn expectedInnerLayers(max_log: u32, last_log: u32, fold_step: u32) Error!usize {
    if (max_log < fold_step) return error.InvalidPreflightShape;
    const after_first = max_log - fold_step;
    if (after_first < last_log) return error.InvalidPreflightShape;
    const remaining = after_first - last_log;
    const rounds = std.math.divCeil(u32, remaining, fold_step) catch
        return error.InvalidPreflightShape;
    return @intCast(rounds);
}

fn readFriLayer(cursor: *Cursor, bounds: Bounds) Error!void {
    const witness_count = try cursor.readUsize();
    if (witness_count > bounds.max_fri_witnesses)
        return error.ProofResourceLimitExceeded;
    for (0..witness_count) |_| try cursor.readQm31();
    try skipHashWitness(cursor, bounds);
    try skipHash(cursor, bounds);
}

fn skipHashWitness(cursor: *Cursor, bounds: Bounds) Error!void {
    const hash_count = try cursor.readUsize();
    if (hash_count > bounds.max_hash_witnesses)
        return error.ProofResourceLimitExceeded;
    switch (bounds.hash_encoding) {
        .raw_bytes => try cursor.skip(try multiply(hash_count, bounds.hash_size)),
        .canonical_m31_words => {
            for (0..hash_count) |_| try skipHash(cursor, bounds);
        },
    }
}

fn skipHash(cursor: *Cursor, bounds: Bounds) Error!void {
    switch (bounds.hash_encoding) {
        .raw_bytes => try cursor.skip(bounds.hash_size),
        .canonical_m31_words => {
            for (0..bounds.hash_word_count) |_| try cursor.readM31();
        },
    }
}

fn multiply(left: usize, right: usize) Error!usize {
    return std.math.mul(usize, left, right) catch
        return error.ProofResourceLimitExceeded;
}

const cursor_owner = @import("proof_preflight_cursor.zig");
const Cursor = cursor_owner.Cursor;
const expectConfig = cursor_owner.expectConfig;
const expectCount = cursor_owner.expectCount;
const expectCountAt = cursor_owner.expectCountAt;
const recordMismatch = cursor_owner.recordMismatch;

test {
    _ = @import("proof_preflight_test.zig");
}
