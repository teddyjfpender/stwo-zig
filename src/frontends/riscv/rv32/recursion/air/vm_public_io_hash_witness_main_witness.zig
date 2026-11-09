//! Internal vm public io hash witness authority shard; use vm_public_io_hash_witness.zig publicly.

const dependency_0 = @import("vm_public_io_hash_witness_contract.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const MainRow = dependency_0.MainRow;
const POSEIDON_MAIN_COLUMN_COUNT = dependency_0.POSEIDON_MAIN_COLUMN_COUNT;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const PoseidonCall = dependency_0.PoseidonCall;
const Preprocessed = dependency_0.Preprocessed;
const PreprocessedRow = dependency_0.PreprocessedRow;
const ProofKind = dependency_0.ProofKind;
const RATE = dependency_0.RATE;
const STATE_WIDTH = dependency_0.STATE_WIDTH;
const Source = dependency_0.Source;
const callFor = dependency_0.callFor;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const m31 = dependency_0.m31;
const materialize = dependency_0.materialize;
const poseidon_executor = dependency_0.poseidon_executor;
const std = dependency_0.std;
const validateMainRowFor = dependency_0.validateMainRowFor;
const validatePreprocessedRow = dependency_0.validatePreprocessedRow;
const witnessDigest = dependency_0.witnessDigest;
const wordsDigest = dependency_0.wordsDigest;
const zeroMainRow = dependency_0.zeroMainRow;

pub const PoseidonExecutor = poseidon_executor.Executor;

pub const MainWitness = struct {
    allocator: std.mem.Allocator,
    proof_kind: ProofKind,
    rows: []MainRow,
    poseidon_calls: []PoseidonCall,
    preprocessing_digest: digest.Digest,
    claim_words_digest: digest.Digest,
    output_digests: [2][RATE]u32,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        source_value: Source,
    ) Error!MainWitness {
        return switch (source_value) {
            .segment_leaf => |values| initRaw(
                allocator,
                preprocessing,
                .segment_leaf,
                values,
            ),
            .binary_node => initRaw(allocator, preprocessing, .binary_node, null),
            .empty_leaf => initRaw(allocator, preprocessing, .empty_leaf, null),
        };
    }

    /// Admission boundary for decoded wire data where proof kind and optional
    /// claim arrive independently. The typed `Source` constructor makes these
    /// invalid combinations unrepresentable for ordinary in-process callers.
    pub fn initRaw(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        proof_kind: ProofKind,
        words: ?[]const M31,
    ) Error!MainWitness {
        try preprocessing.validate();
        if (proof_kind == .segment_leaf) {
            if (words == null) return error.SegmentClaimMissing;
            if (words.?.len != preprocessing.claim_word_count)
                return error.WordCountMismatch;
            for (words.?) |word| if (word.toU32() >= m31.Modulus)
                return error.InvalidFieldElement;
        } else if (words != null) {
            return error.InactiveClaimProvided;
        }

        const rows = try allocator.alloc(MainRow, preprocessing.rows.len);
        errdefer allocator.free(rows);
        const call_count = if (proof_kind == .segment_leaf) preprocessing.rows.len else 0;
        const calls = try allocator.alloc(PoseidonCall, call_count);
        errdefer allocator.free(calls);

        var state = [_]M31{M31.zero()} ** STATE_WIDTH;
        var call_cursor: usize = 0;
        var output_digests = [_][RATE]u32{.{0} ** RATE} ** 2;
        for (rows, preprocessing.rows) |*target, metadata| {
            if (proof_kind != .segment_leaf) {
                target.* = zeroMainRow();
                continue;
            }
            if (metadata.first == 1) {
                state = .{M31.zero()} ** STATE_WIDTH;
                state[STATE_WIDTH - 1] = M31.fromCanonical(metadata.hash_domain);
            }
            const main_row = materialize(preprocessing.shape, metadata, words.?, state);
            target.* = main_row;
            state = main_row.output;
            calls[call_cursor] = callFor(main_row);
            call_cursor += 1;
            if (metadata.last == 1) {
                const kind: usize = @intCast(metadata.io_kind);
                for (&output_digests[kind], state[0..RATE]) |*digest_word, word|
                    digest_word.* = word.toU32();
            }
        }
        std.debug.assert(call_cursor == calls.len);
        const claim_words_digest = wordsDigest(words orelse &.{});
        const authority_digest = witnessDigest(
            proof_kind,
            preprocessing.authority_digest,
            claim_words_digest,
            output_digests,
            rows,
            calls,
        );
        return .{
            .allocator = allocator,
            .proof_kind = proof_kind,
            .rows = rows,
            .poseidon_calls = calls,
            .preprocessing_digest = preprocessing.authority_digest,
            .claim_words_digest = claim_words_digest,
            .output_digests = output_digests,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *MainWitness) void {
        self.allocator.free(self.poseidon_calls);
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
    ) Error!void {
        try preprocessing.validate();
        const expected_calls = if (self.proof_kind == .segment_leaf) self.rows.len else 0;
        if (self.rows.len != preprocessing.rows.len or
            self.poseidon_calls.len != expected_calls or
            !std.mem.eql(u8, &self.preprocessing_digest, &preprocessing.authority_digest))
        {
            return error.AuthorityMismatch;
        }
        var state = [_]M31{M31.zero()} ** STATE_WIDTH;
        var call_cursor: usize = 0;
        var expected_digests = [_][RATE]u32{.{0} ** RATE} ** 2;
        for (self.rows, preprocessing.rows) |row, metadata| {
            try validateMainRowFor(row, metadata, self.proof_kind);
            if (self.proof_kind == .segment_leaf) {
                if (metadata.first == 1) {
                    state = .{M31.zero()} ** STATE_WIDTH;
                    state[STATE_WIDTH - 1] = M31.fromCanonical(metadata.hash_domain);
                }
                if (!std.meta.eql(row.previous, state)) return error.AuthorityMismatch;
                if (!std.meta.eql(self.poseidon_calls[call_cursor], callFor(row))) {
                    return error.AuthorityMismatch;
                }
                state = row.output;
                call_cursor += 1;
                if (metadata.last == 1) {
                    const kind: usize = @intCast(metadata.io_kind);
                    for (&expected_digests[kind], state[0..RATE]) |*digest_word, word|
                        digest_word.* = word.toU32();
                }
            }
        }
        if (call_cursor != self.poseidon_calls.len) return error.AuthorityMismatch;
        if (!std.meta.eql(expected_digests, self.output_digests))
            return error.DigestMismatch;
        const actual = witnessDigest(
            self.proof_kind,
            self.preprocessing_digest,
            self.claim_words_digest,
            self.output_digests,
            self.rows,
            self.poseidon_calls,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstSource(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
        source_value: Source,
    ) Error!void {
        try self.validateAgainst(preprocessing);
        if (self.proof_kind != source_value.proofKind())
            return error.AuthorityMismatch;
        const words: []const M31 = switch (source_value) {
            .segment_leaf => |values| values,
            .binary_node, .empty_leaf => &.{},
        };
        if (self.proof_kind == .segment_leaf and words.len != preprocessing.claim_word_count)
            return error.WordCountMismatch;
        const actual_words_digest = wordsDigest(words);
        if (!std.mem.eql(u8, &actual_words_digest, &self.claim_words_digest))
            return error.AuthorityMismatch;
        var state = [_]M31{M31.zero()} ** STATE_WIDTH;
        for (self.rows, preprocessing.rows) |row, metadata| {
            if (self.proof_kind == .segment_leaf and metadata.first == 1) {
                state = .{M31.zero()} ** STATE_WIDTH;
                state[STATE_WIDTH - 1] = M31.fromCanonical(metadata.hash_domain);
            }
            const expected = if (self.proof_kind == .segment_leaf)
                materialize(preprocessing.shape, metadata, words, state)
            else
                zeroMainRow();
            if (!std.meta.eql(row, expected)) return error.AuthorityMismatch;
            if (self.proof_kind == .segment_leaf) state = expected.output;
        }
    }

    pub fn validateDigest(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
        expected: [2][RATE]u32,
    ) Error!void {
        try self.validateAgainst(preprocessing);
        if (!std.meta.eql(self.output_digests, expected)) return error.DigestMismatch;
    }
};

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) Error!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.BindingMismatch;
        const actual = supplied.identityDigest();
        if (!std.mem.eql(u8, &actual, &BINDING_DIGEST))
            return error.BindingMismatch;
        return .{ .binding = supplied.*, .binding_digest = actual };
    }

    pub fn validate(self: *const Executor) Error!void {
        const actual = self.binding.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest) or
            !std.mem.eql(u8, &actual, &BINDING_DIGEST) or
            !std.mem.eql(
                u8,
                &self.binding.source_authority_digest,
                &component.SOURCE_AUTHORITY_DIGEST,
            ))
        {
            return error.BindingMismatch;
        }
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try preprocessing.validate();
        try protectHeader(columns, preprocessing);
        return direct.generateMainInto(
            M31,
            PreprocessedRow,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            preprocessing.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validatePreprocessedRowDirect,
            writePreprocessedRow,
        );
    }

    pub fn generateMainInto(
        self: *const Executor,
        witness: *const MainWitness,
        preprocessing: *const Preprocessed,
        columns: *[MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try witness.validateAgainst(preprocessing);
        try protectHeader(columns, witness);
        try protectHeader(columns, preprocessing);
        try protectSlice(columns, MainRow, witness.rows);
        try protectSlice(columns, PoseidonCall, witness.poseidon_calls);
        return direct.generateMainInto(
            M31,
            MainRow,
            MAIN_COLUMN_COUNT,
            columns,
            witness.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validateMainRowDirect,
            writeMainRow,
        );
    }

    /// Reuses the single shared typed Poseidon2 provider. No permutation AIR
    /// or provider witness logic is duplicated by row 14.
    pub fn generatePoseidonProviderInto(
        self: *const Executor,
        witness: *const MainWitness,
        preprocessing: *const Preprocessed,
        provider: *PoseidonExecutor,
        columns: *[POSEIDON_MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try witness.validateAgainst(preprocessing);
        try protectHeader(columns, self);
        try protectHeader(columns, witness);
        try protectHeader(columns, preprocessing);
        try protectSlice(columns, MainRow, witness.rows);
        try protectSlice(columns, PoseidonCall, witness.poseidon_calls);
        return provider.generateMainInto(
            columns,
            witness.poseidon_calls,
            preprocessing.log_size,
        );
    }
};

pub fn logicalInputs(
    main: MainRow,
    preprocessing: PreprocessedRow,
    proof_kind: ProofKind,
) [component.LOGICAL_INPUT_COUNT]M31 {
    return main.values() ++ preprocessing.values() ++ .{
        proof_kind.selectors()[0],
    };
}

pub fn validatePreprocessedRowDirect(row: PreprocessedRow) direct.Error!void {
    validatePreprocessedRow(row) catch return error.InvalidTraceRow;
}

pub fn validateMainRowDirect(row: MainRow) direct.Error!void {
    if (row.enabler > 1) return error.InvalidTraceRow;
    for (row.previous) |word| if (word.toU32() >= m31.Modulus)
        return error.InvalidTraceRow;
    for (row.chunks) |word| if (word.toU32() >= m31.Modulus)
        return error.InvalidTraceRow;
    for (row.output) |word| if (word.toU32() >= m31.Modulus)
        return error.InvalidTraceRow;
}

pub fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    row_index: usize,
    row: PreprocessedRow,
) void {
    for (columns, row.values()) |column, value| column[row_index] = value;
}

pub fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    row: MainRow,
) void {
    for (columns, row.values()) |column, value| column[row_index] = value;
}

pub fn protectHeader(columns: anytype, object: anytype) direct.Error!void {
    const header = try objectRange(object);
    const descriptors = try objectRange(columns);
    if (header.overlaps(descriptors)) return error.AliasedInput;
    for (columns.*) |column| {
        const destination = (try sliceRange(M31, column)) orelse continue;
        if (destination.overlaps(header)) return error.AliasedInput;
    }
}

pub fn protectSlice(
    columns: anytype,
    comptime T: type,
    values: []const T,
) direct.Error!void {
    const protected = (try sliceRange(T, values)) orelse return;
    const descriptors = try objectRange(columns);
    if (protected.overlaps(descriptors)) return error.AliasedInput;
    for (columns.*) |column| {
        const destination = (try sliceRange(M31, column)) orelse continue;
        if (destination.overlaps(protected)) return error.AliasedInput;
    }
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected header must be a single-item pointer");
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!?AddressRange {
    if (values.len == 0) return null;
    const bytes = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, bytes) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}
