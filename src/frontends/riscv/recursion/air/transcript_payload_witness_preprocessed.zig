//! Internal transcript payload witness authority shard; use transcript_payload_witness.zig publicly.

const dependency_0 = @import("transcript_payload_witness_binding.zig");
const dependency_1 = @import("transcript_payload_witness_source.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const ConstructionError = dependency_0.ConstructionError;
const Error = dependency_0.Error;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const PAYLOAD_WORD_OFFSET = dependency_0.PAYLOAD_WORD_OFFSET;
const PCS_PARAMETER_WORDS = dependency_0.PCS_PARAMETER_WORDS;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const ProofKind = dependency_0.ProofKind;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const Receipts = dependency_1.Receipts;
const Row = dependency_0.Row;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const Sink = dependency_0.Sink;
const Source = dependency_1.Source;
const batchDigest = dependency_1.batchDigest;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const emitLane = dependency_0.emitLane;
const fillValues = dependency_1.fillValues;
const laneRowCount = dependency_0.laneRowCount;
const logSizeFor = dependency_1.logSizeFor;
const m31 = dependency_0.m31;
const objectRange = dependency_1.objectRange;
const preprocessingDigest = dependency_1.preprocessingDigest;
const protocol = dependency_0.protocol;
const requiresInputRelation = dependency_0.requiresInputRelation;
const rowActive = dependency_0.rowActive;
const schedule = dependency_0.schedule;
const sliceRange = dependency_1.sliceRange;
const sourceReceipts = dependency_1.sourceReceipts;
const std = dependency_0.std;
const validateLanePlans = dependency_0.validateLanePlans;
const validateMainValue = dependency_0.validateMainValue;
const validateRow = dependency_0.validateRow;
const validateSource = dependency_1.validateSource;
const valueFor = dependency_1.valueFor;
const writeMainValue = dependency_1.writeMainValue;
const writePreprocessedRow = dependency_1.writePreprocessedRow;

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) ConstructionError!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
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
            return error.InvalidWitnessBinding;
        }
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        return preprocessing.generateInto(columns, self);
    }

    pub fn generateMainInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        batch: *const PreparedBatch,
        columns: *[MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try preprocessing.validate();
        try batch.validateAgainstPreprocessing(preprocessing);
        try protectMainHeaders(columns, preprocessing, batch);
        return direct.generateMainInto(
            M31,
            M31,
            MAIN_COLUMN_COUNT,
            columns,
            batch.values,
            preprocessing.log_size,
            M31.zero(),
            self,
            validateMainValue,
            writeMainValue,
        );
    }
};

/// Exactly one retained allocation owns every payload slot in all three lanes.
pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    vm_row_count: usize,
    recursion_row_count: usize,
    protocol_id: [component.DIGEST_WORD_COUNT]u32,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!Preprocessed {
        try component.SourceAuthority.pinned().validate();
        try (protocol.Profile{}).validate();
        try validateLanePlans(vm, recursion);
        const protocol_id = protocol.protocolId();
        const vm_rows = try laneRowCount(vm);
        const recursion_rows = try laneRowCount(recursion);
        const row_count = std.math.add(
            usize,
            vm_rows,
            std.math.mul(usize, recursion_rows, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        const log_size = try logSizeFor(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        var sink = Sink.write(rows);
        try emitLane(&sink, vm, &protocol_id, SEGMENT_VERIFIER_ID, 1, 0);
        try emitLane(
            &sink,
            recursion,
            &protocol_id,
            LEFT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        try emitLane(
            &sink,
            recursion,
            &protocol_id,
            RIGHT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        if (sink.at != row_count) return error.InvalidTranscriptLayout;
        for (rows) |row| try validateRow(row);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_row_count = vm_rows,
            .recursion_row_count = recursion_rows,
            .protocol_id = protocol_id,
            .vm_schedule_digest = vm.authority_digest,
            .recursion_schedule_digest = recursion.authority_digest,
            .authority_digest = preprocessingDigest(
                log_size,
                vm_rows,
                recursion_rows,
                protocol_id,
                vm.authority_digest,
                recursion.authority_digest,
                rows,
            ),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const Preprocessed) Error!void {
        try component.SourceAuthority.pinned().validate();
        try (protocol.Profile{}).validate();
        const expected_len = std.math.add(
            usize,
            self.vm_row_count,
            std.math.mul(usize, self.recursion_row_count, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        if (self.rows.len != expected_len or
            self.log_size != try logSizeFor(expected_len) or
            !std.meta.eql(self.protocol_id, protocol.protocolId()))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows) |row| try validateRow(row);
        const actual = preprocessingDigest(
            self.log_size,
            self.vm_row_count,
            self.recursion_row_count,
            self.protocol_id,
            self.vm_schedule_digest,
            self.recursion_schedule_digest,
            self.rows,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try self.validate();
        try validateLanePlans(vm, recursion);
        if (!std.meta.eql(self.vm_schedule_digest, vm.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion.authority_digest) or
            self.vm_row_count != try laneRowCount(vm) or
            self.recursion_row_count != try laneRowCount(recursion))
        {
            return error.AuthorityMismatch;
        }
        var sink = Sink.compare(self.rows);
        try emitLane(&sink, vm, &self.protocol_id, SEGMENT_VERIFIER_ID, 1, 0);
        try emitLane(
            &sink,
            recursion,
            &self.protocol_id,
            LEFT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        try emitLane(
            &sink,
            recursion,
            &self.protocol_id,
            RIGHT_RECURSION_VERIFIER_ID,
            0,
            1,
        );
        if (sink.at != self.rows.len) return error.AuthorityMismatch;
    }

    pub fn activePayloadCount(self: *const Preprocessed, kind: ProofKind) usize {
        return switch (kind) {
            .segment_leaf => self.vm_row_count,
            .binary_node => 2 * self.recursion_row_count,
            .empty_leaf => 0,
        };
    }

    /// Counts distinct dynamic payload rows, matching Stark-V's diagnostic.
    pub fn activeInputCount(self: *const Preprocessed, kind: ProofKind) usize {
        var result: usize = 0;
        for (self.rows) |row| {
            result += @intFromBool(
                rowActive(row, kind) and requiresInputRelation(row.source_kind),
            );
        }
        return result;
    }

    /// Counts emitted verifier-input multiplicity, including sampled-value
    /// double use and the VM claimed-sum retagging event.
    pub fn activeInputMultiplicity(self: *const Preprocessed, kind: ProofKind) usize {
        var result: usize = 0;
        for (self.rows) |row| {
            if (rowActive(row, kind)) {
                result += row.input_use_count;
            }
        }
        return result;
    }

    fn generateInto(
        self: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        executor: *const Executor,
    ) Error!void {
        try self.validate();
        try protectPreprocessedHeaders(columns, self);
        return direct.generateMainInto(
            M31,
            Row,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            executor,
            validateRow,
            writePreprocessedRow,
        );
    }
};

/// One retained allocation snapshots every main-column value, including fixed
/// constants, so the hot writer never dereferences transcript structures.
pub const PreparedBatch = struct {
    allocator: std.mem.Allocator,
    proof_kind: ProofKind,
    values: []M31,
    preprocessing_digest: digest.Digest,
    schedule_receipts: [2][8]u32,
    transcript_receipts: [2]digest.Digest,
    lane_count: u8,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
        source: Source,
    ) Error!PreparedBatch {
        try preprocessing.validateAgainst(vm, recursion);
        try validateSource(vm, recursion, source);
        const values = try allocator.alloc(M31, preprocessing.rows.len);
        errdefer allocator.free(values);
        fillValues(values, preprocessing.rows, source);
        for (values, preprocessing.rows) |value, row| {
            if (rowActive(row, std.meta.activeTag(source)) and
                row.constant_mask == 1 and value.v != row.constant_value)
            {
                return error.InvalidTranscriptSource;
            }
        }
        var receipts = sourceReceipts(source);
        switch (source) {
            .segment_leaf => receipts.schedules[0] = vm.authority_digest,
            .binary_node => {
                receipts.schedules[0] = recursion.authority_digest;
                receipts.schedules[1] = recursion.authority_digest;
            },
            .empty_leaf => {},
        }
        return .{
            .allocator = allocator,
            .proof_kind = std.meta.activeTag(source),
            .values = values,
            .preprocessing_digest = preprocessing.authority_digest,
            .schedule_receipts = receipts.schedules,
            .transcript_receipts = receipts.transcripts,
            .lane_count = receipts.lane_count,
            .authority_digest = batchDigest(
                std.meta.activeTag(source),
                preprocessing.authority_digest,
                receipts,
                values,
            ),
        };
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn validate(self: *const PreparedBatch) Error!void {
        try component.SourceAuthority.pinned().validate();
        const expected_lanes: u8 = switch (self.proof_kind) {
            .segment_leaf => 1,
            .binary_node => 2,
            .empty_leaf => 0,
        };
        if (self.lane_count != expected_lanes) return error.AuthorityMismatch;
        for (self.values) |value| if (value.v >= m31.Modulus)
            return error.InvalidFieldElement;
        const receipts = Receipts{
            .lane_count = self.lane_count,
            .schedules = self.schedule_receipts,
            .transcripts = self.transcript_receipts,
        };
        const actual = batchDigest(
            self.proof_kind,
            self.preprocessing_digest,
            receipts,
            self.values,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstPreprocessing(
        self: *const PreparedBatch,
        preprocessing: *const Preprocessed,
    ) Error!void {
        try self.validate();
        try preprocessing.validate();
        if (self.values.len != preprocessing.rows.len or
            !std.mem.eql(
                u8,
                &self.preprocessing_digest,
                &preprocessing.authority_digest,
            ))
        {
            return error.AuthorityMismatch;
        }
        for (self.values, preprocessing.rows) |value, row| {
            const active = rowActive(row, self.proof_kind);
            if ((!active and !value.isZero()) or
                (active and row.constant_mask == 1 and
                    value.v != row.constant_value))
            {
                return error.AuthorityMismatch;
            }
        }
    }

    pub fn validateAgainstSource(
        self: *const PreparedBatch,
        preprocessing: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
        source: Source,
    ) Error!void {
        try self.validateAgainstPreprocessing(preprocessing);
        if (std.meta.activeTag(source) != self.proof_kind)
            return error.AuthorityMismatch;
        try preprocessing.validateAgainst(vm, recursion);
        try validateSource(vm, recursion, source);
        var receipts = sourceReceipts(source);
        switch (source) {
            .segment_leaf => receipts.schedules[0] = vm.authority_digest,
            .binary_node => {
                receipts.schedules[0] = recursion.authority_digest;
                receipts.schedules[1] = recursion.authority_digest;
            },
            .empty_leaf => {},
        }
        if (receipts.lane_count != self.lane_count or
            !std.meta.eql(receipts.schedules, self.schedule_receipts) or
            !std.meta.eql(receipts.transcripts, self.transcript_receipts))
        {
            return error.AuthorityMismatch;
        }
        for (self.values, preprocessing.rows) |value, row| {
            if (!value.eql(valueFor(row, source))) return error.AuthorityMismatch;
        }
    }
};

pub fn mainRow(value: M31) Error![MAIN_COLUMN_COUNT]M31 {
    if (value.v >= m31.Modulus) return error.InvalidFieldElement;
    return .{ M31.one(), value };
}

pub fn logicalRow(
    row: Row,
    value: M31,
    kind: ProofKind,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try validateRow(row);
    const main = try mainRow(value);
    const selectors = kind.selectors();
    return main ++ row.values() ++ .{
        selectors[0],
        selectors[1],
    };
}

pub fn protectPreprocessedHeaders(
    columns: *const [PREPROCESSED_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
) direct.Error!void {
    const descriptor = try objectRange(columns);
    const preprocessing_header = try objectRange(preprocessing);
    for (columns) |column| {
        const destination = try sliceRange(M31, column);
        if (destination.overlaps(descriptor) or
            destination.overlaps(preprocessing_header))
        {
            return error.AliasedDestination;
        }
    }
}

pub fn protectMainHeaders(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    batch: *const PreparedBatch,
) direct.Error!void {
    const descriptor = try objectRange(columns);
    const preprocessing_header = try objectRange(preprocessing);
    const batch_header = try objectRange(batch);
    const preprocessing_rows = try sliceRange(Row, preprocessing.rows);
    for (columns) |column| {
        const destination = try sliceRange(M31, column);
        if (destination.overlaps(descriptor) or
            destination.overlaps(preprocessing_header) or
            destination.overlaps(batch_header))
        {
            return error.AliasedDestination;
        }
        if (destination.overlaps(preprocessing_rows))
            return error.AliasedInput;
    }
}

comptime {
    if (MAIN_COLUMN_COUNT != 2 or PREPROCESSED_COLUMN_COUNT != 17 or
        PCS_PARAMETER_WORDS.len != component.PCS_PARAMETER_WORD_COUNT or
        PAYLOAD_WORD_OFFSET != 16)
    {
        @compileError("transcript-payload witness geometry drifted");
    }
}
