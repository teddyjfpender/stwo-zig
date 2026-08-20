//! Internal transcript air witness authority shard; use transcript_air_witness.zig publicly.

const dependency_0 = @import("transcript_air_witness_contract.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const ConstructionError = dependency_0.ConstructionError;
const Error = dependency_0.Error;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const MAX_LOG_SIZE = dependency_0.MAX_LOG_SIZE;
const MIN_LOG_SIZE = dependency_0.MIN_LOG_SIZE;
const PREPARED_BATCH_DOMAIN = dependency_0.PREPARED_BATCH_DOMAIN;
const PREPARED_BATCH_FORMAT_VERSION = dependency_0.PREPARED_BATCH_FORMAT_VERSION;
const ProofKind = dependency_0.ProofKind;
const ProviderCall = dependency_0.ProviderCall;
const RATE = dependency_0.RATE;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const Receipts = dependency_0.Receipts;
const Row = dependency_0.Row;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const Source = dependency_0.Source;
const WIDTH = dependency_0.WIDTH;
const compareLane = dependency_0.compareLane;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const fieldArrayEql = dependency_0.fieldArrayEql;
const fillLane = dependency_0.fillLane;
const hashInt = dependency_0.hashInt;
const objectRange = dependency_0.objectRange;
const protectHeader = dependency_0.protectHeader;
const providerCallAssumeValid = dependency_0.providerCallAssumeValid;
const sliceRange = dependency_0.sliceRange;
const sourceReceipts = dependency_0.sourceReceipts;
const std = dependency_0.std;
const validateRow = dependency_0.validateRow;
const validateRowDirect = dependency_0.validateRowDirect;
const validateSource = dependency_0.validateSource;
const writeRow = dependency_0.writeRow;

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
        const actual = supplied.identityDigest();
        if (!std.mem.eql(u8, &actual, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
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
            return error.InvalidWitnessBinding;
        }
    }

    pub fn generateMainInto(
        self: *const Executor,
        batch: *const PreparedBatch,
        columns: *[MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try batch.validate();
        try protectHeader(columns, batch);
        return direct.generateMainInto(
            M31,
            Row,
            MAIN_COLUMN_COUNT,
            columns,
            batch.rows,
            batch.log_size,
            M31.zero(),
            self,
            validateRowDirect,
            writeRow,
        );
    }
};

/// One retained allocation snapshots every active call in proof order.
pub const PreparedBatch = struct {
    allocator: std.mem.Allocator,
    proof_kind: ProofKind,
    log_size: u32,
    rows: []Row,
    lane_count: u8,
    lane_row_counts: [2]usize,
    schedule_receipts: [2][8]u32,
    transcript_receipts: [2]digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        source_value: Source,
    ) Error!PreparedBatch {
        try component.SourceAuthority.pinned().validate();
        try validateSource(source_value);
        const receipts = sourceReceipts(source_value);
        const row_count = std.math.add(
            usize,
            receipts.lane_rows[0],
            receipts.lane_rows[1],
        ) catch return error.ArithmeticOverflow;
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        var at: usize = 0;
        switch (source_value) {
            .segment_leaf => |lane| fillLane(
                rows,
                &at,
                SEGMENT_VERIFIER_ID,
                lane.trace,
            ),
            .binary_node => |lanes| {
                fillLane(rows, &at, LEFT_RECURSION_VERIFIER_ID, lanes.left.trace);
                fillLane(rows, &at, RIGHT_RECURSION_VERIFIER_ID, lanes.right.trace);
            },
            .empty_leaf => {},
        }
        if (at != rows.len) return error.InvalidTranscriptSource;
        try validatePreparedShape(
            std.meta.activeTag(source_value),
            rows,
            receipts.lane_count,
            receipts.lane_rows,
        );
        return .{
            .allocator = allocator,
            .proof_kind = std.meta.activeTag(source_value),
            .log_size = log_size,
            .rows = rows,
            .lane_count = receipts.lane_count,
            .lane_row_counts = receipts.lane_rows,
            .schedule_receipts = receipts.schedules,
            .transcript_receipts = receipts.transcripts,
            .authority_digest = batchDigest(
                std.meta.activeTag(source_value),
                log_size,
                receipts,
                rows,
            ),
        };
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const PreparedBatch) Error!void {
        try component.SourceAuthority.pinned().validate();
        if (self.log_size != try traceLogSize(self.rows.len))
            return error.AuthorityMismatch;
        try validatePreparedShape(
            self.proof_kind,
            self.rows,
            self.lane_count,
            self.lane_row_counts,
        );
        const receipts = Receipts{
            .lane_count = self.lane_count,
            .lane_rows = self.lane_row_counts,
            .schedules = self.schedule_receipts,
            .transcripts = self.transcript_receipts,
        };
        const actual = batchDigest(
            self.proof_kind,
            self.log_size,
            receipts,
            self.rows,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstSource(
        self: *const PreparedBatch,
        source_value: Source,
    ) Error!void {
        try self.validate();
        if (std.meta.activeTag(source_value) != self.proof_kind)
            return error.AuthorityMismatch;
        try validateSource(source_value);
        const receipts = sourceReceipts(source_value);
        if (receipts.lane_count != self.lane_count or
            !std.meta.eql(receipts.lane_rows, self.lane_row_counts) or
            !std.meta.eql(receipts.schedules, self.schedule_receipts) or
            !std.meta.eql(receipts.transcripts, self.transcript_receipts))
        {
            return error.AuthorityMismatch;
        }
        var at: usize = 0;
        switch (source_value) {
            .segment_leaf => |lane| try compareLane(
                self.rows,
                &at,
                SEGMENT_VERIFIER_ID,
                lane.trace,
            ),
            .binary_node => |lanes| {
                try compareLane(
                    self.rows,
                    &at,
                    LEFT_RECURSION_VERIFIER_ID,
                    lanes.left.trace,
                );
                try compareLane(
                    self.rows,
                    &at,
                    RIGHT_RECURSION_VERIFIER_ID,
                    lanes.right.trace,
                );
            },
            .empty_leaf => {},
        }
        if (at != self.rows.len) return error.AuthorityMismatch;
    }

    /// Converts the authenticated snapshot into the existing typed Poseidon2
    /// provider ABI without allocating or recomputing the permutation.
    pub fn fillProviderCallsInto(
        self: *const PreparedBatch,
        destination: []ProviderCall,
    ) Error!void {
        try self.validate();
        if (destination.len != self.rows.len)
            return error.InvalidProviderCallGeometry;
        try rejectProviderAlias(destination, self);

        // Infallible after this boundary: errors leave every destination byte
        // untouched, and each provider call has exact `wide=0, io=1` flags.
        for (destination, self.rows) |*target, row|
            target.* = providerCallAssumeValid(row);
    }
};

pub fn providerCall(row: Row) Error!ProviderCall {
    try validateRow(row);
    return providerCallAssumeValid(row);
}

pub fn logicalRow(row: Row) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try validateRow(row);
    return row.values();
}

pub fn validatePreparedShape(
    proof_kind: ProofKind,
    rows: []const Row,
    lane_count: u8,
    lane_rows: [2]usize,
) Error!void {
    const expected_lanes: u8 = switch (proof_kind) {
        .segment_leaf => 1,
        .binary_node => 2,
        .empty_leaf => 0,
    };
    if (lane_count != expected_lanes or
        rows.len != std.math.add(usize, lane_rows[0], lane_rows[1]) catch
            return error.ArithmeticOverflow)
    {
        return error.AuthorityMismatch;
    }
    switch (proof_kind) {
        .segment_leaf => {
            if (lane_rows[0] == 0 or lane_rows[1] != 0)
                return error.AuthorityMismatch;
            try validateLaneRows(rows, SEGMENT_VERIFIER_ID);
        },
        .binary_node => {
            if (lane_rows[0] == 0 or lane_rows[1] == 0)
                return error.AuthorityMismatch;
            try validateLaneRows(rows[0..lane_rows[0]], LEFT_RECURSION_VERIFIER_ID);
            try validateLaneRows(rows[lane_rows[0]..], RIGHT_RECURSION_VERIFIER_ID);
        },
        .empty_leaf => if (rows.len != 0 or lane_rows[0] != 0 or lane_rows[1] != 0)
            return error.AuthorityMismatch,
    }
}

pub fn validateLaneRows(rows: []const Row, verifier_id: u32) Error!void {
    if (rows.len == 0) return error.AuthorityMismatch;
    for (rows, 0..) |row, index| {
        try validateRow(row);
        if (row.verifier_id != verifier_id or row.call_id != index)
            return error.InvalidWitnessRow;
        if (index == 0) {
            if (row.hash_id != 0 or row.step != 0 or row.is_first != 1)
                return error.InvalidWitnessRow;
            continue;
        }
        const previous = rows[index - 1];
        if (row.hash_id == previous.hash_id) {
            if (previous.is_last != 0 or row.is_first != 0 or
                row.step != previous.step + 1 or row.is_draw != previous.is_draw or
                !fieldArrayEql(WIDTH, row.previous, previous.output))
            {
                return error.InvalidWitnessRow;
            }
        } else if (row.hash_id == previous.hash_id + 1) {
            if (previous.is_last != 1 or row.is_first != 1 or row.step != 0)
                return error.InvalidWitnessRow;
        } else return error.InvalidWitnessRow;
    }
    if (rows[rows.len - 1].is_last != 1)
        return error.InvalidWitnessRow;
}

pub fn batchDigest(
    proof_kind: ProofKind,
    log_size: u32,
    receipts: Receipts,
    rows: []const Row,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPARED_BATCH_DOMAIN);
    hashInt(&hash, u16, PREPARED_BATCH_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u8, @intFromEnum(proof_kind));
    hashInt(&hash, u32, log_size);
    hashInt(&hash, u8, receipts.lane_count);
    for (receipts.lane_rows) |count| hashInt(&hash, u64, count);
    for (receipts.schedules) |receipt| for (receipt) |word|
        hashInt(&hash, u32, word);
    for (receipts.transcripts) |receipt| hash.update(&receipt);
    hashInt(&hash, u64, rows.len);
    for (rows) |row| hashRow(&hash, row);
    return hash.finalResult();
}

pub fn hashRow(hash: anytype, row: Row) void {
    hashInt(hash, u32, row.enabler);
    hashInt(hash, u32, row.verifier_id);
    hashInt(hash, u32, row.call_id);
    hashInt(hash, u32, row.hash_id);
    hashInt(hash, u32, row.step);
    hashInt(hash, u32, row.is_first);
    hashInt(hash, u32, row.is_last);
    hashInt(hash, u32, row.is_draw);
    for (row.previous) |word| hashInt(hash, u32, word.v);
    for (row.chunk) |word| hashInt(hash, u32, word.v);
    for (row.output) |word| hashInt(hash, u32, word.v);
}

pub fn traceLogSize(row_count: usize) Error!u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.ArithmeticOverflow;
    const log_size: u32 = @max(MIN_LOG_SIZE, std.math.log2_int(usize, padded));
    if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return log_size;
}

pub fn rejectProviderAlias(
    destination: []ProviderCall,
    batch: *const PreparedBatch,
) direct.Error!void {
    const output = (try sliceRange(ProviderCall, destination)) orelse return;
    const header = try objectRange(batch);
    const rows = (try sliceRange(Row, batch.rows)) orelse return;
    if (output.overlaps(header) or output.overlaps(rows))
        return error.AliasedInput;
}

comptime {
    if (MAIN_COLUMN_COUNT != 48 or RATE != 8 or WIDTH != 16 or
        @sizeOf(ProviderCall) == 0)
    {
        @compileError("transcript-air witness geometry drifted");
    }
}
