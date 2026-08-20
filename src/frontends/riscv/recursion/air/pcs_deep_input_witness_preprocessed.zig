//! Internal pcs deep input witness authority shard; use pcs_deep_input_witness.zig publicly.

const dependency_0 = @import("pcs_deep_input_witness_reference.zig");

const AddressRange = dependency_0.AddressRange;
const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const DEEP_POSITION_KIND = dependency_0.DEEP_POSITION_KIND;
const DEEP_RANDOMNESS_KIND = dependency_0.DEEP_RANDOMNESS_KIND;
const Error = dependency_0.Error;
const InputWitness = dependency_0.InputWitness;
const Lane = dependency_0.Lane;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const OODS_POINT_KIND = dependency_0.OODS_POINT_KIND;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const ProofKind = dependency_0.ProofKind;
const Reference = dependency_0.Reference;
const Row = dependency_0.Row;
const SAMPLED_VALUE_KIND = dependency_0.SAMPLED_VALUE_KIND;
const SCHEDULE_DOMAIN = dependency_0.SCHEDULE_DOMAIN;
const SCHEDULE_FORMAT_VERSION = dependency_0.SCHEDULE_FORMAT_VERSION;
const component = dependency_0.component;
const computeUseCounts = dependency_0.computeUseCounts;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const hashInt = dependency_0.hashInt;
const hashSource = dependency_0.hashSource;
const maximumNodeCount = dependency_0.maximumNodeCount;
const objectRange = dependency_0.objectRange;
const referenceDigest = dependency_0.referenceDigest;
const sliceRange = dependency_0.sliceRange;
const std = dependency_0.std;
const totalRows = dependency_0.totalRows;
const traceLogSize = dependency_0.traceLogSize;
const validateRowDirect = dependency_0.validateRowDirect;
const validateWitness = dependency_0.validateWitness;
const writePreprocessedRow = dependency_0.writePreprocessedRow;

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(definition: *const component.Definition, supplied: *const Binding) !Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        reference: Reference,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        return preprocessing.generatePreprocessedInto(reference, columns, self);
    }

    pub fn generateMainInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        reference: Reference,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        input_witness: InputWitness,
        proof_kind: ProofKind,
    ) Error!void {
        return preprocessing.generateMainInto(
            reference,
            columns,
            input_witness,
            proof_kind,
            self,
        );
    }
};

pub const MainRow = struct {
    enabler: M31,
    value: M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{ self.enabler, self.value };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    reference_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(allocator: std.mem.Allocator, reference: Reference) Error!Preprocessed {
        try reference.validate();
        const row_count = try totalRows(reference);
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        const scratch = try allocator.alloc(u32, maximumNodeCount(reference));
        defer allocator.free(scratch);
        var cursor: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| {
            try computeUseCounts(lane.graph, scratch);
            for (lane.bindings, 0..) |binding, binding_index| {
                rows[cursor] = .{
                    .source = binding.source,
                    .lane = @intCast(lane_index),
                    .binding = @intCast(binding_index),
                    .verifier_id = lane.verifier_id,
                    .circuit_id = lane.circuit_id,
                    .node_id = binding.node_id,
                    .use_count = scratch[binding.node_id],
                };
                cursor += 1;
            }
        }
        std.debug.assert(cursor == rows.len);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .reference_digest = reference.authority_digest,
            .authority_digest = scheduleDigest(reference.authority_digest, rows),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Preprocessed, reference: Reference) Error!void {
        try reference.validate();
        if (self.rows.len != try totalRows(reference) or
            self.log_size != try traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_digest, &reference.authority_digest) or
            !std.mem.eql(
                u8,
                &self.authority_digest,
                &scheduleDigest(reference.authority_digest, self.rows),
            ))
        {
            return error.AuthorityMismatch;
        }
    }

    /// Cold independent regeneration; hot writers use the sealed scan above.
    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        reference: Reference,
    ) Error!void {
        try self.validateAgainst(reference);
        const scratch = try self.allocator.alloc(u32, maximumNodeCount(reference));
        defer self.allocator.free(scratch);
        var cursor: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| {
            try computeUseCounts(lane.graph, scratch);
            for (lane.bindings, 0..) |binding, binding_index| {
                const expected = Row{
                    .source = binding.source,
                    .lane = @intCast(lane_index),
                    .binding = @intCast(binding_index),
                    .verifier_id = lane.verifier_id,
                    .circuit_id = lane.circuit_id,
                    .node_id = binding.node_id,
                    .use_count = scratch[binding.node_id],
                };
                if (!std.meta.eql(expected, self.rows[cursor]))
                    return error.AuthorityMismatch;
                cursor += 1;
            }
        }
        if (cursor != self.rows.len) return error.AuthorityMismatch;
    }

    fn generatePreprocessedInto(
        self: *const Preprocessed,
        reference: Reference,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        return direct.generateMainInto(
            M31,
            Row,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            executor,
            validateRowDirect,
            writePreprocessedRow,
        );
    }

    fn generateMainInto(
        self: *const Preprocessed,
        reference: Reference,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        input_witness: InputWitness,
        proof_kind: ProofKind,
        executor: *const Executor,
    ) Error!void {
        try self.validateAgainst(reference);
        try validateWitness(reference, input_witness, proof_kind);
        _ = try preflightMain(columns, self, input_witness, executor);
        for (columns) |column| @memset(column, M31.zero());
        for (self.rows, 0..) |row, row_index| {
            columns[0][row_index] = M31.one();
            columns[1][row_index] = input_witness.lanes[row.lane].input_values[row.binding];
        }
    }
};

pub fn logicalRow(
    reference: Reference,
    preprocessing: *const Preprocessed,
    row_index: usize,
    input_witness: InputWitness,
    proof_kind: ProofKind,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try preprocessing.validateAgainst(reference);
    try validateWitness(reference, input_witness, proof_kind);
    if (row_index >= preprocessing.rows.len) return error.InvalidWitness;
    const row = preprocessing.rows[row_index];
    const value = input_witness.lanes[row.lane].input_values[row.binding];
    return logicalInputs(
        (MainRow{ .enabler = M31.one(), .value = value }).values(),
        row.values(),
        proof_kind,
    );
}

/// Allocation-free assembly after the reference, schedule, and complete input
/// witness have passed their bulk checks. This prevents an O(rows * graph)
/// validation loop while interaction rows are prepared.
pub fn logicalInputs(
    main: [MAIN_COLUMN_COUNT]M31,
    preprocessed: [PREPROCESSED_COLUMN_COUNT]M31,
    proof_kind: ProofKind,
) [component.LOGICAL_INPUT_COUNT]M31 {
    const selectors = proof_kind.selectors();
    return main ++ preprocessed ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(SAMPLED_VALUE_KIND),
        M31.fromCanonical(OODS_POINT_KIND),
        M31.fromCanonical(DEEP_RANDOMNESS_KIND),
        M31.fromCanonical(DEEP_POSITION_KIND),
    };
}

pub fn computeReferenceDigest(lanes: [3]Lane) digest.Digest {
    return referenceDigest(lanes);
}

pub fn preflightMain(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    input_witness: InputWitness,
    executor: *const Executor,
) direct.Error!usize {
    if (preprocessing.log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    var destinations: [MAIN_COLUMN_COUNT]AddressRange = undefined;
    for (columns, 0..) |column, index| {
        if (column.len != size) return error.InvalidTraceShape;
        destinations[index] = try sliceRange(M31, column);
        for (destinations[0..index]) |previous| if (destinations[index].overlaps(previous))
            return error.AliasedDestination;
    }
    const objects = [_]AddressRange{
        try objectRange(columns),
        try objectRange(preprocessing),
        try objectRange(executor),
    };
    const rows = try sliceRange(Row, preprocessing.rows);
    for (destinations) |destination| {
        for (objects) |object| if (destination.overlaps(object)) return error.AliasedDestination;
        if (destination.overlaps(rows)) return error.AliasedInput;
        for (input_witness.lanes) |lane| {
            const source_range = try sliceRange(M31, lane.input_values);
            if (destination.overlaps(source_range)) return error.AliasedInput;
        }
    }
    return size;
}

pub fn scheduleDigest(reference_digest: digest.Digest, rows: []const Row) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SCHEDULE_DOMAIN);
    hashInt(&hash, u16, SCHEDULE_FORMAT_VERSION);
    hash.update(&reference_digest);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| {
        hashSource(&hash, row.source);
        hashInt(&hash, u32, row.lane);
        hashInt(&hash, u32, row.binding);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.circuit_id);
        hashInt(&hash, u32, row.node_id);
        hashInt(&hash, u32, row.use_count);
    }
    return hash.finalResult();
}
