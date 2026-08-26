//! Internal verifier arithmetic lowering authority shard; use verifier_arithmetic_lowering.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const digest = @import("../../air/lang/digest.zig");
pub const relation = @import("../../air/lang/relation.zig");
pub const graph_mod = @import("composition_circuit.zig");
pub const linear = @import("linear_ops_witness.zig");
pub const inverse = @import("qm31_inv_witness.zig");
pub const multiply = @import("qm31_mul_full_witness.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const universal = @import("universal_challenges.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const DOMAIN = "stwo-zig/typed-air/recursion-verifier-arithmetic-lowering/v1\x00";
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-verifier-arithmetic-reference/v1\x00";

pub const ProofKind = proof_kind_mod.ProofKind;
pub const Mode = enum(u8) { segment, binary };

pub const Error = std.mem.Allocator.Error || graph_mod.Error || error{
    AliasedDestination,
    AliasedInput,
    ArithmeticOverflow,
    AuthorityMismatch,
    BufferShapeMismatch,
    CircuitCoordinateNotCanonical,
    CircuitIdNotCanonical,
    DuplicateCircuitId,
    EmptyReference,
    EvaluationCountMismatch,
    InvalidCircuitOperation,
    InvalidPublicAnchor,
    MissingProofMode,
};

pub const PublicClaimError = universal.Error || QM31.Error || error{
    InvalidPublicAnchor,
    ZeroDenominator,
};

/// The graph-derived input boundary is a cold trust-boundary audit.  It
/// authenticates the lowering plan and evaluations before allocating its one
/// reusable use-count scratch buffer.
pub const InputClaimError = Error || PublicClaimError;

pub const Counts = struct {
    multiply: usize = 0,
    inverse: usize = 0,
    linear: usize = 0,
    public: usize = 0,

    pub fn add(self: Counts, other: Counts) Error!Counts {
        return .{
            .multiply = try checkedAdd(self.multiply, other.multiply),
            .inverse = try checkedAdd(self.inverse, other.inverse),
            .linear = try checkedAdd(self.linear, other.linear),
            .public = try checkedAdd(self.public, other.public),
        };
    }
};

/// Borrowed graph authority. `circuit_identity` is the producer's complete
/// profile/graph/input seal; `graph.identity_digest` independently seals the
/// operation DAG lowered here.
pub const Lane = struct {
    circuit_id: u32,
    active_in: Mode,
    circuit_identity: digest.Digest,
    graph: graph_mod.CircuitGraph,
};

pub const Reference = struct {
    lanes: []const Lane,
    authority_digest: digest.Digest,

    pub fn seal(lanes: []const Lane) Error!Reference {
        try validateLanesAuthority(lanes);
        return .{
            .lanes = lanes,
            .authority_digest = referenceDigest(lanes),
        };
    }

    /// Allocation-free proof-path check. Full graph hashing remains a cold
    /// admission operation in `validateAuthority`.
    pub fn validate(self: Reference) Error!void {
        try validateLanesHot(self.lanes);
        if (!std.mem.eql(u8, &self.authority_digest, &referenceDigest(self.lanes)))
            return error.AuthorityMismatch;
    }

    pub fn validateAuthority(self: Reference) Error!void {
        try self.validate();
        for (self.lanes) |lane| try lane.graph.validate();
    }
};

pub const Evaluation = struct {
    circuit_identity: digest.Digest,
    values: []const QM31,
};

pub const Evaluations = struct {
    lanes: []const Evaluation,

    pub fn validateAgainst(self: Evaluations, reference: Reference) Error!void {
        if (self.lanes.len != reference.lanes.len)
            return error.EvaluationCountMismatch;
        for (reference.lanes, self.lanes) |lane, evaluation| {
            if (evaluation.values.len != lane.graph.nodes.len or
                !std.mem.eql(
                    u8,
                    &evaluation.circuit_identity,
                    &lane.circuit_identity,
                ))
            {
                return error.AuthorityMismatch;
            }
        }
    }
};

pub const PublicWireTerm = struct {
    lane: u32,
    active_in: Mode,
    role: relation.Role,
    circuit_id: u32,
    node_id: u32,
    value: QM31,
    multiplicity: u32,
};

pub const InvocationBuffers = struct {
    multiply: []multiply.Invocation,
    inverse: []inverse.Invocation,
    linear: []linear.Invocation,
};

pub const OperationCursors = struct {
    multiply: usize = 0,
    inverse: usize = 0,
    linear: usize = 0,
};

pub fn computeUseCountsInto(
    graph: graph_mod.CircuitGraph,
    scratch: []u32,
) Error![]u32 {
    if (scratch.len < graph.nodes.len) return error.AuthorityMismatch;
    const uses = scratch[0..graph.nodes.len];
    @memset(uses, 0);
    for (graph.nodes) |node| switch (node.op) {
        .add, .sub, .mul => |operation| {
            try incrementUse(&uses[operation.lhs]);
            try incrementUse(&uses[operation.rhs]);
        },
        .neg, .inverse => |operand| try incrementUse(&uses[operand]),
        .input, .constant => {},
    };
    for (graph.outputs) |output| try incrementUse(&uses[output]);
    return uses;
}

pub fn incrementUse(value: *u32) Error!void {
    value.* = std.math.add(u32, value.*, 1) catch
        return error.ArithmeticOverflow;
    if (value.* >= m31.Modulus)
        return error.CircuitCoordinateNotCanonical;
}

pub fn countGraph(graph: graph_mod.CircuitGraph, uses: []const u32) Error!Counts {
    if (uses.len != graph.nodes.len) return error.AuthorityMismatch;
    var result = Counts{};
    for (graph.nodes, 0..) |node, node_id| switch (node.op) {
        .input => {},
        .constant => if (uses[node_id] != 0) {
            result.public = try checkedAdd(result.public, 1);
        },
        .mul => result.multiply = try checkedAdd(result.multiply, 1),
        .inverse => result.inverse = try checkedAdd(result.inverse, 1),
        .add, .sub, .neg => result.linear = try checkedAdd(result.linear, 1),
    };
    result.public = try checkedAdd(result.public, graph.outputs.len);
    return result;
}

pub fn fillLane(
    lane: Lane,
    lane_index: u32,
    uses: []const u32,
    multiply_rows: []multiply.PreprocessedRow,
    inverse_rows: []inverse.PreprocessedRow,
    linear_rows: []linear.PreprocessedRow,
    cursors: *OperationCursors,
    public_terms: []PublicWireTerm,
    public_cursor: *usize,
) Error!void {
    for (lane.graph.nodes, 0..) |node, node_id_usize| {
        const node_id = try coordinate(node_id_usize);
        const use_count = uses[node_id_usize];
        const circuit_id = M31.fromCanonical(lane.circuit_id);
        const uses_field = M31.fromCanonical(use_count);
        switch (node.op) {
            .input => {},
            .constant => |words| if (use_count != 0) {
                if (public_cursor.* >= public_terms.len)
                    return error.AuthorityMismatch;
                public_terms[public_cursor.*] = .{
                    .lane = lane_index,
                    .active_in = lane.active_in,
                    .role = .emit,
                    .circuit_id = lane.circuit_id,
                    .node_id = node_id,
                    .value = QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]),
                    .multiplicity = use_count,
                };
                public_cursor.* += 1;
            },
            .mul => |operation| {
                assignMultiply(multiply_rows, cursors.multiply, lane.active_in, .{
                    .circuit_id = circuit_id,
                    .node_id = M31.fromCanonical(node_id),
                    .lhs_id = M31.fromCanonical(operation.lhs),
                    .rhs_id = M31.fromCanonical(operation.rhs),
                    .uses = uses_field,
                });
                cursors.multiply += 1;
            },
            .inverse => |operand| {
                assignInverse(inverse_rows, cursors.inverse, lane.active_in, .{
                    .circuit_id = circuit_id,
                    .node_id = M31.fromCanonical(node_id),
                    .lhs_id = M31.fromCanonical(operand),
                    .uses = uses_field,
                });
                cursors.inverse += 1;
            },
            .add, .sub => |operation| {
                const kind: linear.Operation = switch (node.op) {
                    .add => .add,
                    .sub => .sub,
                    else => unreachable,
                };
                assignLinear(linear_rows, cursors.linear, lane.active_in, .{
                    .operation = kind,
                    .circuit = .{
                        .circuit_id = circuit_id,
                        .node_id = M31.fromCanonical(node_id),
                        .lhs_id = M31.fromCanonical(operation.lhs),
                        .rhs_id = M31.fromCanonical(operation.rhs),
                        .uses = uses_field,
                    },
                });
                cursors.linear += 1;
            },
            .neg => |operand| {
                assignLinear(linear_rows, cursors.linear, lane.active_in, .{
                    .operation = .neg,
                    .circuit = .{
                        .circuit_id = circuit_id,
                        .node_id = M31.fromCanonical(node_id),
                        .lhs_id = M31.fromCanonical(operand),
                        .rhs_id = M31.zero(),
                        .uses = uses_field,
                    },
                });
                cursors.linear += 1;
            },
        }
    }
    for (lane.graph.outputs) |output| {
        if (public_cursor.* >= public_terms.len)
            return error.AuthorityMismatch;
        public_terms[public_cursor.*] = .{
            .lane = lane_index,
            .active_in = lane.active_in,
            .role = .consume,
            .circuit_id = lane.circuit_id,
            .node_id = try coordinate(output),
            .value = QM31.zero(),
            .multiplicity = 1,
        };
        public_cursor.* += 1;
    }
}

pub fn assignMultiply(
    rows: []multiply.PreprocessedRow,
    index: usize,
    mode: Mode,
    metadata: multiply.CircuitMetadata,
) void {
    switch (mode) {
        .segment => rows[index].segment = metadata,
        .binary => rows[index].binary = metadata,
    }
}

pub fn assignInverse(
    rows: []inverse.PreprocessedRow,
    index: usize,
    mode: Mode,
    metadata: inverse.CircuitMetadata,
) void {
    switch (mode) {
        .segment => rows[index].segment = metadata,
        .binary => rows[index].binary = metadata,
    }
}

pub fn assignLinear(
    rows: []linear.PreprocessedRow,
    index: usize,
    mode: Mode,
    metadata: linear.ScheduleRow,
) void {
    switch (mode) {
        .segment => rows[index].segment = metadata,
        .binary => rows[index].binary = metadata,
    }
}

pub fn selectedMultiply(
    row: multiply.PreprocessedRow,
    mode: Mode,
) ?multiply.CircuitMetadata {
    return switch (mode) {
        .segment => row.segment,
        .binary => row.binary,
    };
}

pub fn selectedInverse(row: inverse.PreprocessedRow, mode: Mode) ?inverse.CircuitMetadata {
    return switch (mode) {
        .segment => row.segment,
        .binary => row.binary,
    };
}

pub fn selectedLinear(row: linear.PreprocessedRow, mode: Mode) ?linear.ScheduleRow {
    return switch (mode) {
        .segment => row.segment,
        .binary => row.binary,
    };
}

pub fn metadataMatches(
    metadata: anytype,
    circuit_id: u32,
    node_id: u32,
    lhs_id: u32,
    rhs_id: u32,
) bool {
    return metadata.circuit_id.toU32() == circuit_id and
        metadata.node_id.toU32() == node_id and
        metadata.lhs_id.toU32() == lhs_id and
        metadata.rhs_id.toU32() == rhs_id;
}

pub fn publicTermClaim(
    challenge: *const universal.Elements,
    term: PublicWireTerm,
) PublicClaimError!QM31 {
    if (term.circuit_id >= m31.Modulus or term.node_id >= m31.Modulus or
        term.multiplicity == 0 or term.multiplicity >= m31.Modulus or
        term.role == .request)
    {
        return error.InvalidPublicAnchor;
    }
    const words = term.value.toM31Array();
    const denominator = challenge.combineSecure(&.{
        QM31.fromBase(M31.fromCanonical(term.circuit_id)),
        QM31.fromBase(M31.fromCanonical(term.node_id)),
        QM31.fromBase(words[0]),
        QM31.fromBase(words[1]),
        QM31.fromBase(words[2]),
        QM31.fromBase(words[3]),
    }) catch return error.InvalidPublicAnchor;
    const inverse_value = denominator.inv() catch return error.ZeroDenominator;
    var numerator = QM31.fromBase(M31.fromCanonical(term.multiplicity));
    if (term.role == .consume) numerator = numerator.neg();
    return numerator.mul(inverse_value);
}

pub fn inputTermClaim(
    challenge: *const universal.Elements,
    circuit_id: u32,
    node_id: u32,
    value: QM31,
    multiplicity: u32,
) PublicClaimError!QM31 {
    if (circuit_id >= m31.Modulus or node_id >= m31.Modulus or
        multiplicity == 0 or multiplicity >= m31.Modulus)
    {
        return error.InvalidPublicAnchor;
    }
    const words = value.toM31Array();
    const denominator = challenge.combineSecure(&.{
        QM31.fromBase(M31.fromCanonical(circuit_id)),
        QM31.fromBase(M31.fromCanonical(node_id)),
        QM31.fromBase(words[0]),
        QM31.fromBase(words[1]),
        QM31.fromBase(words[2]),
        QM31.fromBase(words[3]),
    }) catch return error.InvalidPublicAnchor;
    const inverse_value = denominator.inv() catch return error.ZeroDenominator;
    return QM31.fromBase(M31.fromCanonical(multiplicity)).mul(inverse_value);
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    pub fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn rangeOf(comptime T: type, values: []const T) Error!?AddressRange {
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.ArithmeticOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.ArithmeticOverflow,
    };
}

pub fn validateLanesHot(lanes: []const Lane) Error!void {
    if (lanes.len == 0 or lanes.len >= m31.Modulus)
        return error.EmptyReference;
    var seen_modes = [2]bool{ false, false };
    for (lanes, 0..) |lane, lane_index| {
        if (lane.circuit_id >= m31.Modulus)
            return error.CircuitIdNotCanonical;
        seen_modes[@intFromEnum(lane.active_in)] = true;
        for (lanes[0..lane_index]) |previous| {
            if (previous.circuit_id == lane.circuit_id)
                return error.DuplicateCircuitId;
        }
    }
    if (!seen_modes[0] or !seen_modes[1]) return error.MissingProofMode;
}

pub fn validateLanesAuthority(lanes: []const Lane) Error!void {
    try validateLanesHot(lanes);
    for (lanes) |lane| try lane.graph.validate();
}

pub fn maximumNodeCount(reference: Reference) usize {
    var result: usize = 0;
    for (reference.lanes) |lane| result = @max(result, lane.graph.nodes.len);
    return result;
}

pub fn proofMode(kind: ProofKind) ?Mode {
    return switch (kind) {
        .segment_leaf => .segment,
        .binary_node => .binary,
        .empty_leaf => null,
    };
}

pub fn referenceDigest(lanes: []const Lane) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashInt(&hash, u32, lanes.len);
    for (lanes) |lane| {
        hashInt(&hash, u32, lane.circuit_id);
        hashInt(&hash, u8, @intFromEnum(lane.active_in));
        hash.update(&lane.circuit_identity);
        hash.update(&lane.graph.identity_digest);
    }
    return hash.finalResult();
}

pub fn planDigest(
    reference_digest: digest.Digest,
    multiply_rows: []const multiply.PreprocessedRow,
    inverse_rows: []const inverse.PreprocessedRow,
    linear_rows: []const linear.PreprocessedRow,
    public_terms: []const PublicWireTerm,
    mode_counts: [2]Counts,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&reference_digest);
    for (mode_counts) |counts| hashCounts(&hash, counts);
    hashInt(&hash, u32, multiply_rows.len);
    for (multiply_rows) |row|
        hashOptionalSchedule(&hash, row.segment, row.binary, row.empty);
    hashInt(&hash, u32, inverse_rows.len);
    for (inverse_rows) |row|
        hashOptionalSchedule(&hash, row.segment, row.binary, row.empty);
    hashInt(&hash, u32, linear_rows.len);
    for (linear_rows) |row| {
        hashOptionalLinear(&hash, row.segment);
        hashOptionalLinear(&hash, row.binary);
        hashOptionalLinear(&hash, row.empty);
    }
    hashInt(&hash, u32, public_terms.len);
    for (public_terms) |term| {
        hashInt(&hash, u32, term.lane);
        hashInt(&hash, u8, @intFromEnum(term.active_in));
        hashInt(&hash, u8, @intFromEnum(term.role));
        hashInt(&hash, u32, term.circuit_id);
        hashInt(&hash, u32, term.node_id);
        for (term.value.toM31Array()) |word|
            hashInt(&hash, u32, word.toU32());
        hashInt(&hash, u32, term.multiplicity);
    }
    return hash.finalResult();
}

pub fn hashCounts(hash: anytype, value: Counts) void {
    hashInt(hash, u32, value.multiply);
    hashInt(hash, u32, value.inverse);
    hashInt(hash, u32, value.linear);
    hashInt(hash, u32, value.public);
}

pub fn hashOptionalSchedule(
    hash: anytype,
    segment: anytype,
    binary: anytype,
    empty: anytype,
) void {
    hashOptionalMetadata(hash, segment);
    hashOptionalMetadata(hash, binary);
    hashOptionalMetadata(hash, empty);
}

pub fn hashOptionalMetadata(hash: anytype, value: anytype) void {
    hashInt(hash, u8, @intFromBool(value != null));
    if (value) |metadata| {
        hashInt(hash, u32, metadata.circuit_id.toU32());
        hashInt(hash, u32, metadata.node_id.toU32());
        hashInt(hash, u32, metadata.lhs_id.toU32());
        if (@hasField(@TypeOf(metadata), "rhs_id"))
            hashInt(hash, u32, metadata.rhs_id.toU32());
        hashInt(hash, u32, metadata.uses.toU32());
    }
}

pub fn hashOptionalLinear(hash: anytype, value: ?linear.ScheduleRow) void {
    hashInt(hash, u8, @intFromBool(value != null));
    if (value) |scheduled| {
        hashInt(hash, u8, @intFromEnum(scheduled.operation));
        hashInt(hash, u32, scheduled.circuit.circuit_id.toU32());
        hashInt(hash, u32, scheduled.circuit.node_id.toU32());
        hashInt(hash, u32, scheduled.circuit.lhs_id.toU32());
        hashInt(hash, u32, scheduled.circuit.rhs_id.toU32());
        hashInt(hash, u32, scheduled.circuit.uses.toU32());
    }
}

pub fn metaSliceEql(comptime T: type, lhs: []const T, rhs: []const T) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |left, right| if (!std.meta.eql(left, right)) return false;
    return true;
}

pub fn publicSliceEql(lhs: []const PublicWireTerm, rhs: []const PublicWireTerm) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |left, right| {
        if (left.lane != right.lane or left.active_in != right.active_in or
            left.role != right.role or left.circuit_id != right.circuit_id or
            left.node_id != right.node_id or left.multiplicity != right.multiplicity or
            !left.value.eql(right.value))
        {
            return false;
        }
    }
    return true;
}

pub fn coordinate(value: usize) Error!u32 {
    const result = std.math.cast(u32, value) orelse
        return error.CircuitCoordinateNotCanonical;
    if (result >= m31.Modulus)
        return error.CircuitCoordinateNotCanonical;
    return result;
}

pub fn checkedAdd(lhs: usize, rhs: usize) Error!usize {
    return std.math.add(usize, lhs, rhs) catch error.ArithmeticOverflow;
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
