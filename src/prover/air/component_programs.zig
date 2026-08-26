//! Typed base/lookup polynomial programs and backend capability contracts.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const BasePolynomialOp = enum(u8) { constant, column, add, sub, mul, neg };

pub const BasePolynomialNode = struct {
    op: BasePolynomialOp,
    lhs: u32 = 0,
    rhs: u32 = 0,
    value: u32 = 0,
};

pub const OwnedBasePolynomialProgram = struct {
    allocator: std.mem.Allocator,
    nodes: []BasePolynomialNode,
    roots: []u32,
    column_count: usize,

    pub fn deinit(self: *OwnedBasePolynomialProgram) void {
        self.allocator.free(self.roots);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn validate(self: OwnedBasePolynomialProgram) !void {
        if (self.column_count == 0 or self.nodes.len == 0 or self.roots.len == 0)
            return error.InvalidBasePolynomialProgram;
        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => {},
            .column => if (node.value >= self.column_count)
                return error.InvalidBasePolynomialProgram,
            .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index)
                return error.InvalidBasePolynomialProgram,
            .neg => if (node.lhs >= index)
                return error.InvalidBasePolynomialProgram,
        };
        for (self.roots) |root| if (root >= self.nodes.len)
            return error.InvalidBasePolynomialProgram;
    }
};

/// A committed base-polynomial component that a backend may evaluate from the
/// proof's own residency handles. The selector is the final program input;
/// preceding inputs are the contiguous main-column block. The exporter is
/// invoked only during proving and must derive its program from the production
/// evaluator rather than maintain an independent constraint transcription.
pub const BasePolynomialCapabilityV1 = struct {
    program_id: u64,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedBasePolynomialProgram,
};

pub const MAX_LOOKUP_POLYNOMIAL_ARITY: usize = 32;

pub const LookupPolynomialEntry = struct {
    numerator: u32,
    values: [MAX_LOOKUP_POLYNOMIAL_ARITY]u32 = undefined,
    arity: u8,
};

pub const OwnedLookupPolynomialProgram = struct {
    allocator: std.mem.Allocator,
    nodes: []BasePolynomialNode,
    entries: []LookupPolynomialEntry,
    column_count: usize,
    batch_size: usize,

    pub fn deinit(self: *OwnedLookupPolynomialProgram) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn batchCount(self: OwnedLookupPolynomialProgram) usize {
        return (self.entries.len + self.batch_size - 1) / self.batch_size;
    }

    pub fn parameterCount(self: OwnedLookupPolynomialProgram) usize {
        var count = self.batchCount();
        for (self.entries) |entry| count += 1 + entry.arity;
        return count;
    }

    pub fn validate(self: OwnedLookupPolynomialProgram) !void {
        if (self.column_count == 0 or self.nodes.len == 0 or
            self.entries.len == 0 or (self.batch_size != 1 and self.batch_size != 2))
            return error.InvalidLookupPolynomialProgram;
        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => {},
            .column => if (node.value >= self.column_count)
                return error.InvalidLookupPolynomialProgram,
            .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index)
                return error.InvalidLookupPolynomialProgram,
            .neg => if (node.lhs >= index)
                return error.InvalidLookupPolynomialProgram,
        };
        for (self.entries) |entry| {
            if (entry.arity == 0 or entry.arity > MAX_LOOKUP_POLYNOMIAL_ARITY or
                entry.numerator >= self.nodes.len)
                return error.InvalidLookupPolynomialProgram;
            for (entry.values[0..entry.arity]) |value| if (value >= self.nodes.len)
                return error.InvalidLookupPolynomialProgram;
        }
    }
};

/// Append-only variable-partition lookup layout. V1 stores one uniform
/// `batch_size`; V2 records the exact ordered singleton/pair partition chosen
/// for one component. The fixed header is suitable for a future physical
/// manifest, while the degree and batch slices remain part of the
/// content-addressed program authority.
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION: u16 = 2;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE: u8 = 2;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES: u8 = 4;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE: u32 = 16;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN =
    "stwo/prover/lookup-polynomial-layout/v2\x00";
pub const LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN =
    "stwo/prover/lookup-polynomial-program/v2\x00";
pub const LookupPolynomialIdentity = [32]u8;

pub const LookupPolynomialProgramV2Error = error{
    CountOverflow,
    DegreeOverflow,
    InvalidAuthorityGeometry,
    InvalidAuthorityVersion,
    InvalidBatchCount,
    InvalidBatchCoverage,
    InvalidBatchDegree,
    InvalidBatchWidth,
    InvalidColumnCapacity,
    InvalidComponentIdentity,
    InvalidDegreeCap,
    InvalidEntry,
    InvalidEntryCount,
    InvalidEventDegree,
    InvalidEventOrder,
    InvalidInteractionCapacity,
    InvalidLayoutIdentity,
    InvalidLayoutVersion,
    InvalidMaximumDegree,
    InvalidNode,
    InvalidPartitionIdentity,
    InvalidProgramIdentity,
};

/// Degree certificate for one relation event in its immutable transcript
/// order. Ordinals are explicit so a partition cannot cover the right count
/// while silently permuting relation parameters.
pub const LookupPolynomialEventDegreeV2 = struct {
    ordinal: u32,
    numerator_degree: u32,
    denominator_degree: u32,
};

/// One exact contiguous range in the relation-event sequence. The stored
/// interaction degree is independently recomputed during validation.
pub const LookupPolynomialBatchV2 = struct {
    first_entry: u32,
    entry_count: u8,
    interaction_degree: u32,
};

pub const LookupPolynomialLayoutV2 = struct {
    format_version: u16 = LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION,
    maximum_batch_size: u8 = LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE,
    interaction_coordinates_per_batch: u8 =
        LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES,
    /// Identity of the typed component/relation program whose ordered entries
    /// are being partitioned.
    component_identity: LookupPolynomialIdentity,
    /// Identity of the deterministic selection policy, degree schedule, and
    /// exact chosen partition.
    partition_identity: LookupPolynomialIdentity,
    column_count: u32,
    entry_count: u32,
    batch_count: u32,
    interaction_column_count: u32,
    degree_cap: u32,
    maximum_interaction_degree: u32,
    layout_identity: LookupPolynomialIdentity,

    pub fn init(
        component_identity: LookupPolynomialIdentity,
        partition_identity: LookupPolynomialIdentity,
        column_count: usize,
        degree_cap: u32,
        events: []const LookupPolynomialEventDegreeV2,
        batches: []const LookupPolynomialBatchV2,
    ) LookupPolynomialProgramV2Error!LookupPolynomialLayoutV2 {
        const entry_count = std.math.cast(u32, events.len) orelse
            return error.CountOverflow;
        const batch_count = std.math.cast(u32, batches.len) orelse
            return error.CountOverflow;
        const columns = std.math.cast(u32, column_count) orelse
            return error.CountOverflow;
        const interaction_columns = std.math.mul(
            u32,
            batch_count,
            LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES,
        ) catch return error.CountOverflow;
        var maximum_degree: u32 = 0;
        for (batches) |batch|
            maximum_degree = @max(maximum_degree, batch.interaction_degree);

        var result = LookupPolynomialLayoutV2{
            .component_identity = component_identity,
            .partition_identity = partition_identity,
            .column_count = columns,
            .entry_count = entry_count,
            .batch_count = batch_count,
            .interaction_column_count = interaction_columns,
            .degree_cap = degree_cap,
            .maximum_interaction_degree = maximum_degree,
            .layout_identity = .{0} ** 32,
        };
        try result.validateStructure(events, batches);
        result.layout_identity = result.identityDigest(events, batches);
        try result.validate(events, batches);
        return result;
    }

    pub fn validate(
        self: *const LookupPolynomialLayoutV2,
        events: []const LookupPolynomialEventDegreeV2,
        batches: []const LookupPolynomialBatchV2,
    ) LookupPolynomialProgramV2Error!void {
        try self.validateStructure(events, batches);
        const actual = self.identityDigest(events, batches);
        if (!std.mem.eql(u8, &actual, &self.layout_identity))
            return error.InvalidLayoutIdentity;
    }

    fn validateStructure(
        self: *const LookupPolynomialLayoutV2,
        events: []const LookupPolynomialEventDegreeV2,
        batches: []const LookupPolynomialBatchV2,
    ) LookupPolynomialProgramV2Error!void {
        if (self.format_version != LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION or
            self.maximum_batch_size !=
                LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE or
            self.interaction_coordinates_per_batch !=
                LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES)
        {
            return error.InvalidLayoutVersion;
        }
        if (identityIsZeroV2(self.component_identity))
            return error.InvalidComponentIdentity;
        if (identityIsZeroV2(self.partition_identity))
            return error.InvalidPartitionIdentity;
        if (self.column_count == 0) return error.InvalidColumnCapacity;
        const event_count = std.math.cast(u32, events.len) orelse
            return error.CountOverflow;
        if (events.len == 0 or self.entry_count != event_count) {
            return error.InvalidEntryCount;
        }
        const batch_count = std.math.cast(u32, batches.len) orelse
            return error.CountOverflow;
        if (batches.len == 0 or self.batch_count != batch_count) {
            return error.InvalidBatchCount;
        }
        if (self.degree_cap == 0 or
            self.degree_cap > LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE)
        {
            return error.InvalidDegreeCap;
        }

        for (events, 0..) |event, ordinal| {
            const expected_ordinal = std.math.cast(u32, ordinal) orelse
                return error.CountOverflow;
            if (event.ordinal != expected_ordinal)
                return error.InvalidEventOrder;
            if (event.numerator_degree >
                LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE or
                event.denominator_degree >
                    LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE)
            {
                return error.InvalidEventDegree;
            }
        }

        var cursor: usize = 0;
        var maximum_degree: u32 = 0;
        for (batches) |batch| {
            const expected_first = std.math.cast(u32, cursor) orelse
                return error.CountOverflow;
            if (batch.first_entry != expected_first)
                return error.InvalidBatchCoverage;
            if (batch.entry_count == 0 or
                batch.entry_count > self.maximum_batch_size)
            {
                return error.InvalidBatchWidth;
            }
            const end = std.math.add(
                usize,
                cursor,
                batch.entry_count,
            ) catch return error.CountOverflow;
            if (end > events.len) return error.InvalidBatchCoverage;
            const expected_degree = try lookupInteractionDegreeV2(
                events[cursor],
                if (batch.entry_count == 2) events[cursor + 1] else null,
            );
            if (batch.interaction_degree != expected_degree)
                return error.InvalidBatchDegree;
            if (expected_degree > self.degree_cap)
                return error.InvalidDegreeCap;
            maximum_degree = @max(maximum_degree, expected_degree);
            cursor = end;
        }
        if (cursor != events.len) return error.InvalidBatchCoverage;
        if (self.maximum_interaction_degree != maximum_degree)
            return error.InvalidMaximumDegree;

        const expected_columns = std.math.mul(
            u32,
            self.batch_count,
            self.interaction_coordinates_per_batch,
        ) catch return error.CountOverflow;
        if (self.interaction_column_count != expected_columns)
            return error.InvalidInteractionCapacity;
    }

    pub fn identityDigest(
        self: *const LookupPolynomialLayoutV2,
        events: []const LookupPolynomialEventDegreeV2,
        batches: []const LookupPolynomialBatchV2,
    ) LookupPolynomialIdentity {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN);
        hashIntegerV2(&hash, u16, self.format_version);
        hashIntegerV2(&hash, u8, self.maximum_batch_size);
        hashIntegerV2(
            &hash,
            u8,
            self.interaction_coordinates_per_batch,
        );
        hash.update(&self.component_identity);
        hash.update(&self.partition_identity);
        hashIntegerV2(&hash, u32, self.column_count);
        hashIntegerV2(&hash, u32, self.entry_count);
        hashIntegerV2(&hash, u32, self.batch_count);
        hashIntegerV2(&hash, u32, self.interaction_column_count);
        hashIntegerV2(&hash, u32, self.degree_cap);
        hashIntegerV2(&hash, u32, self.maximum_interaction_degree);
        for (events) |event| {
            hashIntegerV2(&hash, u32, event.ordinal);
            hashIntegerV2(&hash, u32, event.numerator_degree);
            hashIntegerV2(&hash, u32, event.denominator_degree);
        }
        for (batches) |batch| {
            hashIntegerV2(&hash, u32, batch.first_entry);
            hashIntegerV2(&hash, u8, batch.entry_count);
            hashIntegerV2(&hash, u32, batch.interaction_degree);
        }
        return hash.finalResult();
    }
};

/// Pointer-free compiler output suitable for embedding beside a physical
/// component manifest. A decoded or rebuilt owner is admitted only by matching
/// all four identities and the exact committed geometry in this record.
pub const LookupPolynomialAuthorityV2 = struct {
    format_version: u16 = LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION,
    component_identity: LookupPolynomialIdentity,
    partition_identity: LookupPolynomialIdentity,
    layout_identity: LookupPolynomialIdentity,
    program_identity: LookupPolynomialIdentity,
    entry_count: u32,
    batch_count: u32,
    interaction_column_count: u32,
    maximum_interaction_degree: u32,

    pub fn validate(self: *const LookupPolynomialAuthorityV2) LookupPolynomialProgramV2Error!void {
        if (self.format_version != LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION)
            return error.InvalidAuthorityVersion;
        if (identityIsZeroV2(self.component_identity))
            return error.InvalidComponentIdentity;
        if (identityIsZeroV2(self.partition_identity))
            return error.InvalidPartitionIdentity;
        if (identityIsZeroV2(self.layout_identity))
            return error.InvalidLayoutIdentity;
        if (identityIsZeroV2(self.program_identity))
            return error.InvalidProgramIdentity;
        const expected_columns = std.math.mul(
            u32,
            self.batch_count,
            LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES,
        ) catch return error.InvalidAuthorityGeometry;
        if (self.entry_count == 0 or self.batch_count == 0 or
            self.interaction_column_count != expected_columns or
            self.maximum_interaction_degree == 0 or
            self.maximum_interaction_degree >
                LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE)
        {
            return error.InvalidAuthorityGeometry;
        }
    }
};

/// Owned polynomial DAG plus an authenticated variable batch layout. The V2
/// capability remains opt-in: constructing this owner alone cannot change V1
/// dispatch or a production proof layout.
pub const OwnedLookupPolynomialProgramV2 = struct {
    allocator: std.mem.Allocator,
    layout: LookupPolynomialLayoutV2,
    nodes: []BasePolynomialNode,
    entries: []LookupPolynomialEntry,
    event_degrees: []LookupPolynomialEventDegreeV2,
    batches: []LookupPolynomialBatchV2,
    program_identity: LookupPolynomialIdentity,

    pub fn deinit(self: *OwnedLookupPolynomialProgramV2) void {
        self.allocator.free(self.batches);
        self.allocator.free(self.event_degrees);
        self.allocator.free(self.entries);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn seal(self: *OwnedLookupPolynomialProgramV2) LookupPolynomialProgramV2Error!void {
        self.program_identity = .{0} ** 32;
        try self.validateStructure();
        self.program_identity = self.identityDigest();
        try self.validate();
    }

    pub fn validate(self: *const OwnedLookupPolynomialProgramV2) LookupPolynomialProgramV2Error!void {
        try self.validateStructure();
        const actual = self.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.program_identity))
            return error.InvalidProgramIdentity;
    }

    pub fn authority(self: *const OwnedLookupPolynomialProgramV2) LookupPolynomialProgramV2Error!LookupPolynomialAuthorityV2 {
        try self.validate();
        var result = LookupPolynomialAuthorityV2{
            .component_identity = self.layout.component_identity,
            .partition_identity = self.layout.partition_identity,
            .layout_identity = self.layout.layout_identity,
            .program_identity = self.program_identity,
            .entry_count = self.layout.entry_count,
            .batch_count = self.layout.batch_count,
            .interaction_column_count = self.layout.interaction_column_count,
            .maximum_interaction_degree = self.layout.maximum_interaction_degree,
        };
        try result.validate();
        return result;
    }

    pub fn validateAgainst(
        self: *const OwnedLookupPolynomialProgramV2,
        expected: *const LookupPolynomialAuthorityV2,
    ) LookupPolynomialProgramV2Error!void {
        try expected.validate();
        try self.validate();
        if (!std.mem.eql(
            u8,
            &self.layout.component_identity,
            &expected.component_identity,
        )) return error.InvalidComponentIdentity;
        if (!std.mem.eql(
            u8,
            &self.layout.partition_identity,
            &expected.partition_identity,
        )) return error.InvalidPartitionIdentity;
        if (!std.mem.eql(
            u8,
            &self.layout.layout_identity,
            &expected.layout_identity,
        )) return error.InvalidLayoutIdentity;
        if (!std.mem.eql(
            u8,
            &self.program_identity,
            &expected.program_identity,
        )) return error.InvalidProgramIdentity;
        if (self.layout.entry_count != expected.entry_count or
            self.layout.batch_count != expected.batch_count or
            self.layout.interaction_column_count !=
                expected.interaction_column_count or
            self.layout.maximum_interaction_degree !=
                expected.maximum_interaction_degree)
        {
            return error.InvalidAuthorityGeometry;
        }
    }

    fn validateStructure(self: *const OwnedLookupPolynomialProgramV2) LookupPolynomialProgramV2Error!void {
        try self.layout.validate(self.event_degrees, self.batches);
        if (self.nodes.len == 0) return error.InvalidNode;
        if (self.nodes.len > std.math.maxInt(u32))
            return error.CountOverflow;
        if (self.entries.len != self.event_degrees.len or
            self.entries.len != @as(usize, self.layout.entry_count))
        {
            return error.InvalidEntryCount;
        }

        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => if (node.lhs != 0 or node.rhs != 0 or
                node.value >= m31.Modulus)
            {
                return error.InvalidNode;
            },
            .column => if (node.lhs != 0 or node.rhs != 0 or
                node.value >= self.layout.column_count)
            {
                return error.InvalidNode;
            },
            .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index or
                node.value != 0)
            {
                return error.InvalidNode;
            },
            .neg => if (node.lhs >= index or node.rhs != 0 or node.value != 0) {
                return error.InvalidNode;
            },
        };

        for (self.entries) |entry| {
            if (entry.arity == 0 or
                entry.arity > MAX_LOOKUP_POLYNOMIAL_ARITY or
                entry.numerator >= self.nodes.len)
            {
                return error.InvalidEntry;
            }
            for (entry.values[0..entry.arity]) |value| {
                if (value >= self.nodes.len) return error.InvalidEntry;
            }
        }
    }

    pub fn batchCount(self: *const OwnedLookupPolynomialProgramV2) usize {
        return self.batches.len;
    }

    pub fn interactionColumnCount(self: *const OwnedLookupPolynomialProgramV2) usize {
        return @as(usize, self.layout.interaction_column_count);
    }

    pub fn parameterCount(self: *const OwnedLookupPolynomialProgramV2) LookupPolynomialProgramV2Error!usize {
        var count = self.batches.len;
        for (self.entries) |entry| {
            count = std.math.add(usize, count, 1 + @as(usize, entry.arity)) catch
                return error.CountOverflow;
        }
        return count;
    }

    /// Migration invariant for components whose selected partition is the V1
    /// uniform partition. Polynomial node/entry order, parameter order, and
    /// every batch range must be exactly equal.
    pub fn isExactUniformV1(
        self: *const OwnedLookupPolynomialProgramV2,
        legacy: *const OwnedLookupPolynomialProgram,
    ) bool {
        legacy.validate() catch return false;
        self.validate() catch return false;
        if (legacy.column_count != @as(usize, self.layout.column_count) or
            legacy.nodes.len != self.nodes.len or
            legacy.entries.len != self.entries.len or
            legacy.batchCount() != self.batches.len)
        {
            return false;
        }
        for (legacy.nodes, self.nodes) |expected, actual| {
            if (expected.op != actual.op or expected.lhs != actual.lhs or
                expected.rhs != actual.rhs or expected.value != actual.value)
            {
                return false;
            }
        }
        for (legacy.entries, self.entries) |expected, actual| {
            if (expected.numerator != actual.numerator or
                expected.arity != actual.arity)
            {
                return false;
            }
            for (
                expected.values[0..expected.arity],
                actual.values[0..actual.arity],
            ) |expected_value, actual_value| {
                if (expected_value != actual_value) return false;
            }
        }
        var cursor: usize = 0;
        for (self.batches) |batch| {
            const expected_width = @min(
                legacy.batch_size,
                legacy.entries.len - cursor,
            );
            if (@as(usize, batch.first_entry) != cursor or
                @as(usize, batch.entry_count) != expected_width)
            {
                return false;
            }
            cursor += expected_width;
        }
        const parameter_count = self.parameterCount() catch return false;
        return cursor == legacy.entries.len and
            parameter_count == legacy.parameterCount();
    }

    fn identityDigest(self: *const OwnedLookupPolynomialProgramV2) LookupPolynomialIdentity {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN);
        hash.update(&self.layout.layout_identity);
        hashIntegerV2(&hash, u32, @intCast(self.nodes.len));
        for (self.nodes) |node| {
            hashIntegerV2(&hash, u8, @intFromEnum(node.op));
            hashIntegerV2(&hash, u32, node.lhs);
            hashIntegerV2(&hash, u32, node.rhs);
            hashIntegerV2(&hash, u32, node.value);
        }
        hashIntegerV2(&hash, u32, @intCast(self.entries.len));
        for (self.entries) |entry| {
            hashIntegerV2(&hash, u32, entry.numerator);
            hashIntegerV2(&hash, u8, entry.arity);
            for (entry.values[0..entry.arity]) |value|
                hashIntegerV2(&hash, u32, value);
        }
        return hash.finalResult();
    }
};

fn lookupInteractionDegreeV2(
    first: LookupPolynomialEventDegreeV2,
    second: ?LookupPolynomialEventDegreeV2,
) LookupPolynomialProgramV2Error!u32 {
    const second_denominator = if (second) |item|
        item.denominator_degree
    else
        0;
    const denominator_product = std.math.add(
        u32,
        first.denominator_degree,
        second_denominator,
    ) catch return error.DegreeOverflow;
    const first_numerator_term = std.math.add(
        u32,
        first.numerator_degree,
        second_denominator,
    ) catch return error.DegreeOverflow;
    const second_numerator_term = if (second) |item|
        std.math.add(
            u32,
            item.numerator_degree,
            first.denominator_degree,
        ) catch return error.DegreeOverflow
    else
        0;
    const transition_term = std.math.add(
        u32,
        1,
        denominator_product,
    ) catch return error.DegreeOverflow;
    return @max(
        transition_term,
        @max(first_numerator_term, second_numerator_term),
    );
}

fn identityIsZeroV2(identity: LookupPolynomialIdentity) bool {
    return std.mem.allEqual(u8, &identity, 0);
}

fn hashIntegerV2(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

/// Pairs-batched LogUp transition constraints whose base tuple expressions are
/// exported from a production typed builder. Parameter order is canonical:
/// for every entry, `(z, alpha^0, ..., alpha^(arity-1))`, followed by one
/// claimed sum per batch.
pub const LookupPolynomialCapabilityV1 = struct {
    program_id: u64,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    interaction_tree_index: usize,
    first_interaction_column: usize,
    interaction_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedLookupPolynomialProgram,
    export_parameters: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]QM31,
};

/// Variable singleton/pair lookup capability authenticated by a pointer-free
/// compiler authority. This is append-only beside V1: a component must opt in
/// explicitly, and existing backends may decline it through their ordinary
/// capability fallback until they implement the V2 partition.
pub const LookupPolynomialCapabilityV2 = struct {
    /// Borrowed from the same stable owner as `ComponentProver.ctx` and copied
    /// into backend preparation before any worker can start.
    authority: *const LookupPolynomialAuthorityV2,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    interaction_tree_index: usize,
    first_interaction_column: usize,
    interaction_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedLookupPolynomialProgramV2,
    export_parameters: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]QM31,
};

comptime {
    if (@sizeOf(LookupPolynomialCapabilityV2) >
        @sizeOf(LookupPolynomialCapabilityV1))
    {
        @compileError("dormant lookup-polynomial V2 must not inflate every production component");
    }
}

/// Reviewed semantic contracts that a backend may accelerate without
/// identifying a workload or trusting a coincidental vtable address. Each
/// variant names the complete AIR relation implemented by the accelerated
/// kernel; unmarked components always use the reference evaluator.
pub const BackendCompositionCapability = union(enum) {
    /// For one trace tree with columns `[a, b, c, ...]`, contributes one
    /// constraint per consecutive triple: `c - (a^2 + b^2)`, in canonical
    /// component constraint order, divided by the trace-coset vanishing
    /// polynomial.
    quadratic_sum_squares_v1: struct {
        trace_tree_index: usize,
        first_column: usize,
    },
    /// Direct base-field constraints exported from the frontend's production
    /// typed AIR builder. Random-coefficient order and vanishing denominators
    /// remain owned by the generic prover.
    base_polynomial_v1: BasePolynomialCapabilityV1,
    /// Pairs-batched LogUp transition constraints over production-exported
    /// base tuple expressions and committed secure cumulative columns.
    lookup_polynomial_v1: LookupPolynomialCapabilityV1,
    /// Authenticated variable singleton/pair partition used by the versioned
    /// SegmentV2 statement and proof layout.
    lookup_polynomial_v2: LookupPolynomialCapabilityV2,
};
