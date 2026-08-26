//! Internal segment public native sum authority v2 authority shard; use segment_public_native_sum_authority_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const program_decode = @import("../air/program/decode.zig");
pub const arithmetic = @import("arithmetic_circuit.zig");
pub const public_source = @import("segment_public_outer_source_v2.zig");
pub const span_statement = @import("span_statement.zig");
pub const wire_statement = @import("segment_statement_v2.zig");
pub const graph_mod = @import("air/composition_circuit.zig");
pub const lowering = @import("air/verifier_arithmetic_lowering.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = public_source.NATIVE_SUM_CIRCUIT_ID;
pub const DOMAIN_COUNT: usize = 4;
pub const PUBLISHED_WORD_COUNT: usize =
    public_source.ARITHMETIC_PUBLICATION_WORD_COUNT;
pub const CHALLENGE_WORD_COUNT: usize = public_source.CHALLENGE_WORD_COUNT;
pub const OUTPUT_COUNT: usize = 5;
pub const INPUT_SUFFIX_WORD_COUNT: usize =
    PUBLISHED_WORD_COUNT + CHALLENGE_WORD_COUNT;
pub const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/segment-v2-native-public-sum-authority/v1\x00";
pub const EVALUATION_DOMAIN =
    "stwo-zig/typed-air/segment-v2-native-public-sum-evaluation/v1\x00";

pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const DESTINATION_FAILS_ATOMICALLY = true;
pub const POINTER_STABLE_OWNERSHIP = true;
pub const EXACT_GRAPH_AND_USE_COUNTS_SEALED = true;
pub const ROW11_OWNS_CANONICAL_PARSING = true;
pub const GRAPH_OWNS_RELATION_ARITHMETIC = true;
pub const PUBLISHED_SUMS_ARE_NOT_AUTHORITY = true;

pub const Error = public_source.Error || arithmetic.Error || graph_mod.Error ||
    error{
        AliasedBuffer,
        ArithmeticAuthorityMismatch,
        BufferLengthMismatch,
        GraphMirrorMismatch,
        InputBindingMismatch,
        InvalidAuthenticatedTopology,
        PublishedSumMismatch,
    };

pub const RelationDomainV2 = enum(u8) {
    registers_state = 0,
    memory_access = 1,
    program_access = 2,
    merkle = 3,
};

pub const PublishedCoordinateV2 = struct {
    domain: RelationDomainV2,
    limb: u2,
    /// Exact circuit-44 bridge coordinate emitted by row 37 and relayed by
    /// public-spine row 13.
    publication_index: u8,
};

pub const PublishedTotalCoordinateV2 = struct {
    limb: u2,
    /// Exact circuit-44 bridge coordinate emitted by row 37 and relayed by
    /// public-spine row 14.
    publication_index: u8,
};

pub const ChallengeCoordinateV2 = struct {
    relation: RelationDomainV2,
    /// 0--3 are z; 4--7 are alpha, in native transcript order.
    limb: u3,
};

pub const InputSourceV2 = union(enum) {
    wire_word: u32,
    published_sum_word: PublishedCoordinateV2,
    published_total_word: PublishedTotalCoordinateV2,
    native_challenge_word: ChallengeCoordinateV2,
};

pub const InputBindingV2 = struct {
    node_id: u32,
    use_count: u32,
    source: InputSourceV2,
};

pub const TermCountsV2 = struct {
    registers_state: u32,
    memory_access: u32,
    program_access: u32,
    merkle: u32,

    pub fn total(self: TermCountsV2) u64 {
        return @as(u64, self.registers_state) + self.memory_access +
            self.program_access + self.merkle;
    }
};

pub const OwnedGraph = struct {
    allocator: std.mem.Allocator,
    nodes: []graph_mod.Node,
    outputs: []u32,
    graph: graph_mod.CircuitGraph,

    pub fn init(
        allocator: std.mem.Allocator,
        circuit: *const arithmetic.Circuit,
    ) !OwnedGraph {
        const nodes = try allocator.alloc(graph_mod.Node, circuit.nodes().len);
        errdefer allocator.free(nodes);
        for (nodes, circuit.nodes()) |*destination, source| {
            destination.* = .{ .op = switch (source.op) {
                .input => .input,
                .constant => |words| .{ .constant = words },
                .add => |operands| .{ .add = .{
                    .lhs = operands.lhs,
                    .rhs = operands.rhs,
                } },
                .sub => |operands| .{ .sub = .{
                    .lhs = operands.lhs,
                    .rhs = operands.rhs,
                } },
                .mul => |operands| .{ .mul = .{
                    .lhs = operands.lhs,
                    .rhs = operands.rhs,
                } },
                .neg => |operand| .{ .neg = operand },
                .inverse => |operand| .{ .inverse = operand },
            } };
        }
        const outputs = try allocator.dupe(u32, circuit.outputs());
        errdefer allocator.free(outputs);
        const identity = graph_mod.computeGraphDigest(nodes, outputs);
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .outputs = outputs,
            .graph = try graph_mod.CircuitGraph.authenticate(
                nodes,
                outputs,
                identity,
            ),
        };
    }

    pub fn validate(self: *const OwnedGraph) !void {
        if (self.graph.nodes.ptr != self.nodes.ptr or
            self.graph.nodes.len != self.nodes.len or
            self.graph.outputs.ptr != self.outputs.ptr or
            self.graph.outputs.len != self.outputs.len)
        {
            return error.GraphMirrorMismatch;
        }
        try self.graph.validate();
    }

    pub fn deinit(self: *OwnedGraph) void {
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }
};

pub const EvaluationBuffersV2 = struct {
    destination_values: []QM31,
    scratch_inputs: []QM31,
    scratch_values: []QM31,
    use_count_scratch: []u32,
};

pub const AuthoredGraph = struct {
    circuit: arithmetic.Circuit,
    term_counts: TermCountsV2,
};

pub const GraphInputs = struct {
    wire: []const arithmetic.Value,
    published_sums: [DOMAIN_COUNT]arithmetic.Value,
    published_total: arithmetic.Value,
    relations: [DOMAIN_COUNT]BoundRelation,
};

pub const BoundRelation = struct {
    z: arithmetic.Value,
    alpha_powers: [7]arithmetic.Value,
    arity: u8,

    fn init(
        builder: *arithmetic.Builder,
        words: []const arithmetic.Value,
        arity: u8,
    ) Error!BoundRelation {
        if (words.len != 8 or arity == 0 or arity > 7)
            return error.InputBindingMismatch;
        const z = try composeSecure(builder, words[0..4]);
        const alpha = try composeSecure(builder, words[4..8]);
        var powers: [7]arithmetic.Value = undefined;
        var power = arithmetic.Value.one();
        for (powers[0..arity]) |*destination| {
            destination.* = power;
            power = try builder.mul(power, alpha);
        }
        for (powers[arity..]) |*destination|
            destination.* = arithmetic.Value.zero();
        return .{ .z = z, .alpha_powers = powers, .arity = arity };
    }

    fn combine(
        self: BoundRelation,
        builder: *arithmetic.Builder,
        values: []const arithmetic.Value,
    ) Error!arithmetic.Value {
        if (values.len != self.arity) return error.InputBindingMismatch;
        var result = arithmetic.Value.zero();
        for (values, self.alpha_powers[0..self.arity]) |value, power| {
            result = try builder.add(result, try builder.mul(value, power));
        }
        return builder.sub(result, self.z);
    }
};

pub const RelationAccumulator = struct {
    builder: *arithmetic.Builder,
    relations: *const [DOMAIN_COUNT]BoundRelation,
    sums: [DOMAIN_COUNT]arithmetic.Value = .{arithmetic.Value.zero()} **
        DOMAIN_COUNT,
    counts: TermCountsV2 = .{
        .registers_state = 0,
        .memory_access = 0,
        .program_access = 0,
        .merkle = 0,
    },

    pub fn add(
        self: *RelationAccumulator,
        domain: RelationDomainV2,
        tuple: []const arithmetic.Value,
        sign: enum { positive, negative },
    ) Error!void {
        const index = @intFromEnum(domain);
        const denominator = try self.relations[index].combine(
            self.builder,
            tuple,
        );
        const inverse = try self.builder.inverse(denominator);
        self.sums[index] = switch (sign) {
            .positive => try self.builder.add(self.sums[index], inverse),
            .negative => try self.builder.sub(self.sums[index], inverse),
        };
        const count = switch (domain) {
            .registers_state => &self.counts.registers_state,
            .memory_access => &self.counts.memory_access,
            .program_access => &self.counts.program_access,
            .merkle => &self.counts.merkle,
        };
        count.* = std.math.add(u32, count.*, 1) catch
            return error.ArithmeticOverflow;
    }
};

pub fn bindGraphInputs(
    builder: *arithmetic.Builder,
    values: []const arithmetic.Value,
    wire_count: usize,
) Error!GraphInputs {
    if (values.len != try checkedAdd(wire_count, INPUT_SUFFIX_WORD_COUNT))
        return error.InputBindingMismatch;
    const published_start = wire_count;
    var published_sums: [DOMAIN_COUNT]arithmetic.Value = undefined;
    for (&published_sums, 0..) |*sum, domain| {
        const start = published_start + domain * 4;
        sum.* = try composeSecure(builder, values[start..][0..4]);
    }
    const total_start = published_start + DOMAIN_COUNT * 4;
    const published_total = try composeSecure(
        builder,
        values[total_start..][0..4],
    );
    const challenge_start = wire_count + PUBLISHED_WORD_COUNT;
    const arities = [_]u8{ 2, 7, 5, 4 };
    var relations: [DOMAIN_COUNT]BoundRelation = undefined;
    for (&relations, arities, 0..) |*relation, arity, index| {
        const start = challenge_start + index * 8;
        relation.* = try BoundRelation.init(
            builder,
            values[start..][0..8],
            arity,
        );
    }
    return .{
        .wire = values[0..wire_count],
        .published_sums = published_sums,
        .published_total = published_total,
        .relations = relations,
    };
}

pub fn addSparseMemoryTerms(
    accumulator: *RelationAccumulator,
    view: *const wire_statement.CanonicalWireViewV2,
    wire: []const arithmetic.Value,
) Error!void {
    var positions = [_]usize{0} ** 4;
    while (nextMemoryAddress(view, positions)) |address| {
        const entry_value_match = positions[0] < view.entry_snapshot.count and
            view.sparseEntry(view.entry_snapshot, positions[0]).address == address;
        const exit_value_match = positions[1] < view.exit_snapshot.count and
            view.sparseEntry(view.exit_snapshot, positions[1]).address == address;
        const entry_clock_match = positions[2] < view.entry_memory_clocks.count and
            view.clockEntry(view.entry_memory_clocks, positions[2]).address == address;
        const exit_clock_match = positions[3] < view.exit_memory_clocks.count and
            view.clockEntry(view.exit_memory_clocks, positions[3]).address == address;

        const address_start = if (entry_value_match)
            retainedStart(view.entry_snapshot, positions[0])
        else if (exit_value_match)
            retainedStart(view.exit_snapshot, positions[1])
        else if (entry_clock_match)
            retainedStart(view.entry_memory_clocks, positions[2])
        else if (exit_clock_match)
            retainedStart(view.exit_memory_clocks, positions[3])
        else
            return error.InvalidAuthenticatedTopology;
        const address_value = try u32At(
            accumulator.builder,
            wire,
            address_start,
        );
        const entry_value = if (entry_value_match)
            view.sparseEntry(view.entry_snapshot, positions[0]).value
        else
            0;
        const exit_value = if (exit_value_match)
            view.sparseEntry(view.exit_snapshot, positions[1]).value
        else
            0;
        const entry_clock = if (entry_clock_match)
            try u32At(
                accumulator.builder,
                wire,
                retainedStart(view.entry_memory_clocks, positions[2]) + 2,
            )
        else
            arithmetic.Value.zero();
        const exit_clock = if (exit_clock_match)
            try u32At(
                accumulator.builder,
                wire,
                retainedStart(view.exit_memory_clocks, positions[3]) + 2,
            )
        else
            arithmetic.Value.zero();

        try accumulator.add(.memory_access, &.{
            baseValue(1),
            address_value,
            entry_clock,
            baseValue(@as(u8, @truncate(entry_value))),
            baseValue(@as(u8, @truncate(entry_value >> 8))),
            baseValue(@as(u8, @truncate(entry_value >> 16))),
            baseValue(@as(u8, @truncate(entry_value >> 24))),
        }, .positive);
        try accumulator.add(.memory_access, &.{
            baseValue(1),
            address_value,
            exit_clock,
            baseValue(@as(u8, @truncate(exit_value))),
            baseValue(@as(u8, @truncate(exit_value >> 8))),
            baseValue(@as(u8, @truncate(exit_value >> 16))),
            baseValue(@as(u8, @truncate(exit_value >> 24))),
        }, .negative);

        positions[0] += @intFromBool(entry_value_match);
        positions[1] += @intFromBool(exit_value_match);
        positions[2] += @intFromBool(entry_clock_match);
        positions[3] += @intFromBool(exit_clock_match);
    }
}

pub fn addContinuationCompensation(
    accumulator: *RelationAccumulator,
    view: *const wire_statement.CanonicalWireViewV2,
    wire: []const arithmetic.Value,
    section: wire_statement.RetainedSectionV2,
    root: arithmetic.Value,
) Error!void {
    if (section.count == 0) {
        try accumulator.add(.merkle, &.{
            baseValue(0), baseValue(0), root, root,
        }, .negative);
        return;
    }
    for (0..section.count) |index| {
        const entry = view.sparseEntry(section, index);
        const address = try u32At(
            accumulator.builder,
            wire,
            retainedStart(section, index),
        );
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const byte: u8 = @truncate(entry.value >> shift);
            if (byte == 0) continue;
            try accumulator.add(.merkle, &.{
                try accumulator.builder.add(
                    address,
                    baseValue(@as(u32, @intCast(limb))),
                ),
                baseValue(@import("../air/memory_commitment/sparse_merkle.zig").LEAF_DEPTH),
                baseValue(byte),
                root,
            }, .negative);
        }
    }
}

pub fn nextMemoryAddress(
    view: *const wire_statement.CanonicalWireViewV2,
    positions: [4]usize,
) ?u32 {
    var result: ?u32 = null;
    const candidates = [_]?u32{
        if (positions[0] < view.entry_snapshot.count)
            view.sparseEntry(view.entry_snapshot, positions[0]).address
        else
            null,
        if (positions[1] < view.exit_snapshot.count)
            view.sparseEntry(view.exit_snapshot, positions[1]).address
        else
            null,
        if (positions[2] < view.entry_memory_clocks.count)
            view.clockEntry(view.entry_memory_clocks, positions[2]).address
        else
            null,
        if (positions[3] < view.exit_memory_clocks.count)
            view.clockEntry(view.exit_memory_clocks, positions[3]).address
        else
            null,
    };
    for (candidates) |candidate| if (candidate) |address| {
        if (result == null or address < result.?) result = address;
    };
    return result;
}

pub fn retainedStart(
    section: wire_statement.RetainedSectionV2,
    index: usize,
) usize {
    return section.payload_start + index * wire_statement.RETAINED_ENTRY_WORDS;
}

pub fn baseU32(
    builder: *arithmetic.Builder,
    wire: []const arithmetic.Value,
    base_index: usize,
) Error!arithmetic.Value {
    return u32At(
        builder,
        wire,
        wire_statement.fixed_layout.base_statement + base_index,
    );
}

pub fn baseU64(
    builder: *arithmetic.Builder,
    wire: []const arithmetic.Value,
    base_index: usize,
) Error!arithmetic.Value {
    const start = wire_statement.fixed_layout.base_statement + base_index;
    if (start + 4 > wire.len) return error.InputBindingMismatch;
    var result = arithmetic.Value.zero();
    var radix: u64 = 1;
    for (wire[start..][0..4], 0..) |limb, index| {
        result = try builder.add(
            result,
            try builder.mul(baseValue(radix), limb),
        );
        if (index + 1 != 4) radix *= 1 << 16;
    }
    return result;
}

pub fn fixedU32(
    builder: *arithmetic.Builder,
    wire: []const arithmetic.Value,
    index: usize,
) Error!arithmetic.Value {
    return u32At(builder, wire, index);
}

pub fn u32At(
    builder: *arithmetic.Builder,
    wire: []const arithmetic.Value,
    index: usize,
) Error!arithmetic.Value {
    if (index + 2 > wire.len) return error.InputBindingMismatch;
    return builder.add(
        wire[index],
        try builder.mul(baseValue(1 << 16), wire[index + 1]),
    );
}

pub fn composeSecure(
    builder: *arithmetic.Builder,
    words: []const arithmetic.Value,
) Error!arithmetic.Value {
    if (words.len != 4) return error.InputBindingMismatch;
    var result = words[0];
    result = try builder.add(result, try builder.mul(
        words[1],
        arithmetic.Value.fromSecure(QM31.fromU32Unchecked(0, 1, 0, 0)),
    ));
    result = try builder.add(result, try builder.mul(
        words[2],
        arithmetic.Value.fromSecure(QM31.fromU32Unchecked(0, 0, 1, 0)),
    ));
    return builder.add(result, try builder.mul(
        words[3],
        arithmetic.Value.fromSecure(QM31.fromU32Unchecked(0, 0, 0, 1)),
    ));
}

pub fn baseValue(value: anytype) arithmetic.Value {
    return arithmetic.Value.fromBase(M31.fromU64(@as(u64, value)));
}

pub fn checkedAdd(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}
