//! Internal composition circuit authority shard; use composition_circuit.zig publicly.

const dependency_0 = @import("composition_circuit_reference.zig");

const AnchorLane = dependency_0.AnchorLane;
const ChallengeCoordinate = dependency_0.ChallengeCoordinate;
const CircuitGraph = dependency_0.CircuitGraph;
const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const ModeSet = dependency_0.ModeSet;
const RELATION_CHALLENGE_WORD_COUNT = dependency_0.RELATION_CHALLENGE_WORD_COUNT;
const RecursionInput = dependency_0.RecursionInput;
const RecursionLane = dependency_0.RecursionLane;
const RecursionSource = dependency_0.RecursionSource;
const Reference = dependency_0.Reference;
const SCHEDULE_DOMAIN = dependency_0.SCHEDULE_DOMAIN;
const SCHEDULE_FORMAT_VERSION = dependency_0.SCHEDULE_FORMAT_VERSION;
const SECURE_VALUE_WORD_COUNT = dependency_0.SECURE_VALUE_WORD_COUNT;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const SecureCoordinate = dependency_0.SecureCoordinate;
const VmLane = dependency_0.VmLane;
const VmSource = dependency_0.VmSource;
const digest = dependency_0.digest;
const hashInt = dependency_0.hashInt;
const hashRecursionSource = dependency_0.hashRecursionSource;
const hashVmSource = dependency_0.hashVmSource;
const m31 = dependency_0.m31;
const recursionSourceIndices = dependency_0.recursionSourceIndices;
const relation = dependency_0.relation;
const statement = dependency_0.statement;
const std = dependency_0.std;
const validateCircuitId = dependency_0.validateCircuitId;
const vmSourceIndices = dependency_0.vmSourceIndices;

pub const Classification = union(enum) {
    vm_input: VmSource,
    recursion_input: RecursionInput,
    constant_anchor: ModeSet,
    output_anchor: ModeSet,
};

pub const PREPROCESSED_COLUMN_COUNT: usize = 22;

pub const Row = struct {
    classification: Classification,
    circuit_id: u32,
    node_id: u32,
    use_count: u32,
    fixed_value: [4]u32 = .{ 0, 0, 0, 0 },

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        const source_value = sourceClass(self.classification);
        const indices = sourceIndices(self.classification);
        const tag = std.meta.activeTag(self.classification);
        const is_vm = tag == .vm_input;
        const is_recursion = tag == .recursion_input;
        const recursion = switch (self.classification) {
            .recursion_input => |input| input,
            else => RecursionInput{
                .verifier_id = SEGMENT_VERIFIER_ID,
                .statement_scope = 0,
                .source = .parent_binary_selector,
            },
        };
        return .{
            M31.one(),
            boolM31(source_value == .sampled_value),
            boolM31(
                source_value == .claimed_sum or
                    source_value == .transcript_claimed_sum,
            ),
            boolM31(source_value == .relation_challenge),
            boolM31(source_value == .composition_randomness),
            boolM31(source_value == .oods_point),
            boolM31(source_value == .segment_selector),
            M31.fromU64(self.circuit_id),
            M31.fromU64(self.node_id),
            M31.fromU64(self.use_count),
            M31.fromU64(indices[0]),
            M31.fromU64(indices[1]),
            boolM31(tag == .constant_anchor or tag == .output_anchor),
            boolM31(is_vm),
            boolM31(is_recursion),
            boolM31(source_value == .parent_binary_selector),
            boolM31(source_value == .child_kind_selector),
            boolM31(source_value == .statement_word),
            M31.fromU64(if (is_recursion) recursion.verifier_id else SEGMENT_VERIFIER_ID),
            M31.fromU64(if (is_recursion) recursion.statement_scope else 0),
            boolM31(is_recursion and source_value == .claimed_sum),
            boolM31(source_value == .transcript_claimed_sum),
        };
    }
};

pub const CompiledSchedule = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    reference_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn deinit(self: *CompiledSchedule) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn releaseRows(self: *CompiledSchedule) []Row {
        const rows = self.rows;
        self.* = undefined;
        return rows;
    }
};

/// Cold O(nodes + bindings + outputs) compiler. It performs two bounded
/// allocations regardless of lane count: final rows plus a reusable use-count
/// scratch vector. The returned writer hot path performs no allocation.
pub fn compile(
    allocator: std.mem.Allocator,
    reference: *const Reference,
) Error!CompiledSchedule {
    try reference.validate();
    const row_count = try scheduleRowCount(reference);
    const rows = try allocator.alloc(Row, row_count);
    errdefer allocator.free(rows);
    const scratch_len = maximumNodeCount(reference);
    const use_scratch = try allocator.alloc(u32, scratch_len);
    defer allocator.free(use_scratch);

    var cursor: usize = 0;
    try appendVmInputs(rows, &cursor, reference.vm, use_scratch);
    for (reference.recursion_lanes) |lane| {
        try appendRecursionInputs(rows, &cursor, lane, use_scratch);
    }
    try appendAnchors(rows, &cursor, .{
        .circuit_id = reference.vm.circuit_id,
        .graph = reference.vm.graph,
        .active_in = .SEGMENT,
    }, use_scratch);
    for (reference.additional_anchors) |anchor| {
        try appendAnchors(rows, &cursor, anchor, use_scratch);
    }
    std.debug.assert(cursor == rows.len);
    try validateCompiledRows(rows);
    return .{
        .allocator = allocator,
        .rows = rows,
        .reference_digest = reference.identity_digest,
        .authority_digest = computeScheduleDigest(reference.identity_digest, rows),
    };
}

pub fn computeScheduleDigest(
    reference_digest: digest.Digest,
    rows: []const Row,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SCHEDULE_DOMAIN);
    hashInt(&hash, u16, SCHEDULE_FORMAT_VERSION);
    hash.update(&reference_digest);
    hashInt(&hash, u32, rows.len);
    for (rows) |row| hashRow(&hash, row);
    return hash.finalResult();
}

pub fn validateCompiledRows(rows: []const Row) Error!void {
    var phase: enum { vm, recursion, anchors } = .vm;
    var segment_selectors: usize = 0;
    var anchor_circuit: ?u32 = null;
    var anchor_mode: ?ModeSet = null;
    for (rows) |row| {
        try validateRow(row);
        switch (row.classification) {
            .vm_input => |source_value| {
                if (phase != .vm) return error.InvalidScheduleOrder;
                segment_selectors += @intFromBool(
                    std.meta.activeTag(source_value) == .segment_selector,
                );
            },
            .recursion_input => {
                if (phase == .anchors) return error.InvalidScheduleOrder;
                phase = .recursion;
            },
            .constant_anchor, .output_anchor => |mode| {
                phase = .anchors;
                if (anchor_circuit == null or anchor_circuit.? != row.circuit_id) {
                    anchor_circuit = row.circuit_id;
                    anchor_mode = mode;
                } else if (!std.meta.eql(anchor_mode.?, mode)) {
                    return error.AnchorModeMismatch;
                }
            },
        }
    }
    if (segment_selectors != 1) return error.InvalidInputSource;
}

pub fn validateRow(row: Row) Error!void {
    try validateCircuitId(row.circuit_id);
    if (row.node_id >= m31.Modulus) return error.NodeCountNotCanonical;
    if (row.use_count >= m31.Modulus) return error.UseCountNotCanonical;
    for (row.fixed_value) |limb| if (limb >= m31.Modulus)
        return error.FixedValueNotCanonical;
    switch (row.classification) {
        .vm_input => |source_value| {
            if (!allZero(row.fixed_value)) return error.InvalidInputSource;
            try validateVmSourceBounds(source_value);
        },
        .recursion_input => |input| {
            if (!allZero(row.fixed_value) or input.verifier_id >= m31.Modulus or
                input.statement_scope >= m31.Modulus)
            {
                return error.InvalidInputSource;
            }
            try validateRecursionSourceBounds(input.source);
        },
        .constant_anchor => |modes| try modes.validate(),
        .output_anchor => |modes| {
            try modes.validate();
            if (row.use_count != 0 or !allZero(row.fixed_value))
                return error.InvalidScheduleOrder;
        },
    }
}

pub fn scheduleRowCount(reference: *const Reference) Error!usize {
    var count = reference.vm.bindings.len;
    for (reference.recursion_lanes) |lane| {
        count = std.math.add(usize, count, lane.bindings.len) catch
            return error.ArithmeticOverflow;
    }
    count = try addAnchorRowCount(count, reference.vm.graph);
    for (reference.additional_anchors) |anchor| {
        count = try addAnchorRowCount(count, anchor.graph);
    }
    if (count >= m31.Modulus) return error.ScheduleTooLarge;
    return count;
}

pub fn addAnchorRowCount(base: usize, graph: CircuitGraph) Error!usize {
    var constants: usize = 0;
    for (graph.nodes) |node| constants += @intFromBool(std.meta.activeTag(node.op) == .constant);
    const with_constants = std.math.add(usize, base, constants) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, with_constants, graph.outputs.len) catch
        return error.ArithmeticOverflow;
}

pub fn maximumNodeCount(reference: *const Reference) usize {
    var result = reference.vm.graph.nodes.len;
    for (reference.recursion_lanes) |lane| result = @max(result, lane.graph.nodes.len);
    for (reference.additional_anchors) |anchor| result = @max(result, anchor.graph.nodes.len);
    return result;
}

pub fn appendVmInputs(
    rows: []Row,
    cursor: *usize,
    lane: VmLane,
    scratch: []u32,
) Error!void {
    try computeUseCounts(lane.graph, scratch);
    for (lane.bindings) |binding| {
        rows[cursor.*] = .{
            .classification = .{ .vm_input = binding.source },
            .circuit_id = lane.circuit_id,
            .node_id = binding.node_id,
            .use_count = scratch[binding.node_id],
        };
        cursor.* += 1;
    }
}

pub fn appendRecursionInputs(
    rows: []Row,
    cursor: *usize,
    lane: RecursionLane,
    scratch: []u32,
) Error!void {
    try computeUseCounts(lane.graph, scratch);
    for (lane.bindings) |binding| {
        rows[cursor.*] = .{
            .classification = .{ .recursion_input = .{
                .verifier_id = lane.verifier_id,
                .statement_scope = lane.statement_scope,
                .source = binding.source,
            } },
            .circuit_id = lane.circuit_id,
            .node_id = binding.node_id,
            .use_count = scratch[binding.node_id],
        };
        cursor.* += 1;
    }
}

pub fn appendAnchors(
    rows: []Row,
    cursor: *usize,
    anchor: AnchorLane,
    scratch: []u32,
) Error!void {
    try computeUseCounts(anchor.graph, scratch);
    for (anchor.graph.nodes, 0..) |node, node_id| switch (node.op) {
        .constant => |fixed_value| {
            rows[cursor.*] = .{
                .classification = .{ .constant_anchor = anchor.active_in },
                .circuit_id = anchor.circuit_id,
                .node_id = @intCast(node_id),
                .use_count = scratch[node_id],
                .fixed_value = fixed_value,
            };
            cursor.* += 1;
        },
        else => {},
    };
    for (anchor.graph.outputs) |output| {
        rows[cursor.*] = .{
            .classification = .{ .output_anchor = anchor.active_in },
            .circuit_id = anchor.circuit_id,
            .node_id = output,
            .use_count = 0,
        };
        cursor.* += 1;
    }
}

pub fn computeUseCounts(graph: CircuitGraph, scratch: []u32) Error!void {
    const uses = scratch[0..graph.nodes.len];
    @memset(uses, 0);
    for (graph.nodes) |node| switch (node.op) {
        .add, .sub, .mul => |operands| {
            try incrementUse(&uses[operands.lhs]);
            try incrementUse(&uses[operands.rhs]);
        },
        .neg, .inverse => |operand| try incrementUse(&uses[operand]),
        .input, .constant => {},
    };
    for (graph.outputs) |output| try incrementUse(&uses[output]);
}

pub fn incrementUse(value: *u32) Error!void {
    value.* = std.math.add(u32, value.*, 1) catch return error.ArithmeticOverflow;
    if (value.* >= m31.Modulus) return error.UseCountNotCanonical;
}

pub const SourceClass = enum(u8) {
    none,
    sampled_value,
    claimed_sum,
    relation_challenge,
    composition_randomness,
    oods_point,
    segment_selector,
    parent_binary_selector,
    child_kind_selector,
    statement_word,
    transcript_claimed_sum,
};

pub fn sourceClass(classification: Classification) SourceClass {
    return switch (classification) {
        .vm_input => |source_value| switch (source_value) {
            .segment_selector => .segment_selector,
            .sampled_value => .sampled_value,
            .claimed_sum => .claimed_sum,
            .relation_challenge => .relation_challenge,
            .composition_randomness => .composition_randomness,
            .oods_point => .oods_point,
            .transcript_claimed_sum => .transcript_claimed_sum,
        },
        .recursion_input => |input| switch (input.source) {
            .parent_binary_selector => .parent_binary_selector,
            .child_kind_selector => .child_kind_selector,
            .statement_word => .statement_word,
            .sampled_value => .sampled_value,
            .claimed_sum => .claimed_sum,
            .relation_challenge => .relation_challenge,
            .composition_randomness => .composition_randomness,
            .oods_point => .oods_point,
            .public_wire_boundary => .claimed_sum,
        },
        .constant_anchor, .output_anchor => .none,
    };
}

pub fn sourceIndices(classification: Classification) [2]u32 {
    return switch (classification) {
        .vm_input => |source_value| vmSourceIndices(source_value),
        .recursion_input => |input| recursionSourceIndices(input.source),
        .constant_anchor, .output_anchor => .{ 0, 0 },
    };
}

pub fn validateVmSourceBounds(source_value: VmSource) Error!void {
    switch (source_value) {
        .segment_selector => {},
        .sampled_value, .claimed_sum, .transcript_claimed_sum => |coordinate| try validateSecure(coordinate),
        .relation_challenge => |coordinate| try validateChallenge(coordinate),
        .composition_randomness, .oods_point => |word_index| if (word_index >= SECURE_VALUE_WORD_COUNT)
            return error.InvalidInputSource,
    }
}

pub fn validateRecursionSourceBounds(source_value: RecursionSource) Error!void {
    switch (source_value) {
        .parent_binary_selector, .child_kind_selector => {},
        .statement_word => |word_index| if (word_index >= statement.CANONICAL_WORD_COUNT)
            return error.InvalidInputSource,
        .sampled_value, .claimed_sum => |coordinate| try validateSecure(coordinate),
        .relation_challenge => |coordinate| try validateChallenge(coordinate),
        .composition_randomness, .oods_point => |word_index| if (word_index >= SECURE_VALUE_WORD_COUNT)
            return error.InvalidInputSource,
        .public_wire_boundary => |coordinate| try validateSecure(coordinate),
    }
}

pub fn validateSecure(coordinate: SecureCoordinate) Error!void {
    if (coordinate.item_index >= m31.Modulus or coordinate.word_index >= SECURE_VALUE_WORD_COUNT)
        return error.InvalidInputSource;
}

pub fn validateChallenge(coordinate: ChallengeCoordinate) Error!void {
    if (coordinate.challenge >= relation.UNIVERSAL_RELATION_COUNT or
        coordinate.word_index >= RELATION_CHALLENGE_WORD_COUNT)
    {
        return error.InvalidInputSource;
    }
}

pub fn allZero(values: [4]u32) bool {
    return values[0] == 0 and values[1] == 0 and values[2] == 0 and values[3] == 0;
}

pub fn boolM31(value: bool) M31 {
    return M31.fromU64(@intFromBool(value));
}

pub fn hashRow(hash: anytype, row: Row) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(row.classification)));
    switch (row.classification) {
        .vm_input => |source_value| hashVmSource(hash, source_value),
        .recursion_input => |input| {
            hashInt(hash, u32, input.verifier_id);
            hashInt(hash, u32, input.statement_scope);
            hashRecursionSource(hash, input.source);
        },
        .constant_anchor, .output_anchor => |modes| {
            hashInt(hash, u8, @as(u8, @bitCast(modes)));
        },
    }
    hashInt(hash, u32, row.circuit_id);
    hashInt(hash, u32, row.node_id);
    hashInt(hash, u32, row.use_count);
    for (row.fixed_value) |limb| hashInt(hash, u32, limb);
}
