//! Internal shard of vm_air_composition_circuit.zig; use the public facade.

const dependency_0 = @import("vm_air_composition_circuit_error.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const m31 = dependency_0.m31;
const QM31 = dependency_0.QM31;
const qm31 = dependency_0.qm31;
const verifier_types = dependency_0.verifier_types;
const opcode_interaction = dependency_0.opcode_interaction;
const statement_mod = dependency_0.statement_mod;
const graph_mod = dependency_0.graph_mod;
const vm_leaf_context = dependency_0.vm_leaf_context;
const transcript_claims = dependency_0.transcript_claims;
const Sha256 = dependency_0.Sha256;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const CIRCUIT_DOMAIN = dependency_0.CIRCUIT_DOMAIN;
const CIRCUIT_ID = dependency_0.CIRCUIT_ID;
const TREE_COUNT = dependency_0.TREE_COUNT;
const Error = dependency_0.Error;

pub const Evaluation = struct {
    allocator: std.mem.Allocator,
    values: []QM31,
    circuit_identity: [Sha256.digest_length]u8,

    pub fn deinit(self: *Evaluation) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

pub const Handle = union(enum) {
    constant: QM31,
    node: u32,
};

pub const OpKey = union(enum) {
    constant: [4]u32,
    add: graph_mod.BinaryOperands,
    sub: graph_mod.BinaryOperands,
    mul: graph_mod.BinaryOperands,
    neg: u32,
    inverse: u32,
};

pub fn validateSampleGeometry(context: *const vm_leaf_context.Context, capture: anytype) Error!void {
    if (capture.sampled_points.len != TREE_COUNT or
        capture.column_log_sizes.len != TREE_COUNT)
    {
        return error.InvalidCaptureShape;
    }
    var expected_preprocessed = 2 * context.component_descs.len;
    var expected_main: usize = 0;
    var expected_interaction: usize = 0;
    for (context.component_descs) |descriptor| {
        expected_main += descriptor.n_columns;
        expected_interaction += opcode_interaction.nColumns(descriptor.family);
    }
    for (context.infra_descs) |descriptor| {
        expected_preprocessed += statement_mod.nPreprocessedColumnsForInfra(descriptor.kind);
        expected_main += descriptor.n_columns;
        expected_interaction += statement_mod.nInteractionColsForInfra(descriptor.kind);
    }
    const expected_composition = verifier_types.compositionColumnCount(
        context.profile.composition_log_split,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidCaptureShape;
    const expected_columns = [TREE_COUNT]usize{
        expected_preprocessed,
        expected_main,
        expected_interaction,
        expected_composition,
    };
    var sampled_total: usize = 0;
    for (capture.sampled_points, capture.column_log_sizes, expected_columns, 0..) |
        points,
        logs,
        expected,
        tree,
    | {
        if (points.len != expected or logs.len != expected)
            return error.InvalidSampleGeometry;
        const expected_samples: usize = if (tree == 2) 2 else 1;
        for (points) |column| {
            if (column.len != expected_samples) return error.InvalidSampleGeometry;
            sampled_total = std.math.add(usize, sampled_total, column.len) catch
                return error.ArithmeticOverflow;
        }
    }
    if (sampled_total != capture.sampled_values.len)
        return error.InvalidSampleGeometry;
}

pub fn inputWord(
    source: graph_mod.VmSource,
    context: *const vm_leaf_context.Context,
    capture: anytype,
    active: bool,
) Error!M31 {
    return switch (source) {
        .segment_selector => M31.fromCanonical(@intFromBool(active)),
        .sampled_value => |coordinate| secureWord(
            capture.sampled_values,
            coordinate.item_index,
            coordinate.word_index,
        ),
        .claimed_sum => |coordinate| secureWord(
            context.detailed_claims,
            coordinate.item_index,
            coordinate.word_index,
        ),
        .transcript_claimed_sum => |coordinate| secureWord(
            &context.canonical_claims,
            coordinate.item_index,
            coordinate.word_index,
        ),
        .relation_challenge => |coordinate| blk: {
            if (coordinate.challenge >= context.profile.relation_challenge_count or
                coordinate.word_index >= 8)
            {
                return error.BindingCountMismatch;
            }
            const value = context.relation_draws[
                2 * coordinate.challenge + coordinate.word_index / 4
            ];
            break :blk value.toM31Array()[coordinate.word_index % 4];
        },
        .composition_randomness => |word| secureValueWord(
            capture.composition_randomness,
            word,
        ),
        .oods_point => |word| secureValueWord(capture.oods_seed, word),
    };
}

pub fn secureWord(values: []const QM31, item: u32, word: u32) Error!M31 {
    if (item >= values.len or word >= 4) return error.BindingCountMismatch;
    return values[item].toM31Array()[word];
}

pub fn secureValueWord(value: QM31, word: u32) Error!M31 {
    if (word >= 4) return error.BindingCountMismatch;
    return value.toM31Array()[word];
}

pub fn constantPair(lhs: Handle, rhs: Handle) ?[2]QM31 {
    return switch (lhs) {
        .constant => |a| switch (rhs) {
            .constant => |b| .{ a, b },
            else => null,
        },
        else => null,
    };
}

pub fn handleIsZero(value: Handle) bool {
    return switch (value) {
        .constant => |constant| constant.isZero(),
        else => false,
    };
}

pub fn isOne(value: Handle) bool {
    return switch (value) {
        .constant => |constant| constant.eql(QM31.one()),
        else => false,
    };
}

pub fn canonicalPair(lhs: u32, rhs: u32) graph_mod.BinaryOperands {
    return if (lhs <= rhs) .{ .lhs = lhs, .rhs = rhs } else .{ .lhs = rhs, .rhs = lhs };
}

pub fn qm31Words(value: QM31) [4]u32 {
    var words: [4]u32 = undefined;
    for (value.toM31Array(), &words) |limb, *word| word.* = limb.toU32();
    return words;
}

pub fn indexU32(index: usize) Error!u32 {
    if (index >= m31.Modulus) return error.CircuitTooLarge;
    return @intCast(index);
}

pub fn countInputNodes(nodes: []const graph_mod.Node) usize {
    var result: usize = 0;
    for (nodes) |node| result += @intFromBool(std.meta.activeTag(node.op) == .input);
    return result;
}

pub fn circuitDigest(
    air_profile_digest: [Sha256.digest_length]u8,
    graph_digest: [Sha256.digest_length]u8,
    reference_digest: [Sha256.digest_length]u8,
    schedule_digest: [Sha256.digest_length]u8,
    profile: graph_mod.InputProfile,
    bindings: []const graph_mod.VmInputBinding,
) [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update(CIRCUIT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u32, CIRCUIT_ID);
    hash.update(&air_profile_digest);
    hash.update(&graph_digest);
    hash.update(&reference_digest);
    hash.update(&schedule_digest);
    hashInt(&hash, u32, profile.sampled_value_count);
    hashInt(&hash, u32, profile.claimed_sum_count);
    hashInt(&hash, u32, profile.relation_challenge_count);
    hashInt(&hash, u32, profile.transcript_claimed_sum_count);
    hashInt(&hash, u32, @intCast(bindings.len));
    for (bindings) |binding| hashInt(&hash, u32, binding.node_id);
    return hash.finalResult();
}

pub fn transcriptComponentForInfra(
    kind: statement_mod.InfraKind,
) transcript_claims.Component {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
