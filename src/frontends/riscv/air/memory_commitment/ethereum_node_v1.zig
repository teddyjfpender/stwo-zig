//! Ethereum-only binary-node sponge and its caller AIR constraints.
//!
//! Rate 7, capacity 9, and a 9-M31 digest avoid the generic sub-128-bit
//! collision ceiling of an eight-lane digest. The last two digest words
//! require another squeeze permutation; capacity words are never exposed.
//! This does not change the scalar CSP commitment or recursion channel.
//!
//! Integration must consume all four full Poseidon I/O tuples and bind these
//! nodes into a Merkle tree and its public root. Caller constraints alone are
//! not a commitment proof or an end-to-end security claim.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const permutation = @import("poseidon2.zig");
const permutation_air = @import("poseidon2_air.zig");
const logup = @import("../logup.zig");
const relation_challenges = @import("../relation_challenges.zig");
const work_pool = @import("stwo_prover_engine").work_pool;

pub const SCHEMA_VERSION: u32 = 1;
pub const RATE: usize = 7;
pub const CAPACITY: usize = 9;
pub const DIGEST_WORDS: usize = 9;
pub const CALLS: usize = 4;
pub const DIGEST_COLUMN: usize = 1 + 5 + 2 * DIGEST_WORDS;
pub const N_MAIN_COLUMNS: usize = 1 + 5 + 3 * DIGEST_WORDS + 2 * CALLS * permutation.WIDTH;
pub const N_SUMS: usize = CALLS / 2;
pub const N_INTERACTION_COLUMNS: usize = N_SUMS * 4;
pub const N_LINK_CONSTRAINTS: usize = 1 + 5 + CALLS * permutation.WIDTH + DIGEST_WORDS;
pub const N_CONSTRAINTS: usize = 1 + N_LINK_CONSTRAINTS + N_SUMS;
pub const Digest = [DIGEST_WORDS]u32;
pub const Kind = enum(u1) { memory = 0, program = 1 };
const DOMAIN: u32 = 0x4554_4e30; // "ETN0", with a separate program domain.

comptime {
    std.debug.assert(RATE + CAPACITY == permutation.WIDTH);
    std.debug.assert(3 * RATE == 2 + 2 * DIGEST_WORDS + 1);
}

pub fn Row(comptime F: type) type {
    return struct {
        kind: F,
        height_bits: [5]F,
        left: [DIGEST_WORDS]F,
        right: [DIGEST_WORDS]F,
        digest: [DIGEST_WORDS]F,
        inputs: [CALLS][permutation.WIDTH]F,
        outputs: [CALLS][permutation.WIDTH]F,
    };
}

/// Height is part of the hash domain. The tree component separately owns
/// legal parent/child positions and its maximum depth.
pub fn build(kind: Kind, height: u5, left: Digest, right: Digest) !Row(M31) {
    var row: Row(M31) = undefined;
    row.kind = M31.fromCanonical(@intFromEnum(kind));
    for (&row.height_bits, 0..) |*bit, index|
        bit.* = M31.fromCanonical((@as(u32, height) >> @intCast(index)) & 1);
    for (left, right, &row.left, &row.right) |a, b, *x, *y| {
        if (a >= core.fields.m31.Modulus or b >= core.fields.m31.Modulus)
            return error.NonCanonicalDigest;
        x.* = M31.fromCanonical(a);
        y.* = M31.fromCanonical(b);
    }
    const words = absorptionWords(M31, row);
    var state = [_]M31{M31.zero()} ** permutation.WIDTH;
    state[permutation.WIDTH - 1] = M31.fromCanonical(DOMAIN + @intFromEnum(kind));
    for (0..3) |call| {
        for (words[call * RATE ..][0..RATE], state[0..RATE]) |word, *lane|
            lane.* = lane.add(word);
        row.inputs[call] = state;
        permutation.permute(&state);
        row.outputs[call] = state;
    }
    @memcpy(row.digest[0..RATE], state[0..RATE]);
    row.inputs[3] = state;
    permutation.permute(&state);
    row.outputs[3] = state;
    @memcpy(row.digest[RATE..], state[0 .. DIGEST_WORDS - RATE]);
    return row;
}

/// The provider must authenticate these full input/output pairs with its
/// atomic `poseidon2_io` relation, not its one-lane narrow-output relation.
pub fn providerCalls(row: *const Row(M31)) [CALLS]permutation_air.Call {
    var calls: [CALLS]permutation_air.Call = undefined;
    for (&calls, row.inputs) |*call, input| {
        call.* = .{ .input = undefined, .io = true };
        for (&call.input, input) |*word, value| word.* = value.toU32();
    }
    return calls;
}

pub fn liftRow(comptime F: type, row: Row(M31)) Row(F) {
    if (F == M31) return row;
    var lifted: Row(F) = undefined;
    lifted.kind = F.fromBase(row.kind);
    inline for (.{ "height_bits", "left", "right", "digest" }) |name| {
        for (@field(row, name), &@field(lifted, name)) |value, *word|
            word.* = F.fromBase(value);
    }
    inline for (.{ "inputs", "outputs" }) |name| {
        for (@field(row, name), &@field(lifted, name)) |values, *call| {
            for (values, call) |value, *word| word.* = F.fromBase(value);
        }
    }
    return lifted;
}

/// Explicit physical order, independent of Zig struct layout.
pub fn columns(comptime F: type, row: Row(F)) [N_MAIN_COLUMNS]F {
    var result: [N_MAIN_COLUMNS]F = undefined;
    result[0] = row.kind;
    var at: usize = 1;
    inline for (.{ "height_bits", "left", "right", "digest" }) |name| {
        const values = @field(row, name);
        @memcpy(result[at..][0..values.len], &values);
        at += values.len;
    }
    inline for (.{ "inputs", "outputs" }) |name| {
        for (@field(row, name)) |values| {
            @memcpy(result[at..][0..values.len], &values);
            at += values.len;
        }
    }
    std.debug.assert(at == N_MAIN_COLUMNS);
    return result;
}

pub fn fromColumns(comptime F: type, values: [N_MAIN_COLUMNS]F) Row(F) {
    var row: Row(F) = undefined;
    row.kind = values[0];
    var at: usize = 1;
    inline for (.{ "height_bits", "left", "right", "digest" }) |name| {
        const target = &@field(row, name);
        @memcpy(target, values[at..][0..target.len]);
        at += target.len;
    }
    inline for (.{ "inputs", "outputs" }) |name| {
        for (&@field(row, name)) |*target| {
            @memcpy(target, values[at..][0..target.len]);
            at += target.len;
        }
    }
    std.debug.assert(at == N_MAIN_COLUMNS);
    return row;
}

fn InteractionScalar(comptime F: type) type {
    return if (F == M31) QM31 else F;
}

/// Native trace generation combines base tuples directly; OODS and symbolic
/// evaluation use the same tuples with the secure-field relation interface.
pub fn rowPairsGeneric(comptime F: type, row: Row(F), active: F, relations: anytype) [N_SUMS]logup.RowPairFor(InteractionScalar(F)) {
    const I = InteractionScalar(F);
    const numerator = if (F == M31) QM31.fromBase(active).neg() else active.neg();
    var denominators: [CALLS]I = undefined;
    for (&denominators, row.inputs, row.outputs) |*denominator, input, output| {
        var tuple: [2 * permutation.WIDTH]F = undefined;
        @memcpy(tuple[0..permutation.WIDTH], &input);
        @memcpy(tuple[permutation.WIDTH..], &output);
        denominator.* = if (F == M31)
            relations.poseidon2_io.combineBase(tuple)
        else
            relations.poseidon2_io.combine(tuple);
    }
    var pairs: [N_SUMS]logup.RowPairFor(I) = undefined;
    for (&pairs, 0..) |*pair, index| pair.* = .{
        .n1 = numerator,
        .d1 = denominators[2 * index],
        .n2 = numerator,
        .d2 = denominators[2 * index + 1],
    };
    return pairs;
}

/// The active selector and first-row selector belong to authenticated
/// preprocessed columns. Inactive padding emits no provider requests.
pub fn evaluateCallerGeneric(
    comptime F: type,
    row: Row(F),
    active: F,
    first: F,
    sums: [N_SUMS]F,
    previous: [N_SUMS]F,
    claims: [N_SUMS]F,
    relations: anytype,
) [N_CONSTRAINTS]F {
    var result: [N_CONSTRAINTS]F = undefined;
    result[0] = active.mul(active.sub(F.one()));
    for (evaluateGeneric(F, row), result[1..][0..N_LINK_CONSTRAINTS]) |constraint, *out|
        out.* = active.mul(constraint);
    const pairs = rowPairsGeneric(F, row, active, relations);
    for (pairs, 0..) |pair, index|
        result[1 + N_LINK_CONSTRAINTS + index] = logup.pairConstraintGeneric(
            F,
            sums[index],
            previous[index],
            first,
            claims[index],
            pair,
        );
    return result;
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    rows: []const Row(M31),
    log_size: u32,
    relations: *const relation_challenges.Relations,
    pool: *work_pool.WorkPool,
) !logup.ParallelColumns(N_SUMS) {
    if (log_size < 4 or log_size > 24 or rows.len > (@as(usize, 1) << @intCast(log_size)))
        return error.InvalidTraceShape;
    return logup.generateParallelColumns(N_SUMS, allocator, InteractionContext{
        .rows = rows,
        .relations = relations,
    }, log_size, pool);
}

const InteractionContext = struct {
    rows: []const Row(M31),
    relations: *const relation_challenges.Relations,

    pub fn rowPairsAt(self: @This(), index: usize) [N_SUMS]logup.RowPair {
        if (index < self.rows.len)
            return rowPairsGeneric(M31, self.rows[index], M31.one(), self.relations);
        return .{logup.RowPair.single(QM31.zero(), QM31.one())} ** N_SUMS;
    }
};

/// These degree-two caller equations bind domain, height, child order,
/// absorption, padding and both squeeze outputs to the four provider calls.
pub fn evaluateGeneric(comptime F: type, row: Row(F)) [N_LINK_CONSTRAINTS]F {
    var constraints: [N_LINK_CONSTRAINTS]F = undefined;
    var at: usize = 0;
    constraints[at] = row.kind.mul(row.kind.sub(F.one()));
    at += 1;
    for (row.height_bits) |bit| {
        constraints[at] = bit.mul(bit.sub(F.one()));
        at += 1;
    }
    const words = absorptionWords(F, row);
    for (0..CALLS) |call| {
        var expected = if (call == 0)
            [_]F{F.zero()} ** permutation.WIDTH
        else
            row.outputs[call - 1];
        if (call == 0) expected[permutation.WIDTH - 1] = constant(F, DOMAIN).add(row.kind);
        if (call < 3) {
            for (words[call * RATE ..][0..RATE], expected[0..RATE]) |word, *lane|
                lane.* = lane.add(word);
        }
        for (row.inputs[call], expected) |actual, value| {
            constraints[at] = actual.sub(value);
            at += 1;
        }
    }
    for (row.digest, 0..) |word, index| {
        const expected = if (index < RATE) row.outputs[2][index] else row.outputs[3][index - RATE];
        constraints[at] = word.sub(expected);
        at += 1;
    }
    std.debug.assert(at == N_LINK_CONSTRAINTS);
    return constraints;
}

fn absorptionWords(comptime F: type, row: Row(F)) [3 * RATE]F {
    var words: [3 * RATE]F = undefined;
    words[0] = constant(F, SCHEMA_VERSION);
    words[1] = F.zero();
    for (row.height_bits, 0..) |bit, index|
        words[1] = words[1].add(bit.mul(constant(F, @as(u32, 1) << @intCast(index))));
    @memcpy(words[2..][0..DIGEST_WORDS], &row.left);
    @memcpy(words[2 + DIGEST_WORDS ..][0..DIGEST_WORDS], &row.right);
    words[words.len - 1] = F.one();
    return words;
}

fn constant(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    if (F == M31) return base;
    return F.fromBase(base);
}

fn linksHold(row: Row(M31)) bool {
    for (evaluateGeneric(M31, row)) |value| if (value.toU32() != 0) return false;
    return true;
}

test "Ethereum node V1 links all digest lanes and full provider permutations" {
    const row = try build(.memory, 30, .{1} ** DIGEST_WORDS, .{2} ** DIGEST_WORDS);
    try std.testing.expect(linksHold(row));
    const secure = liftRow(QM31, row);
    for (evaluateGeneric(QM31, secure)) |constraint|
        try std.testing.expectEqualDeep(QM31.zero(), constraint);
    const calls = providerCalls(&row);
    for (calls, row.outputs) |call, expected| {
        const main = permutation_air.fill(call);
        var secure_main: [permutation_air.N_MAIN_COLUMNS]QM31 = undefined;
        for (main, &secure_main) |value, *word| word.* = QM31.fromBase(value);
        for (permutation_air.evaluate(secure_main)) |constraint|
            try std.testing.expectEqualDeep(QM31.zero(), constraint);
        try std.testing.expectEqualDeep(expected, permutation_air.output(main));
    }
    for (0..DIGEST_WORDS) |index| {
        var changed = row;
        changed.digest[index] = changed.digest[index].add(M31.one());
        try std.testing.expect(!linksHold(changed));
    }
    for (0..CALLS) |call| {
        for (0..permutation.WIDTH) |lane| {
            var changed = row;
            changed.inputs[call][lane] = changed.inputs[call][lane].add(M31.one());
            try std.testing.expect(!linksHold(changed));
        }
    }
    var changed = row;
    changed.kind = M31.one();
    try std.testing.expect(!linksHold(changed));
    changed = row;
    changed.height_bits[0] = M31.one();
    try std.testing.expect(!linksHold(changed));
    changed = row;
    changed.left = row.right;
    changed.right = row.left;
    try std.testing.expect(!linksHold(changed));
    const program = try build(.program, 30, .{1} ** DIGEST_WORDS, .{2} ** DIGEST_WORDS);
    try std.testing.expect(!std.meta.eql(row.digest, program.digest));
    var invalid = [_]u32{0} ** DIGEST_WORDS;
    invalid[8] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalDigest, build(.memory, 0, invalid, .{0} ** DIGEST_WORDS));
}

test "Ethereum node V1 provider bus binds the second squeeze and padded trace" {
    const allocator = std.testing.allocator;
    const relations = relation_challenges.Relations.dummy();
    const rows = [_]Row(M31){
        try build(.memory, 30, .{1} ** DIGEST_WORDS, .{2} ** DIGEST_WORDS),
        try build(.program, 4, .{3} ** DIGEST_WORDS, .{4} ** DIGEST_WORDS),
        try build(.memory, 8, .{5} ** DIGEST_WORDS, .{6} ** DIGEST_WORDS),
    };
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = allocator });
    defer pool.deinit();
    var interaction = try generateInteraction(allocator, &rows, 4, &relations, &pool);
    defer interaction.deinit(allocator);
    var calls: [rows.len * CALLS]permutation_air.Call = undefined;
    var outputs: [rows.len * CALLS][permutation.WIDTH]u32 = undefined;
    for (rows, 0..) |row, index| {
        @memcpy(calls[index * CALLS ..][0..CALLS], &providerCalls(&row));
        for (row.outputs, outputs[index * CALLS ..][0..CALLS]) |values, *out|
            for (values, out) |value, *word| {
                word.* = value.toU32();
            };
    }
    const provider = try permutation_air.claimsFromIoOutputs(&calls, &outputs, 4, &relations);
    const caller_sum = interaction.claims[0].add(interaction.claims[1]);
    try std.testing.expect(caller_sum.add(provider.total()).isZero());
    const placement = try @import("../../infra_trace.zig").BitReversalTable.init(allocator, 4);
    defer placement.deinit(allocator);
    for (0..16) |logical| {
        const current = placement.map(logical);
        const prior = placement.map((logical + 15) % 16);
        var sums: [N_SUMS]QM31 = undefined;
        var previous: [N_SUMS]QM31 = undefined;
        for (0..N_SUMS) |sum| {
            var now_words: [4]M31 = undefined;
            var prior_words: [4]M31 = undefined;
            for (0..4) |limb| {
                now_words[limb] = interaction.columns[4 * sum + limb][current];
                prior_words[limb] = interaction.columns[4 * sum + limb][prior];
            }
            sums[sum] = QM31.fromM31Array(now_words);
            previous[sum] = QM31.fromM31Array(prior_words);
        }
        const row = rows[@min(logical, rows.len - 1)];
        for (evaluateCallerGeneric(QM31, liftRow(QM31, row), constant(QM31, @intFromBool(logical < rows.len)), constant(QM31, @intFromBool(logical == 0)), sums, previous, interaction.claims, &relations)) |constraint|
            try std.testing.expect(constraint.isZero());
    }
    // This forgery satisfies every sponge-link equation. Only the full
    // permutation-output bus binds the last digest lane to the provider.
    var forged = rows;
    forged[0].outputs[3][1] = forged[0].outputs[3][1].add(M31.one());
    forged[0].digest[8] = forged[0].digest[8].add(M31.one());
    try std.testing.expect(linksHold(forged[0]));
    var forged_interaction = try generateInteraction(allocator, &forged, 4, &relations, &pool);
    defer forged_interaction.deinit(allocator);
    try std.testing.expect(!forged_interaction.claims[0].add(forged_interaction.claims[1]).add(provider.total()).isZero());
    const omitted = try permutation_air.claimsFromIoOutputs(calls[0 .. calls.len - 1], outputs[0 .. outputs.len - 1], 4, &relations);
    try std.testing.expect(!caller_sum.add(omitted.total()).isZero());
}
