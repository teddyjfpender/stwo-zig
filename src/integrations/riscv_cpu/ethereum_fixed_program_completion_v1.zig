//! Full-width completion membership for an independently admitted program.
//! Leaves bind PC, raw instruction and the canonical decoder projection. The
//! existing Poseidon permutation and Merkle child compression own all hash
//! equations. This tree is optional; legacy native program commitments retain
//! their exact descriptor and transcript.
//! Eight canonical M31 lanes carry about 248 output bits (about 124 generic
//! collision bits), using the existing admitted Poseidon2-M31 assumptions.
//! The u32 container width is not a 128-bit collision-security claim.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const arithmetic = frontend.recursion.arithmetic_circuit;
const channel = frontend.recursion.poseidon2_channel;
const poseidon = frontend.air.memory_commitment.poseidon2_air;
const decode = frontend.air.program.decode;
pub const VERSION: u32 = 1;
pub const MAX_DEPTH: u5 = 22;
pub const LEAF_TAG: u32 = 0x434f4d50;
pub const PADDING_TAG: u32 = 0x434f4d51;
pub const Digest = channel.Digest;
pub const Row = struct {
    pc: u32,
    raw_word: u32,
    decoded: [4]u32,
    pub fn words(self: Row) [7]u32 {
        return .{ self.pc, self.raw_word & 0xffff, self.raw_word >> 16 } ++ self.decoded;
    }
    pub fn values(self: Row) [6]u32 {
        return self.words()[1..7].*;
    }
};
pub const Opening = struct {
    row: Row,
    depth: u5,
    index: u32,
    siblings: [MAX_DEPTH]Digest,
    pub fn wordCount(self: Opening) usize {
        return @as(usize, self.depth) * 9;
    }
    pub fn word(self: Opening, at: usize) !u32 {
        if (at >= self.wordCount()) return error.InvalidCompletionOpening;
        const level: u5 = @intCast(at / 9);
        return if (at % 9 == 0) (self.index >> level) & 1 else self.siblings[level][at % 9 - 1];
    }
};
/// The containing opaque ELF owner retains this private allocation. Every
/// fallible allocation precedes transfer and only deeply readonly views escape.
pub const Tree = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    nodes: []Digest,
    depth: u5,
    pub fn init(allocator: std.mem.Allocator, declared: []const frontend.runner.memory_state.WordState) !Tree {
        var count: usize = 0;
        for (declared) |word| {
            if (word.initial_word == 0 or decode.isDeclaredPaddingForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word)) continue;
            _ = try decode.decodeProgramWordForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word);
            count += 1;
        }
        if (count == 0 or count > (@as(usize, 1) << MAX_DEPTH)) return error.CompletionProgramExceedsOpeningProfile;
        const leaves = try std.math.ceilPowerOfTwo(usize, count);
        const depth: u5 = @intCast(std.math.log2_int(usize, leaves));
        const rows = try allocator.alloc(Row, count);
        errdefer allocator.free(rows);
        const nodes = try allocator.alloc(Digest, 2 * leaves);
        errdefer allocator.free(nodes);
        var at: usize = 0;
        for (declared) |word| {
            if (word.initial_word == 0 or decode.isDeclaredPaddingForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word)) continue;
            if (word.addr >= core.fields.m31.Modulus or (word.addr & 3) != 0 or (at > 0 and rows[at - 1].pc >= word.addr)) return error.InvalidCompletionProgramTable;
            rows[at] = .{ .pc = word.addr, .raw_word = word.initial_word, .decoded = try decode.decodeProgramWordForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word) };
            for (rows[at].words()) |value| if (value >= core.fields.m31.Modulus) return error.InvalidCompletionProgramTable;
            nodes[leaves + at] = leafHash(rows[at]);
            at += 1;
        }
        const padding = channel.hashCanonicalU32s(&.{}, PADDING_TAG);
        @memset(nodes[leaves + count ..], padding);
        nodes[0] = [_]u32{0} ** 8;
        var index = leaves;
        while (index > 1) {
            index -= 1;
            nodes[index] = channel.MerkleHasher.hashChildren(.{ .left = nodes[index * 2], .right = nodes[index * 2 + 1] });
        }
        return .{ .allocator = allocator, .rows = rows, .nodes = nodes, .depth = depth };
    }
    pub fn root(self: *const Tree) Digest {
        return self.nodes[1];
    }
    pub fn opening(self: *const Tree, pc: u32) !Opening {
        var low: usize = 0;
        var high: usize = self.rows.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.rows[mid].pc < pc) low = mid + 1 else high = mid;
        }
        if (low == self.rows.len or self.rows[low].pc != pc) return error.CompletionPcNotInAdmittedProgram;
        var result = Opening{ .row = self.rows[low], .depth = self.depth, .index = @intCast(low), .siblings = [_]Digest{[_]u32{0} ** 8} ** MAX_DEPTH };
        var index = (@as(usize, 1) << self.depth) + low;
        for (result.siblings[0..self.depth]) |*sibling| {
            sibling.* = self.nodes[index ^ 1];
            index >>= 1;
        }
        return result;
    }
    pub fn deinit(self: *Tree) void {
        self.allocator.free(self.nodes);
        self.allocator.free(self.rows);
        self.* = undefined;
    }
};
pub fn leafHash(row: Row) Digest {
    // Seven words plus canonical terminator fill exactly one sponge block.
    var words: [7]M31 = undefined;
    for (&words, row.words()) |*value, word| value.* = M31.fromCanonical(word);
    return channel.hashCanonicalWords(&words, LEAF_TAG);
}

/// Every path word is a base-field row16 input. Direction constraints are
/// unconditional; the completed leaf is checked against one fixed root.
pub fn constrain(builder: *arithmetic.Builder, root: Digest, depth: u5, row_count: u32, row: [7]arithmetic.Value, path: []const arithmetic.Value) !void {
    if (depth > MAX_DEPTH or row_count == 0 or row_count > (@as(u32, 1) << depth) or (depth != 0 and row_count <= (@as(u32, 1) << (depth - 1))) or path.len != @as(usize, depth) * 9) return error.InvalidCompletionOpening;
    // Directions are the actual leaf-index bits. Compare their binary integer
    // to row_count-1, without a field-wrap alias or private comparator witness.
    var equal = arithmetic.Value.one();
    var less = arithmetic.Value.zero();
    var bit_index: usize = depth;
    while (bit_index != 0) {
        bit_index -= 1;
        const bit = path[bit_index * 9];
        const complement = try builder.sub(arithmetic.Value.one(), bit);
        if ((((row_count - 1) >> @as(u5, @intCast(bit_index))) & 1) == 1) {
            less = try builder.add(less, try builder.mul(equal, complement));
            equal = try builder.mul(equal, bit);
        } else equal = try builder.mul(equal, complement);
    }
    _ = try builder.markOutput(try builder.sub(try builder.add(less, equal), arithmetic.Value.one()));
    var context = Recording{ .builder = builder };
    var state = [_]Scalar{Scalar.zero()} ** 16;
    for (row, state[0..7]) |value, *slot| slot.* = .{ .value = value, .context = &context };
    state[7] = Scalar.fromBase(M31.one());
    state[15] = Scalar.fromBase(M31.fromCanonical(LEAF_TAG));
    poseidon.permuteGeneric(Scalar, &state);
    if (context.failure) |failure| return failure;
    for (0..depth) |level| {
        const direction = path[level * 9];
        _ = try builder.markOutput(try builder.mul(direction, try builder.sub(direction, arithmetic.Value.one())));
        const previous = state[0..8].*;
        for (0..8) |limb| {
            const sibling = path[level * 9 + 1 + limb];
            const swap = try builder.mul(direction, try builder.sub(sibling, previous[limb].value));
            state[limb] = .{ .value = try builder.add(previous[limb].value, swap), .context = &context };
            state[8 + limb] = .{ .value = try builder.sub(sibling, swap), .context = &context };
        }
        poseidon.permuteGeneric(Scalar, &state);
        if (context.failure) |failure| return failure;
    }
    for (state[0..8], root) |value, expected| _ = try builder.markOutput(try builder.sub(value.value, arithmetic.Value.fromBase(M31.fromCanonical(expected))));
}
const Recording = struct { builder: *arithmetic.Builder, failure: ?arithmetic.Error = null };
// Small adapter for the existing shared symbolic permutation. Context follows
// values rather than thread-local/global state; allocation failures propagate.
const Scalar = struct {
    value: arithmetic.Value,
    context: ?*Recording = null,
    pub fn zero() Scalar {
        return .{ .value = arithmetic.Value.zero() };
    }
    pub fn fromBase(value: M31) Scalar {
        return .{ .value = arithmetic.Value.fromBase(value) };
    }
    pub fn add(a: Scalar, b: Scalar) Scalar {
        return binary(a, b, .add);
    }
    pub fn sub(a: Scalar, b: Scalar) Scalar {
        return binary(a, b, .sub);
    }
    pub fn mul(a: Scalar, b: Scalar) Scalar {
        return binary(a, b, .mul);
    }
    pub fn square(a: Scalar) Scalar {
        return a.mul(a);
    }
    fn binary(a: Scalar, b: Scalar, comptime operation: enum { add, sub, mul }) Scalar {
        const context = a.context orelse b.context orelse {
            const av = a.value.constant;
            const bv = b.value.constant;
            return .{ .value = arithmetic.Value.fromSecure(switch (operation) {
                .add => av.add(bv),
                .sub => av.sub(bv),
                .mul => av.mul(bv),
            }) };
        };
        if (a.context != null and b.context != null) std.debug.assert(a.context == b.context);
        if (context.failure != null) return .{ .value = arithmetic.Value.zero(), .context = context };
        const value = switch (operation) {
            .add => context.builder.add(a.value, b.value),
            .sub => context.builder.sub(a.value, b.value),
            .mul => context.builder.mul(a.value, b.value),
        };
        return .{ .value = value catch |failure| blk: {
            context.failure = failure;
            break :blk arithmetic.Value.zero();
        }, .context = context };
    }
};
