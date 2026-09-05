//! Compiled row program for the degree-five Poseidon2 candidate main trace.
//!
//! The candidate arena is a straight-line DAG evaluated identically for every
//! call, so the per-row tagged-union interpreter is replaced by one flat
//! instruction list that only covers nodes reachable from the committed
//! outputs.  Eight logical rows are evaluated at once as two four-lane M31
//! vectors, and blocks are addressed by *committed* row so every column store
//! is a contiguous 32-byte stream instead of 239 scattered writes per row.
//!
//! Semantics are exactly those of the scalar interpreter: canonical M31
//! arithmetic, `select` on a non-zero selector, inputs reduced modulo p, and
//! padding rows (logical row >= call count) written as zero in every column.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const poseidon = @import("typed_poseidon2.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const types = @import("types.zig");

pub const FORMAT_VERSION: u16 = 1;
/// Rows evaluated per block: two hardware four-lane vectors.
pub const LANES: usize = 8;
const HALF: usize = m31.VEC_WIDTH;
const Vec = m31.Vec4u32;
const P_VEC: Vec = @splat(m31.Modulus);
const ZERO: Vec = @splat(0);
const ONE: Vec = @splat(1);

/// Eight canonical M31 lanes.
pub const Block = struct {
    lo: Vec,
    hi: Vec,

    pub const zero = Block{ .lo = ZERO, .hi = ZERO };
    pub const one = Block{ .lo = ONE, .hi = ONE };

    pub inline fn splat(value: u32) Block {
        return .{ .lo = @splat(value), .hi = @splat(value) };
    }

    pub inline fn add(a: Block, b: Block) Block {
        return .{ .lo = m31.addVec4(a.lo, b.lo), .hi = m31.addVec4(a.hi, b.hi) };
    }

    pub inline fn sub(a: Block, b: Block) Block {
        return .{ .lo = m31.subVec4(a.lo, b.lo), .hi = m31.subVec4(a.hi, b.hi) };
    }

    pub inline fn mul(a: Block, b: Block) Block {
        return .{ .lo = m31.mulVec4(a.lo, b.lo), .hi = m31.mulVec4(a.hi, b.hi) };
    }

    /// Canonical negation: p - a for a != 0, 0 for a == 0.
    pub inline fn neg(a: Block) Block {
        return .{ .lo = negVec(a.lo), .hi = negVec(a.hi) };
    }

    pub inline fn select(selector: Block, when_true: Block, when_false: Block) Block {
        return .{
            .lo = @select(u32, selector.lo != ZERO, when_true.lo, when_false.lo),
            .hi = @select(u32, selector.hi != ZERO, when_true.hi, when_false.hi),
        };
    }

    /// Zeroes every lane whose mask lane is zero.
    pub inline fn mask(a: Block, active: Block) Block {
        return .{
            .lo = @select(u32, active.lo != ZERO, a.lo, ZERO),
            .hi = @select(u32, active.hi != ZERO, a.hi, ZERO),
        };
    }

    pub inline fn store(self: Block, destination: [*]M31) void {
        m31.storeVec4(destination, self.lo);
        m31.storeVec4(destination + HALF, self.hi);
    }
};

inline fn negVec(a: Vec) Vec {
    const d = P_VEC -% a;
    return @select(u32, a == ZERO, ZERO, d);
}

/// Reduces arbitrary 32-bit words modulo p, matching `M31.fromU64` on u32.
pub inline fn reduceWordsVec(x: Vec) Vec {
    const t = (x & P_VEC) +% (x >> @splat(31));
    return @min(t, t -% P_VEC);
}

pub const Op = enum(u8) { constant, input, gate, add, sub, mul, neg, select };

pub const Instruction = struct {
    op: Op,
    /// `constant`: canonical value; `input`: lane; otherwise operand slot.
    a: u32 = 0,
    b: u32 = 0,
    c: u32 = 0,
    /// Destination slot.
    destination: u32,
};

pub const Error = error{
    UnsupportedCandidateExpression,
    InvalidCandidateTrace,
    InvalidTraceShape,
};

/// Flattened, reachability-pruned candidate semantics.
pub const RowProgram = struct {
    allocator: std.mem.Allocator,
    instructions: []Instruction,
    /// Slot of every canonical selected value, in materialization order.
    output_slots: []u32,
    slot_count: usize,
    main_column_count: usize,

    pub fn compile(
        allocator: std.mem.Allocator,
        candidate: *const candidate_mod.Candidate,
    ) !RowProgram {
        const nodes = candidate.arena.nodesView();
        const inputs = poseidon.values(candidate.definition.inputs);
        const reachable = try allocator.alloc(bool, nodes.len);
        defer allocator.free(reachable);
        @memset(reachable, false);
        for (candidate.selected_values) |value| {
            const index = types.idIndex(value);
            if (index >= nodes.len) return error.InvalidCandidateTrace;
            reachable[index] = true;
        }
        // Operands always precede their consumers in the arena, so one
        // reverse sweep closes the reachable set.
        var index = nodes.len;
        while (index > 0) {
            index -= 1;
            if (!reachable[index]) continue;
            switch (nodes[index].key.op) {
                .constant, .input => {},
                .add, .sub, .mul => |operation| {
                    try markOperand(reachable, index, operation.lhs);
                    try markOperand(reachable, index, operation.rhs);
                },
                .neg => |operand| try markOperand(reachable, index, operand),
                .select => |selection| {
                    try markOperand(reachable, index, selection.selector);
                    try markOperand(reachable, index, selection.when_true);
                    try markOperand(reachable, index, selection.when_false);
                },
                .hint_output, .call_output, .machine_derived => return error.UnsupportedCandidateExpression,
            }
        }

        const slot_of = try allocator.alloc(u32, nodes.len);
        defer allocator.free(slot_of);
        var slot_count: usize = 0;
        for (reachable, slot_of) |is_reachable, *slot| {
            if (!is_reachable) continue;
            slot.* = @intCast(slot_count);
            slot_count += 1;
        }

        var instructions = try std.ArrayList(Instruction).initCapacity(allocator, slot_count);
        errdefer instructions.deinit(allocator);
        for (nodes, 0..) |node, node_index| {
            if (!reachable[node_index]) continue;
            const destination = slot_of[node_index];
            const instruction: Instruction = switch (node.key.op) {
                .constant => |constant| .{
                    .op = .constant,
                    .a = switch (constant) {
                        .field => |value| M31.fromCanonical(value).toU32(),
                        .unsigned => |value| M31.fromU64(value).toU32(),
                    },
                    .destination = destination,
                },
                .input => blk: {
                    const value: types.ValueId = @enumFromInt(@as(u32, @intCast(node_index)));
                    if (value == candidate.gate)
                        break :blk .{ .op = .gate, .destination = destination };
                    for (inputs, 0..) |input_value, lane| {
                        if (value == input_value)
                            break :blk .{ .op = .input, .a = @intCast(lane), .destination = destination };
                    }
                    return error.UnsupportedCandidateExpression;
                },
                .add => |operation| .{
                    .op = .add,
                    .a = slot_of[types.idIndex(operation.lhs)],
                    .b = slot_of[types.idIndex(operation.rhs)],
                    .destination = destination,
                },
                .sub => |operation| .{
                    .op = .sub,
                    .a = slot_of[types.idIndex(operation.lhs)],
                    .b = slot_of[types.idIndex(operation.rhs)],
                    .destination = destination,
                },
                .mul => |operation| .{
                    .op = .mul,
                    .a = slot_of[types.idIndex(operation.lhs)],
                    .b = slot_of[types.idIndex(operation.rhs)],
                    .destination = destination,
                },
                .neg => |operand| .{
                    .op = .neg,
                    .a = slot_of[types.idIndex(operand)],
                    .destination = destination,
                },
                .select => |selection| .{
                    .op = .select,
                    .a = slot_of[types.idIndex(selection.selector)],
                    .b = slot_of[types.idIndex(selection.when_true)],
                    .c = slot_of[types.idIndex(selection.when_false)],
                    .destination = destination,
                },
                .hint_output, .call_output, .machine_derived => return error.UnsupportedCandidateExpression,
            };
            instructions.appendAssumeCapacity(instruction);
        }

        const output_slots = try allocator.alloc(u32, candidate.selected_values.len);
        errdefer allocator.free(output_slots);
        for (candidate.selected_values, output_slots) |value, *slot|
            slot.* = slot_of[types.idIndex(value)];

        return .{
            .allocator = allocator,
            .instructions = try instructions.toOwnedSlice(allocator),
            .output_slots = output_slots,
            .slot_count = slot_count,
            .main_column_count = candidate.mainColumnCount(),
        };
    }

    pub fn deinit(self: *RowProgram) void {
        self.allocator.free(self.output_slots);
        self.allocator.free(self.instructions);
        self.* = undefined;
    }

    /// Evaluates one committed block.  `logical_rows[i]` is the logical row
    /// stored at committed row `committed_start + i`; lanes at or beyond
    /// `calls.len` are padding and are written as zero in every column.
    pub fn writeBlock(
        self: *const RowProgram,
        columns: []const []M31,
        committed_start: usize,
        logical_rows: *const [LANES]usize,
        calls: []const production.Call,
        slots: []Block,
    ) void {
        std.debug.assert(columns.len == self.main_column_count);
        std.debug.assert(slots.len == self.slot_count);
        std.debug.assert(committed_start % LANES == 0);

        var active_words: [LANES]u32 = undefined;
        var wide_words: [LANES]u32 = undefined;
        var io_words: [LANES]u32 = undefined;
        var input_words: [production.WIDTH][LANES]u32 = undefined;
        for (logical_rows, 0..) |logical, lane| {
            if (logical < calls.len) {
                const call = &calls[logical];
                active_words[lane] = 1;
                wide_words[lane] = @intFromBool(call.wide);
                io_words[lane] = @intFromBool(call.io);
                for (call.input, 0..) |word, input_lane| input_words[input_lane][lane] = word;
            } else {
                active_words[lane] = 0;
                wide_words[lane] = 0;
                io_words[lane] = 0;
                for (0..production.WIDTH) |input_lane| input_words[input_lane][lane] = 0;
            }
        }
        const active = loadBlock(&active_words);
        var inputs: [production.WIDTH]Block = undefined;
        for (&inputs, &input_words) |*input, *words| {
            const raw = loadBlock(words);
            input.* = .{ .lo = reduceWordsVec(raw.lo), .hi = reduceWordsVec(raw.hi) };
        }

        for (self.instructions) |instruction| {
            slots[instruction.destination] = switch (instruction.op) {
                .constant => Block.splat(instruction.a),
                .input => inputs[instruction.a],
                .gate => Block.one,
                .add => slots[instruction.a].add(slots[instruction.b]),
                .sub => slots[instruction.a].sub(slots[instruction.b]),
                .mul => slots[instruction.a].mul(slots[instruction.b]),
                .neg => slots[instruction.a].neg(),
                .select => Block.select(slots[instruction.a], slots[instruction.b], slots[instruction.c]),
            };
        }

        active.store(columns[0].ptr + committed_start);
        for (inputs, 0..) |input, lane|
            input.mask(active).store(columns[1 + lane].ptr + committed_start);
        for (self.output_slots, 0..) |slot, ordinal| {
            slots[slot].mask(active).store(
                columns[candidate_mod.MATERIALIZATION_COLUMN_START + ordinal].ptr + committed_start,
            );
        }
        loadBlock(&wide_words).store(columns[columns.len - 2].ptr + committed_start);
        loadBlock(&io_words).store(columns[columns.len - 1].ptr + committed_start);
    }
};

pub inline fn loadBlock(words: *const [LANES]u32) Block {
    return .{
        .lo = words[0..HALF].*,
        .hi = words[HALF..LANES].*,
    };
}

fn markOperand(reachable: []bool, consumer: usize, operand: types.ValueId) Error!void {
    const index = types.idIndex(operand);
    if (index >= consumer) return error.UnsupportedCandidateExpression;
    reachable[index] = true;
}
