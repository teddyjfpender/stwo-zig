//! S31 relation IR v1. This normalized form is intentionally machine-readable:
//! every array length and loop bound is static, and witness values cannot add
//! nodes or change circuit topology.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const P = core.fields.m31.Modulus;
const poseidon2 = @import("../library/hash/poseidon2.zig");

pub const Kind = enum { u16, m31 };
pub const Visibility = enum { public, private };
/// ABI visibility and proof blinding are independent. `blinded` is the
/// experimental pinned random-row construction, not a general ZK guarantee.
pub const ProofMode = enum {
    transparent,
    blinded,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
        if (try source.peekNextTokenType() != .string) return error.UnexpectedToken;
        const name = try std.json.innerParse([]const u8, allocator, source, options);
        return std.meta.stringToEnum(@This(), name) orelse error.InvalidEnumTag;
    }
};
pub const Input = struct {
    name: []const u8,
    kind: Kind,
    length: u32,
    visibility: Visibility,
};
pub const StepOp = enum { square, add_const, mul_const, mix4 };
pub const Step = struct {
    op: StepOp,
    constant: ?u32 = null,
};
/// A four-lane linear diffusion step: y_i = x_i + sum(x_0..x_3).
/// Its matrix I + J is invertible in M31 (determinant 5).
pub fn applyStep(values: []M31, step: Step) !void {
    switch (step.op) {
        .square => {
            if (step.constant != null) return error.InvalidStep;
            for (values) |*value| value.* = value.mul(value.*);
        },
        .add_const, .mul_const => {
            const constant = step.constant orelse return error.InvalidStep;
            if (constant >= P) return error.InvalidStep;
            const operand = M31.fromCanonical(constant);
            for (values) |*value| value.* = if (step.op == .add_const) value.add(operand) else value.mul(operand);
        },
        .mix4 => {
            if (step.constant != null or values.len != 4) return error.InvalidStep;
            var sum = M31.zero();
            for (values) |value| sum = sum.add(value);
            for (values) |*value| value.* = value.add(sum);
        },
    }
}
pub const Op = enum { constant, cast_m31, add, mul, add_const, mul_const, repeat, hash_blake2s, hash_blake2s_leaf, hash_blake2s_pair, select, hash_poseidon2_leaf, hash_poseidon2_pair, sum_lanes, u256_add, u256_le, u256_add_checked, hash_sha256d_header, bitcoin_target_mainnet, bitcoin_prev_hash, bitcoin_header_bits, bitcoin_genesis_hash_mainnet, bitcoin_header_time, u32_lt, inv, is_zero, u256_sub, u256_sub_checked, array_get, array_concat, array_slice, bool_not, bool_and, bool_or, bool_xor, bool_select, bitcoin_block_work, int_view, int_add_checked, int_add_wrapping, int_sub_checked, int_sub_wrapping, int_le };
/// The node constant binds an integer's width and signedness into canonical IR.
/// The source-level scalar is carried as little-endian u16 words; an 8-bit
/// scalar uses one u16 word with an additional circuit-enforced byte bound.
pub const IntegerSpec = struct {
    width: u32,
    signed: bool,

    pub fn limbCount(self: IntegerSpec) usize {
        return @max(1, self.width / 16);
    }

    pub fn decode(encoded: ?u32) ?IntegerSpec {
        const value = encoded orelse return null;
        const width = value & 0xff;
        if (value != width and value != width + 256) return null;
        if (width != 8 and width != 16 and width != 32 and width != 64 and width != 128) return null;
        return .{ .width = width, .signed = value >= 256 };
    }
};
pub const mainnet_genesis_hash_raw: [32]u8 = .{ 0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00 };
pub const leaf_personalization = [8]u8{ 'S', '3', '1', 'L', 'E', 'A', 'F', '1' };
pub const pair_personalization = [8]u8{ 'S', '3', '1', 'P', 'A', 'I', 'R', '1' };
pub const Node = struct {
    name: []const u8,
    op: Op,
    lhs: ?[]const u8 = null,
    rhs: ?[]const u8 = null,
    selector: ?[]const u8 = null,
    index: ?u32 = null,
    constant: ?u32 = null,
    length: ?u32 = null,
    rounds: ?u32 = null,
    body: ?[]Step = null,
};
pub const Assertion = struct {
    lhs: []const u8,
    rhs: []const u8,
};
pub const Shape = struct {
    kind: Kind,
    length: usize,
};
pub const ChipSpec = struct { rounds: u32, constant: u32 };
pub const StateFoldSpec = struct { rounds: u32, body: []const Step };
pub const Program = struct {
    version: u32,
    name: []const u8,
    proof_mode: ProofMode = .transparent,
    inputs: []Input,
    nodes: []Node,
    assertions: []Assertion,
    public_outputs: [][]const u8,

    /// A state fold uses the exact, statically validated step body of a public
    /// four-lane recurrence. No private inputs, side assertions, or extra
    /// computations can affect the extracted state transition.
    pub fn stateFoldStep(self: Program) ?StateFoldSpec {
        if (self.inputs.len != 1 or self.assertions.len != 0 or
            self.public_outputs.len != 1)
            return null;
        const input = self.inputs[0];
        if (input.visibility != .public or input.length != 4) return null;
        var lhs_name = input.name;
        var repeat_index: usize = 0;
        if (input.kind == .u16) {
            if (self.nodes.len != 2 or self.nodes[0].op != .cast_m31 or
                !std.mem.eql(u8, self.nodes[0].lhs orelse return null, input.name))
                return null;
            lhs_name = self.nodes[0].name;
            repeat_index = 1;
        } else if (self.nodes.len != 1) return null;
        const node = self.nodes[repeat_index];
        if (node.op != .repeat or
            !std.mem.eql(u8, node.lhs orelse return null, lhs_name) or
            !std.mem.eql(u8, self.public_outputs[0], node.name) or
            node.rounds == null or node.body == null)
            return null;
        const rounds = node.rounds.?;
        const body = node.body.?;
        if (rounds < 1 or rounds > 32768 or body.len < 1 or body.len > 16)
            return null;
        return .{ .rounds = rounds, .body = body };
    }

    /// The dedicated hybrid chip still accepts only its narrow, power-of-two
    /// square/add profile. Its extraction must not expand with the fold.
    pub fn repeatedStepChip(self: Program) ?ChipSpec {
        const spec = self.stateFoldStep() orelse return null;
        const rounds = spec.rounds;
        if (rounds < 16 or rounds > 32768 or !std.math.isPowerOfTwo(rounds))
            return null;
        const body = spec.body;
        if (body.len != 2 or body[0].op != .square or
            body[1].op != .add_const or body[1].constant == null)
            return null;
        return .{ .rounds = rounds, .constant = body[1].constant.? };
    }

    /// A direct-M31 chip may take its four endpoints from private circuit
    /// wires. The repeat is the first source node; later nodes may compute a
    /// public claim from the final state without publishing either endpoint.
    pub fn privateRepeatedStepChip(self: Program) ?ChipSpec {
        if (self.inputs.len != 1 or self.nodes.len < 2 or self.public_outputs.len == 0)
            return null;
        const input = self.inputs[0];
        if (input.visibility != .private or input.kind != .m31 or input.length != 4)
            return null;
        const repeated = self.nodes[0];
        if (repeated.op != .repeat or
            !std.mem.eql(u8, repeated.lhs orelse return null, input.name) or
            repeated.rounds == null or repeated.body == null)
            return null;
        const rounds = repeated.rounds.?;
        const body = repeated.body.?;
        if (rounds < 16 or rounds > 32768 or !std.math.isPowerOfTwo(rounds) or
            body.len != 2 or body[0].op != .square or body[1].op != .add_const or
            body[1].constant == null)
            return null;
        for (self.nodes[1..]) |node| if (node.op == .repeat) return null;
        for (self.public_outputs) |name| {
            if (std.mem.eql(u8, name, input.name) or std.mem.eql(u8, name, repeated.name))
                return null;
        }
        return .{ .rounds = rounds, .constant = body[1].constant.? };
    }

    pub fn validate(self: Program, allocator: std.mem.Allocator) !void {
        if (self.version != 1) return error.UnsupportedVersion;
        if (!validName(self.name)) return error.InvalidProgramName;
        var shapes = std.StringHashMapUnmanaged(Shape){};
        defer shapes.deinit(allocator);
        var public_words: usize = 0;
        for (self.inputs) |input| {
            if (!validName(input.name) or shapes.contains(input.name)) return error.DuplicateOrInvalidName;
            if (input.length == 0 or input.length > 4096) return error.InvalidArrayLength;
            if (input.visibility == .public) public_words += input.length;
            try shapes.put(allocator, input.name, .{ .kind = input.kind, .length = input.length });
        }
        for (self.nodes) |node| {
            if (!validName(node.name) or shapes.contains(node.name)) return error.DuplicateOrInvalidName;
            const lhs: ?Shape = if (node.lhs) |name| shapes.get(name) orelse return error.UnknownOperand else null;
            const rhs: ?Shape = if (node.rhs) |name| shapes.get(name) orelse return error.UnknownOperand else null;
            const selector: ?Shape = if (node.selector) |name| shapes.get(name) orelse return error.UnknownOperand else null;
            if (node.op != .select and node.op != .bool_select and selector != null) return error.InvalidNode;
            if (node.op != .array_get and node.op != .array_slice and node.index != null) return error.InvalidNode;
            var result: Shape = undefined;
            switch (node.op) {
                .array_get => {
                    if (lhs == null or rhs != null or node.index == null or node.index.? >= lhs.?.length or
                        node.constant != null or node.length != null or node.rounds != null or node.body != null)
                        return error.InvalidNode;
                    result = .{ .kind = lhs.?.kind, .length = 1 };
                },
                .array_concat => {
                    if (lhs == null or rhs == null or lhs.?.kind != rhs.?.kind or
                        lhs.?.length + rhs.?.length > 4096 or node.constant != null or
                        node.length != null or node.rounds != null or node.body != null)
                        return error.InvalidNode;
                    result = .{ .kind = lhs.?.kind, .length = lhs.?.length + rhs.?.length };
                },
                .array_slice => {
                    if (lhs == null or rhs != null or node.index == null or node.length == null or
                        node.length.? == 0 or node.index.? > lhs.?.length or
                        node.length.? > lhs.?.length - node.index.? or node.constant != null or
                        node.rounds != null or node.body != null)
                        return error.InvalidNode;
                    result = .{ .kind = lhs.?.kind, .length = node.length.? };
                },
                .constant => {
                    if (lhs != null or rhs != null or node.constant == null or node.constant.? >= P or node.length == null or node.length.? == 0 or node.length.? > 4096 or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = node.length.? };
                },
                .cast_m31 => {
                    if (lhs == null or lhs.?.kind != .u16 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = lhs.?.length };
                },
                .add, .mul => {
                    if (lhs == null or rhs == null or lhs.?.kind != .m31 or rhs.?.kind != .m31 or lhs.?.length != rhs.?.length or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = lhs.?;
                },
                .inv => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = lhs.?;
                },
                .is_zero => {
                    if (lhs == null or lhs.?.kind != .m31 or lhs.?.length != 1 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 1 };
                },
                .bool_not => {
                    if (lhs == null or lhs.?.kind != .m31 or lhs.?.length != 1 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 1 };
                },
                .bool_and, .bool_or, .bool_xor => {
                    if (lhs == null or rhs == null or lhs.?.kind != .m31 or rhs.?.kind != .m31 or lhs.?.length != 1 or rhs.?.length != 1 or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 1 };
                },
                .bool_select => {
                    if (lhs == null or rhs == null or selector == null or lhs.?.kind != .m31 or rhs.?.kind != .m31 or selector.?.kind != .m31 or lhs.?.length != 1 or rhs.?.length != 1 or selector.?.length != 1 or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 1 };
                },
                .add_const, .mul_const => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant == null or node.constant.? >= P or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = lhs.?;
                },
                .sum_lanes => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 1 };
                },
                .u256_add, .u256_le, .u256_add_checked, .u256_sub, .u256_sub_checked => {
                    if (lhs == null or rhs == null or lhs.?.kind != .u16 or rhs.?.kind != .u16 or
                        lhs.?.length != 16 or rhs.?.length != 16 or node.constant != null or
                        node.length != null or node.rounds != null or node.body != null)
                        return error.InvalidNode;
                    result = if (node.op == .u256_add or node.op == .u256_add_checked or node.op == .u256_sub or node.op == .u256_sub_checked)
                        .{ .kind = .u16, .length = 16 }
                    else
                        .{ .kind = .m31, .length = 1 };
                },
                .int_view, .int_add_checked, .int_add_wrapping, .int_sub_checked, .int_sub_wrapping, .int_le => {
                    const spec = IntegerSpec.decode(node.constant) orelse return error.InvalidIntegerSpec;
                    if (lhs == null or lhs.?.kind != .u16 or lhs.?.length != spec.limbCount() or
                        node.selector != null or node.index != null or node.length != null or
                        node.rounds != null or node.body != null) return error.InvalidNode;
                    if (node.op == .int_view) {
                        if (rhs != null) return error.InvalidNode;
                    } else if (rhs == null or rhs.?.kind != .u16 or rhs.?.length != spec.limbCount()) {
                        return error.InvalidNode;
                    }
                    result = if (node.op == .int_le) .{ .kind = .m31, .length = 1 } else lhs.?;
                },
                .bitcoin_block_work => {
                    if (lhs == null or lhs.?.kind != .u16 or lhs.?.length != 16 or
                        rhs != null or node.selector != null or node.constant != null or
                        node.length != null or node.rounds != null or node.body != null)
                        return error.InvalidNode;
                    result = .{ .kind = .u16, .length = 16 };
                },
                .u32_lt => {
                    if (lhs == null or rhs == null or lhs.?.kind != .u16 or rhs.?.kind != .u16 or
                        lhs.?.length != 2 or rhs.?.length != 2 or node.constant != null or
                        node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 1 };
                },
                .hash_sha256d_header, .bitcoin_target_mainnet, .bitcoin_prev_hash, .bitcoin_header_bits, .bitcoin_header_time => {
                    if (lhs == null or lhs.?.kind != .u16 or lhs.?.length != 40 or
                        rhs != null or node.constant != null or node.length != null or
                        node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .u16, .length = if (node.op == .bitcoin_header_bits or node.op == .bitcoin_header_time) 2 else 16 };
                },
                .bitcoin_genesis_hash_mainnet => {
                    if (lhs != null or rhs != null or node.selector != null or node.constant != null or
                        node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .u16, .length = 16 };
                },
                .repeat => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant != null or node.length != null or node.rounds == null or node.rounds.? == 0 or node.rounds.? > 32768 or node.body == null or node.body.?.len == 0 or node.body.?.len > 16) return error.InvalidNode;
                    for (node.body.?) |step| switch (step.op) {
                        .square => if (step.constant != null) return error.InvalidNode,
                        .add_const, .mul_const => if (step.constant == null or step.constant.? >= P) return error.InvalidNode,
                        .mix4 => if (step.constant != null or lhs.?.length != 4) return error.InvalidNode,
                    };
                    result = lhs.?;
                },
                .hash_blake2s => {
                    if (lhs == null or lhs.?.kind != .m31 or lhs.?.length > 16 or lhs.?.length % 4 != 0 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 8 };
                },
                .hash_blake2s_leaf => {
                    if (lhs == null or lhs.?.kind != .m31 or lhs.?.length > 16 or lhs.?.length % 4 != 0 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 8 };
                },
                .hash_blake2s_pair => {
                    if (lhs == null or rhs == null or lhs.?.kind != .m31 or rhs.?.kind != .m31 or lhs.?.length != 8 or rhs.?.length != 8 or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 8 };
                },
                .select => {
                    if (lhs == null or rhs == null or selector == null or lhs.?.kind != rhs.?.kind or selector.?.kind != .m31 or lhs.?.length != rhs.?.length or selector.?.length != 1 or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = lhs.?;
                },
                .hash_poseidon2_leaf => {
                    if (lhs == null or lhs.?.kind != .m31 or lhs.?.length > 16 or lhs.?.length % 4 != 0 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 8 };
                },
                .hash_poseidon2_pair => {
                    if (lhs == null or rhs == null or lhs.?.kind != .m31 or rhs.?.kind != .m31 or lhs.?.length != 8 or rhs.?.length != 8 or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 8 };
                },
            }
            try shapes.put(allocator, node.name, result);
        }
        for (self.assertions) |assertion| {
            const lhs = shapes.get(assertion.lhs) orelse return error.UnknownOperand;
            const rhs = shapes.get(assertion.rhs) orelse return error.UnknownOperand;
            if (lhs.kind != rhs.kind or lhs.length != rhs.length) return error.AssertionShapeMismatch;
        }
        for (self.public_outputs) |name| {
            const shape = shapes.get(name) orelse return error.UnknownOutput;
            public_words += shape.length;
        }
        if (public_words == 0 or public_words > 8) return error.PublicAbiTooWide;
    }

    pub fn shapeOf(self: Program, allocator: std.mem.Allocator, name: []const u8) !?Shape {
        var shapes = std.StringHashMapUnmanaged(Shape){};
        defer shapes.deinit(allocator);
        for (self.inputs) |input| {
            const shape: Shape = .{ .kind = input.kind, .length = input.length };
            if (std.mem.eql(u8, input.name, name)) return shape;
            try shapes.put(allocator, input.name, shape);
        }
        for (self.nodes) |node| {
            const length: usize = switch (node.op) {
                .constant => node.length orelse return error.InvalidNode,
                .array_get => 1,
                .array_slice => node.length orelse return error.InvalidNode,
                .array_concat => (shapes.get(node.lhs orelse return error.InvalidNode) orelse return error.UnknownOperand).length +
                    (shapes.get(node.rhs orelse return error.InvalidNode) orelse return error.UnknownOperand).length,
                .sum_lanes, .u256_le, .u32_lt, .int_le, .is_zero, .bool_not, .bool_and, .bool_or, .bool_xor, .bool_select => 1,
                .hash_sha256d_header, .bitcoin_target_mainnet, .bitcoin_genesis_hash_mainnet, .bitcoin_block_work => 16,
                .bitcoin_prev_hash => 16,
                .bitcoin_header_bits, .bitcoin_header_time => 2,
                .hash_blake2s, .hash_blake2s_leaf, .hash_blake2s_pair, .hash_poseidon2_leaf, .hash_poseidon2_pair => 8,
                else => (shapes.get(node.lhs orelse return error.InvalidNode) orelse return error.UnknownOperand).length,
            };
            const shape: Shape = .{ .kind = if (node.op == .array_get or node.op == .array_concat or node.op == .array_slice or node.op == .select)
                (shapes.get(node.lhs.?) orelse return error.UnknownOperand).kind
            else if (node.op == .int_view or node.op == .int_add_checked or node.op == .int_add_wrapping or node.op == .int_sub_checked or node.op == .int_sub_wrapping or node.op == .u256_add or node.op == .u256_add_checked or node.op == .u256_sub or node.op == .u256_sub_checked or node.op == .hash_sha256d_header or node.op == .bitcoin_target_mainnet or node.op == .bitcoin_prev_hash or node.op == .bitcoin_header_bits or node.op == .bitcoin_header_time or node.op == .bitcoin_genesis_hash_mainnet or node.op == .bitcoin_block_work) .u16 else .m31, .length = length };
            if (std.mem.eql(u8, node.name, name)) return shape;
            try shapes.put(allocator, node.name, shape);
        }
        return null;
    }
};

pub const Assignment = struct {
    public_inputs: std.json.Value,
    private_inputs: ?std.json.Value = null,
    public_outputs: std.json.Value,
};
pub const ParsedProgram = std.json.Parsed(Program);
pub const ParsedAssignment = std.json.Parsed(Assignment);

pub fn parseProgram(allocator: std.mem.Allocator, source: []const u8) !ParsedProgram {
    var parsed = try std.json.parseFromSlice(Program, allocator, source, .{ .ignore_unknown_fields = false });
    errdefer parsed.deinit();
    try parsed.value.validate(allocator);
    return parsed;
}

test "unknown proof mode is rejected rather than downgraded" {
    const source =
        \\{"version":1,"name":"bad_mode","proof_mode":"zk","inputs":[],"nodes":[],"assertions":[],"public_outputs":[]}
    ;
    try std.testing.expectError(error.InvalidEnumTag, parseProgram(std.testing.allocator, source));
    try std.testing.expectError(error.UnexpectedToken, parseProgram(std.testing.allocator, "{\"version\":1,\"name\":\"bad_mode\",\"proof_mode\":1,\"inputs\":[],\"nodes\":[],\"assertions\":[],\"public_outputs\":[]}"));
}

pub fn parseAssignment(allocator: std.mem.Allocator, source: []const u8) !ParsedAssignment {
    var parsed = try std.json.parseFromSlice(Assignment, allocator, source, .{ .ignore_unknown_fields = false });
    errdefer parsed.deinit();
    if (parsed.value.public_inputs != .object or parsed.value.public_outputs != .object) return error.InvalidAssignment;
    if (parsed.value.private_inputs) |private| if (private != .object) return error.InvalidAssignment;
    return parsed;
}

pub fn inputValues(allocator: std.mem.Allocator, assignment: Assignment, input: Input) ![]M31 {
    const object = if (input.visibility == .public) assignment.public_inputs else assignment.private_inputs orelse return error.MissingPrivateInputs;
    return arrayValues(allocator, object, input.name, .{ .kind = input.kind, .length = input.length });
}

pub fn claimedWords(allocator: std.mem.Allocator, program: Program, assignment: Assignment) ![8]u32 {
    try program.validate(allocator);
    var expected_public_inputs: usize = 0;
    for (program.inputs) |input| if (input.visibility == .public) {
        expected_public_inputs += 1;
    };
    if (assignment.public_inputs.object.count() != expected_public_inputs or
        assignment.public_outputs.object.count() != program.public_outputs.len)
        return error.UnknownPublicField;
    var out = [_]u32{0} ** 8;
    var at: usize = 0;
    for (program.inputs) |input| {
        if (input.visibility != .public) continue;
        const values = try arrayValues(allocator, assignment.public_inputs, input.name, .{ .kind = input.kind, .length = input.length });
        defer allocator.free(values);
        for (values) |value| {
            out[at] = value.toU32();
            at += 1;
        }
    }
    for (program.public_outputs) |name| {
        const shape = (try program.shapeOf(allocator, name)) orelse return error.UnknownOutput;
        const values = try arrayValues(allocator, assignment.public_outputs, name, shape);
        defer allocator.free(values);
        for (values) |value| {
            out[at] = value.toU32();
            at += 1;
        }
    }
    return out;
}

pub fn evaluate(allocator: std.mem.Allocator, program: Program, assignment: Assignment) ![8]u32 {
    try program.validate(allocator);
    var expected_private_inputs: usize = 0;
    for (program.inputs) |input| if (input.visibility == .private) {
        expected_private_inputs += 1;
    };
    const provided_private = if (assignment.private_inputs) |private| private.object.count() else 0;
    if (provided_private != expected_private_inputs) return error.UnknownPrivateField;
    var values = std.StringHashMapUnmanaged([]M31){};
    defer {
        var it = values.valueIterator();
        while (it.next()) |value| allocator.free(value.*);
        values.deinit(allocator);
    }
    for (program.inputs) |input| try values.put(allocator, input.name, try inputValues(allocator, assignment, input));
    for (program.nodes) |node| {
        const length: usize = if (node.op == .constant or node.op == .array_slice) node.length.? else if (node.op == .array_get or node.op == .sum_lanes or node.op == .u256_le or node.op == .u32_lt or node.op == .int_le or node.op == .is_zero or node.op == .bool_not or node.op == .bool_and or node.op == .bool_or or node.op == .bool_xor or node.op == .bool_select) 1 else if (node.op == .array_concat) (values.get(node.lhs.?) orelse return error.UnknownOperand).len + (values.get(node.rhs.?) orelse return error.UnknownOperand).len else if (node.op == .hash_sha256d_header or node.op == .bitcoin_target_mainnet or node.op == .bitcoin_prev_hash or node.op == .bitcoin_genesis_hash_mainnet or node.op == .bitcoin_block_work) 16 else if (node.op == .bitcoin_header_bits or node.op == .bitcoin_header_time) 2 else if (node.op == .hash_blake2s or node.op == .hash_blake2s_leaf or node.op == .hash_blake2s_pair or node.op == .hash_poseidon2_leaf or node.op == .hash_poseidon2_pair) 8 else (values.get(node.lhs.?) orelse return error.UnknownOperand).len;
        const out = try allocator.alloc(M31, length);
        errdefer allocator.free(out);
        const lhs = if (node.lhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        const rhs = if (node.rhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        if (node.op == .bitcoin_genesis_hash_mainnet) {
            for (out, 0..) |*slot, i| slot.* = M31.fromCanonical(std.mem.readInt(u16, mainnet_genesis_hash_raw[2 * i ..][0..2], .little));
            try values.put(allocator, node.name, out);
            continue;
        }
        const selector = if (node.selector) |name| values.get(name) orelse return error.UnknownOperand else null;
        if (node.op == .array_get or node.op == .array_concat or node.op == .array_slice) {
            if (node.op == .array_get) {
                out[0] = lhs.?[node.index.?];
            } else if (node.op == .array_slice) {
                @memcpy(out, lhs.?[node.index.?..][0..length]);
            } else {
                @memcpy(out[0..lhs.?.len], lhs.?);
                @memcpy(out[lhs.?.len..], rhs.?);
            }
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .hash_sha256d_header) {
            var header: [80]u8 = undefined;
            for (lhs.?, 0..) |word, i|
                std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
            var first: [32]u8 = undefined;
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&header, &first, .{});
            std.crypto.hash.sha2.Sha256.hash(&first, &digest, .{});
            for (out, 0..) |*slot, i| slot.* = M31.fromCanonical(std.mem.readInt(u16, digest[2 * i ..][0..2], .little));
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .bitcoin_target_mainnet) {
            const compact = lhs.?[36].toU32() | (lhs.?[37].toU32() << 16);
            const target = try mainnetTarget(compact);
            for (out, 0..) |*slot, i| slot.* = M31.fromCanonical(@intCast((target >> @as(u8, @intCast(16 * i))) & 0xffff));
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .bitcoin_block_work) {
            var target: u256 = 0;
            for (lhs.?, 0..) |word, i|
                target |= @as(u256, word.toU32()) << @as(u8, @intCast(16 * i));
            if (target == 0 or target == std.math.maxInt(u256)) return error.InvalidBlockWorkTarget;
            const denominator = target + 1;
            const work = (~target) / denominator + 1;
            for (out, 0..) |*slot, i|
                slot.* = M31.fromCanonical(@intCast((work >> @as(u8, @intCast(16 * i))) & 0xffff));
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .bitcoin_prev_hash or node.op == .bitcoin_header_bits or node.op == .bitcoin_header_time) {
            const start: usize = if (node.op == .bitcoin_prev_hash) 2 else if (node.op == .bitcoin_header_time) 34 else 36;
            @memcpy(out, lhs.?[start .. start + length]);
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .int_view or node.op == .int_add_checked or node.op == .int_add_wrapping or
            node.op == .int_sub_checked or node.op == .int_sub_wrapping or node.op == .int_le)
        {
            const spec = IntegerSpec.decode(node.constant) orelse return error.InvalidIntegerSpec;
            const base: u32 = if (spec.width == 8) 256 else 65536;
            for (lhs.?) |word| if (word.v >= base) return error.IntegerOutOfRange;
            if (rhs) |right| for (right) |word| {
                if (word.v >= base) return error.IntegerOutOfRange;
            };
            if (node.op == .int_view) {
                @memcpy(out, lhs.?);
            } else if (node.op == .int_le) {
                const sign_mask: u32 = base / 2;
                const left_sign = spec.signed and (lhs.?[lhs.?.len - 1].v & sign_mask != 0);
                const right_sign = spec.signed and (rhs.?[rhs.?.len - 1].v & sign_mask != 0);
                var le = true;
                if (left_sign != right_sign) {
                    le = left_sign;
                } else {
                    for (0..lhs.?.len) |offset| {
                        const index = lhs.?.len - 1 - offset;
                        if (lhs.?[index].v == rhs.?[index].v) continue;
                        le = lhs.?[index].v < rhs.?[index].v;
                        break;
                    }
                }
                out[0] = M31.fromCanonical(@intFromBool(le));
            } else {
                const subtract = node.op == .int_sub_checked or node.op == .int_sub_wrapping;
                var carry: u32 = 0;
                for (out, lhs.?, rhs.?) |*slot, a, b| {
                    if (subtract) {
                        slot.* = M31.fromCanonical((a.v + base - b.v - carry) & (base - 1));
                        carry = @intFromBool(a.v < b.v + carry);
                    } else {
                        const total = a.v + b.v + carry;
                        slot.* = M31.fromCanonical(total & (base - 1));
                        carry = total / base;
                    }
                }
                const checked = node.op == .int_add_checked or node.op == .int_sub_checked;
                if (checked) {
                    if (!spec.signed) {
                        if (carry != 0) return error.IntegerOverflow;
                    } else {
                        const sign_mask: u32 = base / 2;
                        const sa = lhs.?[lhs.?.len - 1].v & sign_mask != 0;
                        const sb = rhs.?[rhs.?.len - 1].v & sign_mask != 0;
                        const sr = out[out.len - 1].v & sign_mask != 0;
                        if ((if (subtract) sa != sb else sa == sb) and sr != sa)
                            return error.IntegerOverflow;
                    }
                }
            }
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .u256_add or node.op == .u256_add_checked or node.op == .u256_sub or node.op == .u256_sub_checked) {
            var carry: u32 = 0;
            for (out, lhs.?, rhs.?) |*slot, a, b| {
                if (node.op == .u256_sub or node.op == .u256_sub_checked) {
                    slot.* = M31.fromCanonical((a.v + (1 << 16) - b.v - carry) & 0xffff);
                    carry = @intFromBool(a.v < b.v + carry);
                } else {
                    const total = a.v + b.v + carry;
                    slot.* = M31.fromCanonical(total & 0xffff);
                    carry = total >> 16;
                }
            }
            if (node.op == .u256_add_checked and carry != 0) return error.U256Overflow;
            if (node.op == .u256_sub_checked and carry != 0) return error.U256Underflow;
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .u256_le) {
            var le = true;
            for (0..16) |offset| {
                const index = 15 - offset;
                if (lhs.?[index].v == rhs.?[index].v) continue;
                le = lhs.?[index].v < rhs.?[index].v;
                break;
            }
            out[0] = M31.fromCanonical(@intFromBool(le));
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .u32_lt) {
            const a = lhs.?[0].v | (lhs.?[1].v << 16);
            const b = rhs.?[0].v | (rhs.?[1].v << 16);
            out[0] = M31.fromCanonical(@intFromBool(a < b));
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .hash_blake2s or node.op == .hash_blake2s_leaf or node.op == .hash_blake2s_pair) {
            const message = try allocator.alloc(u8, (lhs.?.len + if (node.op == .hash_blake2s_pair) rhs.?.len else @as(usize, 0)) * 4);
            defer allocator.free(message);
            for (lhs.?, 0..) |word, i| std.mem.writeInt(u32, message[i * 4 ..][0..4], word.toU32(), .little);
            if (node.op == .hash_blake2s_pair) for (rhs.?, 0..) |word, i| {
                std.mem.writeInt(u32, message[(lhs.?.len + i) * 4 ..][0..4], word.toU32(), .little);
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.blake2.Blake2s256.hash(message, &digest, .{ .context = switch (node.op) {
                .hash_blake2s_leaf => leaf_personalization,
                .hash_blake2s_pair => pair_personalization,
                else => null,
            } });
            for (out, 0..) |*slot, i| slot.* = M31.fromU64(std.mem.readInt(u32, digest[i * 4 ..][0..4], .little));
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .hash_poseidon2_leaf or node.op == .hash_poseidon2_pair) {
            const digest = if (node.op == .hash_poseidon2_leaf) poseidon2.leafWords(lhs.?) else poseidon2.pairWords(lhs.?, rhs.?);
            @memcpy(out, &digest);
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .repeat) {
            @memcpy(out, lhs.?);
            for (0..node.rounds.?) |_| for (node.body.?) |step| try applyStep(out, step);
            try values.put(allocator, node.name, out);
            continue;
        }
        const c = M31.fromCanonical(node.constant orelse 0);
        for (out, 0..) |*slot, i| slot.* = switch (node.op) {
            .constant => c,
            .cast_m31 => lhs.?[i],
            .add => lhs.?[i].add(rhs.?[i]),
            .mul => lhs.?[i].mul(rhs.?[i]),
            .inv => try lhs.?[i].inv(),
            .is_zero => M31.fromCanonical(@intFromBool(lhs.?[i].isZero())),
            .bool_not, .bool_and, .bool_or, .bool_xor, .bool_select => blk: {
                const a = lhs.?[i].toU32();
                if (a > 1) return error.InvalidBooleanOperand;
                const b: u32 = if (node.op == .bool_not) 0 else rhs.?[i].toU32();
                if (b > 1) return error.InvalidBooleanOperand;
                const s: u32 = if (node.op == .bool_select) selector.?[0].toU32() else 0;
                if (s > 1) return error.InvalidBooleanOperand;
                const bit: u32 = switch (node.op) {
                    .bool_not => 1 - a,
                    .bool_and => a & b,
                    .bool_or => a | b,
                    .bool_xor => a ^ b,
                    .bool_select => if (s == 0) a else b,
                    else => unreachable,
                };
                break :blk M31.fromCanonical(bit);
            },
            .add_const => lhs.?[i].add(c),
            .mul_const => lhs.?[i].mul(c),
            .sum_lanes => blk: {
                var sum = M31.zero();
                for (lhs.?) |word| sum = sum.add(word);
                break :blk sum;
            },
            .repeat => unreachable,
            .select => blk: {
                const bit = selector.?[0].toU32();
                if (bit > 1) return error.InvalidSelector;
                break :blk if (bit == 0) lhs.?[i] else rhs.?[i];
            },
            .hash_blake2s, .hash_blake2s_leaf, .hash_blake2s_pair, .hash_poseidon2_leaf, .hash_poseidon2_pair, .u256_add, .u256_le, .u256_add_checked, .u256_sub, .u256_sub_checked, .u32_lt, .hash_sha256d_header, .bitcoin_target_mainnet, .bitcoin_block_work, .bitcoin_prev_hash, .bitcoin_header_bits, .bitcoin_header_time, .bitcoin_genesis_hash_mainnet, .array_get, .array_concat, .array_slice, .int_view, .int_add_checked, .int_add_wrapping, .int_sub_checked, .int_sub_wrapping, .int_le => unreachable,
        };
        try values.put(allocator, node.name, out);
    }
    for (program.assertions) |assertion| {
        const lhs = values.get(assertion.lhs) orelse return error.UnknownOperand;
        const rhs = values.get(assertion.rhs) orelse return error.UnknownOperand;
        for (lhs, rhs) |a, b| if (!a.eql(b)) return error.AssertionFailed;
    }
    const claimed = try claimedWords(allocator, program, assignment);
    for (program.public_outputs) |name| {
        const actual = values.get(name) orelse return error.UnknownOutput;
        const claimed_values = try arrayValues(allocator, assignment.public_outputs, name, (try program.shapeOf(allocator, name)).?);
        defer allocator.free(claimed_values);
        for (actual, claimed_values) |a, b| if (!a.eql(b)) return error.PublicOutputMismatch;
    }
    return claimed;
}

/// Bitcoin Core's mainnet powLimit is 2^224 - 1. Its compact encoding
/// `0x1d00ffff` decodes to the slightly smaller genesis target.
pub const mainnet_pow_limit: u256 = (@as(u256, 1) << 224) - 1;

pub fn mainnetTarget(compact: u32) !u256 {
    const exponent: u8 = @intCast(compact >> 24);
    const mantissa: u32 = compact & 0x007f_ffff;
    if (compact & 0x0080_0000 != 0 or exponent == 0 or exponent > 32 or mantissa == 0)
        return error.InvalidCompactTarget;
    const target: u256 = if (exponent <= 3)
        @as(u256, mantissa) >> @as(u8, @intCast(8 * (3 - @as(u32, exponent))))
    else
        @as(u256, mantissa) << @as(u8, @intCast(8 * (@as(u32, exponent) - 3)));
    if (target == 0 or target > mainnet_pow_limit) return error.InvalidCompactTarget;
    return target;
}

test "mainnet powLimit and compact genesis target are distinct Core values" {
    const genesis_target = try mainnetTarget(0x1d00ffff);
    try std.testing.expectEqual(@as(u256, 0xffff) << 208, genesis_target);
    try std.testing.expectEqual((@as(u256, 1) << 208) - 1, mainnet_pow_limit - genesis_target);
    try std.testing.expectEqual(@as(u256, 0x7fffff) << 200, try mainnetTarget(0x1c7fffff));
    try std.testing.expectError(error.InvalidCompactTarget, mainnetTarget(0x1d010000));
}

fn arrayValues(allocator: std.mem.Allocator, object: std.json.Value, name: []const u8, shape: Shape) ![]M31 {
    if (object != .object) return error.InvalidAssignment;
    const field = object.object.get(name) orelse return error.MissingAssignedValue;
    if (field != .array or field.array.items.len != shape.length) return error.InvalidAssignedShape;
    const out = try allocator.alloc(M31, shape.length);
    errdefer allocator.free(out);
    for (field.array.items, out) |item, *slot| {
        if (item != .integer or item.integer < 0) return error.InvalidAssignedValue;
        const number: u64 = @intCast(item.integer);
        if (number >= (if (shape.kind == .u16) @as(u64, 65536) else @as(u64, P))) return error.InvalidAssignedValue;
        slot.* = M31.fromCanonical(@intCast(number));
    }
    return out;
}

fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128) return false;
    for (name) |char| if (!std.ascii.isAlphanumeric(char) and char != '_') return false;
    return true;
}

test "state fold extracts the source body but refuses private or side relations" {
    const source =
        \\{"version":1,"name":"general_fold","inputs":[{"name":"x","kind":"m31","length":4,"visibility":"public"}],"nodes":[{"name":"y","op":"repeat","lhs":"x","rounds":3,"body":[{"op":"square"},{"op":"mul_const","constant":3},{"op":"add_const","constant":5}]}],"assertions":[],"public_outputs":["y"]}
    ;
    var parsed = try parseProgram(std.testing.allocator, source);
    defer parsed.deinit();
    const spec = parsed.value.stateFoldStep() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 3), spec.rounds);
    try std.testing.expectEqual(@as(usize, 3), spec.body.len);
    try std.testing.expectEqual(StepOp.square, spec.body[0].op);
    try std.testing.expectEqual(StepOp.mul_const, spec.body[1].op);
    try std.testing.expectEqual(@as(?u32, 3), spec.body[1].constant);
    try std.testing.expectEqual(StepOp.add_const, spec.body[2].op);
    try std.testing.expectEqual(@as(?u32, 5), spec.body[2].constant);
    try std.testing.expect(parsed.value.repeatedStepChip() == null);

    var private_input = [1]Input{parsed.value.inputs[0]};
    private_input[0].visibility = .private;
    var private_program = parsed.value;
    private_program.inputs = &private_input;
    try std.testing.expect(private_program.stateFoldStep() == null);

    var side_assertion = [1]Assertion{.{ .lhs = "x", .rhs = "x" }};
    var side_program = parsed.value;
    side_program.assertions = &side_assertion;
    try std.testing.expect(side_program.stateFoldStep() == null);
}

test "malformed relation nodes cannot introduce unconstrained operands or metadata" {
    const malformed = [_][]const u8{
        // An extra parser field must not silently change the author's relation.
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":1,"visibility":"public"}],"nodes":[{"name":"y","op":"add_const","lhs":"x","constant":1,"ignored":"x"}],"assertions":[],"public_outputs":["y"]}
        ,
        // A selector on any other operation would otherwise be unproved data.
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":1,"visibility":"public"}],"nodes":[{"name":"y","op":"add_const","lhs":"x","constant":1,"selector":"x"}],"assertions":[],"public_outputs":["y"]}
        ,
        // A select must have a scalar selector, regardless of its value.
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":2,"visibility":"public"}],"nodes":[{"name":"y","op":"select","lhs":"x","rhs":"x","selector":"x"}],"assertions":[],"public_outputs":["y"]}
        ,
        // Noncanonical constants must not enter the circuit or public ABI.
        \\{"version":1,"name":"bad","inputs":[],"nodes":[{"name":"y","op":"constant","constant":2147483647,"length":1}],"assertions":[],"public_outputs":["y"]}
        ,
        // A compile-time index must stay inside the source array.
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":1,"visibility":"public"}],"nodes":[{"name":"y","op":"array_get","lhs":"x","index":1}],"assertions":[],"public_outputs":["y"]}
        ,
        // A stray index cannot influence a different operation's identity.
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":1,"visibility":"public"}],"nodes":[{"name":"y","op":"add_const","lhs":"x","constant":1,"index":0}],"assertions":[],"public_outputs":["y"]}
        ,
        // Concatenation cannot silently cast a bounded limb to an M31 word.
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":1,"visibility":"public"},{"name":"z","kind":"u16","length":1,"visibility":"public"}],"nodes":[{"name":"y","op":"array_concat","lhs":"x","rhs":"z"}],"assertions":[],"public_outputs":["y"]}
        ,
        // A slice must name a nonempty interval inside one source array.
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":4,"visibility":"private"}],"nodes":[{"name":"y","op":"array_slice","lhs":"x","index":2,"length":3}],"assertions":[],"public_outputs":["y"]}
        ,
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":4,"visibility":"private"}],"nodes":[{"name":"y","op":"array_slice","lhs":"x","index":0,"length":0}],"assertions":[],"public_outputs":["y"]}
        ,
        \\{"version":1,"name":"bad","inputs":[{"name":"x","kind":"m31","length":4,"visibility":"private"}],"nodes":[{"name":"y","op":"array_slice","lhs":"x","index":0,"length":1,"rhs":"x"}],"assertions":[],"public_outputs":["y"]}
        ,
    };
    for (malformed) |source| {
        if (parseProgram(std.testing.allocator, source)) |parsed| {
            var accepted = parsed;
            accepted.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "public statement binds exact fields and canonical M31 words" {
    const source =
        \\{"version":1,"name":"public_binding","inputs":[{"name":"x","kind":"m31","length":1,"visibility":"public"}],"nodes":[{"name":"y","op":"add_const","lhs":"x","constant":1}],"assertions":[],"public_outputs":["y"]}
    ;
    var program = try parseProgram(std.testing.allocator, source);
    defer program.deinit();
    const malformed = [_][]const u8{
        \\{"public_inputs":{"x":[3],"other":[0]},"public_outputs":{"y":[4]}}
        ,
        \\{"public_inputs":{"x":[3]},"public_outputs":{"other":[4]}}
        ,
        \\{"public_inputs":{"x":[2147483647]},"public_outputs":{"y":[4]}}
        ,
        \\{"public_inputs":{"x":[3]},"public_outputs":{"y":[2147483647]}}
        ,
    };
    for (malformed) |source_json| {
        var assignment = try parseAssignment(std.testing.allocator, source_json);
        defer assignment.deinit();
        if (claimedWords(std.testing.allocator, program.value, assignment.value)) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}
