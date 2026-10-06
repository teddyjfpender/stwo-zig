//! S31 relation IR v1. This normalized form is intentionally machine-readable:
//! every array length and loop bound is static, and witness values cannot add
//! nodes or change circuit topology.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const P = core.fields.m31.Modulus;
const poseidon2 = @import("poseidon2.zig");

pub const Kind = enum { u16, m31 };
pub const Visibility = enum { public, private };
pub const Input = struct {
    name: []const u8,
    kind: Kind,
    length: u32,
    visibility: Visibility,
};
pub const StepOp = enum { square, add_const, mul_const };
pub const Step = struct {
    op: StepOp,
    constant: ?u32 = null,
};
pub const Op = enum { constant, cast_m31, add, mul, add_const, mul_const, repeat, hash_blake2s, hash_blake2s_leaf, hash_blake2s_pair, select, hash_poseidon2_leaf, hash_poseidon2_pair, sum_lanes };
pub const leaf_personalization = [8]u8{ 'S', '3', '1', 'L', 'E', 'A', 'F', '1' };
pub const pair_personalization = [8]u8{ 'S', '3', '1', 'P', 'A', 'I', 'R', '1' };
pub const Node = struct {
    name: []const u8,
    op: Op,
    lhs: ?[]const u8 = null,
    rhs: ?[]const u8 = null,
    selector: ?[]const u8 = null,
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
pub const Program = struct {
    version: u32,
    name: []const u8,
    inputs: []Input,
    nodes: []Node,
    assertions: []Assertion,
    public_outputs: [][]const u8,

    /// The first hybrid profile accepts exactly one public four-lane
    /// square/add recurrence. Broader extraction requires a private boundary
    /// relation and a new versioned chip registry.
    pub fn repeatedStepChip(self: Program) ?ChipSpec {
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
        if (rounds < 16 or rounds > 32768 or !std.math.isPowerOfTwo(rounds))
            return null;
        const body = node.body.?;
        if (body.len != 2 or body[0].op != .square or
            body[1].op != .add_const or body[1].constant == null)
            return null;
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
            if (node.op != .select and selector != null) return error.InvalidNode;
            var result: Shape = undefined;
            switch (node.op) {
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
                .add_const, .mul_const => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant == null or node.constant.? >= P or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = lhs.?;
                },
                .sum_lanes => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = .{ .kind = .m31, .length = 1 };
                },
                .repeat => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant != null or node.length != null or node.rounds == null or node.rounds.? == 0 or node.rounds.? > 32768 or node.body == null or node.body.?.len == 0 or node.body.?.len > 16) return error.InvalidNode;
                    for (node.body.?) |step| switch (step.op) {
                        .square => if (step.constant != null) return error.InvalidNode,
                        .add_const, .mul_const => if (step.constant == null or step.constant.? >= P) return error.InvalidNode,
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
                    if (lhs == null or rhs == null or selector == null or lhs.?.kind != .m31 or rhs.?.kind != .m31 or selector.?.kind != .m31 or lhs.?.length != rhs.?.length or selector.?.length != 1 or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
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

    pub fn shapeOf(self: Program, name: []const u8) ?Shape {
        for (self.inputs) |input| if (std.mem.eql(u8, input.name, name)) return .{ .kind = input.kind, .length = input.length };
        for (self.nodes) |node| {
            if (std.mem.eql(u8, node.name, name)) {
                if (node.op == .constant) return .{ .kind = .m31, .length = node.length.? };
                if (node.op == .sum_lanes) return .{ .kind = .m31, .length = 1 };
                if (node.op == .hash_blake2s or node.op == .hash_blake2s_leaf or node.op == .hash_blake2s_pair or node.op == .hash_poseidon2_leaf or node.op == .hash_poseidon2_pair) return .{ .kind = .m31, .length = 8 };
                const previous = self.shapeOf(node.lhs.?) orelse return null;
                return .{ .kind = .m31, .length = previous.length };
            }
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
        const shape = program.shapeOf(name) orelse return error.UnknownOutput;
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
        const length: usize = if (node.op == .constant) node.length.? else if (node.op == .sum_lanes) 1 else if (node.op == .hash_blake2s or node.op == .hash_blake2s_leaf or node.op == .hash_blake2s_pair or node.op == .hash_poseidon2_leaf or node.op == .hash_poseidon2_pair) 8 else (values.get(node.lhs.?) orelse return error.UnknownOperand).len;
        const out = try allocator.alloc(M31, length);
        errdefer allocator.free(out);
        const lhs = if (node.lhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        const rhs = if (node.rhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        const selector = if (node.selector) |name| values.get(name) orelse return error.UnknownOperand else null;
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
        const c = M31.fromCanonical(node.constant orelse 0);
        for (out, 0..) |*slot, i| slot.* = switch (node.op) {
            .constant => c,
            .cast_m31 => lhs.?[i],
            .add => lhs.?[i].add(rhs.?[i]),
            .mul => lhs.?[i].mul(rhs.?[i]),
            .add_const => lhs.?[i].add(c),
            .mul_const => lhs.?[i].mul(c),
            .sum_lanes => blk: {
                var sum = M31.zero();
                for (lhs.?) |word| sum = sum.add(word);
                break :blk sum;
            },
            .repeat => blk: {
                var v = lhs.?[i];
                for (0..node.rounds.?) |_| for (node.body.?) |step| {
                    v = switch (step.op) {
                        .square => v.mul(v),
                        .add_const => v.add(M31.fromCanonical(step.constant.?)),
                        .mul_const => v.mul(M31.fromCanonical(step.constant.?)),
                    };
                };
                break :blk v;
            },
            .select => blk: {
                const bit = selector.?[0].toU32();
                if (bit > 1) return error.InvalidSelector;
                break :blk if (bit == 0) lhs.?[i] else rhs.?[i];
            },
            .hash_blake2s, .hash_blake2s_leaf, .hash_blake2s_pair, .hash_poseidon2_leaf, .hash_poseidon2_pair => unreachable,
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
        const claimed_values = try arrayValues(allocator, assignment.public_outputs, name, program.shapeOf(name).?);
        defer allocator.free(claimed_values);
        for (actual, claimed_values) |a, b| if (!a.eql(b)) return error.PublicOutputMismatch;
    }
    return claimed;
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
