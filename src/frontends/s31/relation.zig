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
pub const Op = enum { constant, cast_m31, add, mul, add_const, mul_const, repeat, hash_blake2s, hash_blake2s_leaf, hash_blake2s_pair, select, hash_poseidon2_leaf, hash_poseidon2_pair, sum_lanes, u256_add, u256_le, u256_add_checked, hash_sha256d_header, bitcoin_target_mainnet, bitcoin_prev_hash, bitcoin_header_bits, bitcoin_genesis_hash_mainnet, bitcoin_header_time, u32_lt, inv, is_zero };
pub const mainnet_genesis_hash_raw: [32]u8 = .{ 0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00 };
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
                .inv => {
                    if (lhs == null or lhs.?.kind != .m31 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
                    result = lhs.?;
                },
                .is_zero => {
                    if (lhs == null or lhs.?.kind != .m31 or lhs.?.length != 1 or rhs != null or node.constant != null or node.length != null or node.rounds != null or node.body != null) return error.InvalidNode;
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
                .u256_add, .u256_le, .u256_add_checked => {
                    if (lhs == null or rhs == null or lhs.?.kind != .u16 or rhs.?.kind != .u16 or
                        lhs.?.length != 16 or rhs.?.length != 16 or node.constant != null or
                        node.length != null or node.rounds != null or node.body != null)
                        return error.InvalidNode;
                    result = if (node.op == .u256_add or node.op == .u256_add_checked)
                        .{ .kind = .u16, .length = 16 }
                    else
                        .{ .kind = .m31, .length = 1 };
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
                .sum_lanes, .u256_le, .u32_lt, .is_zero => 1,
                .hash_sha256d_header, .bitcoin_target_mainnet, .bitcoin_genesis_hash_mainnet => 16,
                .bitcoin_prev_hash => 16,
                .bitcoin_header_bits, .bitcoin_header_time => 2,
                .hash_blake2s, .hash_blake2s_leaf, .hash_blake2s_pair, .hash_poseidon2_leaf, .hash_poseidon2_pair => 8,
                else => (shapes.get(node.lhs orelse return error.InvalidNode) orelse return error.UnknownOperand).length,
            };
            const shape: Shape = .{ .kind = if (node.op == .u256_add or node.op == .u256_add_checked or node.op == .hash_sha256d_header or node.op == .bitcoin_target_mainnet or node.op == .bitcoin_prev_hash or node.op == .bitcoin_header_bits or node.op == .bitcoin_header_time or node.op == .bitcoin_genesis_hash_mainnet) .u16 else .m31, .length = length };
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
        const length: usize = if (node.op == .constant) node.length.? else if (node.op == .sum_lanes or node.op == .u256_le or node.op == .u32_lt or node.op == .is_zero) 1 else if (node.op == .hash_sha256d_header or node.op == .bitcoin_target_mainnet or node.op == .bitcoin_prev_hash or node.op == .bitcoin_genesis_hash_mainnet) 16 else if (node.op == .bitcoin_header_bits or node.op == .bitcoin_header_time) 2 else if (node.op == .hash_blake2s or node.op == .hash_blake2s_leaf or node.op == .hash_blake2s_pair or node.op == .hash_poseidon2_leaf or node.op == .hash_poseidon2_pair) 8 else (values.get(node.lhs.?) orelse return error.UnknownOperand).len;
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
        if (node.op == .bitcoin_prev_hash or node.op == .bitcoin_header_bits or node.op == .bitcoin_header_time) {
            const start: usize = if (node.op == .bitcoin_prev_hash) 2 else if (node.op == .bitcoin_header_time) 34 else 36;
            @memcpy(out, lhs.?[start .. start + length]);
            try values.put(allocator, node.name, out);
            continue;
        }
        if (node.op == .u256_add or node.op == .u256_add_checked) {
            var carry: u32 = 0;
            for (out, lhs.?, rhs.?) |*slot, a, b| {
                const total = a.v + b.v + carry;
                slot.* = M31.fromCanonical(total & 0xffff);
                carry = total >> 16;
            }
            if (node.op == .u256_add_checked and carry != 0) return error.U256Overflow;
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
        const c = M31.fromCanonical(node.constant orelse 0);
        for (out, 0..) |*slot, i| slot.* = switch (node.op) {
            .constant => c,
            .cast_m31 => lhs.?[i],
            .add => lhs.?[i].add(rhs.?[i]),
            .mul => lhs.?[i].mul(rhs.?[i]),
            .inv => try lhs.?[i].inv(),
            .is_zero => M31.fromCanonical(@intFromBool(lhs.?[i].isZero())),
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
            .hash_blake2s, .hash_blake2s_leaf, .hash_blake2s_pair, .hash_poseidon2_leaf, .hash_poseidon2_pair, .u256_add, .u256_le, .u256_add_checked, .u32_lt, .hash_sha256d_header, .bitcoin_target_mainnet, .bitcoin_prev_hash, .bitcoin_header_bits, .bitcoin_header_time, .bitcoin_genesis_hash_mainnet => unreachable,
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

pub fn mainnetTarget(compact: u32) !u256 {
    const exponent: u8 = @intCast(compact >> 24);
    const mantissa: u32 = compact & 0x007f_ffff;
    if (compact & 0x0080_0000 != 0 or exponent == 0 or exponent > 32 or mantissa == 0)
        return error.InvalidCompactTarget;
    const target: u256 = if (exponent <= 3)
        @as(u256, mantissa) >> @as(u8, @intCast(8 * (3 - @as(u32, exponent))))
    else
        @as(u256, mantissa) << @as(u8, @intCast(8 * (@as(u32, exponent) - 3)));
    if (target == 0 or target > (@as(u256, 0xffff) << 208)) return error.InvalidCompactTarget;
    return target;
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
