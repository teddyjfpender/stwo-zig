//! S31 v0: a deliberately small, normalized circuit language. Its source is
//! JSON so the first implementation can validate circuit and verifier lowering
//! without a surface-syntax parser. Every node is a four-lane vector operation.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;

pub const Op = enum { add, mul, add_const, mul_const, repeat_square_add };
pub const Node = struct {
    name: []const u8,
    op: Op,
    lhs: []const u8,
    rhs: ?[]const u8 = null,
    constant: ?u32 = null,
    rounds: ?u32 = null,
};

pub const Program = struct {
    version: u32,
    name: []const u8,
    lanes: u32,
    input: []const u8,
    nodes: []Node,
    result: []const u8,
    public_abi: []const u8,

    pub fn validate(self: Program, allocator: std.mem.Allocator) !void {
        if (self.version != 0) return error.UnsupportedVersion;
        if (self.name.len == 0 or self.input.len == 0) return error.EmptyName;
        for (self.name) |char| {
            if (!std.ascii.isAlphanumeric(char) and char != '_' and char != '-') return error.InvalidProgramName;
        }
        if (self.lanes != 4) return error.InvalidLaneCount;
        if (!std.mem.eql(u8, self.public_abi, "u32x8_input_result")) return error.UnsupportedPublicAbi;
        var names = std.StringHashMapUnmanaged(void){};
        defer names.deinit(allocator);
        try names.put(allocator, self.input, {});
        for (self.nodes) |node| {
            if (node.name.len == 0 or names.contains(node.name)) return error.DuplicateOrEmptyNode;
            if (!names.contains(node.lhs)) return error.UnknownOperand;
            switch (node.op) {
                .add, .mul => {
                    if (node.rhs == null or !names.contains(node.rhs.?) or node.constant != null or node.rounds != null) return error.InvalidNode;
                },
                .add_const, .mul_const => {
                    if (node.rhs != null or node.constant == null or node.constant.? >= core.fields.m31.Modulus or node.rounds != null) return error.InvalidNode;
                },
                .repeat_square_add => {
                    if (node.rhs != null or node.constant == null or node.constant.? >= core.fields.m31.Modulus or node.rounds == null or node.rounds.? == 0 or node.rounds.? > 32768) return error.InvalidNode;
                },
            }
            try names.put(allocator, node.name, {});
        }
        if (!names.contains(self.result)) return error.UnknownResult;
    }
};

pub const Parsed = std.json.Parsed(Program);

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !Parsed {
    var parsed = try std.json.parseFromSlice(Program, allocator, source, .{ .ignore_unknown_fields = false });
    errdefer parsed.deinit();
    try parsed.value.validate(allocator);
    return parsed;
}

/// Reference semantics of the normalized source: each operation is in M31.
/// Inputs are u16. Every operation, including each repeat iteration, reduces
/// modulo the M31 prime.
pub fn evaluate(allocator: std.mem.Allocator, source: Program, input: []const u16) ![]M31 {
    try source.validate(allocator);
    if (input.len != source.lanes) return error.InputLengthMismatch;
    var values = std.StringHashMapUnmanaged([]M31){};
    defer {
        var iter = values.valueIterator();
        while (iter.next()) |vector| allocator.free(vector.*);
        values.deinit(allocator);
    }
    const first = try allocator.alloc(M31, input.len);
    for (input, first) |x, *slot| slot.* = M31.fromCanonical(x);
    values.put(allocator, source.input, first) catch |err| {
        allocator.free(first);
        return err;
    };
    for (source.nodes) |node| {
        const lhs = values.get(node.lhs) orelse return error.UnknownOperand;
        const rhs = if (node.rhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        const constant = M31.fromCanonical(node.constant orelse 0);
        const out = try allocator.alloc(M31, input.len);
        for (out, lhs, 0..) |*slot, a, index| slot.* = switch (node.op) {
            .add => a.add(rhs.?[index]),
            .mul => a.mul(rhs.?[index]),
            .add_const => a.add(constant),
            .mul_const => a.mul(constant),
            .repeat_square_add => blk: {
                var value = a;
                for (0..node.rounds.?) |_| value = value.mul(value).add(constant);
                break :blk value;
            },
        };
        values.put(allocator, node.name, out) catch |err| {
            allocator.free(out);
            return err;
        };
    }
    return allocator.dupe(M31, values.get(source.result) orelse return error.UnknownResult);
}

test "repeated squaring uses M31 semantics" {
    const source =
        \\{"version":0,"name":"square3","lanes":4,"input":"x","nodes":[{"name":"y","op":"repeat_square_add","lhs":"x","constant":7,"rounds":3}],"result":"y","public_abi":"u32x8_input_result"}
    ;
    var parsed = try parse(std.testing.allocator, source);
    defer parsed.deinit();
    const got = try evaluate(std.testing.allocator, parsed.value, &.{ 1, 2, 3, 65535 });
    defer std.testing.allocator.free(got);
    for (got, [_]u16{ 1, 2, 3, 65535 }) |actual, input_word| {
        var expected: u64 = input_word;
        for (0..3) |_| expected = (expected * expected + 7) % core.fields.m31.Modulus;
        try std.testing.expectEqual(@as(u32, @intCast(expected)), actual.toU32());
    }
}

/// Eight verifier-bound output words: four input values, then four results.
/// The upstream proof field calls them an output digest, but the protocol
/// binds their raw u32 values. This v0 ABI uses those slots directly.
pub fn expectedPublicWords(allocator: std.mem.Allocator, source: Program, input: []const u16) ![8]u32 {
    const result = try evaluate(allocator, source, input);
    defer allocator.free(result);
    var words: [8]u32 = undefined;
    for (input, words[0..4]) |value, *slot| slot.* = value;
    for (result, words[4..]) |value, *slot| slot.* = value.toU32();
    return words;
}

test "parse and evaluate an affine circuit" {
    const source =
        \\{"version":0,"name":"affine4","lanes":4,"input":"x","nodes":[{"name":"scaled","op":"mul_const","lhs":"x","constant":7},{"name":"y","op":"add_const","lhs":"scaled","constant":11}],"result":"y","public_abi":"u32x8_input_result"}
    ;
    var parsed = try parse(std.testing.allocator, source);
    defer parsed.deinit();
    const got = try evaluate(std.testing.allocator, parsed.value, &.{ 1, 2, 3, 65535 });
    defer std.testing.allocator.free(got);
    for (got, [_]u32{ 18, 25, 32, 458756 }) |actual, want| try std.testing.expectEqual(want, actual.toU32());
}
