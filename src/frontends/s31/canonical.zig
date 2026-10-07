//! Deterministic, versioned circuit SSA for S31 relations. Names used only for
//! source mapping are removed from arithmetic nodes; constant expressions are
//! folded and repeated expressions share one node.

const std = @import("std");
const core = @import("stwo_core");
const relation = @import("relation.zig");
const M31 = core.fields.m31.M31;

pub const Tag = enum { input, constant, cast_m31, add, mul, add_const, mul_const, repeat, hash_blake2s, hash_blake2s_leaf, hash_blake2s_pair, select, hash_poseidon2_leaf, hash_poseidon2_pair, sum_lanes, u256_add, u256_le, u256_add_checked, hash_sha256d_header, bitcoin_target_mainnet, bitcoin_prev_hash, bitcoin_header_bits, bitcoin_genesis_hash_mainnet, bitcoin_header_time, u32_lt, inv, is_zero, u256_sub, u256_sub_checked, array_get, array_concat };
pub const Node = struct {
    tag: Tag,
    kind: relation.Kind,
    length: u32,
    lhs: ?u32 = null,
    rhs: ?u32 = null,
    selector: ?u32 = null,
    index: ?u32 = null,
    constant: ?u32 = null,
    rounds: ?u32 = null,
    body: ?[]const relation.Step = null,
    input_name: ?[]const u8 = null,
    visibility: ?relation.Visibility = null,
};
/// Preserve the canonical encoding of programs that predate `select`.
const LegacyNode = struct {
    tag: Tag,
    kind: relation.Kind,
    length: u32,
    lhs: ?u32 = null,
    rhs: ?u32 = null,
    constant: ?u32 = null,
    rounds: ?u32 = null,
    body: ?[]const relation.Step = null,
    input_name: ?[]const u8 = null,
    visibility: ?relation.Visibility = null,
};
pub const Source = struct { name: []const u8, id: u32 };
/// The pre-index encoding of selector programs stays byte-for-byte stable.
const SelectorNode = struct {
    tag: Tag,
    kind: relation.Kind,
    length: u32,
    lhs: ?u32 = null,
    rhs: ?u32 = null,
    selector: ?u32 = null,
    constant: ?u32 = null,
    rounds: ?u32 = null,
    body: ?[]const relation.Step = null,
    input_name: ?[]const u8 = null,
    visibility: ?relation.Visibility = null,
};
pub const Assertion = struct { lhs: u32, rhs: u32 };
pub const Output = struct { name: []const u8, id: u32 };
pub const IR = struct {
    allocator: std.mem.Allocator,
    nodes: []Node,
    source_map: []Source,
    assertions: []Assertion,
    public_outputs: []Output,
    sha256: [32]u8,

    pub fn deinit(self: *IR) void {
        self.allocator.free(self.nodes);
        self.allocator.free(self.source_map);
        self.allocator.free(self.assertions);
        self.allocator.free(self.public_outputs);
        self.* = undefined;
    }
};

pub fn build(allocator: std.mem.Allocator, program: relation.Program) !IR {
    try program.validate(allocator);
    var nodes: std.ArrayListUnmanaged(Node) = .empty;
    errdefer nodes.deinit(allocator);
    var source: std.ArrayListUnmanaged(Source) = .empty;
    errdefer source.deinit(allocator);
    var assertions: std.ArrayListUnmanaged(Assertion) = .empty;
    errdefer assertions.deinit(allocator);
    var outputs: std.ArrayListUnmanaged(Output) = .empty;
    errdefer outputs.deinit(allocator);
    var ids = std.StringHashMapUnmanaged(u32){};
    defer ids.deinit(allocator);
    var expressions = std.StringHashMapUnmanaged(u32){};
    defer expressions.deinit(allocator);
    var key_arena = std.heap.ArenaAllocator.init(allocator);
    defer key_arena.deinit();

    for (program.inputs) |input| {
        const id: u32 = @intCast(nodes.items.len);
        try nodes.append(allocator, .{
            .tag = .input,
            .kind = input.kind,
            .length = input.length,
            .input_name = input.name,
            .visibility = input.visibility,
        });
        try ids.put(allocator, input.name, id);
        try source.append(allocator, .{ .name = input.name, .id = id });
    }

    for (program.nodes) |raw| {
        const lhs: ?u32 = if (raw.lhs) |name| ids.get(name) orelse return error.UnknownOperand else null;
        const rhs: ?u32 = if (raw.rhs) |name| ids.get(name) orelse return error.UnknownOperand else null;
        const selector: ?u32 = if (raw.selector) |name| ids.get(name) orelse return error.UnknownOperand else null;
        // The relation validator has already checked shapes. Canonical nodes
        // are in dependency order, so derive this shape from the preceding
        // operand rather than recursively rescanning the full source chain.
        const length: u32 = switch (raw.op) {
            .constant => raw.length.?,
            .array_get => 1,
            .array_concat => nodes.items[lhs.?].length + nodes.items[rhs.?].length,
            .sum_lanes, .u256_le, .u32_lt, .is_zero => 1,
            .hash_sha256d_header, .bitcoin_target_mainnet, .bitcoin_prev_hash, .bitcoin_genesis_hash_mainnet => 16,
            .bitcoin_header_bits, .bitcoin_header_time => 2,
            .hash_blake2s, .hash_blake2s_leaf, .hash_blake2s_pair, .hash_poseidon2_leaf, .hash_poseidon2_pair => 8,
            else => nodes.items[lhs.?].length,
        };
        var node: Node = .{
            .tag = @enumFromInt(@as(u8, @intFromEnum(raw.op)) + 1),
            .kind = if (raw.op == .array_get or raw.op == .array_concat)
                nodes.items[lhs.?].kind
            else if (raw.op == .u256_add or raw.op == .u256_add_checked or raw.op == .u256_sub or raw.op == .u256_sub_checked or raw.op == .hash_sha256d_header or raw.op == .bitcoin_target_mainnet or raw.op == .bitcoin_prev_hash or raw.op == .bitcoin_header_bits or raw.op == .bitcoin_header_time or raw.op == .bitcoin_genesis_hash_mainnet) .u16 else .m31,
            .length = length,
            .lhs = lhs,
            .rhs = rhs,
            .selector = selector,
            .index = raw.index,
            .constant = raw.constant,
            .rounds = raw.rounds,
            .body = raw.body,
        };
        if (node.tag == .add or node.tag == .mul) {
            if (node.lhs.? > node.rhs.?) std.mem.swap(u32, &node.lhs.?, &node.rhs.?);
        }
        const alias = simplify(&node, nodes.items);
        const id: u32 = if (alias) |existing| existing else blk: {
            const key = try expressionKey(key_arena.allocator(), node);
            if (expressions.get(key)) |existing| break :blk existing;
            const fresh: u32 = @intCast(nodes.items.len);
            try nodes.append(allocator, node);
            try expressions.put(allocator, key, fresh);
            break :blk fresh;
        };
        try ids.put(allocator, raw.name, id);
        try source.append(allocator, .{ .name = raw.name, .id = id });
    }
    for (program.assertions) |assertion| try assertions.append(allocator, .{
        .lhs = ids.get(assertion.lhs) orelse return error.UnknownOperand,
        .rhs = ids.get(assertion.rhs) orelse return error.UnknownOperand,
    });
    for (program.public_outputs) |name| try outputs.append(allocator, .{
        .name = name,
        .id = ids.get(name) orelse return error.UnknownOutput,
    });

    var uses_selector = false;
    for (nodes.items) |node| if (node.tag == .select) {
        uses_selector = true;
        break;
    };
    var uses_index = false;
    for (nodes.items) |node| if (node.tag == .array_get or node.tag == .array_concat) {
        uses_index = true;
        break;
    };
    const encoded = if (uses_index) try std.json.Stringify.valueAlloc(allocator, .{
        .version = @as(u32, 1),
        .nodes = nodes.items,
        .assertions = assertions.items,
        .public_outputs = outputs.items,
    }, .{}) else if (uses_selector) blk: {
        const selector_nodes = try allocator.alloc(SelectorNode, nodes.items.len);
        defer allocator.free(selector_nodes);
        for (nodes.items, selector_nodes) |node, *previous| previous.* = .{
            .tag = node.tag,
            .kind = node.kind,
            .length = node.length,
            .lhs = node.lhs,
            .rhs = node.rhs,
            .selector = node.selector,
            .constant = node.constant,
            .rounds = node.rounds,
            .body = node.body,
            .input_name = node.input_name,
            .visibility = node.visibility,
        };
        break :blk try std.json.Stringify.valueAlloc(allocator, .{
            .version = @as(u32, 1),
            .nodes = selector_nodes,
            .assertions = assertions.items,
            .public_outputs = outputs.items,
        }, .{});
    } else blk: {
        const legacy_nodes = try allocator.alloc(LegacyNode, nodes.items.len);
        defer allocator.free(legacy_nodes);
        for (nodes.items, legacy_nodes) |node, *legacy| legacy.* = .{
            .tag = node.tag,
            .kind = node.kind,
            .length = node.length,
            .lhs = node.lhs,
            .rhs = node.rhs,
            .constant = node.constant,
            .rounds = node.rounds,
            .body = node.body,
            .input_name = node.input_name,
            .visibility = node.visibility,
        };
        break :blk try std.json.Stringify.valueAlloc(allocator, .{
            .version = @as(u32, 1),
            .nodes = legacy_nodes,
            .assertions = assertions.items,
            .public_outputs = outputs.items,
        }, .{});
    };
    defer allocator.free(encoded);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    const owned_nodes = try nodes.toOwnedSlice(allocator);
    errdefer allocator.free(owned_nodes);
    const owned_source = try source.toOwnedSlice(allocator);
    errdefer allocator.free(owned_source);
    const owned_assertions = try assertions.toOwnedSlice(allocator);
    errdefer allocator.free(owned_assertions);
    const owned_outputs = try outputs.toOwnedSlice(allocator);
    return .{
        .allocator = allocator,
        .nodes = owned_nodes,
        .source_map = owned_source,
        .assertions = owned_assertions,
        .public_outputs = owned_outputs,
        .sha256 = digest,
    };
}

fn simplify(node: *Node, nodes: []const Node) ?u32 {
    const lhs = if (node.lhs) |id| nodes[id] else null;
    const rhs = if (node.rhs) |id| nodes[id] else null;
    switch (node.tag) {
        .cast_m31 => {
            if (lhs.?.kind == .m31) return node.lhs;
        },
        .add => {
            if (lhs.?.tag == .constant and rhs.?.tag == .constant) {
                node.* = constantNode(node.length, M31.fromCanonical(lhs.?.constant.?).add(M31.fromCanonical(rhs.?.constant.?)).toU32());
            }
        },
        .mul => {
            if (lhs.?.tag == .constant and rhs.?.tag == .constant) {
                node.* = constantNode(node.length, M31.fromCanonical(lhs.?.constant.?).mul(M31.fromCanonical(rhs.?.constant.?)).toU32());
            }
        },
        .add_const => {
            if (node.constant.? == 0) return node.lhs;
            if (lhs.?.tag == .constant) node.* = constantNode(node.length, M31.fromCanonical(lhs.?.constant.?).add(M31.fromCanonical(node.constant.?)).toU32());
        },
        .mul_const => {
            if (node.constant.? == 1) return node.lhs;
            if (node.constant.? == 0) node.* = constantNode(node.length, 0) else if (lhs.?.tag == .constant)
                node.* = constantNode(node.length, M31.fromCanonical(lhs.?.constant.?).mul(M31.fromCanonical(node.constant.?)).toU32());
        },
        .repeat => {
            if (lhs.?.tag == .constant) {
                var value = M31.fromCanonical(lhs.?.constant.?);
                for (0..node.rounds.?) |_| for (node.body.?) |step| {
                    value = switch (step.op) {
                        .square => value.mul(value),
                        .add_const => value.add(M31.fromCanonical(step.constant.?)),
                        .mul_const => value.mul(M31.fromCanonical(step.constant.?)),
                        .mix4 => value.mul(M31.fromCanonical(5)),
                    };
                };
                node.* = constantNode(node.length, value.toU32());
            }
        },
        .sum_lanes => {
            if (lhs.?.length == 1) return node.lhs;
            if (lhs.?.tag == .constant) {
                const value = M31.fromCanonical(lhs.?.constant.?);
                node.* = constantNode(1, value.mul(M31.fromU64(lhs.?.length)).toU32());
            }
        },
        .is_zero => {
            if (lhs.?.tag == .constant) node.* = constantNode(1, @intFromBool(lhs.?.constant.? == 0));
        },
        else => {},
    }
    return null;
}

fn constantNode(length: u32, value: u32) Node {
    return .{ .tag = .constant, .kind = .m31, .length = length, .constant = value };
}

fn expressionKey(allocator: std.mem.Allocator, node: Node) ![]const u8 {
    const body_json = if (node.body) |body| try std.json.Stringify.valueAlloc(allocator, body, .{}) else "";
    return std.fmt.allocPrint(allocator, "{d}|{d}|{d}|{d}|{d}|{d}|{d}|{d}|{d}|{s}", .{
        @intFromEnum(node.tag),                    @intFromEnum(node.kind),              node.length,
        node.lhs orelse std.math.maxInt(u32),      node.rhs orelse std.math.maxInt(u32), node.constant orelse std.math.maxInt(u32),
        node.selector orelse std.math.maxInt(u32), node.rounds orelse 0,                 node.index orelse std.math.maxInt(u32),
        body_json,
    });
}

test "inverse extends the opcode roster without renumbering existing circuit tags" {
    try std.testing.expectEqual(@as(u8, 23), @intFromEnum(relation.Op.u32_lt));
    try std.testing.expectEqual(@as(u8, 24), @intFromEnum(Tag.u32_lt));
    try std.testing.expectEqual(@as(u8, 24), @intFromEnum(relation.Op.inv));
    try std.testing.expectEqual(@as(u8, 25), @intFromEnum(Tag.inv));
    try std.testing.expectEqual(@as(u8, 26), @intFromEnum(Tag.is_zero));
}

test "canonical graph folds constants and shares repeated expressions" {
    const source_text =
        \\{"version":1,"name":"optimizer","inputs":[{"name":"x","kind":"m31","length":4,"visibility":"public"}],"nodes":[{"name":"a","op":"constant","constant":7,"length":4},{"name":"b","op":"add_const","lhs":"a","constant":3},{"name":"c","op":"mul","lhs":"x","rhs":"b"},{"name":"d","op":"mul","lhs":"b","rhs":"x"}],"assertions":[{"lhs":"c","rhs":"d"}],"public_outputs":["c"]}
    ;
    var parsed = try relation.parseProgram(std.testing.allocator, source_text);
    defer parsed.deinit();
    var ir = try build(std.testing.allocator, parsed.value);
    defer ir.deinit();
    try std.testing.expectEqual(@as(usize, 4), ir.nodes.len);
    try std.testing.expectEqual(@as(u32, 10), ir.nodes[2].constant.?);
    try std.testing.expectEqual(ir.source_map[3].id, ir.source_map[4].id);
}

test "deep source chain canonicalizes without recursive shape lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain_len = 4096;
    const source_nodes = try allocator.alloc(relation.Node, chain_len);
    var previous: []const u8 = "x";
    for (source_nodes, 0..) |*node, index| {
        const name = try std.fmt.allocPrint(allocator, "step_{d}", .{index});
        node.* = .{ .name = name, .op = .add_const, .lhs = previous, .constant = 1 };
        previous = name;
    }
    var inputs = [_]relation.Input{.{ .name = "x", .kind = .m31, .length = 1, .visibility = .private }};
    var outputs = [_][]const u8{previous};
    const program: relation.Program = .{
        .version = 1,
        .name = "deep_chain",
        .inputs = &inputs,
        .nodes = source_nodes,
        .assertions = &.{},
        .public_outputs = &outputs,
    };
    const shape = (try program.shapeOf(std.testing.allocator, previous)) orelse return error.UnknownOutput;
    try std.testing.expectEqual(@as(usize, 1), shape.length);
    var ir = try build(std.testing.allocator, program);
    defer ir.deinit();
    try std.testing.expectEqual(@as(usize, chain_len + 1), ir.nodes.len);
    try std.testing.expectEqual(@as(u32, chain_len), ir.public_outputs[0].id);
}

test "legacy arithmetic canonical digest remains stable after select extension" {
    var parsed = try relation.parseProgram(std.testing.allocator, @embedFile("examples/arith4.s31.json"));
    defer parsed.deinit();
    var ir = try build(std.testing.allocator, parsed.value);
    defer ir.deinit();
    const actual = std.fmt.bytesToHex(ir.sha256, .lower);
    try std.testing.expectEqualStrings("afdd4467b3e476e55b583f0f570d0ecbf71687fb4bdf6d3935b1d130ce57cfad", &actual);
}
