//! Ethereum-only authenticated binary paths. This proves digest membership;
//! the VM profile must separately bind its leaf encoding and memory/program use.
const std = @import("std");
const core = @import("stwo_core");
const node = @import("ethereum_node_v1.zig");
const M31 = core.fields.m31.M31;
pub const PREPROCESSED_COLUMNS: usize = 10;
pub const N_CONSTRAINTS: usize = node.N_CONSTRAINTS + 6 + 2 * node.DIGEST_WORDS;
pub const STATEMENT_BYTES: usize = 8 + 8 * node.DIGEST_WORDS;

pub const Statement = struct {
    kind: node.Kind,
    depth: u32,
    index: u32,
    leaf: node.Digest,
    root: node.Digest,

    pub fn validate(self: Statement) !void {
        if (self.depth == 0 or self.depth > 30 or self.index >= (@as(u32, 1) << @intCast(self.depth)))
            return error.InvalidPathPosition;
        for (self.leaf ++ self.root) |word|
            if (word >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
    }

    pub fn encode(self: Statement) ![STATEMENT_BYTES]u8 {
        try self.validate();
        var bytes = [_]u8{0} ** STATEMENT_BYTES;
        bytes[0] = 1;
        bytes[1] = @intFromEnum(self.kind);
        bytes[2] = @intCast(self.depth);
        std.mem.writeInt(u32, bytes[4..8], self.index, .little);
        for (self.leaf ++ self.root, 0..) |word, index|
            std.mem.writeInt(u32, bytes[8 + 4 * index ..][0..4], word, .little);
        return bytes;
    }

    pub fn decode(bytes: *const [STATEMENT_BYTES]u8) !Statement {
        if (bytes[0] != 1 or bytes[1] > 1 or bytes[3] != 0) return error.InvalidPathEncoding;
        var digests: [2 * node.DIGEST_WORDS]u32 = undefined;
        for (&digests, 0..) |*word, index|
            word.* = std.mem.readInt(u32, bytes[8 + 4 * index ..][0..4], .little);
        const result = Statement{
            .kind = @enumFromInt(bytes[1]),
            .depth = bytes[2],
            .index = std.mem.readInt(u32, bytes[4..8], .little),
            .leaf = digests[0..node.DIGEST_WORDS].*,
            .root = digests[node.DIGEST_WORDS..].*,
        };
        try result.validate();
        return result;
    }

    /// First, active, last, direction, kind, five height bits.
    /// The verifier reconstructs these columns from the public statement.
    pub fn preprocessedAt(self: Statement, logical: usize) [PREPROCESSED_COLUMNS]M31 {
        var values = [_]M31{M31.zero()} ** PREPROCESSED_COLUMNS;
        values[0] = M31.fromCanonical(@intFromBool(logical == 0));
        if (logical >= self.depth) return values;
        values[1] = M31.one();
        values[2] = M31.fromCanonical(@intFromBool(logical + 1 == self.depth));
        values[3] = M31.fromCanonical((self.index >> @intCast(logical)) & 1);
        values[4] = M31.fromCanonical(@intFromEnum(self.kind));
        for (0..5) |bit| values[5 + bit] = M31.fromCanonical(@intCast((logical >> @intCast(bit)) & 1));
        return values;
    }
};

pub fn buildInto(rows: []node.Row(M31), kind: node.Kind, index: u32, leaf: node.Digest, siblings: []const node.Digest) !Statement {
    if (rows.len != siblings.len or rows.len == 0 or rows.len > 30) return error.InvalidPathPosition;
    var statement = Statement{ .kind = kind, .depth = @intCast(rows.len), .index = index, .leaf = leaf, .root = leaf };
    try statement.validate();
    var current = leaf;
    for (rows, siblings, 0..) |*row, sibling, height| {
        const right = ((index >> @intCast(height)) & 1) != 0;
        row.* = try node.build(kind, @intCast(height), if (right) sibling else current, if (right) current else sibling);
        for (&current, row.digest) |*word, value| word.* = value.toU32();
    }
    statement.root = current;
    return statement;
}

pub fn evaluate(comptime F: type, statement: Statement, row: node.Row(F), previous_digest: [node.DIGEST_WORDS]F, pp: [PREPROCESSED_COLUMNS]F, sums: [node.N_SUMS]F, previous: [node.N_SUMS]F, claims: [node.N_SUMS]F, relations: anytype) [N_CONSTRAINTS]F {
    var result: [N_CONSTRAINTS]F = undefined;
    @memcpy(result[0..node.N_CONSTRAINTS], &node.evaluateCallerGeneric(F, row, pp[1], pp[0], sums, previous, claims, relations));
    var at: usize = node.N_CONSTRAINTS;
    result[at] = pp[1].mul(row.kind.sub(pp[4]));
    at += 1;
    for (row.height_bits, pp[5..10]) |actual, expected| {
        result[at] = pp[1].mul(actual.sub(expected));
        at += 1;
    }
    for (row.left, row.right, previous_digest, statement.leaf, row.digest, statement.root) |left, right, prior, leaf, digest, root| {
        const selected = left.add(pp[3].mul(right.sub(left)));
        const expected = prior.add(pp[0].mul(F.fromBase(M31.fromCanonical(leaf)).sub(prior)));
        result[at] = pp[1].mul(selected.sub(expected));
        result[at + 1] = pp[2].mul(digest.sub(F.fromBase(M31.fromCanonical(root))));
        at += 2;
    }
    std.debug.assert(at == N_CONSTRAINTS);
    return result;
}

test "Ethereum node V1 path position and canonical statement are checked" {
    var rows: [3]node.Row(M31) = undefined;
    const statement = try buildInto(&rows, .memory, 5, .{7} ** node.DIGEST_WORDS, &.{ .{1} ** node.DIGEST_WORDS, .{2} ** node.DIGEST_WORDS, .{3} ** node.DIGEST_WORDS });
    try std.testing.expectEqualDeep(statement, try Statement.decode(&try statement.encode()));
    try std.testing.expect(pathLinksHold(statement, &rows));
    for (0..node.DIGEST_WORDS) |lane| {
        var changed = statement;
        changed.root[lane] = (changed.root[lane] + 1) % core.fields.m31.Modulus;
        try std.testing.expect(!pathLinksHold(changed, &rows));
        changed = statement;
        changed.leaf[lane] += 1;
        try std.testing.expect(!pathLinksHold(changed, &rows));
    }
    var changed = statement;
    changed.index ^= 1;
    try std.testing.expect(!pathLinksHold(changed, &rows));
    changed = statement;
    changed.kind = .program;
    try std.testing.expect(!pathLinksHold(changed, &rows));
    try std.testing.expectError(error.InvalidPathPosition, buildInto(&rows, .memory, 8, statement.leaf, &.{ statement.leaf, statement.leaf, statement.leaf }));
    var bytes = try statement.encode();
    bytes[3] = 1;
    try std.testing.expectError(error.InvalidPathEncoding, Statement.decode(&bytes));
}

fn pathLinksHold(statement: Statement, rows: []const node.Row(M31)) bool {
    const F = core.fields.qm31.QM31;
    const relations = @import("../relation_challenges.zig").Relations.dummy();
    for (rows, 0..) |row, index| {
        var pp: [PREPROCESSED_COLUMNS]F = undefined;
        for (&pp, statement.preprocessedAt(index)) |*word, value| word.* = F.fromBase(value);
        var previous = [_]F{F.zero()} ** node.DIGEST_WORDS;
        if (index != 0) for (&previous, rows[index - 1].digest) |*word, value| {
            word.* = F.fromBase(value);
        };
        const zero = [_]F{F.zero()} ** node.N_SUMS;
        const constraints = evaluate(F, statement, node.liftRow(F, row), previous, pp, zero, zero, zero, &relations);
        for (constraints[node.N_CONSTRAINTS..]) |constraint| if (!constraint.isZero()) return false;
    }
    return true;
}
