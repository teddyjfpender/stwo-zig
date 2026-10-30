//! Pure chain/registry metadata for the next reduction layer. This module
//! authenticates no proof. A digest or successful closure is NEVER permission
//! to publish a block: every exact leaf key and public input must first be
//! authenticated by the recursive verifier. Current leaves are nonterminal.
const std = @import("std");
const core = @import("stwo_core");
const Channel = core.proof_suites.Blake3.Channel;
pub const Digest = [32]u8;
pub const VERSION: u32 = 1;
pub const publication_qualified = false;

pub const Span = struct {
    elf: Digest,
    program: Digest,
    incoming: Digest,
    outgoing: Digest,
    begin: u64,
    end: u64,
    leaves: u32,
    pub fn validate(self: Span) !void {
        if (self.begin >= self.end or self.leaves == 0 or zero(self.elf) or zero(self.program) or
            zero(self.incoming) or zero(self.outgoing)) return error.InvalidWindowChainSpan;
    }
    pub fn join(left: Span, right: Span) !Span {
        try left.validate();
        try right.validate();
        if (!same(left.elf, right.elf) or !same(left.program, right.program)) return error.WindowChainProgramMismatch;
        if (left.end != right.begin) return error.NoncontiguousWindowChain;
        // Snapshot identities include ALL CPU registers, PC, and complete
        // sorted memory. Equal CPU endpoints alone do not close RAM.
        if (!same(left.outgoing, right.incoming)) return error.WindowChainStateMismatch;
        return .{ .elf = left.elf, .program = left.program, .incoming = left.incoming, .outgoing = right.outgoing, .begin = left.begin, .end = right.end, .leaves = try std.math.add(u32, left.leaves, right.leaves) };
    }
    pub fn mix(self: Span, ch: *Channel) void {
        ch.mixRoot(self.elf);
        ch.mixRoot(self.program);
        ch.mixRoot(self.incoming);
        ch.mixRoot(self.outgoing);
        ch.mixU64(self.begin);
        ch.mixU64(self.end);
        ch.mixU32s(&.{self.leaves});
    }
};

/// Descriptor only. `key` MUST be independently derived from admitted public
/// metadata and claims, never selected by the child envelope. The recursive
/// reduction must prove that child verification used this exact key/public ID.
pub const Leaf = struct {
    key: Digest,
    public_input: Digest,
    profile: Digest,
    epoch: Digest,
    policy: Digest,
    span: Span,
    pub fn validate(self: Leaf) !void {
        try self.span.validate();
        if (self.span.leaves != 1 or zero(self.key) or zero(self.public_input) or zero(self.profile) or
            zero(self.epoch) or zero(self.policy)) return error.InvalidWindowChainLeaf;
    }
    pub fn digest(self: Leaf, ordinal: u32) !Digest {
        try self.validate();
        var ch = Channel{};
        ch.mixU32s(&.{ 0x4238434c, VERSION, ordinal });
        ch.mixRoot(self.key);
        ch.mixRoot(self.public_input);
        ch.mixRoot(self.profile);
        ch.mixRoot(self.epoch);
        ch.mixRoot(self.policy);
        self.span.mix(&ch);
        return ch.digestBytes();
    }
};

/// Expected roster derives from caller-owned verifier policy, not proof bytes.
/// Padding exists ONLY inside the Merkle commitment: there are exactly count
/// real proof leaves and no dummy proof jobs or power-of-two proof rounding.
pub const Registry = struct {
    a: std.mem.Allocator,
    tree: []Digest,
    padded: usize,
    count: u32,
    span: Span,
    root: Digest,
    pub fn derive(a: std.mem.Allocator, leaves: []const Leaf, max_leaves: u32) !Registry {
        if (leaves.len == 0 or leaves.len > max_leaves or max_leaves > 1 << 20) return error.WindowChainResourceLimit;
        const padded = try std.math.ceilPowerOfTwo(usize, leaves.len);
        const tree = try a.alloc(Digest, try std.math.mul(usize, padded, 2));
        errdefer a.free(tree);
        var span = leaves[0].span;
        for (leaves, 0..) |leaf, index| {
            tree[padded + index] = try leaf.digest(@intCast(index));
            if (index != 0) span = try Span.join(span, leaf.span);
        }
        const count: u32 = @intCast(leaves.len);
        for (leaves.len..padded) |index| tree[padded + index] = padding(count, @intCast(index));
        var index = padded;
        while (index > 1) {
            index -= 1;
            tree[index] = node(tree[2 * index], tree[2 * index + 1]);
        }
        return .{ .a = a, .tree = tree, .padded = padded, .count = count, .span = span, .root = bind(tree[1], count, span) };
    }
    pub fn deinit(self: *Registry) void {
        self.a.free(self.tree);
        self.* = undefined;
    }
    pub fn path(self: Registry, a: std.mem.Allocator, ordinal: u32) ![]Digest {
        if (ordinal >= self.count) return error.InvalidWindowChainIndex;
        const levels = std.math.log2_int(usize, self.padded);
        const result = try a.alloc(Digest, levels);
        var index = self.padded + ordinal;
        for (result) |*item| {
            item.* = self.tree[index ^ 1];
            index >>= 1;
        }
        return result;
    }
};

pub fn requireMembership(expected: Digest, count: u32, span: Span, ordinal: u32, leaf: Leaf, path: []const Digest) !void {
    try span.validate();
    if (count == 0 or count > 1 << 20 or count != span.leaves or ordinal >= count) return error.InvalidWindowChainIndex;
    const padded = try std.math.ceilPowerOfTwo(u32, count);
    if (path.len != std.math.log2_int(u32, padded)) return error.InvalidWindowChainPath;
    var digest = try leaf.digest(ordinal);
    var index = ordinal;
    for (path) |sibling| {
        digest = if (index & 1 == 0) node(digest, sibling) else node(sibling, digest);
        index >>= 1;
    }
    if (!same(bind(digest, count, span), expected)) return error.UntrustedWindowChainRegistry;
}
fn node(left: Digest, right: Digest) Digest {
    var ch = Channel{};
    ch.mixU32s(&.{ 0x4238434e, VERSION });
    ch.mixRoot(left);
    ch.mixRoot(right);
    return ch.digestBytes();
}
fn padding(count: u32, ordinal: u32) Digest {
    var ch = Channel{};
    ch.mixU32s(&.{ 0x42384350, VERSION, count, ordinal });
    return ch.digestBytes();
}
fn bind(root: Digest, count: u32, span: Span) Digest {
    var ch = Channel{};
    ch.mixU32s(&.{ 0x42384352, VERSION, count });
    ch.mixRoot(root);
    span.mix(&ch);
    return ch.digestBytes();
}
fn same(a: Digest, b: Digest) bool {
    return std.meta.eql(a, b);
}
fn zero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}
