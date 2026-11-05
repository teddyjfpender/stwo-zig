//! Dedicated-Poseidon commitment gadget; nine M31 wires per digest.
const S = @import("sponge.zig");
pub const Hash = S.Hash;
pub fn ForContext(comptime Context: type) type {
    return struct {
        const Sponge = S.ForContext(Context);
        pub fn leaf(ctx: *Context, values: []const S.Var) !Hash {
            var s = try Sponge.init(ctx, .leaf);
            try s.absorbMany(values);
            return s.finish();
        }
        pub fn children(ctx: *Context, left: Hash, right: Hash) !Hash {
            var s = try Sponge.init(ctx, .node);
            try s.absorbMany(&left);
            try s.absorbMany(&right);
            return s.finish();
        }
        /// Directions are little-endian node indices; each is constrained bit.
        pub fn verifyPath(ctx: *Context, value: Hash, directions: []const S.Var, siblings: []const Hash, expected: Hash) !void {
            if (directions.len != siblings.len or directions.len > 30) return error.InvalidPoseidonMerklePath;
            const a = ctx.algebra();
            var current = value;
            for (directions, siblings) |direction, sibling| {
                const square = try a.mul(direction, direction);
                try a.eq(square, direction);
                var left: Hash = undefined;
                var right: Hash = undefined;
                for (&left, &right, current, sibling) |*l, *r, x, y| {
                    const delta = try a.mul(direction, try a.sub(y, x));
                    l.* = try a.add(x, delta);
                    r.* = try a.sub(y, delta);
                }
                current = try children(ctx, left, right);
            }
            for (current, expected) |actual, wanted| try a.eq(actual, wanted);
        }
    };
}
