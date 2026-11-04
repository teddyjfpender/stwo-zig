//! Canonicity of transmitted field elements (verifier precondition).
//!
//! Every M31 limb the verifier receives must be in [0, P). The field kernels
//! assume canonical inputs: M31.sub computes (a + P) - b and wraps by
//! 2^32 = 2 (mod P) when b >= P, and QM31.mul's base-field shortcut assumes
//! canonical lanes, while the transcript hashes raw limbs. A non-canonical
//! encoding is therefore a *different* transcript value that the arithmetic
//! interprets inconsistently, which lets a prover shift a sumcheck claim
//! (review finding KERN-1). Values that are not Merkle-bound (round
//! polynomials, finals, claimed MLE values, GKR masks) are not caught by any
//! other check, so every verifier entry point runs `check` on the whole proof
//! object before touching it.
//!
//! `check` is a comptime-reflective walker: it descends through structs,
//! tagged unions, optionals, arrays and slices, and checks every `M31` it
//! reaches (QM31 / CM31 decompose into M31 limbs). Subtrees whose type holds
//! no M31 are pruned at compile time, so hashes, nonces and indices cost
//! nothing. New proof fields are covered automatically.
const std = @import("std");
const f = @import("field.zig");

const M31 = f.M31;

pub const Error = error{NonCanonical};

/// Does a value of type T (transitively) contain an M31?
fn holdsField(comptime T: type) bool {
    return comptime holdsFieldDepth(T, 0);
}

fn holdsFieldDepth(comptime T: type, comptime depth: u32) bool {
    if (T == M31) return true;
    if (depth > 24) @compileError("canonical: proof type nesting too deep: " ++ @typeName(T));
    return switch (@typeInfo(T)) {
        .@"struct" => |s| blk: {
            for (s.fields) |fl| {
                if (fl.is_comptime) continue;
                if (holdsFieldDepth(fl.type, depth + 1)) break :blk true;
            }
            break :blk false;
        },
        .@"union" => |u| blk: {
            for (u.fields) |fl| if (holdsFieldDepth(fl.type, depth + 1)) break :blk true;
            break :blk false;
        },
        .optional => |o| holdsFieldDepth(o.child, depth + 1),
        .array => |ar| holdsFieldDepth(ar.child, depth + 1),
        .pointer => |p| switch (p.size) {
            .slice, .one => if (p.child == anyopaque) false else holdsFieldDepth(p.child, depth + 1),
            else => false,
        },
        else => false,
    };
}

/// Visitor over every M31 in `value`; `visitor.m31(*const M31) !void`.
fn walk(value: anytype, visitor: anytype) !void {
    const T = @TypeOf(value);
    if (comptime !holdsField(T)) return;
    if (T == M31) return visitor.m31(value);
    switch (@typeInfo(T)) {
        .@"struct" => |s| inline for (s.fields) |fl| {
            if (fl.is_comptime) continue;
            if (comptime holdsField(fl.type)) try walk(@field(value, fl.name), visitor);
        },
        .@"union" => |u| {
            if (u.tag_type == null) @compileError("canonical: untagged union in a proof type: " ++ @typeName(T));
            switch (value) {
                inline else => |payload| try walk(payload, visitor),
            }
        },
        .optional => if (value) |v| try walk(v, visitor),
        .array => for (value) |v| try walk(v, visitor),
        .pointer => |p| switch (p.size) {
            .slice => for (value) |v| try walk(v, visitor),
            .one => try walk(value.*, visitor),
            else => unreachable,
        },
        else => unreachable,
    }
}

const Checker = struct {
    fn m31(_: Checker, x: M31) Error!void {
        if (x.v >= f.P) return error.NonCanonical;
    }
};

/// Reject any proof object that carries a non-canonical M31 limb (>= P).
/// Accepts any proof type (by value or pointer).
pub fn check(proof: anytype) Error!void {
    return walk(proof, Checker{});
}

/// Number of M31 limbs `check` inspects in `proof` (tests, size audits).
pub fn countLimbs(proof: anytype) usize {
    const Counter = struct {
        n: *usize,
        fn m31(self: @This(), _: M31) error{}!void {
            self.n.* += 1;
        }
    };
    var n: usize = 0;
    walk(proof, Counter{ .n = &n }) catch unreachable;
    return n;
}

/// Test helper: pointer to the n-th limb `check` inspects (walk order).
/// The proof's slices are mutated through @constCast; tests only.
pub fn nthLimb(proof: anytype, n: usize) ?*u32 {
    const Nth = struct {
        want: usize,
        seen: usize = 0,
        out: ?*u32 = null,
        fn limb(self: *@This(), comptime _: []const u8, p: *u32) void {
            if (self.seen == self.want) self.out = p;
            self.seen += 1;
        }
    };
    var v = Nth{ .want = n };
    forEachLimb(proof, &v);
    return v.out;
}

/// Test helper: calls `visitor.limb(comptime path, *u32)` for every limb
/// `check` inspects, in walk order. `path` names the field class, e.g.
/// ".op_sumchecks[].rounds[].evals[].c0.a" (slice / array indices elided).
pub fn forEachLimb(proof: anytype, visitor: anytype) void {
    walkPtr(proof, "", visitor);
}

fn walkPtr(ptr: anytype, comptime path: []const u8, visitor: anytype) void {
    const T = @typeInfo(@TypeOf(ptr)).pointer.child;
    if (comptime !holdsField(T)) return;
    if (T == M31) return visitor.limb(path, @constCast(&ptr.v));
    switch (@typeInfo(T)) {
        .@"struct" => |s| inline for (s.fields) |fl| {
            if (fl.is_comptime) continue;
            if (comptime holdsField(fl.type)) walkPtr(&@field(ptr.*, fl.name), path ++ "." ++ fl.name, visitor);
        },
        .@"union" => switch (ptr.*) {
            inline else => |*payload, tag| walkPtr(payload, path ++ "<" ++ @tagName(tag) ++ ">", visitor),
        },
        .optional => if (ptr.*) |*v| walkPtr(v, path ++ "?", visitor),
        .array => for (ptr) |*v| walkPtr(v, path ++ "[]", visitor),
        .pointer => |p| switch (p.size) {
            .slice => for (ptr.*) |*v| walkPtr(v, path ++ "[]", visitor),
            .one => walkPtr(ptr.*, path, visitor),
            else => unreachable,
        },
        else => unreachable,
    }
}

test "canonical: walker sees every limb of nested slices, optionals and unions" {
    const U = union(enum) { a: []f.QM31, b: u64 };
    const S = struct { x: f.QM31, xs: [][2]f.QM31, o: ?f.QM31, u: U, h: [32]u8, n: u64 };
    var xs = [_][2]f.QM31{.{ f.QM31.one(), f.QM31.zero() }};
    var ys = [_]f.QM31{f.QM31.one()};
    var s = S{ .x = f.QM31.one(), .xs = &xs, .o = f.QM31.zero(), .u = .{ .a = &ys }, .h = undefined, .n = 7 };
    try std.testing.expectEqual(@as(usize, 4 + 8 + 4 + 4), countLimbs(&s));
    try check(&s);
    for (0..countLimbs(&s)) |i| {
        const p = nthLimb(&s, i).?;
        const old = p.*;
        p.* = old + f.P;
        try std.testing.expectError(error.NonCanonical, check(&s));
        p.* = f.P;
        try std.testing.expectError(error.NonCanonical, check(&s));
        p.* = old;
        try check(&s);
    }
    try std.testing.expect(nthLimb(&s, countLimbs(&s)) == null);
}
