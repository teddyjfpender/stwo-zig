//! Versioned expression identity independent of allocation and insertion order.
//! Callers must separately bind ordered roots, input roles, geometry and lookup
//! contracts. This module alone is not a complete component/protocol identity.
const std = @import("std");
const symbolic = @import("symbolic.zig");
const modulus = @import("stwo_core").fields.m31.Modulus;

pub const FORMAT_VERSION: u32 = 1;
pub const Digest = [32]u8;
pub const Error = std.mem.Allocator.Error || error{InvalidCanonicalExpression};

/// Hash child content rather than arena indices. Unused expressions and a
/// different topological insertion order cannot change a reachable root.
/// Operand order remains significant; no algebraic equivalence is asserted.
pub fn expressions(allocator: std.mem.Allocator, nodes: []const symbolic.Node, input_count: usize) Error![]Digest {
    return expressionDigests(false, allocator, nodes, input_count);
}

/// Typed IR interns commutative operands by arena ID. This separate identity
/// compares those programs independently of allocation order, allowing only
/// addition/multiplication operand swaps. Existing protocol identities retain
/// the ordered `expressions` representation and its original domain.
pub fn commutativeExpressions(allocator: std.mem.Allocator, nodes: []const symbolic.Node, input_count: usize) Error![]Digest {
    return expressionDigests(true, allocator, nodes, input_count);
}

fn expressionDigests(comptime commutative: bool, allocator: std.mem.Allocator, nodes: []const symbolic.Node, input_count: usize) Error![]Digest {
    const result = try allocator.alloc(Digest, nodes.len);
    errdefer allocator.free(result);
    for (nodes, 0..) |node, index| {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(if (commutative) "stwo-zig/air-expression-commutative/v1\x00" else "stwo-zig/air-expression/v1\x00");
        switch (node.op) {
            .constant => {
                if (node.value >= modulus or node.lhs != 0 or node.rhs != 0) return error.InvalidCanonicalExpression;
                hash.update("constant\x00");
                word(&hash, node.value);
            },
            .column => {
                if (node.value >= input_count or node.lhs != 0 or node.rhs != 0) return error.InvalidCanonicalExpression;
                hash.update("input\x00");
                word(&hash, node.value);
            },
            .neg => {
                if (node.lhs >= index or node.rhs != 0 or node.value != 0) return error.InvalidCanonicalExpression;
                hash.update("neg\x00");
                hash.update(&result[node.lhs]);
            },
            .add, .sub, .mul => {
                if (node.lhs >= index or node.rhs >= index or node.value != 0) return error.InvalidCanonicalExpression;
                hash.update(@tagName(node.op));
                hash.update("\x00");
                var lhs = result[node.lhs];
                var rhs = result[node.rhs];
                if (commutative and node.op != .sub and std.mem.order(u8, &rhs, &lhs) == .lt)
                    std.mem.swap(Digest, &lhs, &rhs);
                hash.update(&lhs);
                hash.update(&rhs);
            },
        }
        result[index] = hash.finalResult();
    }
    return result;
}

fn word(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}
