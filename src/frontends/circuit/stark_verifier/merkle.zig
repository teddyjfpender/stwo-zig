//! In-circuit Merkle decommitment: port of
//! `crates/stark_verifier/src/merkle.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! Trees are committed with the plain Blake2s Merkle hasher over full
//! 32-bit words: leaves hash their M31 values (or QM31 values for FRI) as
//! words, nodes hash `left || right`, and the recomputed root is compared
//! word for word with the root the channel absorbed.

const std = @import("std");
const builder = @import("../builder/mod.zig");
const proof_mod = @import("proof.zig");
const sort_queries = @import("sort_queries.zig");

const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const blake = builder.blake;
const HashValue = blake.HashValue;
const U32Wrapper = builder.wrappers.U32Wrapper;
const M31Wrapper = builder.wrappers.M31Wrapper;

/// `PACKED_LEAF_SIZE` of stwo's lifted Merkle verifier: FRI layers hash four
/// QM31 values per leaf.
pub const LOG_PACKED_LEAF_SIZE: usize = 2;
pub const PACKED_LEAF_SIZE: usize = 1 << LOG_PACKED_LEAF_SIZE;

/// `hash_leaf_m31s`: each M31 becomes one message word.
fn hashLeafM31s(comptime V: type, ctx: *Context(V), values: []const M31Wrapper(Var)) Error!HashValue(Var) {
    const words = try ctx.scratch().alloc(U32Wrapper(Var), values.len);
    for (words, values) |*word, value| word.* = try blake.m31ToU32(V, ctx, value.get());
    return blake.blake2sU32s(V, ctx, words, 4 * values.len);
}

/// `hash_leaf_qm31`: a leaf of one QM31.
pub fn hashLeafQm31(comptime V: type, ctx: *Context(V), value: Var) Error!HashValue(Var) {
    return blake.blake2s(V, ctx, &.{value}, 16);
}

/// `hash_packed_leaf_qm31s`: a leaf of `PACKED_LEAF_SIZE` QM31s.
pub fn hashPackedLeafQm31s(comptime V: type, ctx: *Context(V), values: *const [PACKED_LEAF_SIZE]Var) Error!HashValue(Var) {
    return blake.blake2s(V, ctx, values, 16 * PACKED_LEAF_SIZE);
}

/// `hash_node`: Blake2s of `left || right`, whose words are already message
/// words.
pub fn hashNode(comptime V: type, ctx: *Context(V), left: HashValue(Var), right: HashValue(Var)) Error!HashValue(Var) {
    var words: [16]U32Wrapper(Var) = undefined;
    @memcpy(words[0..8], &left.words);
    @memcpy(words[8..], &right.words);
    return blake.blake2sU32s(V, ctx, &words, 64);
}

/// `merkle_node`: the parent of `node` and `sibling`, where `bit` is 1 when
/// `node` is the right child.
pub fn merkleNode(comptime V: type, ctx: *Context(V), node: HashValue(Var), sibling: HashValue(Var), bit: Var) Error!HashValue(Var) {
    var left: HashValue(Var) = undefined;
    var right: HashValue(Var) = undefined;
    for (node.words, sibling.words, &left.words, &right.words) |a, b, *l, *r| {
        const flipped = try builder.ops.condFlipU32(V, ctx, bit, a, b);
        l.* = flipped[0];
        r.* = flipped[1];
    }
    return hashNode(V, ctx, left, right);
}

/// `verify_merkle_path`: recomputes the root from `leaf` along `auth_path`
/// (`auth_path[0]` is the leaf's sibling) and requires it equal to `root`.
pub fn verifyMerklePath(
    comptime V: type,
    ctx: *Context(V),
    leaf: HashValue(Var),
    bits: []const Var,
    root: HashValue(Var),
    auth_path: []const HashValue(Var),
) Error!void {
    std.debug.assert(bits.len == auth_path.len);
    var node = leaf;
    for (bits, auth_path) |bit, sibling| node = try merkleNode(V, ctx, node, sibling, bit);
    for (node.words, root.words) |recomputed, expected| try ctx.eq(recomputed.get(), expected.get());
}

/// `decommit_eval_domain_samples`: every query's values of every tree
/// against the tree's root. `column_log_sizes_by_trace[t]`, when non-null,
/// sorts tree `t`'s query columns into committed order first.
/// `bits[i][q]` is bit `i` of query `q`.
pub fn decommitEvalDomainSamples(
    comptime V: type,
    ctx: *Context(V),
    n_queries: usize,
    column_log_sizes_by_trace: [proof_mod.N_TRACES]?[]const Var,
    samples: *const proof_mod.EvalDomainSamples(Var),
    auth_paths: *const proof_mod.AuthPaths(Var),
    bits: []const []const Var,
    roots: [proof_mod.N_TRACES]HashValue(Var),
) Error!void {
    const bits_for_query = try ctx.scratch().alloc(Var, bits.len);
    for (roots, 0..) |root, trace_idx| {
        var sorter = if (column_log_sizes_by_trace[trace_idx]) |log_sizes|
            try sort_queries.QuerySorter.init(V, ctx, log_sizes)
        else
            sort_queries.QuerySorter.skipSorting();
        const n_columns = samples.nColumns(trace_idx);
        const query_values = try ctx.scratch().alloc(M31Wrapper(Var), n_columns);
        for (0..n_queries) |query_idx| {
            for (query_values, 0..) |*value, column_idx| value.* = samples.at(trace_idx, column_idx, query_idx);
            const sorted = try sorter.sort(V, ctx, query_values);
            const leaf = try hashLeafM31s(V, ctx, sorted);
            for (bits_for_query, bits) |*bit, query_bits| bit.* = query_bits[query_idx];
            try verifyMerklePath(V, ctx, leaf, bits_for_query, root, auth_paths.at(trace_idx, query_idx));
        }
    }
}
