//! One independently pinned mixed-verifier proof plus the complete original
//! block equations. No base proof loader or producer checkpoint is accepted.
//! Qualification requires an independent key factory and assembled real-job
//! tests; this implementation alone does not qualify Ethereum block proving.
const std = @import("std");
const Bus = @import("../recursion/block_v6_mixed_direct_public_v1.zig");
const Protocol = @import("../recursion/block_v6_mixed_direct_protocol_v1.zig");
const Receiver = @import("../recursion/block_v6_mixed_direct_receiver_v1.zig");
const Global = @import("block_v5_global_receiver_v1.zig");
const Closure = @import("block_v6_global_public_closure_v1.zig");
const Pages = @import("block_v5_memory_source_unified_page_proof_v1.zig");
pub const Policy = struct {
    /// Independent registry/setup authority, never learned from proof bytes.
    key: Protocol.Key,
    expected_key: [32]u8,
    wires: []const Bus.Wire,
    roster: []const Bus.Expected,
    globals: Global.Pins,
    source: *const Pages.Context,
    /// Caller request bytes, checked against independently admitted source pins.
    /// Required even for an empty input; an absent binding is not an option.
    expected_public_input: []const u8,
};
pub const Limits = struct {
    max_proof_bytes: usize = 128 << 20,
    max_receiver_bytes: usize = 4 << 30,
    closure: Closure.Limits = .{},
};
pub const Verified = struct {
    algebra: Closure.AlgebraResult,
    key_id: [32]u8,
    proof_sha256: [32]u8,
};

/// Structured public claims are projected onto the exact authenticated mixed
/// bus here, rather than accepting a second unrelated set of closure operands.
pub fn verify(backing: std.mem.Allocator, proof: []const u8, policy: Policy, input: Closure.Input, limits: Limits) !Verified {
    if (proof.len == 0 or proof.len > limits.max_proof_bytes or limits.max_receiver_bytes == 0) return error.CompleteRootResourceLimit;
    const config = policy.globals.tables.seal.config;
    if (!std.meta.eql(policy.key.config, config) or !std.meta.eql(policy.key.context.child_config, config) or !std.meta.eql(policy.source.fold_plan.config, config)) return error.CompleteRootSecurityMismatch;
    const initial = policy.source.admitted.source.pins.initial;
    try @import("block_v5_memory_source_page_transition_admission_v1.zig").requirePublicInput(initial.public_input_len, initial.public_input_sha256, policy.expected_public_input);
    // The expected key and its original typed roster are supplied out of band.
    // This check must precede any claim-driven verifier allocation.
    if (!std.meta.eql(try policy.key.identity(), policy.expected_key) or !std.meta.eql(try Bus.rosterDigest(policy.roster), policy.key.roster_digest)) return error.UntrustedCompleteRootKey;
    _ = try policy.globals.validate();
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_receiver_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    const children = try publicChildren(a, input);
    defer a.free(children);
    const values = Bus.Values{ .children = children };
    try values.requireRoster(policy.roster);
    {
        // Release decoded proof/capture storage before source/global algebra.
        var authenticated = try Receiver.verify(a, proof, policy.key, policy.expected_key, policy.wires, policy.roster, values);
        defer authenticated.deinit();
    }
    const algebra = try Closure.close(a, policy.globals, policy.source, input, limits.closure);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(proof, &digest, .{});
    return .{ .algebra = algebra, .key_id = policy.expected_key, .proof_sha256 = digest };
}

/// Borrowed child views: this array owns no underlying public claim storage.
/// Canonical family/index order has no padding or repeated source child.
pub fn publicChildren(a: std.mem.Allocator, input: Closure.Input) ![]Bus.Child {
    var count: usize = 1; // exactly one complete ROM provider
    for ([_]usize{ input.executions.len, input.source.ranges.len, input.source.lanes.len, input.lookup.len, input.callers.len, input.callers.len, input.source.raw.len, input.source.fold.len }) |n| count = try std.math.add(usize, count, n);
    if (input.executions.len == 0 or count > Bus.MAX_CHILDREN) return error.CompleteRootRosterLimit;
    const result = try a.alloc(Bus.Child, count);
    errdefer a.free(result);
    var at: usize = 0;
    for (input.executions) |execution| {
        result[at] = .{ .native = .{ .index = execution.admitted.native.index, .value = execution.public } };
        at += 1;
    }
    for (input.source.ranges) |value| {
        result[at] = .{ .provider = .{ .range16 = value } };
        at += 1;
    }
    for (input.source.lanes) |value| {
        result[at] = .{ .provider = .{ .ram_lanes = value } };
        at += 1;
    }
    result[at] = .{ .provider = .{ .program_table = input.program } };
    at += 1;
    for (input.lookup) |value| {
        result[at] = .{ .provider = .{ .native_lookup = value } };
        at += 1;
    }
    for (input.callers) |caller| {
        result[at] = .{ .auxiliary = .{ .index = caller.arithmetic.binding.execution_index, .value = .{ .caller_arithmetic = caller.arithmetic } } };
        at += 1;
    }
    for (input.callers) |caller| {
        result[at] = .{ .auxiliary = .{ .index = caller.arithmetic.binding.execution_index, .value = .{ .caller_fused = caller.fused } } };
        at += 1;
    }
    for (input.source.raw, 0..) |page, i| {
        result[at] = .{ .auxiliary = .{ .index = @intCast(i), .value = .{ .source_raw = page.public } } };
        at += 1;
    }
    for (input.source.fold, 0..) |page, i| {
        result[at] = .{ .auxiliary = .{ .index = @intCast(i), .value = .{ .source_fold = page.public } } };
        at += 1;
    }
    std.debug.assert(at == result.len);
    try (Bus.Values{ .children = result }).validate();
    return result;
}
