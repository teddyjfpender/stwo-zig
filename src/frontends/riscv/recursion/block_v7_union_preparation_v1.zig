//! One admitted shared original becomes one recursive verifier. No child-family
//! verifier is duplicated. Public wire closure remains the receiver's duty.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Parent = @import("blake3_execution_parent_preparation.zig");
const Public = @import("block_v7_union_public_v1.zig");
const Capsule = @import("block_v7_union_compiler_capsule_v1.zig").Capsule;
pub const Limits = struct { max_bytes: usize = 8 << 30, max_public_wires: usize = 1 << 20 };
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    recursive: Parent.Prepared,
    wires: []Public.Wire,
    values: Public.Values,
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.allocator.free(self.wires);
        self.values.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn prepare(backing: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, capacity: u32, limits: Limits) !Prepared {
    return prepareMode(backing, profile, capture, capacity, limits, null);
}
pub fn prepareFromCapsule(backing: std.mem.Allocator, capsule: *const Capsule, capture: *const Multi.VerifiedCapture, capacity: u32, limits: Limits) !Prepared {
    try capsule.requireCapture(backing, capture);
    return prepareMode(backing, capsule.profile(), capture, capacity, limits, capsule);
}
fn prepareMode(backing: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, capacity: u32, limits: Limits, capsule: ?*const Capsule) !Prepared {
    if (capacity == 0 or limits.max_bytes == 0 or limits.max_public_wires == 0) return error.UnionPreparationResourceLimit;
    const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var values = if (capsule) |c| try c.values(a) else try Public.reconstruct(a, profile, &capture.claims);
    errdefer values.deinit();
    var planned = try planMode(a, profile, capture, capacity, capsule);
    defer planned.deinit();
    const wires = try Public.collect(a, profile, capture, &planned.state.?.composition, &planned.transcript.?, values, limits.max_public_wires);
    errdefer a.free(wires);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = if (capsule) |c| try emitted.finishReleasingRowsWithArithmetic(&c.compiler().arithmetic) else try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    return .{ .allocator = a, .budget = budget, .recursive = recursive, .wires = wires, .values = values };
}
pub fn plan(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, capacity: u32) !Parent.Planned {
    return planMode(a, profile, capture, capacity, null);
}
fn planMode(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, capacity: u32, capsule: ?*const Capsule) !Parent.Planned {
    if (capacity == 0) return error.UnionPreparationResourceLimit;
    if (capsule) |c| try c.requireCapture(a, capture) else try profile.validateAgainst(&capture.claims);
    const self = try a.create(Parent.State);
    errdefer a.destroy(self);
    self.allocator = a;
    self.row_sources_released = false;
    self.composition = if (capsule) |c| try c.prepareComposition(a, capture) else try @import("air/block_v7_union_composition_v1.zig").prepare(a, profile, capture);
    errdefer self.composition.deinit();
    var transcript = if (capsule) |c| try @import("air/block_v7_union_transcript_v1.zig").replayFromFrame(a, profile, capture, &c.compiler().values.statement, capacity) else try @import("air/block_v7_union_transcript_v1.zig").replay(a, profile, capture, capacity);
    errdefer transcript.deinit();
    const pcs = if (capsule) |c| try @import("block_v7_union_pcs_preparation_v1.zig").prepareFromCapsule(a, c, capture, &transcript) else try @import("block_v7_union_pcs_preparation_v1.zig").prepare(a, profile, capture, &transcript);
    self.deep = pcs.deep;
    errdefer self.deep.deinit();
    self.fri = pcs.fri;
    errdefer self.fri.deinit();
    self.roots = pcs.roots;
    errdefer self.roots.deinit();
    self.payloads = try @import("air/blake3_execution_payloads.zig").prepare(a, &self.composition, &transcript, &self.deep, 1500, 1502, 5_000_012);
    errdefer self.payloads.deinit();
    const pairs = try @import("air/block_v7_union_caller_draws_v1.zig").pairCount(profile.statement.input.callers.len);
    self.challenges = try @import("air/blake3_execution_challenges.zig").prepareForAdmittedRelations(pairs, 949, a, &self.composition, &transcript, &self.deep, &self.fri, .{ 1500, 1502, 1504 }, 5_000_003);
    errdefer self.challenges.deinit();
    self.terminal = try @import("air/blake3_native_terminal_encoding.zig").prepareColumns(a, &transcript, &self.fri, 1504);
    errdefer self.terminal.deinit();
    self.queries = try @import("air/blake3_native_queries.zig").prepare(a, &transcript, &self.deep, &self.fri);
    errdefer self.queries.deinit();
    const layout = try @import("blake3_native_hash_layout.zig").Layout.initForBoundedCommitments(profile.trace_count + 1, a, try transcript.hashCounts(), &capture.proof);
    self.context = .{ .child_key_id = profile.seal, .child_config = profile.statement.input.epoch.config, .graph_ids = .{ self.composition.circuit.identity_digest, self.deep.graph.graph().identity_digest, self.fri.graph.graph().identity_digest }, .transcript_plan_id = transcript.plan.id };
    return .{ .state = self, .transcript = transcript, .layout = layout, .proof = &capture.proof, .union_path_commitments = profile.trace_count + 1 };
}
