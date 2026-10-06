const std = @import("std");
const inputs = @import("../temporal_parent_inputs_v3.zig");
const roster = @import("../temporal_parent_roster_v3.zig");
const interval = @import("../temporal_interval_v3.zig");
const session_mod = @import("../temporal_parent_row11_session_v3.zig");
const channel = @import("../poseidon2_channel.zig");
const fixture = @import("temporal_interval_v3_test.zig");

fn pins() inputs.KeyPinsV3 {
    return .{
        .leaf_wrapper = channel.hashBytes("v3-leaf-wrapper-key", 0x5653_3311),
        .temporal_child = channel.hashBytes("v3-temporal-child-key", 0x5653_3312),
    };
}

fn source(value: *const interval.IntervalV3, policy: inputs.KeyPinsV3) !inputs.ChildSourceV3 {
    return .{
        .family = value.family,
        .verification_key_id = policy.forFamily(value.family),
        .statement_words = try value.statementWords(),
        .entry = value.entry,
        .exit = value.exit,
        .first_leaf_id = value.first_leaf_id,
        .last_leaf_id = value.last_leaf_id,
        .final_completion = value.final_completion,
    };
}

test "V3 temporal parent roster encodes two child sources and reuses pinned row11" {
    const metadata = try fixture.threeLeaves();
    const left = try interval.IntervalV3.fromLeaf(&metadata[0]);
    const right = try interval.IntervalV3.fromLeaf(&metadata[1]);
    const pair = try interval.PairPreflightV3.init(&left, &right);
    const policy = pins();
    const candidate = try inputs.CandidateInputsV3.init(
        &pair,
        &left,
        &right,
        .{ try source(&left, policy), try source(&right, policy) },
        policy,
    );
    const plan = try roster.PlanV3.init(policy);
    try plan.checkCandidate(&candidate);
    try std.testing.expectEqual(@as(u32, inputs.FORMAT_VERSION), candidate.words[0].toU32());
    try std.testing.expectEqual(@as(u32, @intFromEnum(interval.ChildFamily.leaf_wrapper_v3)), candidate.words[inputs.Layout.left_child_start + inputs.Layout.child_family].toU32());
    try std.testing.expectEqual(@as(u32, 0), candidate.words[inputs.Layout.right_child_start + inputs.Layout.child_completion_start].toU32());
    try std.testing.expectEqual(@as(u32, 0), candidate.words[inputs.Layout.parent_start + inputs.Layout.parent_completion_start].toU32());
    try std.testing.expectEqual(@as(u32, 12), plan.descriptors[@intFromEnum(roster.Component.statement_row11)].geometry.?.log_size);
    try std.testing.expect(plan.descriptors[@intFromEnum(roster.Component.statement_circuit)].geometry == null);
    try std.testing.expectError(error.ParentProofUnavailable, candidate.requireVerifiedParent());
    try std.testing.expectError(error.ParentProofUnavailable, plan.requireVerificationKey());

    var session = try session_mod.SessionV3.init(std.testing.allocator);
    defer session.deinit();
    var workspace = try session_mod.WorkspaceV3.init(std.testing.allocator);
    defer workspace.deinit();
    var trace = try session_mod.TraceV3.init(std.testing.allocator);
    defer trace.deinit();
    try candidate.fillRow11(&session, &workspace, &trace);
}

test "V3 temporal parent roster binds odd-carried family, order, keys and endpoints" {
    const metadata = try fixture.threeLeaves();
    const first = try interval.IntervalV3.fromLeaf(&metadata[0]);
    const second = try interval.IntervalV3.fromLeaf(&metadata[1]);
    const left = try interval.IntervalV3.fold(&first, &second);
    const right = try interval.IntervalV3.fromLeaf(&metadata[2]);
    const pair = try interval.PairPreflightV3.init(&left, &right);
    const policy = pins();
    const sources = [2]inputs.ChildSourceV3{
        try source(&left, policy), try source(&right, policy),
    };
    const candidate = try inputs.CandidateInputsV3.init(&pair, &left, &right, sources, policy);
    const plan = try roster.PlanV3.init(policy);
    try plan.checkCandidate(&candidate);
    try std.testing.expectEqual(@as(u32, @intFromEnum(interval.ChildFamily.temporal_parent_v3)), candidate.words[inputs.Layout.left_child_start + inputs.Layout.child_family].toU32());
    try std.testing.expectEqual(@as(u32, @intFromEnum(interval.ChildFamily.leaf_wrapper_v3)), candidate.words[inputs.Layout.right_child_start + inputs.Layout.child_family].toU32());
    try std.testing.expectEqual(@as(u32, 0), candidate.words[inputs.Layout.left_child_start + inputs.Layout.child_completion_start].toU32());
    try std.testing.expectEqual(@as(u32, 1), candidate.words[inputs.Layout.right_child_start + inputs.Layout.child_completion_start].toU32());
    try std.testing.expectEqual(@as(u32, 1), candidate.words[inputs.Layout.parent_start + inputs.Layout.parent_completion_start].toU32());
    try std.testing.expectEqual(@as(u32, @intCast(pair.global_join_cycle & 0xffff)), candidate.words[inputs.Layout.trailer_start + inputs.Layout.global_join_cycle_start].toU32());

    var wrong = sources;
    wrong[0].verification_key_id = policy.leaf_wrapper;
    try std.testing.expectError(error.ChildVerifierKeyMismatch, inputs.CandidateInputsV3.init(&pair, &left, &right, wrong, policy));
    wrong = sources;
    wrong[1].entry.snapshot_id = channel.hashBytes("wrong-boundary", 0x5653_3313);
    try std.testing.expectError(error.ChildVerifierSourceMismatch, inputs.CandidateInputsV3.init(&pair, &left, &right, wrong, policy));
    wrong = sources;
    wrong[1].final_completion = null;
    try std.testing.expectError(error.ChildVerifierSourceMismatch, inputs.CandidateInputsV3.init(&pair, &left, &right, wrong, policy));
    try std.testing.expectError(error.SegmentDiscontinuity, inputs.CandidateInputsV3.init(&pair, &right, &left, sources, policy));

    var changed = candidate;
    changed.words[inputs.Layout.right_child_start + inputs.Layout.child_key_start] = @import("stwo_core").fields.m31.M31.fromCanonical(1);
    try std.testing.expectError(error.ParentInputChanged, changed.validate());
    var changed_plan = plan;
    changed_plan.descriptors[@intFromEnum(roster.Component.statement_row11)].geometry.?.log_size = 11;
    try std.testing.expectError(error.TemporalParentRosterMismatch, changed_plan.validate());
    changed_plan = plan;
    changed_plan.pins.temporal_child = policy.leaf_wrapper;
    try std.testing.expectError(error.ParentChildKeyCollision, changed_plan.validate());
    var other_pins = policy;
    other_pins.leaf_wrapper = channel.hashBytes("other-leaf-wrapper-key", 0x5653_3314);
    const other_plan = try roster.PlanV3.init(other_pins);
    try std.testing.expect(!std.meta.eql(plan.stage_identity, other_plan.stage_identity));
    try std.testing.expectError(error.TemporalParentKeyPinsMismatch, other_plan.checkCandidate(&candidate));
}
