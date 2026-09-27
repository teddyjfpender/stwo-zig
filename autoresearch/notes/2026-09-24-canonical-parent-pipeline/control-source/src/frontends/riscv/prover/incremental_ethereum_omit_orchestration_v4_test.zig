//! Unit gates for the omitted-provider V4 orchestration and cold verifier.
//!
//! No proof is produced here. A real omitted core needs an execution trace, a
//! full V4 witness and a concrete backend, none of which exist in this
//! package's test lane; that end-to-end arm belongs to the integration gate
//! `test-riscv-ethereum-incremental-omitted-leaf-proof-v1`. What this file
//! pins is everything the prove/verify pair cannot re-derive for itself:
//!
//!   * the admission prologue's first three refusals, in the native order;
//!   * that the producer's and the verifier's projected bridge placement are
//!     the same function of the same prefix, and that it removes exactly the
//!     omitted component's (2, 445, 8) columns;
//!   * that `mixRoutePreTree0` is `profile.mixPreTree0` followed by the frame
//!     and nothing else, replayed against a hand-built channel;
//!   * that the leaf omission authority binds all four of its inputs and that
//!     the decoded omission section is refused when any of them drifts.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const fri_core = @import("stwo_core").fri;

const subject = @import("incremental_ethereum_omit_orchestration_v4.zig");
const route = @import("incremental_ethereum_omit_protocol_v4.zig");
const bridge_external = @import("incremental_bridge_external_v3.zig");
const poseidon_channel = @import("../recursion/poseidon2_channel.zig");
const trace_mod = @import("../runner/trace.zig");

const Pins = route.ProviderOmissionPinsV1;
const FrameV4 = subject.IncrementalOmissionFrameV4;
const LeafAuthorityV4 = subject.LeafOmissionAuthorityV4;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A committed prefix wide enough that removing the omitted component leaves a
/// valid placement. The absolute numbers are arbitrary; the deltas are not.
const full_prefix = bridge_external.PrefixColumnsV3{
    .preprocessed = 128,
    .main = 5_000,
    .interaction = 320,
};
const projected_prefix = bridge_external.PrefixColumnsV3{
    .preprocessed = full_prefix.preprocessed - route.omitted_preprocessed_columns,
    .main = full_prefix.main - route.omitted_main_columns,
    .interaction = full_prefix.interaction - route.omitted_interaction_columns,
};
const bridge_rows: u32 = 4_096;

const projection_identity = [_]u8{0x41} ** 32;
const profile_identity = [_]u8{0x42} ** 32;
const shared_identity = [_]u8{0x43} ** 32;
const plan_identity = [_]u8{0x44} ** 32;
const manifest_identity = [_]u8{0x45} ** 32;
const relation_context_identity = [_]u8{0x46} ** 32;
const full_authority_id = [8]u32{ 11, 22, 33, 44, 55, 66, 77, 88 };
const interaction_pow: u64 = 0x0123_4567_89ab_cdef;

fn testPcsConfig() pcs_core.PcsConfig {
    return .{
        .pow_bits = 20,
        .fri_config = fri_core.FriConfig.init(0, 1, 70) catch unreachable,
    };
}

fn otherPcsConfig() pcs_core.PcsConfig {
    return .{
        .pow_bits = 21,
        .fri_config = fri_core.FriConfig.init(0, 1, 70) catch unreachable,
    };
}

/// Minimal stand-in for `AuthorityV4` over the surface the prologue and the
/// shared transcript prefix use. `mixPreTree0` writes a recognisable frame so
/// the replay test can prove the route mixes it first and unmodified.
const StubProfile = struct {
    identity_sha256: [32]u8 = profile_identity,
    bridge_geometry: bridge_external.GeometryV3,
    config: pcs_core.PcsConfig = undefined,
    pre_tree0_calls: usize = 0,

    pub fn pcsConfig(self: *const StubProfile) !pcs_core.PcsConfig {
        return self.config;
    }

    pub fn mixPreTree0(
        self: *const StubProfile,
        native: anytype,
        role_aware_public: anytype,
        channel: anytype,
    ) !void {
        _ = native;
        _ = role_aware_public;
        channel.mixU32s(&[4]u32{ 0xdead_beef, 0x0000_0001, 0, 7 });
        self.bridge_geometry.mixFieldAuthority(channel);
    }
};

fn stubProfile(config: pcs_core.PcsConfig) !StubProfile {
    return .{
        .bridge_geometry = try bridge_external.GeometryV3.canonicalAfterPrefix(
            bridge_rows,
            full_prefix,
        ),
        .config = config,
    };
}

fn canonicalFrame() !FrameV4 {
    return FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows,
        projected_prefix,
    );
}

fn canonicalLeafAuthority(frame: *const FrameV4) !LeafAuthorityV4 {
    return subject.leafOmissionAuthority(
        profile_identity,
        frame,
        shared_identity,
        full_authority_id,
    );
}

fn canonicalBindings() subject.OmissionBindingsV1 {
    return .{
        .projection_identity = projection_identity,
        .plan_identity = plan_identity,
        .manifest_identity = manifest_identity,
        .shared_identity = shared_identity,
        .relation_context_identity = relation_context_identity,
        .interaction_pow = interaction_pow,
    };
}

fn decodedOmission(
    frame: *const FrameV4,
    leaf: *const LeafAuthorityV4,
) subject.DecodedOmissionV1 {
    return .{
        .pins_identity = Pins.identity(),
        .projection_identity = projection_identity,
        .plan_identity = plan_identity,
        .manifest_identity = manifest_identity,
        .shared_identity = shared_identity,
        .relation_context_identity = relation_context_identity,
        .interaction_pow = interaction_pow,
        .projected_bridge_geometry = frame.projected_bridge_geometry,
        .frame_identity = frame.identity,
        .leaf_omission_identity = leaf.identity,
    };
}

// ---------------------------------------------------------------------------
// Admission prologue
// ---------------------------------------------------------------------------

test "incremental omitted orchestration v4: the admission prologue refuses in the native order" {
    const config = testPcsConfig();
    const profile = try stubProfile(config);

    var empty_trace = trace_mod.Trace.init(std.testing.allocator);
    defer empty_trace.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_trace.step_count);

    // A non-strict CPU contention policy is refused before the trace is read,
    // so it wins even on an empty trace.
    try std.testing.expectError(
        error.NonStrictExecutionPolicy,
        subject.admitOmittedExecutionAndTrace(config, &empty_trace, &profile, .{
            .cpu = .{
                .worker_count = 1,
                .host_byte_budget = 1 << 30,
                .contention_policy = .compatibility,
            },
        }),
    );

    // Strict policy, empty trace.
    try std.testing.expectError(
        error.EmptyTrace,
        subject.admitOmittedExecutionAndTrace(config, &empty_trace, &profile, .{
            .cpu = .{
                .worker_count = 1,
                .host_byte_budget = 1 << 30,
                .contention_policy = .strict,
            },
        }),
    );

    // A non-empty trace with a PCS config that is not the profile's.
    var live_trace = trace_mod.Trace.init(std.testing.allocator);
    defer live_trace.deinit();
    live_trace.step_count = 1;
    try std.testing.expectError(
        error.IncrementalEthereumPcsMismatch,
        subject.admitOmittedExecutionAndTrace(
            otherPcsConfig(),
            &live_trace,
            &profile,
            .{},
        ),
    );

    // The matching config passes; the omitted route never relaxes any of the
    // three, it only adds bindings after them.
    try subject.admitOmittedExecutionAndTrace(
        config,
        &live_trace,
        &profile,
        .{},
    );
}

// ---------------------------------------------------------------------------
// Projected geometry
// ---------------------------------------------------------------------------

test "incremental omitted orchestration v4: producer and verifier project the same bridge placement" {
    const full = try bridge_external.GeometryV3.canonicalAfterPrefix(
        bridge_rows,
        full_prefix,
    );
    const producer = try subject.projectedRouteGeometryFromPrefix(
        &full,
        projected_prefix,
    );
    const verifier = try subject.projectedRouteGeometryFromPrefix(
        &full,
        projected_prefix,
    );
    try std.testing.expect(std.meta.eql(producer, verifier));
    try std.testing.expect(std.meta.eql(producer.prefix, projected_prefix));

    // Same rows, same log size: only the placement slides down.
    try std.testing.expectEqual(full.n_rows, producer.bridge.n_rows);
    try std.testing.expectEqual(full.log_size, producer.bridge.log_size);
    try std.testing.expectEqual(
        @as(usize, route.omitted_preprocessed_columns),
        full.placement.is_first_col_idx - producer.bridge.placement.is_first_col_idx,
    );
    try std.testing.expectEqual(
        @as(usize, route.omitted_preprocessed_columns),
        full.placement.is_active_col_idx - producer.bridge.placement.is_active_col_idx,
    );
    try std.testing.expectEqual(
        @as(usize, route.omitted_main_columns),
        full.placement.main_col_offset - producer.bridge.placement.main_col_offset,
    );
    try std.testing.expectEqual(
        @as(usize, route.omitted_interaction_columns),
        full.placement.interaction_col_offset -
            producer.bridge.placement.interaction_col_offset,
    );
    try std.testing.expectEqual(@as(u32, 2), route.omitted_preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 445), route.omitted_main_columns);
    try std.testing.expectEqual(@as(u32, 8), route.omitted_interaction_columns);

    // A prefix that did not shed exactly the omitted component is refused, so
    // a verifier recomputing against a drifted projection fails closed rather
    // than reading the bridge at the wrong offset.
    var wrong = projected_prefix;
    wrong.main += 1;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        subject.projectedRouteGeometryFromPrefix(&full, wrong),
    );
}

// ---------------------------------------------------------------------------
// Transcript order
// ---------------------------------------------------------------------------

test "incremental omitted orchestration v4: mixRoutePreTree0 is the profile prefix then the frame" {
    const profile = try stubProfile(testPcsConfig());
    const frame = try canonicalFrame();

    var actual = poseidon_channel.Channel{};
    try subject.mixRoutePreTree0(&profile, undefined, undefined, &frame, &actual);

    // Hand-built replay of transcript steps [1] then [2].
    var expected = poseidon_channel.Channel{};
    try profile.mixPreTree0(undefined, undefined, &expected);
    frame.mixInto(&expected);
    try std.testing.expectEqual(expected.digestWords(), actual.digestWords());
    try std.testing.expectEqual(expected.n_draws, actual.n_draws);

    // The frame is genuinely absorbed: the profile prefix alone is a different
    // channel state, so a producer that forgot step [2] cannot match a
    // verifier that performed it.
    var prefix_only = poseidon_channel.Channel{};
    try profile.mixPreTree0(undefined, undefined, &prefix_only);
    try std.testing.expect(
        !std.meta.eql(prefix_only.digestWords(), actual.digestWords()),
    );

    // Order matters: frame first, profile second is a different transcript.
    var swapped = poseidon_channel.Channel{};
    frame.mixInto(&swapped);
    try profile.mixPreTree0(undefined, undefined, &swapped);
    try std.testing.expect(
        !std.meta.eql(swapped.digestWords(), actual.digestWords()),
    );

    // A different projection reaches a different pre-Tree0 state, which is
    // what makes Tree 0's column count unforgeable after the fact.
    var other_projection = projection_identity;
    other_projection[7] ^= 0xff;
    const other_frame = try FrameV4.canonicalFromProjectionIdentity(
        other_projection,
        bridge_rows,
        projected_prefix,
    );
    var other = poseidon_channel.Channel{};
    try subject.mixRoutePreTree0(
        &profile,
        undefined,
        undefined,
        &other_frame,
        &other,
    );
    try std.testing.expect(
        !std.meta.eql(other.digestWords(), actual.digestWords()),
    );
}

test "incremental omitted orchestration v4: a mutated frame never reaches the channel" {
    const profile = try stubProfile(testPcsConfig());
    const frame = try canonicalFrame();
    var mutated = frame;
    mutated.pins_identity[0] ^= 0x01;

    const untouched = poseidon_channel.Channel{};
    var channel = poseidon_channel.Channel{};
    try std.testing.expectError(
        error.ProviderOmissionPinDriftV4,
        subject.mixRoutePreTree0(
            &profile,
            undefined,
            undefined,
            &mutated,
            &channel,
        ),
    );
    try std.testing.expectEqual(untouched.digestWords(), channel.digestWords());
}

// ---------------------------------------------------------------------------
// Leaf authority and the decoded omission section
// ---------------------------------------------------------------------------

test "incremental omitted orchestration v4: the leaf authority binds profile, frame, shared draw and full statement" {
    const frame = try canonicalFrame();
    const leaf = try canonicalLeafAuthority(&frame);
    try leaf.validate();
    try leaf.validateAgainst(
        profile_identity,
        &frame,
        shared_identity,
        full_authority_id,
    );

    // Each of the four inputs moves the identity, so a shard proof minted
    // under another leaf, another profile or another draw cannot be relabelled
    // into this one.
    var other_profile = profile_identity;
    other_profile[0] ^= 0xff;
    const with_other_profile = try subject.leafOmissionAuthority(
        other_profile,
        &frame,
        shared_identity,
        full_authority_id,
    );
    try std.testing.expect(
        !std.mem.eql(u8, &leaf.identity, &with_other_profile.identity),
    );

    var other_shared = shared_identity;
    other_shared[31] ^= 0xff;
    const with_other_shared = try subject.leafOmissionAuthority(
        profile_identity,
        &frame,
        other_shared,
        full_authority_id,
    );
    try std.testing.expect(
        !std.mem.eql(u8, &leaf.identity, &with_other_shared.identity),
    );

    var other_authority = full_authority_id;
    other_authority[3] += 1;
    const with_other_authority = try subject.leafOmissionAuthority(
        profile_identity,
        &frame,
        shared_identity,
        other_authority,
    );
    try std.testing.expect(
        !std.mem.eql(u8, &leaf.identity, &with_other_authority.identity),
    );

    var taller_prefix = projected_prefix;
    taller_prefix.interaction += 4;
    const other_frame = try FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows,
        taller_prefix,
    );
    const with_other_frame = try subject.leafOmissionAuthority(
        profile_identity,
        &other_frame,
        shared_identity,
        full_authority_id,
    );
    try std.testing.expect(
        !std.mem.eql(u8, &leaf.identity, &with_other_frame.identity),
    );

    // A leaf authority carrying a mutated identity is refused before it can be
    // mixed into any shard's local prefix.
    var broken = leaf;
    broken.identity[0] ^= 0x01;
    try std.testing.expectError(
        error.InvalidLeafOmissionAuthorityV4,
        broken.validate(),
    );
}

test "incremental omitted orchestration v4: the decoded omission section fails closed on every drift" {
    const frame = try canonicalFrame();
    const leaf = try canonicalLeafAuthority(&frame);
    const bindings = canonicalBindings();
    const good = decodedOmission(&frame, &leaf);
    try good.validate();
    try good.validateAgainstBindings(
        bindings,
        &frame.projected_bridge_geometry,
        &frame,
        &leaf,
    );

    // A section claiming another pin set is refused before any statement is
    // consulted: the pins are comptime, so there is no other admissible value.
    var pin_drift = good;
    pin_drift.pins_identity[0] ^= 0x01;
    try std.testing.expectError(
        error.ProviderOmissionPinDriftV4,
        pin_drift.validate(),
    );

    // A zero digest is a missing binding, not a permitted value.
    var zeroed = good;
    zeroed.shared_identity = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedEthereumOmissionSection,
        zeroed.validate(),
    );

    // Every decoded identity is compared against the live authority, not
    // merely required to be present.
    inline for (.{
        "projection_identity",
        "plan_identity",
        "manifest_identity",
        "shared_identity",
        "relation_context_identity",
        "frame_identity",
        "leaf_omission_identity",
    }) |field| {
        var drifted = good;
        @field(drifted, field)[5] ^= 0xff;
        try std.testing.expectError(
            error.InvalidIncrementalOmittedEthereumOmissionSection,
            drifted.validateAgainstBindings(
                bindings,
                &frame.projected_bridge_geometry,
                &frame,
                &leaf,
            ),
        );
    }

    // The same drift seen from the other side: a live authority that moved
    // under a fixed decoded section.
    inline for (.{
        "projection_identity",
        "plan_identity",
        "manifest_identity",
        "shared_identity",
        "relation_context_identity",
    }) |field| {
        var moved = bindings;
        @field(moved, field)[9] ^= 0xff;
        try std.testing.expectError(
            error.InvalidIncrementalOmittedEthereumOmissionSection,
            good.validateAgainstBindings(
                moved,
                &frame.projected_bridge_geometry,
                &frame,
                &leaf,
            ),
        );
    }

    var wrong_pow = good;
    wrong_pow.interaction_pow ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalOmittedEthereumOmissionSection,
        wrong_pow.validateAgainstBindings(
            bindings,
            &frame.projected_bridge_geometry,
            &frame,
            &leaf,
        ),
    );

    // A decoded placement that disagrees with the recomputed one is the
    // mutation that would otherwise read the bridge at the wrong offset.
    const full = try bridge_external.GeometryV3.canonicalAfterPrefix(
        bridge_rows,
        full_prefix,
    );
    var wrong_geometry = good;
    wrong_geometry.projected_bridge_geometry = full;
    try std.testing.expectError(
        error.IncrementalOmittedEthereumBridgeGeometryMismatch,
        wrong_geometry.validateAgainstBindings(
            bindings,
            &frame.projected_bridge_geometry,
            &frame,
            &leaf,
        ),
    );
    try std.testing.expectError(
        error.IncrementalOmittedEthereumBridgeGeometryMismatch,
        good.validateAgainstBindings(bindings, &full, &frame, &leaf),
    );

    // A leaf authority that does not belong to this frame is refused even when
    // the decoded section agrees with it, because the frame is re-validated.
    var other_projection = projection_identity;
    other_projection[1] ^= 0xff;
    const foreign_frame = try FrameV4.canonicalFromProjectionIdentity(
        other_projection,
        bridge_rows,
        projected_prefix,
    );
    const foreign_leaf = try canonicalLeafAuthority(&foreign_frame);
    try std.testing.expectError(
        error.InvalidIncrementalOmittedEthereumOmissionSection,
        good.validateAgainstBindings(
            bindings,
            &frame.projected_bridge_geometry,
            &foreign_frame,
            &foreign_leaf,
        ),
    );
}
