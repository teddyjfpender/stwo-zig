//! Test-only honest authority fixture shared by the complete binary outer
//! cohort. It deliberately composes the focused non-FRI parent fixture and
//! the FRI recorder fixture instead of maintaining a third synthetic setup.
//!
//! One heap-stable pair authority is the source of truth for both halves. The
//! outer-parent verification key and authenticated Merkle wires are installed
//! before `PairPrepared.init`; rows 0--17/35 and rows 18--34 therefore borrow
//! the same prepared executions, child identities, and root pin.

const std = @import("std");

const pair_fixture = @import("../recursion/binary_pair_test_fixture.zig");
const nonfri_bundle_mod = @import("../recursion/binary_pair_nonfri_outer_bundle.zig");
const nonfri_fixture_mod = @import("../recursion/binary_pair_nonfri_outer_bundle_test.zig");
const fri_source_mod = @import("../recursion/binary_fri_outer_source.zig");
const fri_fixture_mod = @import("../recursion/binary_fri_outer_source_test.zig");
const statement_source_mod = @import("../recursion/outer_parent_statement_air_source.zig");

pub const CHILD_DIMENSIONS = pair_fixture.DIMENSIONS;
pub const STATEMENT_DIMENSIONS = nonfri_fixture_mod.STATEMENT_DIMENSIONS;

const NonFriBundle = nonfri_bundle_mod.Bundle(
    CHILD_DIMENSIONS,
    STATEMENT_DIMENSIONS,
);
const FriSource = fri_source_mod.Source(CHILD_DIMENSIONS);
const CaptureFixture = fri_fixture_mod.CaptureFixture;

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    nonfri: *nonfri_fixture_mod.Fixture,
    capture_children: [2]*CaptureFixture,
    fri_source: *FriSource,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        const nonfri = try allocator.create(nonfri_fixture_mod.Fixture);
        errdefer allocator.destroy(nonfri);
        nonfri.* = try nonfri_fixture_mod.Fixture.init(allocator);
        errdefer nonfri.deinit();

        const left_capture = try allocator.create(CaptureFixture);
        errdefer allocator.destroy(left_capture);
        left_capture.* = try CaptureFixture.init(
            allocator,
            nonfri.pair.wires[0],
            &nonfri.pair_prepared.executions[0],
        );
        errdefer left_capture.deinit();

        const right_capture = try allocator.create(CaptureFixture);
        errdefer allocator.destroy(right_capture);
        right_capture.* = try CaptureFixture.init(
            allocator,
            nonfri.pair.wires[1],
            &nonfri.pair_prepared.executions[1],
        );
        errdefer right_capture.deinit();
        const capture_children = [2]*CaptureFixture{
            left_capture,
            right_capture,
        };

        var composition_profiles: [2]?fri_source_mod.TrustedCompositionProfileV1 = .{
            null,
            null,
        };
        var composition_authorities: [2]?fri_source_mod.VerifiedChildCompositionAuthority = .{
            null,
            null,
        };
        for (capture_children, 0..) |capture_child, child_index| {
            const built = try fri_fixture_mod.buildFullComposition(
                capture_child.arena.allocator(),
                &nonfri.pair,
                &nonfri.pair_prepared,
                capture_child,
                child_index,
            );
            composition_profiles[child_index] = built.profile;
            composition_authorities[child_index] =
                try fri_source_mod.VerifiedChildCompositionAuthority.authenticate(
                    built.profile,
                    child_index,
                    nonfri.pair_prepared.authority.children[child_index],
                    nonfri.pair.shape,
                    built.graph.identity_digest,
                    built.graph,
                    built.evaluation,
                    built.poseidon2_partials,
                    built.poseidon2_roster_total,
                );
        }

        const fri_source = try allocator.create(FriSource);
        errdefer allocator.destroy(fri_source);
        const shared_arithmetic = try fri_source_mod.SharedArithmeticInput.seal(
            statement_source_mod.loweringLane(&nonfri.statement_authority),
            nonfri.statement_prepared.loweringEvaluation(),
        );
        fri_source.* = try FriSource.initWithSharedArithmetic(
            allocator,
            &nonfri.pair_prepared,
            nonfri.pair.pair_inputs.root_pin,
            &nonfri.pair.vm_plan,
            .{
                &nonfri.pair.recursion_plans[0],
                &nonfri.pair.recursion_plans[1],
            },
            .{
                .{
                    .shape = nonfri.pair.shape,
                    .wire = nonfri.pair.wires[0],
                    .capture = &capture_children[0].capture,
                    .composition = composition_authorities[0],
                    .trusted_composition_profile = composition_profiles[0],
                },
                .{
                    .shape = nonfri.pair.shape,
                    .wire = nonfri.pair.wires[1],
                    .capture = &capture_children[1].capture,
                    .composition = composition_authorities[1],
                    .trusted_composition_profile = composition_profiles[1],
                },
            },
            shared_arithmetic,
        );
        errdefer fri_source.deinit();

        return .{
            .allocator = allocator,
            .nonfri = nonfri,
            .capture_children = capture_children,
            .fri_source = fri_source,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.fri_source.deinit();
        self.allocator.destroy(self.fri_source);
        self.capture_children[1].deinit();
        self.allocator.destroy(self.capture_children[1]);
        self.capture_children[0].deinit();
        self.allocator.destroy(self.capture_children[0]);
        self.nonfri.deinit();
        self.allocator.destroy(self.nonfri);
        self.* = undefined;
    }

    pub fn nonFriInputs(self: *Fixture) !NonFriBundle.Inputs {
        return self.nonfri.inputs();
    }

    pub fn friSource(self: *const Fixture) *const FriSource {
        return self.fri_source;
    }
};
