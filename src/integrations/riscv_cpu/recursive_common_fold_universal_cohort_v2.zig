//! Live two-child authority for the field-native common-fold circuit.
//!
//! This layer closes the nonserializable custody boundary which is already
//! available today: ordered wrapper views, verifier-owned PCS captures, and
//! both verifier-rerecorded composition graphs.  It also reconstructs the
//! captured FRI owners used by rows 20--29/33.  It intentionally does not
//! claim that the missing common-fold fixed-wire/source adapter exists.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const empty_child_mod =
    @import("recursive_pipeline_worker_canonical_empty_v2.zig");
const common_child_mod = @import("recursive_common_fold_child_v2.zig");
const child_capability =
    @import("recursive_common_fold_child_capability_v2.zig");
const field_public = @import("recursive_common_fold_field_public_v2.zig");
const input_mod = @import("recursive_common_fold_input_v2.zig");
const manifest_mod =
    @import("recursive_common_fold_universal_manifest_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const recursion = frontend.recursion;
const captured_fri = recursion.captured_fri;
const rows_source = recursion.binary_fri_outer_source;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const LEFT_POSITION_CIRCUIT_ID: u32 = 761;
pub const RIGHT_POSITION_CIRCUIT_ID: u32 = 762;
pub const COMMON_FOLD_ROLE =
    registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const PRODUCTION_ACTIVATION = false;
pub const AUTHENTICATED_COMPOSITION_LANES_AVAILABLE = true;
pub const CAPTURED_FRI_REPLAY_AVAILABLE = true;
pub const FIELD_PUBLIC_POSEIDON_SCHEDULE_AVAILABLE = true;
pub const FULL_QUERY_WORD_AUTHORITY_AVAILABLE = true;
pub const FIXED_WIRE_SOURCE_AVAILABLE =
    FULL_QUERY_WORD_AUTHORITY_AVAILABLE;
pub const COMPLETE_POSEIDON_PROVIDER_TRACE_AVAILABLE = true;
pub const GLOBAL_RELATION_CLOSURE_AVAILABLE =
    FIXED_WIRE_SOURCE_AVAILABLE;
pub const SERIALIZABLE_FRESH_COHORT = false;
pub const ALL_SCHEMA4_ROLE_BRANCHES_AVAILABLE = false;

const AUTHORITY_DOMAIN =
    "stwo-zig/recursive-common-fold-live-cohort/v2\x00";

pub const FreshFoldChildV2 = child_capability.TaggedFoldChildV2(
    child_capability.UnavailableRealLeafChildV2,
    empty_child_mod.FreshFoldChildV2,
    common_child_mod.FreshFoldChildV2,
);
pub const FreshFoldInputV2 = input_mod.FreshFoldInputV2;

pub const Error = empty_child_mod.Error || field_public.Error || input_mod.Error ||
    manifest_mod.Error || captured_fri.Error || rows_source.Error || error{
    AliasedCommonFoldGraph,
    CommonFoldChildCustodyMismatch,
    CommonFoldFixedWireSourceUnavailable,
    CommonFoldPublicScheduleMismatch,
};

/// Exact process-local authority consumed by a future common-fold q193
/// engine. No encoder exists: all pointers borrow live cold-verifier owners.
pub const CohortV2 = struct {
    pub const FoldChild = FreshFoldChildV2;
    pub const CapturedFriPair = CapturedFriPairV2;

    input: *const FreshFoldInputV2,
    children: [CHILD_COUNT]FreshFoldChildV2,
    geometry: *const manifest_mod.AuthorityV2,
    public_schedule: field_public.PoseidonScheduleV2,
    identity_sha256: [32]u8,

    pub fn init(
        input: *const FreshFoldInputV2,
        children: [CHILD_COUNT]FreshFoldChildV2,
        geometry: *const manifest_mod.AuthorityV2,
    ) !CohortV2 {
        const left = try children[0].projection(&geometry.registry);
        const right = try children[1].projection(&geometry.registry);
        const public_schedule = try field_public.PoseidonScheduleV2.build(
            left.wrapper.nodePublic(),
            right.wrapper.nodePublic(),
            input.parent_coordinate,
        );
        var result = CohortV2{
            .input = input,
            .children = children,
            .geometry = geometry,
            .public_schedule = public_schedule,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = try authorityIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn registry(
        self: *const CohortV2,
    ) *const registry_mod.RecursiveCircuitRegistryV1 {
        return self.geometry.registry;
    }

    pub fn validate(self: *const CohortV2) !void {
        try self.geometry.validate();
        try self.input.validateAgainst(self.geometry.registry);
        for (self.children, self.input.child_views, 0..) |
            child,
            expected,
            index,
        | {
            const projection = try child.projection(&self.geometry.registry);
            if (projection.wrapper.artifact != expected.artifact or
                projection.wrapper.geometry != expected.geometry or
                projection.wrapper.capture != expected.capture or
                projection.node_public != projection.wrapper.nodePublic() or
                projection.capture != projection.wrapper.capture or
                projection.geometry != projection.wrapper.geometry or
                projection.wrapper.geometry != &self.geometry.geometries[
                    @intFromEnum(projection.role)
                ] or
                !std.meta.eql(
                    try projection.wrapper.reference(),
                    self.input.child_refs[index],
                )) return error.CommonFoldChildCustodyMismatch;
        }
        const left = try self.children[0].projection(&self.geometry.registry);
        const right = try self.children[1].projection(&self.geometry.registry);
        if (left.graph.lane.graph.nodes.ptr ==
            right.graph.lane.graph.nodes.ptr or
            left.graph.evaluation.values.ptr ==
                right.graph.evaluation.values.ptr)
        {
            return error.AliasedCommonFoldGraph;
        }
        const expected_schedule = try field_public.PoseidonScheduleV2.build(
            left.wrapper.nodePublic(),
            right.wrapper.nodePublic(),
            self.input.parent_coordinate,
        );
        const expected_identity = try authorityIdentity(self);
        if (!std.meta.eql(self.public_schedule, expected_schedule) or
            !std.meta.eql(
                self.public_schedule.parent,
                self.input.outputNodePublic().*,
            ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &expected_identity,
        )) return error.CommonFoldPublicScheduleMismatch;
    }

    /// Minimal generic lane view accepted by the existing rows-18/19 and
    /// rows-30/32 constructors. Child position is supplied by array order;
    /// no canonical-empty verifier/scope tag is promoted to fold semantics.
    pub fn authenticatedCompositionLanes(
        self: *const CohortV2,
    ) ![CHILD_COUNT]rows_source.AuthenticatedCompositionLane {
        try self.validate();
        var result: [CHILD_COUNT]rows_source.AuthenticatedCompositionLane =
            undefined;
        for (self.children, &result, 0..) |child, *destination, index| {
            const projection = try child.projection(&self.geometry.registry);
            destination.* = .{
                .circuit_id = if (index == 0)
                    LEFT_POSITION_CIRCUIT_ID
                else
                    RIGHT_POSITION_CIRCUIT_ID,
                .circuit_identity = projection.graph.lane.graph.identity_digest,
                .graph = projection.graph.lane.graph,
                .evaluation = projection.graph.evaluation,
            };
            try destination.validate();
        }
        return result;
    }

    /// Reconstructs both FRI/PCS arithmetic witnesses only from the two live
    /// verifier captures. This still does not mint the missing fixed wire.
    pub fn initCapturedFriPair(
        self: *const CohortV2,
        allocator: std.mem.Allocator,
    ) !CapturedFriPairV2 {
        try self.validate();
        const left_projection = try self.children[0].projection(
            &self.geometry.registry,
        );
        const right_projection = try self.children[1].projection(
            &self.geometry.registry,
        );
        var left = try captured_fri.Owned.init(
            allocator,
            childProfile(left_projection),
            left_projection.capture,
        );
        errdefer left.deinit();
        var right = try captured_fri.Owned.init(
            allocator,
            childProfile(right_projection),
            right_projection.capture,
        );
        errdefer right.deinit();
        return .{ .children = .{ left, right } };
    }

    /// The common-fold fixed-wire owner is instantiated only by the secure
    /// cohort after this live authority has closed both child capabilities.
    /// This check deliberately grants no owner or serializable authority.
    pub fn requireFixedWireSource(self: *const CohortV2) !void {
        try self.validate();
        if (comptime !ALL_SCHEMA4_ROLE_BRANCHES_AVAILABLE)
            return error.CommonFoldRealLeafCapabilityUnavailable;
        if (comptime !FULL_QUERY_WORD_AUTHORITY_AVAILABLE)
            return error.CommonFoldFixedWireSourceUnavailable;
    }
};

pub const CapturedFriPairV2 = struct {
    children: [CHILD_COUNT]captured_fri.Owned,

    pub fn deinit(self: *CapturedFriPairV2) void {
        self.children[1].deinit();
        self.children[0].deinit();
        self.* = undefined;
    }
};

fn childProfile(
    child: child_capability.ProjectionV2,
) captured_fri.ProfileConfig {
    const pcs = child.wrapper.geometry.pcs;
    return .{
        .log_blowup_factor = pcs.fri_log_blowup_factor,
        .log_last_layer_degree_bound = pcs.fri_log_last_layer_degree_bound,
        .interaction_pow_bits = pcs.interaction_pow_bits,
        .pcs_pow_bits = pcs.pcs_pow_bits,
        .claimed_sum_count = @intCast(child.wrapper.geometry.component_count),
    };
}

fn authorityIdentity(value: *const CohortV2) ![32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.input.identity_sha256);
    hash.update(&value.geometry.identity_sha256);
    for (value.children) |child| {
        const projection = try child.projection(&value.geometry.registry);
        hashInt(&hash, u8, @intFromEnum(projection.role));
        hash.update(projection.graph.capture_identity_sha256);
        hash.update(projection.graph.layout_identity_sha256);
        hash.update(&projection.graph.lane.graph.identity_digest);
        hash.update(&projection.graph.evaluation.circuit_identity);
    }
    for (value.public_schedule.parent.output_digest) |word|
        hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or CHILD_COUNT != 2 or
        LEFT_POSITION_CIRCUIT_ID == RIGHT_POSITION_CIRCUIT_ID or
        field_public.POSEIDON_CALL_COUNT != 116 or PRODUCTION_ACTIVATION or
        !AUTHENTICATED_COMPOSITION_LANES_AVAILABLE or
        !CAPTURED_FRI_REPLAY_AVAILABLE or
        !FIELD_PUBLIC_POSEIDON_SCHEDULE_AVAILABLE or
        !COMPLETE_POSEIDON_PROVIDER_TRACE_AVAILABLE or
        GLOBAL_RELATION_CLOSURE_AVAILABLE !=
            FIXED_WIRE_SOURCE_AVAILABLE or SERIALIZABLE_FRESH_COHORT)
    {
        @compileError("common-fold universal cohort contract drifted");
    }
}
