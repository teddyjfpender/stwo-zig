//! Fixed-wire and rows-18--34 source for the field-native common fold.
//!
//! Both children remain live verifier capabilities.  Their PCS captures,
//! universal claims, interaction/PCS nonces, and rerecorded composition
//! graphs are copied into one position-authenticated binary source.  No
//! canonical-empty, H1, or temporal-parent source/session tag is reused.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const live_mod = @import("recursive_common_fold_universal_cohort_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const schedule_mod = @import("recursive_common_fold_poseidon_schedule_v2.zig");
const wire_boundary =
    @import("recursive_common_fold_wire_boundary_authority_v2.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const captured_fri = recursion.captured_fri;
const fixed_wire = recursion.fixed_wire;
const rows_source = recursion.binary_fri_outer_source;
const rows_bundle = recursion.binary_fri_outer_bundle;
const schedule = recursion.air.verifier_schedule;
const transcript_shape = recursion.transcript_shape;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const ROW_COUNT: usize = rows_source.ROW_COUNT;
pub const SOURCE_DOMAIN =
    "stwo-zig/recursive-common-fold-fixed-source/v2\x00";

pub const PRODUCTION_ACTIVATION = false;
pub const PROOF_BYTE_REPARSES: usize = 0;
pub const CAPTURED_FRI_OWNERS_PER_CHILD: usize = 1;
pub const ROWS_18_THROUGH_34_AVAILABLE = true;

pub const Error = live_mod.Error || manifest_mod.Error ||
    schedule_mod.Error || rows_source.Error || error{
    CommonFoldCaptureMismatch,
    CommonFoldDuplicateChild,
    CommonFoldProfileMismatch,
    CommonFoldQueryAuthorityMismatch,
    CommonFoldQueryWordsUnavailable,
    CommonFoldSourceAuthorityMismatch,
    CommonFoldWireMismatch,
};

pub fn DimensionsFromShape(comptime shape: anytype) fixed_wire.Dimensions {
    return .{
        .commitment_count = shape.tree_count,
        .claimed_sum_count = shape.claimed_sum_count,
        .sampled_value_count = shape.sampled_value_count,
        .queried_value_count = shape.queried_value_count,
        .trace_path_count = shape.trace_path_count,
        .fri_layer_count = shape.fri_layer_count,
        .query_count = shape.query_count,
        .maximum_fold_width = shape.maximum_fold_width,
        .last_layer_coefficient_count = shape.last_layer_coefficient_count,
        .maximum_merkle_depth = shape.maximum_merkle_depth,
    };
}

/// Runtime sibling for a shape minted by a cold verifier. The fixed-wire type
/// remains selected at comptime; this value is used only for exact equality
/// against that selection and never promotes runtime geometry into a type.
pub fn dimensionsFromShapeRuntime(
    shape: anytype,
) !fixed_wire.Dimensions {
    try shape.validate();
    return .{
        .commitment_count = try runtimeDimension(shape.tree_count),
        .claimed_sum_count = try runtimeDimension(shape.claimed_sum_count),
        .sampled_value_count = try runtimeDimension(shape.sampled_value_count),
        .queried_value_count = try runtimeDimension(shape.queried_value_count),
        .trace_path_count = try runtimeDimension(shape.trace_path_count),
        .fri_layer_count = try runtimeDimension(shape.fri_layer_count),
        .query_count = try runtimeDimension(shape.query_count),
        .maximum_fold_width = try runtimeDimension(shape.maximum_fold_width),
        .last_layer_coefficient_count = try runtimeDimension(
            shape.last_layer_coefficient_count,
        ),
        .maximum_merkle_depth = try runtimeDimension(
            shape.maximum_merkle_depth,
        ),
    };
}

fn runtimeDimension(value: anytype) !usize {
    return std.math.cast(usize, value) orelse error.CommonFoldWireMismatch;
}

pub fn Types(comptime dimensions: fixed_wire.Dimensions) type {
    return TypesForLive(dimensions, live_mod.CohortV2, ProductionPolicyV2);
}

/// Shared fixed-wire implementation for the production cohort and the
/// explicitly unrouteable q193 bootstrap. `Policy` owns only the root pin and
/// dimension check; child proof/capture reconstruction remains identical.
pub fn TypesForLive(
    comptime dimensions: fixed_wire.Dimensions,
    comptime Live: type,
    comptime Policy: type,
) type {
    dimensions.validate();
    if (!@hasDecl(Live, "FoldChild") or
        !@hasDecl(Live, "CapturedFriPair"))
    {
        @compileError(
            "common-fold live authority must expose FoldChild and CapturedFriPair",
        );
    }
    const CapturedFriPair = Live.CapturedFriPair;
    const Boundary = CommonFoldBoundaryForLiveV2(
        dimensions,
        Live,
        Policy,
    );
    const Source = rows_source.AuthenticatedSource(dimensions, Boundary);
    const Bundle = rows_bundle.BundleForSourceScheduleAndManifest(
        dimensions,
        Source,
        schedule_mod,
        manifest_mod,
    );
    const Wire = fixed_wire.FixedStarkProofWire(dimensions);

    return struct {
        pub const SourceV2 = Source;
        pub const BundleV2 = Bundle;
        pub const BoundaryV2 = Boundary;
        pub const WireV2 = Wire;

        pub const OwnerV2 = opaque {
            pub fn init(
                allocator: std.mem.Allocator,
                live: *const Live,
            ) !*OwnerV2 {
                try live.validate();
                try live.requireFixedWireSource();
                try Policy.validateDimensions(dimensions, live);

                var captures = try live.initCapturedFriPair(allocator);
                var captures_owned = true;
                errdefer if (captures_owned) captures.deinit();
                const shape = try scheduleShape(&captures.children[0]);
                const right_shape = try scheduleShape(&captures.children[1]);
                if (!std.meta.eql(shape, right_shape))
                    return error.CommonFoldProfileMismatch;
                var vm_plan = try schedule.Plan.initShape(
                    allocator,
                    schedule.VM_PROGRAM_SPEC_V1,
                    shape,
                );
                var vm_plan_owned = true;
                errdefer if (vm_plan_owned) vm_plan.deinit();
                var recursion_plan = try schedule.Plan.initShape(
                    allocator,
                    schedule.RECURSION_PROGRAM_SPEC_V1,
                    shape,
                );
                var recursion_plan_owned = true;
                errdefer if (recursion_plan_owned) recursion_plan.deinit();

                const storage = try allocator.create(Storage);
                errdefer allocator.destroy(storage);
                storage.* = .{
                    .allocator = allocator,
                    .live = live,
                    .captures = captures,
                    .wires = undefined,
                    .vm_plan = vm_plan,
                    .recursion_plan = recursion_plan,
                    .root_pin = try Policy.initRootPin(live),
                    .pair = undefined,
                    .children = undefined,
                    .boundary_layout = undefined,
                    .source = undefined,
                    .authority_sha256 = undefined,
                };
                captures_owned = false;
                vm_plan_owned = false;
                recursion_plan_owned = false;
                errdefer storage.destroyInitialized();

                for (&storage.wires, live.children) |*wire, child|
                    try populateWire(dimensions, wire, child, live, Policy);
                storage.pair = .{
                    .live = live,
                    .identity_sha256 = try pairIdentity(storage),
                };
                const composition = try live.authenticatedCompositionLanes();
                for (&storage.children, live.children, composition, 0..) |
                    *destination,
                    child,
                    lane,
                    index,
                | destination.* = .{
                    .ingress = child,
                    .wire = &storage.wires[index],
                    .capture = &storage.captures.children[index],
                    .composition = lane,
                    .capture_identity_sha256 = captureIdentity(
                        &storage.captures.children[index],
                    ),
                };
                storage.boundary_layout = try schedule_mod.Layout.initBoundary(
                    live.public_schedule.callsSlice(),
                );
                storage.source = try Source.initAuthenticated(
                    allocator,
                    &storage.pair,
                    storage.root_pin,
                    &storage.vm_plan,
                    .{ &storage.recursion_plan, &storage.recursion_plan },
                    storage.children,
                    null,
                );
                storage.authority_sha256 = ownerIdentity(storage);
                try storage.validate();
                return ownerHandle(storage);
            }

            pub fn deinit(self: *OwnerV2) void {
                ownerStorage(self).destroyInitialized();
            }

            pub fn source(self: *const OwnerV2) *const Source {
                return &ownerStorageConst(self).source;
            }

            pub fn boundaryLayout(self: *const OwnerV2) schedule_mod.Layout {
                return ownerStorageConst(self).boundary_layout;
            }

            pub fn boundaryCalls(self: *const OwnerV2) []const schedule_mod.Call {
                return ownerStorageConst(self).live.public_schedule.callsSlice();
            }

            pub fn authorityIdentity(self: *const OwnerV2) [32]u8 {
                return ownerStorageConst(self).authority_sha256;
            }

            pub fn validate(self: *const OwnerV2) !void {
                return ownerStorageConst(self).validate();
            }

            pub fn validateEngineCompositionAuthority(
                self: *const OwnerV2,
            ) !void {
                const storage = ownerStorageConst(self);
                try storage.source.validateAgainstAuthority();
                try Boundary.validateAuthenticatedChildOnlyWireBoundary(
                    &storage.source,
                );
            }
        };

        const Storage = struct {
            allocator: std.mem.Allocator,
            live: *const Live,
            captures: CapturedFriPair,
            wires: [CHILD_COUNT]Wire,
            vm_plan: schedule.Plan,
            recursion_plan: schedule.Plan,
            root_pin: Policy.RootPin,
            pair: Boundary.PairPrepared,
            children: [CHILD_COUNT]Boundary.Child,
            boundary_layout: schedule_mod.Layout,
            source: Source,
            authority_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.live.validate();
                try self.root_pin.validateAgainst(self.live);
                try self.boundary_layout.validate(
                    self.live.public_schedule.callsSlice(),
                );
                try self.source.validateAgainstAuthority();
                try Boundary.validateAuthenticatedChildOnlyWireBoundary(
                    &self.source,
                );
                if (!std.mem.eql(
                    u8,
                    &self.authority_sha256,
                    &ownerIdentity(self),
                )) return error.CommonFoldSourceAuthorityMismatch;
            }

            fn destroyInitialized(self: *Storage) void {
                const allocator = self.allocator;
                self.source.deinit();
                self.recursion_plan.deinit();
                self.vm_plan.deinit();
                self.captures.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        fn ownerHandle(value: *Storage) *OwnerV2 {
            return @ptrCast(value);
        }

        fn ownerStorage(value: *OwnerV2) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn ownerStorageConst(value: *const OwnerV2) *const Storage {
            return @ptrCast(@alignCast(value));
        }

        fn pairIdentity(value: *const Storage) ![32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("stwo-zig/recursive-common-fold-pair/v2\x00");
            hash.update(&value.live.identity_sha256);
            hash.update(&value.root_pin.identity_sha256);
            for (value.live.children) |child| {
                const projection = try Policy.projectChild(
                    child,
                    value.live,
                );
                hashInt(&hash, u8, @intFromEnum(projection.role));
                hash.update(projection.graph.capture_identity_sha256);
                hash.update(projection.graph.layout_identity_sha256);
            }
            return hash.finalResult();
        }

        fn ownerIdentity(value: *const Storage) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(SOURCE_DOMAIN);
            hashInt(&hash, u16, FORMAT_VERSION);
            hashInt(&hash, u16, SCHEMA_VERSION);
            hash.update(&value.pair.identity_sha256);
            hash.update(&value.source.source_authority_digest);
            hash.update(&value.boundary_layout.identity);
            return hash.finalResult();
        }
    };
}

pub const RootPinV2 = struct {
    registry_identity_sha256: [32]u8,
    geometry_identity_sha256: [32]u8,
    proof_shape_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    fn init(live: *const live_mod.CohortV2) !RootPinV2 {
        try live.validate();
        var result = RootPinV2{
            .registry_identity_sha256 = live.geometry.registry.identity_sha256,
            .geometry_identity_sha256 = live.geometry.identity_sha256,
            .proof_shape_identity_sha256 = live.geometry
                .commonFoldGeometry().proof_shape.identity_sha256,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = rootPinIdentity(&result);
        return result;
    }

    fn validateAgainst(
        self: RootPinV2,
        live: *const live_mod.CohortV2,
    ) !void {
        const expected = try init(live);
        if (!std.meta.eql(self, expected))
            return error.CommonFoldSourceAuthorityMismatch;
    }
};

pub fn CommonFoldBoundaryV2(comptime dimensions: fixed_wire.Dimensions) type {
    return CommonFoldBoundaryForLiveV2(
        dimensions,
        live_mod.CohortV2,
        ProductionPolicyV2,
    );
}

pub fn CommonFoldBoundaryForLiveV2(
    comptime dimensions: fixed_wire.Dimensions,
    comptime Live: type,
    comptime Policy: type,
) type {
    const FixedWire = fixed_wire.FixedStarkProofWire(dimensions);
    const FoldChild = Live.FoldChild;
    return struct {
        pub const IS_LEGACY = false;
        pub const INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS = false;
        pub const RootPin = Policy.RootPin;
        pub const Wire = FixedWire;

        pub const PairPrepared = struct {
            live: *const Live,
            identity_sha256: [32]u8,
        };

        pub const Child = struct {
            ingress: FoldChild,
            wire: *const FixedWire,
            capture: *const captured_fri.Owned,
            composition: ?rows_source.AuthenticatedCompositionLane,
            capture_identity_sha256: [32]u8,
        };

        pub fn validateInputs(
            comptime expected: fixed_wire.Dimensions,
            pair: *const PairPrepared,
            root_pin: RootPin,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            children: [2]Child,
            shared: ?rows_source.SharedArithmeticInput,
        ) !void {
            if (!std.meta.eql(expected, dimensions) or
                recursion_plans[0] != recursion_plans[1] or shared != null)
            {
                return error.CommonFoldProfileMismatch;
            }
            try pair.live.validate();
            try Policy.validateRootPin(root_pin, pair.live);
            try vm_plan.validate();
            try recursion_plans[0].validate();
            if (vm_plan.schema != .vm or recursion_plans[0].schema != .recursion)
                return error.CommonFoldProfileMismatch;
            try validateChildren(pair, children);
        }

        pub fn validateAuthenticatedChildOnlyWireBoundary(
            source: anytype,
        ) !void {
            try wire_boundary.validateAuthenticatedChildOnly(source);
        }

        pub fn fillQueryWords(
            comptime expected: fixed_wire.Dimensions,
            pair: *const PairPrepared,
            children: [2]Child,
            destination: []M31,
        ) !void {
            if (!std.meta.eql(expected, dimensions) or
                destination.len != CHILD_COUNT * dimensions.query_count)
            {
                return error.CommonFoldQueryAuthorityMismatch;
            }
            try validateChildren(pair, children);
            for (children, 0..) |child, child_index| {
                const projection = try Policy.projectChild(
                    child.ingress,
                    pair.live,
                );
                if (child.capture.raw_queries.len !=
                    dimensions.query_count or
                    dimensions.query_count != projection.query_words.len)
                {
                    return error.CommonFoldQueryAuthorityMismatch;
                }
                const words = projection.query_words.*;
                @memcpy(
                    destination[child_index * dimensions.query_count ..][0..dimensions.query_count],
                    &words,
                );
                const mask = (@as(u32, 1) << @intCast(
                    child.capture.circuit.lifting_log_size,
                )) - 1;
                for (words, child.capture.raw_queries) |full, projected|
                    if ((full.toU32() & mask) != projected.toU32())
                        return error.CommonFoldQueryAuthorityMismatch;
            }
        }

        pub fn initCompositionRows(
            allocator: std.mem.Allocator,
            pair: *const PairPrepared,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            children: [2]Child,
        ) !rows_source.CompositionRowsAuthority {
            try validateChildren(pair, children);
            var lanes: [2]recursion.air.composition_circuit.RecursionLane =
                undefined;
            var evaluations: [2]recursion.air.verifier_arithmetic_lowering
                .Evaluation = undefined;
            for (pair.live.children, 0..) |live_child, index| {
                const projection = try Policy.projectChild(
                    live_child,
                    pair.live,
                );
                lanes[index] = projection.graph.lane;
                lanes[index].verifier_id = if (index == 0)
                    rows_source.LEFT_RECURSION_VERIFIER_ID
                else
                    rows_source.RIGHT_RECURSION_VERIFIER_ID;
                lanes[index].circuit_id = if (index == 0)
                    live_mod.LEFT_POSITION_CIRCUIT_ID
                else
                    live_mod.RIGHT_POSITION_CIRCUIT_ID;
                lanes[index].statement_scope = if (index == 0)
                    rows_source.LEFT_COMPOSITION_STATEMENT_SCOPE
                else
                    rows_source.RIGHT_COMPOSITION_STATEMENT_SCOPE;
                evaluations[index] = projection.graph.evaluation;
            }
            return rows_source.CompositionRowsAuthority
                .initFromAuthenticatedRecorderLanes(
                allocator,
                vm_plan,
                recursion_plan,
                children[0].capture.sampled_value_count,
                lanes,
                evaluations,
            );
        }

        pub fn validateCompositionRows(
            comptime expected: fixed_wire.Dimensions,
            source: anytype,
            rows: *const rows_source.CompositionRowsAuthority,
        ) !void {
            if (!std.meta.eql(expected, dimensions))
                return error.CommonFoldProfileMismatch;
            const left = try Policy.projectChild(
                source.pair.live.children[0],
                source.pair.live,
            );
            const right = try Policy.projectChild(
                source.pair.live.children[1],
                source.pair.live,
            );
            const evaluations = [2]recursion.air.verifier_arithmetic_lowering
                .Evaluation{ left.graph.evaluation, right.graph.evaluation };
            try rows.validateAuthenticatedRecorderLanes(evaluations);
            try rows.control_preprocessing.validateAgainst(
                source.vm_plan,
                source.recursion_plans[0],
            );
        }

        pub fn validateSource(
            comptime expected: fixed_wire.Dimensions,
            source: anytype,
        ) !void {
            try validateInputs(
                expected,
                source.pair,
                source.root_pin,
                source.vm_plan,
                source.recursion_plans,
                source.children,
                source.shared_arithmetic,
            );
            var query_words: [CHILD_COUNT * dimensions.query_count]M31 =
                undefined;
            try fillQueryWords(
                expected,
                source.pair,
                source.children,
                &query_words,
            );
            if (!m31SliceEql(&query_words, source.query_word_storage))
                return error.CommonFoldQueryAuthorityMismatch;
        }

        pub fn sourceAuthorityDigest(
            comptime expected: fixed_wire.Dimensions,
            source: anytype,
        ) [32]u8 {
            std.debug.assert(std.meta.eql(expected, dimensions));
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(SOURCE_DOMAIN);
            hash.update(&source.pair.identity_sha256);
            hash.update(&source.root_pin.identity_sha256);
            for (source.children) |child| {
                hash.update(&child.capture_identity_sha256);
                hash.update(&child.composition.?.circuit_identity);
            }
            for (source.query_word_storage) |word|
                hashInt(&hash, u32, word.toU32());
            hash.update(&source.composition_rows.?.authority_digest);
            hash.update(&source.fri_rows.authority_digest);
            hash.update(&source.arithmetic_rows.?.authority_digest);
            hash.update(&source.merkle_rows.authority_digest);
            return hash.finalResult();
        }

        fn validateChildren(
            pair: *const PairPrepared,
            children: [2]Child,
        ) !void {
            if (children[0].wire == children[1].wire or
                children[0].capture == children[1].capture)
            {
                return error.CommonFoldDuplicateChild;
            }
            for (children, pair.live.children) |
                child,
                expected,
            | {
                const projection = try Policy.projectChild(
                    child.ingress,
                    pair.live,
                );
                const expected_projection = try Policy.projectChild(
                    expected,
                    pair.live,
                );
                try Policy.validateChildCustody(
                    projection,
                    expected_projection,
                    pair.live,
                );
                if (projection.capture != expected_projection.capture or
                    !std.mem.eql(
                        u8,
                        &child.capture_identity_sha256,
                        &captureIdentity(child.capture),
                    )) return error.CommonFoldCaptureMismatch;
                try validateWireAgainstFreshCapture(
                    dimensions,
                    child.wire,
                    child.ingress,
                    pair.live,
                    Policy,
                );
                const composition = child.composition orelse
                    return error.CommonFoldCaptureMismatch;
                try composition.validate();
            }
        }
    };
}

fn validateProductionDimensions(
    comptime dimensions: fixed_wire.Dimensions,
    live: *const live_mod.CohortV2,
) !void {
    const shape = live.geometry.commonFoldGeometry().proof_shape;
    const expected = fixed_wire.Dimensions{
        .commitment_count = shape.tree_count,
        .claimed_sum_count = shape.claimed_sum_count,
        .sampled_value_count = shape.sampled_value_count,
        .queried_value_count = shape.queried_value_count,
        .trace_path_count = shape.trace_path_count,
        .fri_layer_count = shape.fri_layer_count,
        .query_count = shape.query_count,
        .maximum_fold_width = shape.maximum_fold_width,
        .last_layer_coefficient_count = shape.last_layer_coefficient_count,
        .maximum_merkle_depth = shape.maximum_merkle_depth,
    };
    if (!std.meta.eql(dimensions, expected))
        return error.CommonFoldProfileMismatch;
}

fn populateWire(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *fixed_wire.FixedStarkProofWire(dimensions),
    ingress: anytype,
    live: anytype,
    comptime Policy: type,
) !void {
    const projection = try Policy.projectChild(ingress, live);
    const capture = projection.capture;
    if (capture.commitments.len != dimensions.commitment_count or
        projection.claimed_sums.len != dimensions.claimed_sum_count or
        capture.sampled_values.len != dimensions.sampled_value_count or
        capture.queried_values.len != dimensions.queried_value_count or
        capture.trace_paths.len * dimensions.query_count !=
            dimensions.trace_path_count or
        capture.fri.layers.len != dimensions.fri_layer_count or
        capture.last_layer_coefficients.len !=
            dimensions.last_layer_coefficient_count)
    {
        return error.CommonFoldWireMismatch;
    }
    @memset(std.mem.asBytes(destination), 0);
    @memcpy(&destination.commitments, capture.commitments);
    for (projection.claimed_sums, &destination.claimed_sums) |
        value,
        *target,
    | target.* = qm31Wire(value);
    for (capture.sampled_values, &destination.sampled_values) |value, *target|
        target.* = qm31Wire(value);
    for (capture.queried_values, &destination.queried_values) |value, *target|
        target.* = value.toU32();
    for (capture.trace_paths) |source| if (source.path_depth > dimensions.maximum_merkle_depth) return error.CommonFoldWireMismatch;
    for (capture.trace_paths, 0..) |source, tree| for (
        0..dimensions.query_count,
    ) |query| {
        const target = &destination.trace_paths[
            tree * dimensions.query_count + query
        ];
        target.active_depth = source.path_depth;
        for (source.path(query), 0..) |sibling, depth|
            target.siblings[depth] = sibling;
    };
    for (capture.fri.layers) |source| if (source.fold_width == 0 or
        source.fold_width > dimensions.maximum_fold_width or
        source.path_depth > dimensions.maximum_merkle_depth) return error.CommonFoldWireMismatch;
    for (capture.fri.layers, &destination.fri_layers) |source, *target| {
        target.active_width = source.fold_width;
        target.commitment = source.commitment;
        for (0..dimensions.query_count) |query| {
            for (source.queryValues(query), 0..) |value, value_index|
                target.queries[query].values[value_index] = qm31Wire(value);
            target.queries[query].path.active_depth = source.path_depth;
            for (source.queryPath(query), 0..) |sibling, depth|
                target.queries[query].path.siblings[depth] = sibling;
        }
    }
    for (capture.last_layer_coefficients, &destination.last_layer_coefficients) |
        value,
        *target,
    | target.* = qm31Wire(value);
    destination.interaction_pow = projection.statement.interaction_pow_nonce;
    destination.pcs_pow = capture.proof_of_work;
    try validateWireAgainstFreshCapture(
        dimensions,
        destination,
        ingress,
        live,
        Policy,
    );
}

/// Deep value comparison retained at the hostile/source-validation boundary.
/// A fixed wire is transport copied from a fresh verifier capture, never an
/// independently trusted statement. This check also detects mutations after
/// `OwnerV2.init` without allocating a second multi-megabyte wire.
fn validateWireAgainstFreshCapture(
    comptime dimensions: fixed_wire.Dimensions,
    wire: *const fixed_wire.FixedStarkProofWire(dimensions),
    ingress: anytype,
    live: anytype,
    comptime Policy: type,
) !void {
    const projection = try Policy.projectChild(ingress, live);
    const capture = projection.capture;
    if (capture.commitments.len != dimensions.commitment_count or
        projection.claimed_sums.len != dimensions.claimed_sum_count or
        capture.sampled_values.len != dimensions.sampled_value_count or
        capture.queried_values.len != dimensions.queried_value_count or
        capture.trace_paths.len * dimensions.query_count !=
            dimensions.trace_path_count or
        capture.fri.layers.len != dimensions.fri_layer_count or
        capture.last_layer_coefficients.len !=
            dimensions.last_layer_coefficient_count or
        wire.interaction_pow != projection.statement.interaction_pow_nonce or
        wire.pcs_pow != capture.proof_of_work)
    {
        return error.CommonFoldWireMismatch;
    }
    for (capture.commitments, wire.commitments) |actual, retained|
        if (!std.meta.eql(actual, retained))
            return error.CommonFoldWireMismatch;
    for (projection.claimed_sums, wire.claimed_sums) |actual, retained|
        if (!std.meta.eql(qm31Wire(actual), retained))
            return error.CommonFoldWireMismatch;
    for (capture.sampled_values, wire.sampled_values) |actual, retained|
        if (!std.meta.eql(qm31Wire(actual), retained))
            return error.CommonFoldWireMismatch;
    for (capture.queried_values, wire.queried_values) |actual, retained|
        if (actual.toU32() != retained)
            return error.CommonFoldWireMismatch;
    for (capture.trace_paths, 0..) |source, tree| for (
        0..dimensions.query_count,
    ) |query| {
        if (source.path_depth > dimensions.maximum_merkle_depth)
            return error.CommonFoldWireMismatch;
        const retained = wire.trace_paths[
            tree * dimensions.query_count + query
        ];
        if (retained.active_depth != source.path_depth)
            return error.CommonFoldWireMismatch;
        for (source.path(query), retained.siblings[0..source.path_depth]) |
            actual,
            sibling,
        | if (!std.meta.eql(actual, sibling))
            return error.CommonFoldWireMismatch;
        for (retained.siblings[source.path_depth..]) |sibling|
            if (!isZeroDigest(sibling))
                return error.CommonFoldWireMismatch;
    };
    for (capture.fri.layers, wire.fri_layers) |source, retained| {
        if (source.fold_width == 0 or
            source.fold_width > dimensions.maximum_fold_width or
            source.path_depth > dimensions.maximum_merkle_depth or
            retained.active_width != source.fold_width or
            !std.meta.eql(retained.commitment, source.commitment))
        {
            return error.CommonFoldWireMismatch;
        }
        for (0..dimensions.query_count) |query| {
            const retained_query = retained.queries[query];
            if (retained_query.path.active_depth != source.path_depth)
                return error.CommonFoldWireMismatch;
            for (source.queryValues(query), retained_query.values[0..source.fold_width]) |
                actual,
                value,
            | if (!std.meta.eql(qm31Wire(actual), value))
                return error.CommonFoldWireMismatch;
            for (retained_query.values[source.fold_width..]) |value|
                if (!isZeroQm31(value))
                    return error.CommonFoldWireMismatch;
            for (
                source.queryPath(query),
                retained_query.path.siblings[0..source.path_depth],
            ) |actual, sibling| if (!std.meta.eql(actual, sibling))
                return error.CommonFoldWireMismatch;
            for (retained_query.path.siblings[source.path_depth..]) |sibling|
                if (!isZeroDigest(sibling))
                    return error.CommonFoldWireMismatch;
        }
    }
    for (
        capture.last_layer_coefficients,
        wire.last_layer_coefficients,
    ) |actual, retained| if (!std.meta.eql(qm31Wire(actual), retained))
        return error.CommonFoldWireMismatch;
}

fn isZeroQm31(value: fixed_wire.Qm31Wire) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

fn isZeroDigest(value: recursion.poseidon2_channel.Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

fn scheduleShape(value: *const captured_fri.Owned) !schedule.ScheduleShape {
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    if (value.trace_tree_heights.len != tree_heights.len)
        return error.CommonFoldProfileMismatch;
    @memcpy(&tree_heights, value.trace_tree_heights);
    return transcript_shape.derive(
        value.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = value.sampled_value_count,
            .queried_values_per_query = value.queried_values_per_query,
            .claimed_sum_count = value.claimed_sum_count,
            .interaction_pow_bits = value.interaction_pow_bits,
            .pcs_pow_bits = value.pcs_pow_bits,
        },
    );
}

fn rootPinIdentity(value: *const RootPinV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/recursive-common-fold-root-pin/v2\x00");
    hash.update(&value.registry_identity_sha256);
    hash.update(&value.geometry_identity_sha256);
    hash.update(&value.proof_shape_identity_sha256);
    return hash.finalResult();
}

const ProductionPolicyV2 = struct {
    pub const RootPin = RootPinV2;

    pub fn initRootPin(live: *const live_mod.CohortV2) !RootPin {
        return RootPin.init(live);
    }

    pub fn validateRootPin(
        pin: RootPin,
        live: *const live_mod.CohortV2,
    ) !void {
        return pin.validateAgainst(live);
    }

    pub fn validateDimensions(
        comptime dimensions: fixed_wire.Dimensions,
        live: *const live_mod.CohortV2,
    ) !void {
        return validateProductionDimensions(dimensions, live);
    }

    pub fn projectChild(
        child: live_mod.FreshFoldChildV2,
        live: *const live_mod.CohortV2,
    ) !@import("recursive_common_fold_child_capability_v2.zig").ProjectionV2 {
        return child.projection(live.registry());
    }

    pub fn validateChildCustody(
        actual: @import("recursive_common_fold_child_capability_v2.zig").ProjectionV2,
        expected: @import("recursive_common_fold_child_capability_v2.zig").ProjectionV2,
        _: *const live_mod.CohortV2,
    ) !void {
        if (actual.wrapper.artifact != expected.wrapper.artifact or
            actual.node_public != expected.node_public or
            actual.geometry != expected.geometry or
            actual.capture != expected.capture)
        {
            return error.CommonFoldCaptureMismatch;
        }
    }
};

fn captureIdentity(value: *const captured_fri.Owned) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/recursive-common-fold-captured-fri/v2\x00");
    hash.update(&value.circuit.identity_digest);
    hash.update(&value.pcs_circuit.identity_digest);
    hashInt(&hash, u32, value.sampled_value_count);
    hashInt(&hash, u32, value.queried_values_per_query);
    hashInt(&hash, u32, value.claimed_sum_count);
    for (value.sampled_values) |item| hashQm31(&hash, item);
    for (value.queried_values) |item| hashInt(&hash, u32, item.toU32());
    for (value.raw_queries) |item| hashInt(&hash, u32, item.toU32());
    for (value.trace_roots) |digest| for (digest) |word|
        hashInt(&hash, u32, word);
    for (value.fri_roots) |digest| for (digest) |word|
        hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn qm31Wire(value: QM31) fixed_wire.Qm31Wire {
    const words = value.toM31Array();
    return .{
        words[0].toU32(),
        words[1].toU32(),
        words[2].toU32(),
        words[3].toU32(),
    };
}

fn m31SliceEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or CHILD_COUNT != 2 or
        ROW_COUNT != 17 or PRODUCTION_ACTIVATION or PROOF_BYTE_REPARSES != 0 or
        CAPTURED_FRI_OWNERS_PER_CHILD != 1 or
        !ROWS_18_THROUGH_34_AVAILABLE)
    {
        @compileError("common-fold fixed-wire source contract drifted");
    }
}
