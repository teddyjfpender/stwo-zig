//! Authenticated temporal-parent source for universal rows 18--34.
//!
//! Two independently verified 39-claim SegmentV2 children cross this
//! boundary exactly once. The owner retains two opaque admissions, exactly
//! one `captured_fri.Owned` per child, one fixed wire per child, and one
//! monomorphized instance of the shared binary FRI row source. No proof bytes
//! are reparsed and no 39-to-36 claim projection exists.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const context_authority = @import("recursive_temporal_parent_context_v3.zig");
const outer_admission = @import("recursive_segment_v2_outer_admission_v2.zig");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const row18_source = @import("recursive_temporal_parent_row18_source_v3.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const temporal_manifest = @import("recursive_temporal_parent_manifest_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const rows_source = recursion.binary_fri_outer_source;
const rows_bundle = recursion.binary_fri_outer_bundle;
const captured_fri = recursion.captured_fri;
const fixed_wire = recursion.fixed_wire;
const schedule = recursion.air.verifier_schedule;
const transcript_shape = recursion.transcript_shape;
const temporal_schedule = recursion.temporal_shared_poseidon_schedule_v3;

pub const FORMAT_VERSION = context_authority.FORMAT_VERSION;
pub const SCHEMA_VERSION = context_authority.SCHEMA_VERSION;
pub const CHILD_COUNT = context_authority.CHILD_COUNT;
pub const ROW_COUNT: usize = rows_source.ROW_COUNT;
pub const CLAIM_COUNT: usize = outer_admission.CLAIM_COUNT;
/// One authoritative SegmentV2 outer-proof profile. Admission derives and
/// checks these dimensions from each verifier capture before this suffix may
/// instantiate its fixed wire.
pub const SEGMENT_V2_OUTER_DIMENSIONS =
    outer_admission.SEGMENT_V2_OUTER_DIMENSIONS;
pub const CONTEXT_DOMAIN = context_authority.CONTEXT_DOMAIN;
pub const SOURCE_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-suffix-source/v3\x00";

pub const PROOF_BYTE_REPARSES: usize = 0;
pub const CAPTURED_FRI_OWNERS_PER_CHILD: usize = 1;
pub const LOSSY_V1_PROJECTION_AVAILABLE = false;
pub const ROWS_18_THROUGH_34_AVAILABLE = true;
pub const COMPLETE_PARENT_PROOF_AVAILABLE = false;
pub const PRODUCTION_CAPABILITY = false;

pub const Error = error{
    ArithmeticOverflow,
    AuthorityIdentityMismatch,
    CaptureAuthorityMismatch,
    ContextAuthorityMismatch,
    DuplicateChild,
    ProfileMismatch,
    QueryAuthorityMismatch,
    SourceAuthorityMismatch,
    WireAuthorityMismatch,
};

pub const Digest = context_authority.Digest;
pub const ContextReceiptV3 = context_authority.ContextReceiptV3;
pub const context_test_support = context_authority.test_support;

/// Compile-time source and bundle family for one exact admitted outer-proof
/// geometry. The owner is opaque so every pointer borrowed by `Source` remains
/// stable until `deinit`.
pub fn Types(comptime proof_dimensions: fixed_wire.Dimensions) type {
    proof_dimensions.validate();
    const Boundary = TemporalBoundaryV3(proof_dimensions);
    const Source = rows_source.AuthenticatedSource(proof_dimensions, Boundary);
    const Bundle = rows_bundle.BundleForSourceScheduleAndManifest(
        proof_dimensions,
        Source,
        temporal_schedule,
        temporal_manifest,
    );
    const Wire = fixed_wire.FixedStarkProofWire(proof_dimensions);

    return struct {
        pub const SourceV3 = Source;
        pub const BundleV3 = Bundle;
        pub const BoundaryV3 = Boundary;
        pub const WireV3 = Wire;
        pub const SharedPoseidonCallLayoutV3 = temporal_schedule.Layout;
        pub const OwnedCompletePoseidonScheduleV3 =
            temporal_schedule.OwnedCompleteSchedule;

        pub const OwnerV3 = opaque {
            pub fn init(
                allocator: std.mem.Allocator,
                inputs: prefix_runtime.RuntimeInputsV1,
                row18: *row18_source.Row18AuthorityV3,
                transcript_rows: *const temporal_nonfri.PreparedTranscriptRowsV2,
                shared_arithmetic: ?rows_source.SharedArithmeticInput,
            ) !*OwnerV3 {
                _ = try inputs.validate();
                try transcript_rows.validate();
                if (!std.meta.eql(
                    transcript_rows.pair_authority_id,
                    inputs.artifacts.pair.authority_id,
                )) return error.ContextAuthorityMismatch;

                var admissions: [CHILD_COUNT]*outer_admission
                    .AdmittedSegmentV2ChildV2 = undefined;
                var admission_count: usize = 0;
                errdefer for (admissions[0..admission_count]) |admission|
                    admission.deinit();
                for (inputs.artifacts.children, 0..) |child, child_index| {
                    admissions[child_index] = try outer_admission
                        .admitVerifiedSegmentV2ChildV2(
                        allocator,
                        child.publication,
                        child.capture,
                        child.recursive_witness,
                        inputs.artifacts.segment_manifests[child_index],
                    );
                    admission_count += 1;
                    if (!std.meta.eql(
                        admissions[child_index].dimensions(),
                        proof_dimensions,
                    )) return error.ProfileMismatch;
                }
                const left_admission_id = admissions[0].identity();
                const right_admission_id = admissions[1].identity();
                if (std.mem.eql(u8, &left_admission_id, &right_admission_id))
                    return error.DuplicateChild;

                var captures: [CHILD_COUNT]captured_fri.Owned = undefined;
                var capture_count: usize = 0;
                errdefer for (captures[0..capture_count]) |*capture|
                    capture.deinit();
                for (&captures, admissions) |*capture, admission| {
                    capture.* = try admission.initCapturedFriOwned(allocator);
                    capture_count += 1;
                }
                try validateMatchingCaptureProfiles(.{
                    &captures[0],
                    &captures[1],
                });

                const shape = try scheduleShape(&captures[0]);
                const right_shape = try scheduleShape(&captures[1]);
                if (!std.meta.eql(shape, right_shape))
                    return error.ProfileMismatch;
                var vm_plan = try schedule.Plan.initShape(
                    allocator,
                    inputs.prepared_leaves[0].vm_plan.spec,
                    shape,
                );
                var vm_plan_owned_locally = true;
                errdefer if (vm_plan_owned_locally) vm_plan.deinit();
                var recursion_plan = try schedule.Plan.initShape(
                    allocator,
                    inputs.prepared_leaves[0].recursion_plan.spec,
                    shape,
                );
                var recursion_plan_owned_locally = true;
                errdefer if (recursion_plan_owned_locally)
                    recursion_plan.deinit();

                const context = try ContextReceiptV3.init(inputs.artifacts);
                const boundary_calls = try allocator.alloc(
                    temporal_schedule.Call,
                    transcript_rows.rows.len,
                );
                var boundary_calls_owned_locally = true;
                errdefer if (boundary_calls_owned_locally)
                    allocator.free(boundary_calls);
                try transcript_rows.fillProviderCallsInto(boundary_calls);
                const boundary_layout = try temporal_schedule.Layout
                    .initTemporalBoundary(boundary_calls.len, boundary_calls);
                const storage_value = try allocator.create(Storage);
                errdefer allocator.destroy(storage_value);
                storage_value.* = .{
                    .allocator = allocator,
                    .inputs = inputs,
                    .row18 = row18,
                    .transcript_rows = transcript_rows,
                    .admissions = admissions,
                    .captures = captures,
                    .wires = undefined,
                    .vm_plan = vm_plan,
                    .recursion_plan = recursion_plan,
                    .context = context,
                    .boundary_calls = boundary_calls,
                    .boundary_layout = boundary_layout,
                    .pair = undefined,
                    .source = undefined,
                    .authority_id = undefined,
                };
                for (storage_value.admissions, 0..) |admission, child_index|
                    try admission.fillFixedWireInto(
                        proof_dimensions,
                        &storage_value.wires[child_index],
                    );
                storage_value.pair = .{
                    .inputs = inputs,
                    .row18 = row18,
                    .transcript_rows = transcript_rows,
                    .context = context,
                    .authority_id = boundaryPairIdentity(storage_value),
                };
                const lanes = row18.arithmeticLanes();
                var children: [CHILD_COUNT]Boundary.Child = undefined;
                for (&children, 0..) |*child, child_index| child.* = .{
                    .admission = storage_value.admissions[child_index],
                    .wire = &storage_value.wires[child_index],
                    .capture = &storage_value.captures[child_index],
                    .composition = lanes[child_index],
                    .admission_id = storage_value.admissions[child_index].identity(),
                    .wire_sha_id = wireIdentity(&storage_value.wires[child_index]),
                    .capture_sha_id = captureIdentity(&storage_value.captures[child_index]),
                };
                storage_value.source = try Source.initAuthenticated(
                    allocator,
                    &storage_value.pair,
                    context,
                    &storage_value.vm_plan,
                    .{ &storage_value.recursion_plan, &storage_value.recursion_plan },
                    children,
                    shared_arithmetic,
                );
                admission_count = 0;
                capture_count = 0;
                vm_plan_owned_locally = false;
                recursion_plan_owned_locally = false;
                boundary_calls_owned_locally = false;
                errdefer {
                    storage_value.source.deinit();
                    storage_value.allocator.free(storage_value.boundary_calls);
                    storage_value.recursion_plan.deinit();
                    storage_value.vm_plan.deinit();
                    for (&storage_value.captures) |*capture| capture.deinit();
                    for (storage_value.admissions) |admission| admission.deinit();
                }
                storage_value.authority_id = ownerIdentity(storage_value);
                try storage_value.validate();
                return ownerHandle(storage_value);
            }

            pub fn deinit(self: *OwnerV3) void {
                const value = ownerStorage(self);
                const allocator = value.allocator;
                value.source.deinit();
                value.allocator.free(value.boundary_calls);
                value.recursion_plan.deinit();
                value.vm_plan.deinit();
                for (&value.captures) |*capture| capture.deinit();
                for (value.admissions) |admission| admission.deinit();
                value.* = undefined;
                allocator.destroy(value);
            }

            pub fn source(self: *const OwnerV3) *const Source {
                return &ownerStorageConst(self).source;
            }

            pub fn dimensions(_: *const OwnerV3) fixed_wire.Dimensions {
                return proof_dimensions;
            }

            pub fn authorityIdentity(self: *const OwnerV3) [32]u8 {
                return ownerStorageConst(self).authority_id;
            }

            pub fn contextReceipt(self: *const OwnerV3) ContextReceiptV3 {
                return ownerStorageConst(self).context;
            }

            pub fn bundleLogSizes(self: *const OwnerV3) ![ROW_COUNT]u32 {
                return self.source().bundleLogSizes();
            }

            pub fn boundaryScheduleReceipt(
                self: *const OwnerV3,
            ) temporal_schedule.Layout {
                return ownerStorageConst(self).boundary_layout;
            }

            pub fn boundaryPoseidonCalls(
                self: *const OwnerV3,
            ) []const temporal_schedule.Call {
                return ownerStorageConst(self).boundary_calls;
            }

            pub fn initCompleteSchedule(
                self: *const OwnerV3,
                allocator: std.mem.Allocator,
                verifier_core_calls: []const temporal_schedule.Call,
            ) !temporal_schedule.OwnedCompleteSchedule {
                const value = ownerStorageConst(self);
                return temporal_schedule.OwnedCompleteSchedule.init(
                    allocator,
                    &value.boundary_layout,
                    value.boundary_calls,
                    verifier_core_calls,
                );
            }

            pub fn validate(self: *const OwnerV3) !void {
                return ownerStorageConst(self).validate();
            }
        };

        const Storage = struct {
            allocator: std.mem.Allocator,
            inputs: prefix_runtime.RuntimeInputsV1,
            row18: *row18_source.Row18AuthorityV3,
            transcript_rows: *const temporal_nonfri.PreparedTranscriptRowsV2,
            admissions: [CHILD_COUNT]*outer_admission.AdmittedSegmentV2ChildV2,
            captures: [CHILD_COUNT]captured_fri.Owned,
            wires: [CHILD_COUNT]Wire,
            vm_plan: schedule.Plan,
            recursion_plan: schedule.Plan,
            context: ContextReceiptV3,
            boundary_calls: []temporal_schedule.Call,
            boundary_layout: temporal_schedule.Layout,
            pair: Boundary.PairPrepared,
            source: Source,
            authority_id: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.source.validateAgainstAuthority();
                try self.context.validateAgainst(self.inputs.artifacts);
                try self.boundary_layout.validate(self.boundary_calls);
                if (!std.mem.eql(
                    u8,
                    &self.authority_id,
                    &ownerIdentity(self),
                )) return error.AuthorityIdentityMismatch;
            }
        };

        fn ownerHandle(value: *Storage) *OwnerV3 {
            return @ptrCast(value);
        }

        fn ownerStorage(value: *OwnerV3) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn ownerStorageConst(value: *const OwnerV3) *const Storage {
            return @ptrCast(@alignCast(value));
        }

        fn boundaryPairIdentity(value: *const Storage) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("stwo-zig/typed-air/temporal-suffix-pair-view/v3\x00");
            hash.update(&value.context.identity);
            hash.update(&value.boundary_layout.identity);
            hash.update(&value.boundary_layout.call_buffer_id);
            const row18_id = value.row18.authorityIdentity();
            hash.update(&row18_id);
            hash.update(&value.transcript_rows.authority_sha_id);
            for (value.admissions) |admission| {
                const admission_id = admission.identity();
                hash.update(&admission_id);
            }
            return hash.finalResult();
        }

        fn ownerIdentity(value: *const Storage) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("stwo-zig/typed-air/temporal-suffix-owner/v3\x00");
            hash.update(&value.pair.authority_id);
            hash.update(&value.source.source_authority_digest);
            hash.update(&value.context.identity);
            for (value.source.bundleLogSizes() catch unreachable) |log_size|
                hashInt(&hash, u32, log_size);
            return hash.finalResult();
        }
    };
}

pub const SegmentV2 = Types(SEGMENT_V2_OUTER_DIMENSIONS);

pub fn TemporalBoundaryV3(comptime dimensions: fixed_wire.Dimensions) type {
    const FixedWire = fixed_wire.FixedStarkProofWire(dimensions);
    return struct {
        pub const IS_LEGACY = false;
        pub const INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS = false;
        pub const RootPin = ContextReceiptV3;
        pub const Wire = FixedWire;

        pub const PairPrepared = struct {
            inputs: prefix_runtime.RuntimeInputsV1,
            row18: *row18_source.Row18AuthorityV3,
            transcript_rows: *const temporal_nonfri.PreparedTranscriptRowsV2,
            context: ContextReceiptV3,
            authority_id: [32]u8,
        };

        pub const Child = struct {
            admission: *const outer_admission.AdmittedSegmentV2ChildV2,
            wire: *const FixedWire,
            capture: *const captured_fri.Owned,
            composition: ?rows_source.AuthenticatedCompositionLane,
            admission_id: [32]u8,
            wire_sha_id: [32]u8,
            capture_sha_id: [32]u8,
        };

        pub fn validateInputs(
            comptime expected_dimensions: fixed_wire.Dimensions,
            pair: *const PairPrepared,
            root_pin: RootPin,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            children: [2]Child,
            shared: ?rows_source.SharedArithmeticInput,
        ) !void {
            if (!std.meta.eql(expected_dimensions, dimensions))
                return error.ProfileMismatch;
            _ = try pair.inputs.validate();
            try pair.context.validateAgainst(pair.inputs.artifacts);
            try root_pin.validateAgainst(pair.inputs.artifacts);
            if (!std.meta.eql(pair.context, root_pin) or
                recursion_plans[0] != recursion_plans[1])
            {
                return error.ContextAuthorityMismatch;
            }
            try vm_plan.validate();
            try recursion_plans[0].validate();
            if (vm_plan.schema != .vm or recursion_plans[0].schema != .recursion)
                return error.ProfileMismatch;
            if (shared) |input| try input.validate();
            try validateChildren(children);
        }

        pub fn fillQueryWords(
            comptime expected_dimensions: fixed_wire.Dimensions,
            pair: *const PairPrepared,
            children: [2]Child,
            destination: []M31,
        ) !void {
            if (!std.meta.eql(expected_dimensions, dimensions) or
                destination.len != CHILD_COUNT * dimensions.query_count or
                dimensions.query_count != temporal_nonfri.CHILD_QUERY_COUNT)
            {
                return error.QueryAuthorityMismatch;
            }
            try validateChildren(children);
            var words: [CHILD_COUNT][temporal_nonfri.CHILD_QUERY_COUNT]M31 =
                undefined;
            try pair.transcript_rows.fillQueryWordsInto(&words);
            @memcpy(destination[0..dimensions.query_count], words[0][0..]);
            @memcpy(
                destination[dimensions.query_count..][0..dimensions.query_count],
                words[1][0..],
            );
            for (children, words) |child, lane_words| {
                const mask = (@as(u32, 1) <<
                    @intCast(child.capture.circuit.lifting_log_size)) - 1;
                for (lane_words, child.capture.raw_queries) |full, projected|
                    if ((full.toU32() & mask) != projected.toU32())
                        return error.QueryAuthorityMismatch;
            }
        }

        pub fn initCompositionRows(
            allocator: std.mem.Allocator,
            pair: *const PairPrepared,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            children: [2]Child,
        ) !rows_source.CompositionRowsAuthority {
            try validateChildren(children);
            return pair.row18.cloneRows(
                allocator,
                pair.inputs,
                vm_plan,
                recursion_plan,
                children[0].capture.sampled_value_count,
            );
        }

        pub fn validateSource(
            comptime expected_dimensions: fixed_wire.Dimensions,
            source: anytype,
        ) !void {
            try validateInputs(
                expected_dimensions,
                source.pair,
                source.root_pin,
                source.vm_plan,
                source.recursion_plans,
                source.children,
                source.shared_arithmetic,
            );
            var expected: [CHILD_COUNT * dimensions.query_count]M31 = undefined;
            try fillQueryWords(
                expected_dimensions,
                source.pair,
                source.children,
                &expected,
            );
            if (!m31SliceEql(&expected, source.query_word_storage))
                return error.QueryAuthorityMismatch;
        }

        pub fn validateCompositionRows(
            comptime expected_dimensions: fixed_wire.Dimensions,
            source: anytype,
            rows: *const rows_source.CompositionRowsAuthority,
        ) !void {
            if (!std.meta.eql(expected_dimensions, dimensions))
                return error.ProfileMismatch;
            const lanes = [CHILD_COUNT]recursion.air
                .verifier_arithmetic_lowering.Evaluation{
                source.children[0].composition.?.evaluation,
                source.children[1].composition.?.evaluation,
            };
            try rows.validateAuthenticatedRecorderLanes(lanes);
            try rows.control_preprocessing.validateAgainst(
                source.vm_plan,
                source.recursion_plans[0],
            );
        }

        pub fn sourceAuthorityDigest(
            comptime expected_dimensions: fixed_wire.Dimensions,
            source: anytype,
        ) [32]u8 {
            std.debug.assert(std.meta.eql(expected_dimensions, dimensions));
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(SOURCE_DOMAIN);
            hashInt(&hash, u16, FORMAT_VERSION);
            hashInt(&hash, u16, SCHEMA_VERSION);
            hash.update(&source.pair.authority_id);
            hash.update(&source.root_pin.identity);
            for (source.vm_plan.authority_digest) |word| hashInt(&hash, u32, word);
            for (source.recursion_plans) |plan| for (plan.authority_digest) |word|
                hashInt(&hash, u32, word);
            for (source.children) |child| {
                hash.update(&child.admission_id);
                hash.update(&child.wire_sha_id);
                hash.update(&child.capture_sha_id);
                hash.update(&child.composition.?.circuit_identity);
            }
            for (source.query_word_storage) |word|
                hashInt(&hash, u32, word.toU32());
            if (source.shared_arithmetic) |input| hash.update(&input.identity_digest);
            hash.update(&source.composition_rows.?.authority_digest);
            hash.update(&source.fri_rows.authority_digest);
            hash.update(&source.arithmetic_rows.?.authority_digest);
            hash.update(&source.merkle_rows.authority_digest);
            return hash.finalResult();
        }

        fn validateChildren(children: [2]Child) !void {
            if (children[0].admission == children[1].admission or
                children[0].wire == children[1].wire or
                children[0].capture == children[1].capture)
            {
                return error.DuplicateChild;
            }
            for (children) |child| {
                try child.admission.validate();
                const admission_id = child.admission.identity();
                const wire_sha_id = wireIdentity(child.wire);
                const capture_sha_id = captureIdentity(child.capture);
                if (!std.meta.eql(child.admission.dimensions(), dimensions) or
                    !std.mem.eql(u8, &child.admission_id, &admission_id) or
                    !std.mem.eql(u8, &child.wire_sha_id, &wire_sha_id) or
                    !std.mem.eql(
                        u8,
                        &child.capture_sha_id,
                        &capture_sha_id,
                    )) return error.CaptureAuthorityMismatch;
                const composition = child.composition orelse
                    return error.CaptureAuthorityMismatch;
                try composition.validate();
                try child.capture.circuit.validate();
                try child.capture.evaluation.validateAgainst(&child.capture.circuit);
                try child.capture.pcs_circuit.validate();
                try child.capture.pcs_evaluation.validateAgainst(
                    &child.capture.pcs_circuit,
                );
            }
            try validateMatchingCaptureProfiles(.{
                children[0].capture,
                children[1].capture,
            });
        }
    };
}

fn scheduleShape(value: *const captured_fri.Owned) !schedule.ScheduleShape {
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    if (value.trace_tree_heights.len != tree_heights.len)
        return error.ProfileMismatch;
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

fn validateMatchingCaptureProfiles(
    captures: [CHILD_COUNT]*const captured_fri.Owned,
) !void {
    const left = captures[0];
    const right = captures[1];
    if (left.claimed_sum_count != CLAIM_COUNT or
        right.claimed_sum_count != CLAIM_COUNT or
        left.circuit.query_count != @as(u32, @intCast(left.raw_queries.len)) or
        right.circuit.query_count != @as(u32, @intCast(right.raw_queries.len)) or
        !std.mem.eql(
            u8,
            &left.circuit.profile_digest,
            &right.circuit.profile_digest,
        ) or !std.mem.eql(
        u8,
        &left.pcs_circuit.profile_digest,
        &right.pcs_circuit.profile_digest,
    )) return error.ProfileMismatch;
}

fn wireIdentity(wire: anytype) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(wire), &result, .{});
    return result;
}

fn captureIdentity(value: *const captured_fri.Owned) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/temporal-owned-captured-fri/v3\x00");
    hash.update(&value.circuit.identity_digest);
    hash.update(&value.pcs_circuit.identity_digest);
    hashInt(&hash, u32, value.sampled_value_count);
    hashInt(&hash, u32, value.queried_values_per_query);
    hashInt(&hash, u32, value.claimed_sum_count);
    hashInt(&hash, u32, value.interaction_pow_bits);
    hashInt(&hash, u32, value.pcs_pow_bits);
    hashQm31Slice(&hash, value.sampled_values);
    hashM31Slice(&hash, value.queried_values);
    hashQm31Slice(&hash, value.deep_answers);
    hashQm31Slice(&hash, value.fri_alphas);
    hashM31Slice(&hash, value.raw_queries);
    hashM31Slice(&hash, value.last_layer_positions);
    hashQm31Slice(&hash, value.last_layer_coefficients);
    for (value.trace_roots) |digest| hashDigest(&hash, digest);
    for (value.fri_roots) |digest| hashDigest(&hash, digest);
    hashQm31(&hash, value.composition_randomness);
    hashQm31(&hash, value.oods_seed);
    hashQm31(&hash, value.deep_randomness);
    hashQm31Slice(&hash, value.evaluation.values);
    hashQm31Slice(&hash, value.pcs_evaluation.values);
    for (value.fold_widths) |word| hashInt(&hash, u32, word);
    for (value.trace_tree_heights) |word| hashInt(&hash, u32, word);
    for (value.column_log_storage) |word| hashInt(&hash, u32, word);
    for (value.sample_layouts) |layout| hashInt(&hash, u8, @intFromEnum(layout));
    for (value.trace_siblings) |siblings| for (siblings) |digest|
        hashDigest(&hash, digest);
    for (value.authenticated_values) |items| hashQm31Slice(&hash, items);
    for (value.fri_positions) |items| hashM31Slice(&hash, items);
    for (value.fri_offsets) |items| hashM31Slice(&hash, items);
    for (value.fri_siblings) |siblings| for (siblings) |digest|
        hashDigest(&hash, digest);
    return hash.finalResult();
}

fn m31SliceEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn hashDigest(hash: anytype, value: anytype) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashM31Slice(hash: anytype, values: []const M31) void {
    hashInt(hash, u64, values.len);
    for (values) |value| hashInt(hash, u32, value.toU32());
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashQm31Slice(hash: anytype, values: []const QM31) void {
    hashInt(hash, u64, values.len);
    for (values) |value| hashQm31(hash, value);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 3 or SCHEMA_VERSION != 1 or CHILD_COUNT != 2 or
        CLAIM_COUNT != 39 or ROW_COUNT != 17 or PROOF_BYTE_REPARSES != 0 or
        CAPTURED_FRI_OWNERS_PER_CHILD != 1 or
        LOSSY_V1_PROJECTION_AVAILABLE or
        !ROWS_18_THROUGH_34_AVAILABLE or COMPLETE_PARENT_PROOF_AVAILABLE or
        PRODUCTION_CAPABILITY)
    {
        @compileError("temporal suffix V3 contract drifted");
    }
    SEGMENT_V2_OUTER_DIMENSIONS.validate();
    if (SEGMENT_V2_OUTER_DIMENSIONS.commitment_count != 4 or
        SEGMENT_V2_OUTER_DIMENSIONS.claimed_sum_count != 39 or
        SEGMENT_V2_OUTER_DIMENSIONS.sampled_value_count != 2_245 or
        SEGMENT_V2_OUTER_DIMENSIONS.queried_value_count != 6_255 or
        SEGMENT_V2_OUTER_DIMENSIONS.trace_path_count != 12 or
        SEGMENT_V2_OUTER_DIMENSIONS.fri_layer_count != 16 or
        SEGMENT_V2_OUTER_DIMENSIONS.query_count != 3 or
        SEGMENT_V2_OUTER_DIMENSIONS.maximum_fold_width != 2 or
        SEGMENT_V2_OUTER_DIMENSIONS.last_layer_coefficient_count != 1 or
        SEGMENT_V2_OUTER_DIMENSIONS.maximum_merkle_depth != 17)
    {
        @compileError("SegmentV2 outer dimensions drifted");
    }
}
