//! Authenticated rows 18--34 for two verified temporal-parent children.
//!
//! This is a narrow custody adapter around the shared binary FRI source. It
//! owns no AIR equations: each child is re-admitted from the successful
//! parent verifier, copied into the exact fixed wire selected by that receipt,
//! and paired with its retained parent-specific composition graph.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const driver = @import("recursive_binary_outer.zig");
const level2 = @import("recursive_temporal_parent_pair_authority_v1.zig");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const composition_capture = @import("recursive_temporal_level2_composition_v1.zig");
const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const temporal_manifest = @import("recursive_temporal_parent_manifest_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const captured_fri = recursion.captured_fri;
const fixed_wire = recursion.fixed_wire;
const rows_source = recursion.binary_fri_outer_source;
const rows_bundle = recursion.binary_fri_outer_bundle;
const schedule = recursion.air.verifier_schedule;
const temporal_schedule = recursion.temporal_shared_poseidon_schedule_v3;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const ROW_COUNT: usize = rows_source.ROW_COUNT;
pub const CLAIM_COUNT: usize = temporal_manifest.COMPONENT_COUNT;
pub const SOURCE_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-level2-suffix/v1\x00";

pub const PARENT_OUTER_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = CLAIM_COUNT,
    .sampled_value_count = 2_330,
    .queried_value_count = 6_546,
    .trace_path_count = 12,
    .fri_layer_count = 17,
    .query_count = 3,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 18,
};

const Boundary = Level2BoundaryV1(PARENT_OUTER_DIMENSIONS);
const Source = rows_source.AuthenticatedSource(PARENT_OUTER_DIMENSIONS, Boundary);
const Bundle = rows_bundle.BundleForSourceScheduleAndManifest(
    PARENT_OUTER_DIMENSIONS,
    Source,
    temporal_schedule,
    temporal_manifest,
);
const Wire = fixed_wire.FixedStarkProofWire(PARENT_OUTER_DIMENSIONS);

pub const SourceV1 = Source;
pub const BundleV1 = Bundle;
pub const BoundaryV1 = Boundary;
pub const WireV1 = Wire;

pub const ChildInputV1 = struct {
    publication: *const publication_mod.VerifiedPublicationV1,
    artifact: *const artifact_mod.VerifiedTemporalParentArtifactV1,
    capture: *const driver.OuterProofCapture,
    composition: *composition_capture.CaptureV1,

    pub fn validate(self: ChildInputV1) !void {
        try self.artifact.validateAgainst(self.publication);
        try self.artifact.recursive_admission.validateAgainst(self.capture);
        try self.composition.validateRetained();
        if (!std.meta.eql(self.publication.capture_id, self.composition.capture_id) or
            !std.meta.eql(self.artifact.artifact_id, self.composition.artifact_id))
        {
            return error.ChildAuthorityMismatch;
        }
    }
};

pub const OwnerV1 = opaque {
    pub fn init(
        allocator: std.mem.Allocator,
        pair: *const level2.PreparedLevel2PairV1,
        prefix: *prefix_runtime.OwnerV1,
        inputs: [CHILD_COUNT]ChildInputV1,
    ) !*OwnerV1 {
        try pair.validate();
        try prefix.validateCold();
        for (inputs, pair.child_publication_ids) |input, publication_id| {
            try input.validate();
            if (!std.meta.eql(input.artifact.publication_id, publication_id))
                return error.ChildAuthorityMismatch;
        }
        if (inputs[0].capture == inputs[1].capture or
            inputs[0].composition == inputs[1].composition)
        {
            return error.DuplicateChild;
        }

        const storage_value = try allocator.create(Storage);
        errdefer allocator.destroy(storage_value);
        storage_value.* = undefined;
        storage_value.allocator = allocator;
        storage_value.pair_input = pair;
        storage_value.prefix = prefix;
        storage_value.inputs = inputs;

        var capture_count: usize = 0;
        errdefer for (storage_value.captures[0..capture_count]) |*capture|
            capture.deinit();
        for (inputs, &storage_value.captures, 0..) |input, *capture, child_index| {
            capture.* = captured_fri.Owned.init(
                allocator,
                .{
                    .log_blowup_factor = admission.LOG_BLOWUP_FACTOR,
                    .log_last_layer_degree_bound = admission.LOG_LAST_LAYER_DEGREE_BOUND,
                    .interaction_pow_bits = admission.INTERACTION_POW_BITS,
                    .pcs_pow_bits = admission.PCS_POW_BITS,
                    .claimed_sum_count = CLAIM_COUNT,
                },
                input.capture,
            ) catch |err| return initStageFailure(
                "captured_fri",
                child_index,
                err,
            );
            capture_count += 1;
        }
        if (!std.mem.eql(
            u8,
            &storage_value.captures[0].circuit.profile_digest,
            &storage_value.captures[1].circuit.profile_digest,
        ) or !std.mem.eql(
            u8,
            &storage_value.captures[0].pcs_circuit.profile_digest,
            &storage_value.captures[1].pcs_circuit.profile_digest,
        )) return error.ProfileMismatch;

        for (inputs, &storage_value.wires, 0..) |input, *wire, child_index| {
            const derived = admission.deriveAdmission(
                &input.artifact.recursive_admission.receipt,
                input.capture,
            ) catch |err| return initStageFailure(
                "wire_admission",
                child_index,
                err,
            );
            if (!std.meta.eql(derived.dimensions, PARENT_OUTER_DIMENSIONS))
                return error.ProfileMismatch;
            wire.* = std.mem.zeroes(Wire);
            admission.populatePayload(
                PARENT_OUTER_DIMENSIONS,
                wire,
                &input.artifact.recursive_admission.receipt,
                input.capture,
            );
        }

        const transcript_rows = try prefix.transcriptRows();
        storage_value.boundary_calls = try allocator.alloc(
            temporal_schedule.Call,
            transcript_rows.rows.len,
        );
        errdefer allocator.free(storage_value.boundary_calls);
        try transcript_rows.fillProviderCallsInto(storage_value.boundary_calls);
        storage_value.boundary_layout = try temporal_schedule.Layout
            .initTemporalBoundary(
            storage_value.boundary_calls.len,
            storage_value.boundary_calls,
        );
        storage_value.pair = .{
            .pair = pair,
            .prefix = prefix,
            .authority_id = pair.authority_id,
        };
        storage_value.children = makeChildren(storage_value);
        storage_value.source = try Source.initAuthenticated(
            allocator,
            &storage_value.pair,
            pair.authority_id,
            &prefix.vm_plan,
            .{ &prefix.recursion_plan, &prefix.recursion_plan },
            storage_value.children,
            try prefix.sharedArithmeticInput(),
        );
        errdefer storage_value.source.deinit();
        storage_value.authority_id = ownerIdentity(storage_value);
        try storage_value.validate();
        return handle(storage_value);
    }

    pub fn deinit(self: *OwnerV1) void {
        const value = storage(self);
        const allocator = value.allocator;
        value.source.deinit();
        allocator.free(value.boundary_calls);
        for (&value.captures) |*capture| capture.deinit();
        value.* = undefined;
        allocator.destroy(value);
    }

    pub fn validate(self: *const OwnerV1) !void {
        return storageConst(self).validate();
    }

    pub fn source(self: *const OwnerV1) *const Source {
        return &storageConst(self).source;
    }

    pub fn boundaryScheduleReceipt(self: *const OwnerV1) temporal_schedule.Layout {
        return storageConst(self).boundary_layout;
    }

    pub fn boundaryPoseidonCalls(self: *const OwnerV1) []const temporal_schedule.Call {
        return storageConst(self).boundary_calls;
    }

    pub fn authorityIdentity(self: *const OwnerV1) [32]u8 {
        return storageConst(self).authority_id;
    }
};

fn initStageFailure(
    stage: []const u8,
    child_index: usize,
    err: anyerror,
) anyerror {
    std.debug.print(
        "\nTEMPORAL_LEVEL2_SUFFIX_INIT_FAIL stage={s} child={d} error={s}\n",
        .{ stage, child_index, @errorName(err) },
    );
    return err;
}

const Storage = struct {
    allocator: std.mem.Allocator,
    pair_input: *const level2.PreparedLevel2PairV1,
    prefix: *prefix_runtime.OwnerV1,
    inputs: [CHILD_COUNT]ChildInputV1,
    captures: [CHILD_COUNT]captured_fri.Owned,
    wires: [CHILD_COUNT]Wire,
    boundary_calls: []temporal_schedule.Call,
    boundary_layout: temporal_schedule.Layout,
    pair: Boundary.PairPrepared,
    children: [CHILD_COUNT]Boundary.Child,
    source: Source,
    authority_id: [32]u8,

    fn validate(self: *const Storage) !void {
        try self.pair_input.validate();
        try self.prefix.validateCold();
        try self.boundary_layout.validate(self.boundary_calls);
        try self.source.validateAgainstAuthority();
        if (!std.meta.eql(self.children, makeChildren(self)) or
            !std.mem.eql(u8, &self.authority_id, &ownerIdentity(self)))
        {
            return error.AuthorityIdentityMismatch;
        }
    }
};

pub fn Level2BoundaryV1(comptime dimensions: fixed_wire.Dimensions) type {
    const FixedWire = fixed_wire.FixedStarkProofWire(dimensions);
    return struct {
        pub const IS_LEGACY = false;
        pub const INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS = false;
        pub const RootPin = level2.Digest;
        pub const Wire = FixedWire;

        pub const PairPrepared = struct {
            pair: *const level2.PreparedLevel2PairV1,
            prefix: *prefix_runtime.OwnerV1,
            authority_id: level2.Digest,
        };

        pub const Child = struct {
            input: ChildInputV1,
            wire: *const FixedWire,
            capture: *const captured_fri.Owned,
            composition: ?rows_source.AuthenticatedCompositionLane,
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
            if (!std.meta.eql(expected, dimensions)) return error.ProfileMismatch;
            try pair.pair.validate();
            try pair.prefix.validateCold();
            if (!std.meta.eql(pair.authority_id, pair.pair.authority_id) or
                !std.meta.eql(root_pin, pair.authority_id) or
                vm_plan != &pair.prefix.vm_plan or
                recursion_plans[0] != &pair.prefix.recursion_plan or
                recursion_plans[1] != &pair.prefix.recursion_plan)
            {
                return error.PairAuthorityMismatch;
            }
            if (shared) |value| try value.validate();
            try validateChildren(children, pair.pair);
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
                return error.QueryAuthorityMismatch;
            }
            try validateChildren(children, pair.pair);
            var words: [CHILD_COUNT][dimensions.query_count]M31 = undefined;
            const transcript_rows = try pair.prefix.transcriptRows();
            try transcript_rows.fillQueryWordsInto(&words);
            @memcpy(destination[0..dimensions.query_count], &words[0]);
            @memcpy(destination[dimensions.query_count..], &words[1]);
            for (children, words) |child, expected_words| {
                if (child.capture.raw_queries.len != dimensions.query_count)
                    return error.QueryAuthorityMismatch;
                const mask = (@as(u32, 1) <<
                    @intCast(child.capture.circuit.lifting_log_size)) - 1;
                for (child.capture.raw_queries, expected_words) |actual, full|
                    if (actual.toU32() != (full.toU32() & mask))
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
            try validateChildren(children, pair.pair);
            const lanes = [2]recursion.air.composition_circuit.RecursionLane{
                children[0].input.composition.lane(
                    rows_source.LEFT_RECURSION_VERIFIER_ID,
                    composition_capture.LEFT_CIRCUIT_ID,
                    rows_source.LEFT_COMPOSITION_STATEMENT_SCOPE,
                ),
                children[1].input.composition.lane(
                    rows_source.RIGHT_RECURSION_VERIFIER_ID,
                    composition_capture.RIGHT_CIRCUIT_ID,
                    rows_source.RIGHT_COMPOSITION_STATEMENT_SCOPE,
                ),
            };
            const evaluations = [2]recursion.air.verifier_arithmetic_lowering.Evaluation{
                children[0].input.composition.evaluation(),
                children[1].input.composition.evaluation(),
            };
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
            if (!std.meta.eql(expected, dimensions)) return error.ProfileMismatch;
            const evaluations = [2]recursion.air.verifier_arithmetic_lowering.Evaluation{
                source.children[0].input.composition.evaluation(),
                source.children[1].input.composition.evaluation(),
            };
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
            var expected_words: [CHILD_COUNT * dimensions.query_count]M31 =
                undefined;
            try fillQueryWords(
                expected,
                source.pair,
                source.children,
                &expected_words,
            );
            for (expected_words, source.query_word_storage) |wanted, actual|
                if (!wanted.eql(actual)) return error.QueryAuthorityMismatch;
        }

        pub fn sourceAuthorityDigest(
            comptime expected: fixed_wire.Dimensions,
            source: anytype,
        ) [32]u8 {
            std.debug.assert(std.meta.eql(expected, dimensions));
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(SOURCE_DOMAIN);
            hashInt(&hash, u16, FORMAT_VERSION);
            hashInt(&hash, u16, SCHEMA_VERSION);
            hashNative(&hash, source.pair.authority_id);
            hashNative(&hash, source.root_pin);
            for (source.children) |child| {
                hashNative(&hash, child.input.artifact.artifact_id);
                hash.update(&child.input.composition.identity);
                hash.update(std.mem.asBytes(child.wire));
                hash.update(&child.capture.circuit.identity_digest);
                hash.update(&child.capture.pcs_circuit.identity_digest);
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
            children: [2]Child,
            pair: *const level2.PreparedLevel2PairV1,
        ) !void {
            if (children[0].wire == children[1].wire or
                children[0].capture == children[1].capture)
            {
                return error.DuplicateChild;
            }
            for (children, pair.child_publication_ids, 0..) |
                child,
                publication_id,
                child_index,
            | {
                try child.input.validate();
                if (!std.meta.eql(child.input.artifact.publication_id, publication_id))
                    return error.ChildAuthorityMismatch;
                var expected_wire = std.mem.zeroes(FixedWire);
                admission.populatePayload(
                    dimensions,
                    &expected_wire,
                    &child.input.artifact.recursive_admission.receipt,
                    child.input.capture,
                );
                if (!std.meta.eql(expected_wire, child.wire.*))
                    return error.WireAuthorityMismatch;
                try child.capture.circuit.validate();
                try child.capture.evaluation.validateAgainst(&child.capture.circuit);
                try child.capture.pcs_circuit.validate();
                try child.capture.pcs_evaluation.validateAgainst(
                    &child.capture.pcs_circuit,
                );
                const lane = child.composition orelse
                    return error.MissingCompositionAuthority;
                try lane.validate();
                const expected_id = if (child_index == 0)
                    composition_capture.LEFT_CIRCUIT_ID
                else
                    composition_capture.RIGHT_CIRCUIT_ID;
                if (lane.circuit_id != expected_id or
                    !std.mem.eql(
                        u8,
                        &lane.circuit_identity,
                        &child.input.composition.circuit.identity_digest,
                    )) return error.ChildAuthorityMismatch;
            }
        }
    };
}

fn makeChildren(value: *const Storage) [CHILD_COUNT]Boundary.Child {
    return .{
        makeChild(value, 0, composition_capture.LEFT_CIRCUIT_ID),
        makeChild(value, 1, composition_capture.RIGHT_CIRCUIT_ID),
    };
}

fn makeChild(
    value: *const Storage,
    index: usize,
    circuit_id: u32,
) Boundary.Child {
    const capture = value.inputs[index].composition;
    return .{
        .input = value.inputs[index],
        .wire = &value.wires[index],
        .capture = &value.captures[index],
        .composition = .{
            .circuit_id = circuit_id,
            .circuit_identity = capture.circuit.identity_digest,
            .graph = capture.circuit.graph(),
            .evaluation = capture.evaluation(),
        },
    };
}

fn handle(value: *Storage) *OwnerV1 {
    return @ptrCast(value);
}

fn storage(value: *OwnerV1) *Storage {
    return @ptrCast(@alignCast(value));
}

fn storageConst(value: *const OwnerV1) *const Storage {
    return @ptrCast(@alignCast(value));
}

fn ownerIdentity(value: *const Storage) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-level2-suffix-owner/v1\x00");
    hashNative(&hash, value.pair.authority_id);
    hash.update(&value.source.source_authority_digest);
    hash.update(&value.boundary_layout.identity);
    return hash.finalResult();
}

fn hashNative(hash: anytype, value: level2.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    PARENT_OUTER_DIMENSIONS.validate();
    if (CLAIM_COUNT != admission.CLAIMED_SUM_COUNT or ROW_COUNT != 17)
        @compileError("level-2 suffix geometry drifted");
}
