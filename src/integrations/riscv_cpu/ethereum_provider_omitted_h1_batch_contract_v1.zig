//! Canonical structural custody for the 210 omitted-provider leaves that feed
//! the 105 real height-one Ethereum parents.
//!
//! This contract deliberately stops before any H1 proof.  A request binds the
//! retained execution/source corpus, every ordered cold-verifiable leaf
//! bundle, and the already-materialized statement/batch plans.  A result binds
//! only the 105 live pair admissions obtained after all 210 bundles were cold
//! verified.  Neither wire may claim upper-tree or final-root admission.

const std = @import("std");

const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const batch_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_batch_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

pub const request_schema =
    "stwo.ethereum.omitted-provider-h1-structural-request.v1";
pub const result_schema =
    "stwo.ethereum.omitted-provider-h1-structural-result.v1";
pub const request_status = "ordered-cold-leaf-admission-requested";
pub const result_status = "ordered-cold-leaf-admission-complete";
pub const production_active = false;
pub const h1_proofs_executed = false;
pub const upper_or_root_admitted = false;
pub const product_admissible = false;
pub const leaf_count: usize = statement_plan.REAL_LEAF_COUNT;
pub const pair_count: usize = batch_mod.REAL_H1_PAIR_COUNT;
pub const maximum_json_bytes: usize = 64 * 1024 * 1024;

comptime {
    if (leaf_count != 210 or pair_count != 105 or
        leaf_count != 2 * pair_count or production_active or
        h1_proofs_executed or upper_or_root_admitted or product_admissible)
    {
        @compileError("omitted-provider H1 structural boundary drifted");
    }
}

/// Exact bundle/source pairing for one canonical real leaf.
pub const BundleRecordV1 = struct {
    artifact: contract.Identity,
    authority_identity_sha256: []const u8,
    segment_index: u32,
    source_authority: contract.Identity,

    pub fn validate(self: BundleRecordV1, expected_index: usize) !void {
        if (self.segment_index != @as(u32, @intCast(expected_index)))
            return error.OmittedH1BundleOrderMismatch;
        try self.artifact.validate(false);
        try self.source_authority.validate(false);
        if (!std.fs.path.isAbsolute(self.artifact.path) or
            !std.fs.path.isAbsolute(self.source_authority.path))
        {
            return error.InvalidOmittedH1StructuralRequest;
        }
        _ = try contract.parseSha256(self.authority_identity_sha256);
        if (std.mem.eql(u8, self.artifact.path, self.source_authority.path))
            return error.OmittedH1DuplicatePath;
    }
};

/// Exact adjacency/task projection for one real H1 pair.
pub const PairTaskV1 = struct {
    left_bundle_sha256: []const u8,
    left_leaf_record_identity_sha256: []const u8,
    left_segment_index: u32,
    ordinal: u32,
    parent_index: u32,
    right_bundle_sha256: []const u8,
    right_leaf_record_identity_sha256: []const u8,
    right_segment_index: u32,
    task_identity_sha256: []const u8,

    pub fn validate(
        self: PairTaskV1,
        expected_ordinal: usize,
        bundles: []const BundleRecordV1,
    ) !void {
        const left = 2 * expected_ordinal;
        const right = left + 1;
        if (self.ordinal != @as(u32, @intCast(expected_ordinal)) or
            self.parent_index != self.ordinal or
            self.left_segment_index != @as(u32, @intCast(left)) or
            self.right_segment_index != @as(u32, @intCast(right)) or
            bundles.len != leaf_count or
            !std.mem.eql(
                u8,
                self.left_bundle_sha256,
                bundles[left].artifact.sha256,
            ) or !std.mem.eql(
            u8,
            self.right_bundle_sha256,
            bundles[right].artifact.sha256,
        )) return error.OmittedH1PairTaskMismatch;
        inline for (.{
            self.left_bundle_sha256,
            self.left_leaf_record_identity_sha256,
            self.right_bundle_sha256,
            self.right_leaf_record_identity_sha256,
            self.task_identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
    }
};

/// Stable constructor storage for the exact 105 adjacency records.  It copies
/// both bundle identities as canonical lowercase hex, so the returned wire
/// slice does not borrow temporary formatting arrays.
pub const OwnedPairTasksV1 = struct {
    storage: [pair_count]OwnedPairTaskV1,

    pub fn init(
        batch: *const batch_mod.BatchPlanV1,
        bundles: []const BundleRecordV1,
    ) !@This() {
        try batch.validateCustody();
        if (bundles.len != leaf_count)
            return error.InvalidOmittedH1StructuralRequest;
        var result: @This() = undefined;
        for (&result.storage, 0..) |*owned, ordinal| {
            owned.* = try OwnedPairTaskV1.init(
                &batch.tasks[ordinal],
                bundles,
            );
        }
        return result;
    }

    pub fn wireInto(
        self: *const @This(),
        destination: *[pair_count]PairTaskV1,
        bundles: []const BundleRecordV1,
    ) !void {
        if (bundles.len != leaf_count)
            return error.InvalidOmittedH1StructuralRequest;
        for (&self.storage, destination[0..], 0..) |*owned, *wire, ordinal| {
            wire.* = owned.wire();
            try wire.validate(ordinal, bundles);
        }
    }
};

pub const OwnedPairTaskV1 = struct {
    left_bundle_sha256: [64]u8,
    left_leaf_record_identity_sha256: [64]u8,
    left_segment_index: u32,
    ordinal: u32,
    parent_index: u32,
    right_bundle_sha256: [64]u8,
    right_leaf_record_identity_sha256: [64]u8,
    right_segment_index: u32,
    task_identity_sha256: [64]u8,

    fn init(
        task: *const batch_mod.RealH1TaskV1,
        bundles: []const BundleRecordV1,
    ) !@This() {
        try task.validate();
        const left: usize = @intCast(task.left_leaf_index);
        const right: usize = @intCast(task.right_leaf_index);
        if (left >= bundles.len or right >= bundles.len)
            return error.OmittedH1PairTaskMismatch;
        return .{
            .left_bundle_sha256 = std.fmt.bytesToHex(
                try contract.parseSha256(bundles[left].artifact.sha256),
                .lower,
            ),
            .left_leaf_record_identity_sha256 = std.fmt.bytesToHex(
                task.left_leaf_record_identity_sha256,
                .lower,
            ),
            .left_segment_index = task.left_leaf_index,
            .ordinal = task.ordinal,
            .parent_index = task.parent_index,
            .right_bundle_sha256 = std.fmt.bytesToHex(
                try contract.parseSha256(bundles[right].artifact.sha256),
                .lower,
            ),
            .right_leaf_record_identity_sha256 = std.fmt.bytesToHex(
                task.right_leaf_record_identity_sha256,
                .lower,
            ),
            .right_segment_index = task.right_leaf_index,
            .task_identity_sha256 = std.fmt.bytesToHex(
                task.identity_sha256,
                .lower,
            ),
        };
    }

    fn wire(self: *const @This()) PairTaskV1 {
        return .{
            .left_bundle_sha256 = &self.left_bundle_sha256,
            .left_leaf_record_identity_sha256 = &self.left_leaf_record_identity_sha256,
            .left_segment_index = self.left_segment_index,
            .ordinal = self.ordinal,
            .parent_index = self.parent_index,
            .right_bundle_sha256 = &self.right_bundle_sha256,
            .right_leaf_record_identity_sha256 = &self.right_leaf_record_identity_sha256,
            .right_segment_index = self.right_segment_index,
            .task_identity_sha256 = &self.task_identity_sha256,
        };
    }
};

pub const UnsignedRequestSetV1 = struct {
    batch_plan_identity_sha256: []const u8,
    bundles: []const BundleRecordV1,
    elf: contract.Identity,
    execution_journal: contract.Identity,
    expected_output: contract.Identity,
    input: contract.Identity,
    leaf_count: u32 = @intCast(leaf_count),
    materialization_result: contract.Identity,
    materialized_plan_identity_sha256: []const u8,
    pair_count: u32 = @intCast(pair_count),
    pairs: []const PairTaskV1,
    product_admissible: bool = product_admissible,
    production_active: bool = production_active,
    proof_execution_requested: bool = h1_proofs_executed,
    schema: []const u8 = request_schema,
    source_request: contract.TypedIdentity,
    status: []const u8 = request_status,
    upper_or_root_requested: bool = upper_or_root_admitted,

    pub fn validate(self: UnsignedRequestSetV1) !void {
        if (!std.mem.eql(u8, self.schema, request_schema) or
            !std.mem.eql(u8, self.status, request_status) or
            self.production_active or self.proof_execution_requested or
            self.upper_or_root_requested or self.product_admissible or
            self.leaf_count != leaf_count or self.pair_count != pair_count or
            self.bundles.len != leaf_count or self.pairs.len != pair_count)
        {
            return error.InvalidOmittedH1StructuralRequest;
        }
        try self.elf.validate(false);
        try self.execution_journal.validate(false);
        try self.expected_output.validate(false);
        try self.input.validate(true);
        try self.materialization_result.validate(false);
        try self.source_request.validate();
        inline for (.{
            self.elf.path,
            self.execution_journal.path,
            self.expected_output.path,
            self.input.path,
            self.materialization_result.path,
            self.source_request.path,
        }) |path| if (!std.fs.path.isAbsolute(path))
            return error.InvalidOmittedH1StructuralRequest;
        inline for (.{
            self.batch_plan_identity_sha256,
            self.materialized_plan_identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        for (self.bundles, 0..) |bundle, index|
            try bundle.validate(index);
        for (self.pairs, 0..) |pair, ordinal|
            try pair.validate(ordinal, self.bundles);
        try requireAllPathsDistinct(self);
    }

    pub fn validateAgainstPlans(
        self: UnsignedRequestSetV1,
        allocator: std.mem.Allocator,
        materialized: *const statement_plan.MaterializedPlanV1,
        batch: *const batch_mod.BatchPlanV1,
    ) !void {
        try self.validate();
        try materialized.validate();
        try batch.validateAgainst(allocator, materialized);
        if (!digestMatches(
            self.materialized_plan_identity_sha256,
            materialized.identity,
        ) or !digestMatches(
            self.batch_plan_identity_sha256,
            batch.identity_sha256,
        )) return error.OmittedH1PlanIdentityMismatch;
        for (self.pairs, batch.tasks, 0..) |pair, task, ordinal| {
            if (task.ordinal != @as(u32, @intCast(ordinal)) or
                pair.parent_index != task.parent_index or
                pair.left_segment_index != task.left_leaf_index or
                pair.right_segment_index != task.right_leaf_index or
                !digestMatches(
                    pair.task_identity_sha256,
                    task.identity_sha256,
                ) or !digestMatches(
                pair.left_leaf_record_identity_sha256,
                task.left_leaf_record_identity_sha256,
            ) or !digestMatches(
                pair.right_leaf_record_identity_sha256,
                task.right_leaf_record_identity_sha256,
            )) return error.OmittedH1PairTaskMismatch;
        }
    }
};

pub const SealedRequestSetV1 = struct {
    content_sha256: []const u8,
    batch_plan_identity_sha256: []const u8,
    bundles: []const BundleRecordV1,
    elf: contract.Identity,
    execution_journal: contract.Identity,
    expected_output: contract.Identity,
    input: contract.Identity,
    leaf_count: u32,
    materialization_result: contract.Identity,
    materialized_plan_identity_sha256: []const u8,
    pair_count: u32,
    pairs: []const PairTaskV1,
    product_admissible: bool,
    production_active: bool,
    proof_execution_requested: bool,
    schema: []const u8,
    source_request: contract.TypedIdentity,
    status: []const u8,
    upper_or_root_requested: bool,

    pub fn unsigned(self: SealedRequestSetV1) UnsignedRequestSetV1 {
        return .{
            .batch_plan_identity_sha256 = self.batch_plan_identity_sha256,
            .bundles = self.bundles,
            .elf = self.elf,
            .execution_journal = self.execution_journal,
            .expected_output = self.expected_output,
            .input = self.input,
            .leaf_count = self.leaf_count,
            .materialization_result = self.materialization_result,
            .materialized_plan_identity_sha256 = self.materialized_plan_identity_sha256,
            .pair_count = self.pair_count,
            .pairs = self.pairs,
            .product_admissible = self.product_admissible,
            .production_active = self.production_active,
            .proof_execution_requested = self.proof_execution_requested,
            .schema = self.schema,
            .source_request = self.source_request,
            .status = self.status,
            .upper_or_root_requested = self.upper_or_root_requested,
        };
    }

    pub fn validate(self: SealedRequestSetV1) !void {
        _ = try contract.parseSha256(self.content_sha256);
        try self.unsigned().validate();
    }
};

/// Pointer-free projection of one freshly admitted pair.  It is not an H1
/// proof result and cannot be used where `OwnedProductV1` is required.
pub const PairAdmissionRecordV1 = struct {
    arm_kind: batch_mod.ArmKindV1,
    h1_profile_identity_sha256: []const u8,
    ingress_identity_sha256: []const u8,
    left_capture_identity_sha256: []const u8,
    left_descriptor_sha256: []const u8,
    left_node_public_authority_sha256: []const u8,
    left_proof_artifact_sha256: []const u8,
    ordinal: u32,
    pair_admission_identity_sha256: []const u8,
    parent_index: u32,
    right_capture_identity_sha256: []const u8,
    right_descriptor_sha256: []const u8,
    right_node_public_authority_sha256: []const u8,
    right_proof_artifact_sha256: []const u8,
    task_identity_sha256: []const u8,

    pub fn validate(self: PairAdmissionRecordV1, ordinal: usize) !void {
        if (self.ordinal != @as(u32, @intCast(ordinal)) or
            self.parent_index != self.ordinal or
            self.arm_kind != .projected_candidate_v1)
        {
            return error.InvalidOmittedH1StructuralResult;
        }
        inline for (.{
            self.h1_profile_identity_sha256,
            self.ingress_identity_sha256,
            self.left_capture_identity_sha256,
            self.left_descriptor_sha256,
            self.left_node_public_authority_sha256,
            self.left_proof_artifact_sha256,
            self.pair_admission_identity_sha256,
            self.right_capture_identity_sha256,
            self.right_descriptor_sha256,
            self.right_node_public_authority_sha256,
            self.right_proof_artifact_sha256,
            self.task_identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
    }
};

/// Stable backing storage for a JSON-facing pair record.  The borrowed wire
/// view is valid only while this value remains alive; unlike a direct
/// `bytesToHex` expression, no field points at a temporary array.
pub const OwnedPairAdmissionRecordV1 = struct {
    arm_kind: batch_mod.ArmKindV1,
    h1_profile_identity_sha256: [64]u8,
    ingress_identity_sha256: [64]u8,
    left_capture_identity_sha256: [64]u8,
    left_descriptor_sha256: [64]u8,
    left_node_public_authority_sha256: [64]u8,
    left_proof_artifact_sha256: [64]u8,
    ordinal: u32,
    pair_admission_identity_sha256: [64]u8,
    parent_index: u32,
    right_capture_identity_sha256: [64]u8,
    right_descriptor_sha256: [64]u8,
    right_node_public_authority_sha256: [64]u8,
    right_proof_artifact_sha256: [64]u8,
    task_identity_sha256: [64]u8,

    pub fn init(
        pair: batch_mod.FreshPairAdmissionV1,
        batch: *const batch_mod.BatchPlanV1,
    ) !@This() {
        try pair.validateAgainst(batch);
        if (pair.arm_kind != .projected_candidate_v1)
            return error.InvalidOmittedH1StructuralResult;
        return .{
            .arm_kind = pair.arm_kind,
            .h1_profile_identity_sha256 = std.fmt.bytesToHex(
                pair.h1_profile_identity_sha256,
                .lower,
            ),
            .ingress_identity_sha256 = std.fmt.bytesToHex(
                pair.ingress_identity_sha256,
                .lower,
            ),
            .left_capture_identity_sha256 = std.fmt.bytesToHex(
                pair.left_capture_identity_sha256,
                .lower,
            ),
            .left_descriptor_sha256 = std.fmt.bytesToHex(
                pair.left_descriptor_sha256,
                .lower,
            ),
            .left_node_public_authority_sha256 = std.fmt.bytesToHex(
                pair.left_node_public_authority_sha256,
                .lower,
            ),
            .left_proof_artifact_sha256 = std.fmt.bytesToHex(
                pair.left_proof_artifact_sha256,
                .lower,
            ),
            .ordinal = pair.ordinal,
            .pair_admission_identity_sha256 = std.fmt.bytesToHex(
                pair.identity_sha256,
                .lower,
            ),
            .parent_index = pair.parent_index,
            .right_capture_identity_sha256 = std.fmt.bytesToHex(
                pair.right_capture_identity_sha256,
                .lower,
            ),
            .right_descriptor_sha256 = std.fmt.bytesToHex(
                pair.right_descriptor_sha256,
                .lower,
            ),
            .right_node_public_authority_sha256 = std.fmt.bytesToHex(
                pair.right_node_public_authority_sha256,
                .lower,
            ),
            .right_proof_artifact_sha256 = std.fmt.bytesToHex(
                pair.right_proof_artifact_sha256,
                .lower,
            ),
            .task_identity_sha256 = std.fmt.bytesToHex(
                pair.task_identity_sha256,
                .lower,
            ),
        };
    }

    pub fn wire(self: *const @This()) PairAdmissionRecordV1 {
        return .{
            .arm_kind = self.arm_kind,
            .h1_profile_identity_sha256 = &self.h1_profile_identity_sha256,
            .ingress_identity_sha256 = &self.ingress_identity_sha256,
            .left_capture_identity_sha256 = &self.left_capture_identity_sha256,
            .left_descriptor_sha256 = &self.left_descriptor_sha256,
            .left_node_public_authority_sha256 = &self.left_node_public_authority_sha256,
            .left_proof_artifact_sha256 = &self.left_proof_artifact_sha256,
            .ordinal = self.ordinal,
            .pair_admission_identity_sha256 = &self.pair_admission_identity_sha256,
            .parent_index = self.parent_index,
            .right_capture_identity_sha256 = &self.right_capture_identity_sha256,
            .right_descriptor_sha256 = &self.right_descriptor_sha256,
            .right_node_public_authority_sha256 = &self.right_node_public_authority_sha256,
            .right_proof_artifact_sha256 = &self.right_proof_artifact_sha256,
            .task_identity_sha256 = &self.task_identity_sha256,
        };
    }
};

pub const UnsignedStructuralResultV1 = struct {
    all_bundles_cold_verified: bool,
    all_pair_capabilities_validated: bool,
    batch_admission_identity_sha256: []const u8,
    batch_plan_identity_sha256: []const u8,
    h1_proofs_executed: bool = h1_proofs_executed,
    leaf_count: u32 = @intCast(leaf_count),
    pair_admissions: []const PairAdmissionRecordV1,
    pair_count: u32 = @intCast(pair_count),
    product_admissible: bool = product_admissible,
    production_active: bool = production_active,
    request_content_sha256: []const u8,
    schema: []const u8 = result_schema,
    status: []const u8 = result_status,
    upper_or_root_admitted: bool = upper_or_root_admitted,

    pub fn validate(self: UnsignedStructuralResultV1) !void {
        if (!std.mem.eql(u8, self.schema, result_schema) or
            !std.mem.eql(u8, self.status, result_status) or
            !self.all_bundles_cold_verified or
            !self.all_pair_capabilities_validated or
            self.h1_proofs_executed or self.upper_or_root_admitted or
            self.product_admissible or self.production_active or
            self.leaf_count != leaf_count or self.pair_count != pair_count or
            self.pair_admissions.len != pair_count)
        {
            return error.InvalidOmittedH1StructuralResult;
        }
        inline for (.{
            self.batch_admission_identity_sha256,
            self.batch_plan_identity_sha256,
            self.request_content_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        for (self.pair_admissions, 0..) |pair, ordinal|
            try pair.validate(ordinal);
    }
};

pub const SealedStructuralResultV1 = struct {
    content_sha256: []const u8,
    all_bundles_cold_verified: bool,
    all_pair_capabilities_validated: bool,
    batch_admission_identity_sha256: []const u8,
    batch_plan_identity_sha256: []const u8,
    h1_proofs_executed: bool,
    leaf_count: u32,
    pair_admissions: []const PairAdmissionRecordV1,
    pair_count: u32,
    product_admissible: bool,
    production_active: bool,
    request_content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    upper_or_root_admitted: bool,

    pub fn unsigned(self: SealedStructuralResultV1) UnsignedStructuralResultV1 {
        return .{
            .all_bundles_cold_verified = self.all_bundles_cold_verified,
            .all_pair_capabilities_validated = self.all_pair_capabilities_validated,
            .batch_admission_identity_sha256 = self.batch_admission_identity_sha256,
            .batch_plan_identity_sha256 = self.batch_plan_identity_sha256,
            .h1_proofs_executed = self.h1_proofs_executed,
            .leaf_count = self.leaf_count,
            .pair_admissions = self.pair_admissions,
            .pair_count = self.pair_count,
            .product_admissible = self.product_admissible,
            .production_active = self.production_active,
            .request_content_sha256 = self.request_content_sha256,
            .schema = self.schema,
            .status = self.status,
            .upper_or_root_admitted = self.upper_or_root_admitted,
        };
    }

    pub fn validate(self: SealedStructuralResultV1) !void {
        _ = try contract.parseSha256(self.content_sha256);
        try self.unsigned().validate();
    }
};

pub fn encodeRequestAlloc(
    allocator: std.mem.Allocator,
    value: UnsignedRequestSetV1,
) ![]u8 {
    try value.validate();
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

pub fn parseRequest(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(SealedRequestSetV1) {
    return parseSealed(SealedRequestSetV1, allocator, bytes);
}

pub fn encodeResultAlloc(
    allocator: std.mem.Allocator,
    value: UnsignedStructuralResultV1,
) ![]u8 {
    try value.validate();
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

pub fn parseResult(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(SealedStructuralResultV1) {
    return parseSealed(SealedStructuralResultV1, allocator, bytes);
}

pub fn publishRequestCreateOnly(path: []const u8, bytes: []const u8) !void {
    var parsed = try parseRequest(std.heap.page_allocator, bytes);
    defer parsed.deinit();
    try artifact_io.publishCreateOnlyDurable(path, bytes);
}

/// Seal-last structural publication.  No partial result is emitted by this
/// module, and the publication never contains an H1 proof claim.
pub fn publishResultCreateOnly(path: []const u8, bytes: []const u8) !void {
    var parsed = try parseResult(std.heap.page_allocator, bytes);
    defer parsed.deinit();
    try artifact_io.publishCreateOnlyDurable(path, bytes);
}

fn parseSealed(
    comptime T: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(T) {
    if (bytes.len == 0 or bytes.len > maximum_json_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidOmittedH1CanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(T, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    try parsed.value.validate();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidOmittedH1CanonicalJson;
    }
    try validateContentSeal(allocator, canonical, parsed.value.content_sha256);
    return parsed;
}

fn validateContentSeal(
    allocator: std.mem.Allocator,
    canonical: []const u8,
    encoded_digest: []const u8,
) !void {
    const digest = try contract.parseSha256(encoded_digest);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, canonical, prefix) or
        canonical.len <= prefix.len + 65 or
        canonical[prefix.len + 64] != '"' or
        canonical[prefix.len + 65] != ',' or
        !std.mem.eql(
            u8,
            canonical[prefix.len .. prefix.len + 64],
            encoded_digest,
        )) return error.InvalidOmittedH1ContentSeal;
    const unsigned = try allocator.alloc(
        u8,
        canonical.len - (prefix.len + 66) + 1,
    );
    defer allocator.free(unsigned);
    unsigned[0] = '{';
    @memcpy(unsigned[1..], canonical[prefix.len + 66 ..]);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    if (!std.mem.eql(u8, &digest, &hash.finalResult()))
        return error.InvalidOmittedH1ContentSeal;
}

fn requireAllPathsDistinct(value: UnsignedRequestSetV1) !void {
    const fixed = [_][]const u8{
        value.elf.path,
        value.execution_journal.path,
        value.expected_output.path,
        value.input.path,
        value.materialization_result.path,
        value.source_request.path,
    };
    for (fixed, 0..) |path, index| {
        for (fixed[index + 1 ..]) |other|
            if (std.mem.eql(u8, path, other))
                return error.OmittedH1DuplicatePath;
        for (value.bundles) |bundle|
            if (std.mem.eql(u8, path, bundle.artifact.path) or
                std.mem.eql(u8, path, bundle.source_authority.path))
                return error.OmittedH1DuplicatePath;
    }
    for (value.bundles, 0..) |bundle, index| {
        for (value.bundles[index + 1 ..]) |other| {
            if (std.mem.eql(u8, bundle.artifact.path, other.artifact.path) or
                std.mem.eql(
                    u8,
                    bundle.artifact.path,
                    other.source_authority.path,
                ) or
                std.mem.eql(
                    u8,
                    bundle.source_authority.path,
                    other.artifact.path,
                ) or
                std.mem.eql(
                    u8,
                    bundle.source_authority.path,
                    other.source_authority.path,
                ) or
                std.mem.eql(
                    u8,
                    bundle.artifact.sha256,
                    other.artifact.sha256,
                ) or
                std.mem.eql(
                    u8,
                    bundle.source_authority.sha256,
                    other.source_authority.sha256,
                ) or
                std.mem.eql(
                    u8,
                    bundle.authority_identity_sha256,
                    other.authority_identity_sha256,
                ))
                return error.OmittedH1DuplicatePath;
        }
    }
}

fn digestMatches(encoded: []const u8, expected: [32]u8) bool {
    const actual = contract.parseSha256(encoded) catch return false;
    return std.mem.eql(u8, &actual, &expected);
}
