//! Ordered 210-leaf admission plan for the real Ethereum h1 cohort.
//!
//! The full temporal tree has 256 height-zero slots and 255 parent proofs.
//! This module deliberately owns only the 105 height-one real/real tasks. The
//! 23 empty/empty height-one tasks and all 127 upper tasks stay on their
//! existing typed routes. A future projected-candidate verifier can enter via
//! the generic pair surface only after its owner mints a live capability; no
//! candidate capture type or digest-only substitute is declared here.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const ingress_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const materializer_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_materializer_v1.zig");
const proof_security =
    @import("recursive_temporal_proof_security_v1.zig");
const statement_plan =
    @import("recursive_temporal_statement_plan_v1.zig");
const topology_mod = @import("recursive_temporal_topology_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const REAL_H1_PAIR_COUNT: usize = 105;
pub const EMPTY_H1_PAIR_COUNT: usize = 23;
pub const HEIGHT_ONE_TASK_COUNT: usize = 128;
pub const UPPER_TASK_COUNT: usize = 127;
pub const TOTAL_PARENT_TASK_COUNT: usize = 255;
pub const MIXED_PARENT_TASK_COUNT: usize = 7;

const TASK_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-batch-task/v1\x00";
const PLAN_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-batch-plan/v1\x00";
const PAIR_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-fresh-pair/v1\x00";
const ADMISSION_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-batch-admission/v1\x00";

pub const ArmKindV1 = enum(u8) {
    retained_baseline_poseidon_v4 = 1,
    projected_candidate_v1 = 2,
};

pub const GeometryV1 = struct {
    real_leaf_count: u32,
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    root_height: u8,
    real_h1_pair_count: u16,
    empty_h1_pair_count: u16,
    upper_task_count: u16,
    mixed_parent_task_count: u8,
    reserved: [2]u8 = .{ 0, 0 },

    pub fn validate(self: GeometryV1) !void {
        if (self.real_leaf_count != statement_plan.REAL_LEAF_COUNT or
            self.padded_leaf_count != statement_plan.PADDED_LEAF_COUNT or
            self.empty_leaf_count != statement_plan.EMPTY_LEAF_COUNT or
            self.root_height != statement_plan.ROOT_HEIGHT or
            self.real_h1_pair_count != REAL_H1_PAIR_COUNT or
            self.empty_h1_pair_count != EMPTY_H1_PAIR_COUNT or
            self.upper_task_count != UPPER_TASK_COUNT or
            self.mixed_parent_task_count != MIXED_PARENT_TASK_COUNT or
            !std.mem.allEqual(u8, &self.reserved, 0))
        {
            return error.InvalidEthereumPoseidonH1BatchGeometry;
        }
    }
};

/// Pointer-free plan record for one height-one real/real proof.
pub const RealH1TaskV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    reserved: u32 = 0,
    ordinal: u32,
    parent_index: u32,
    left_leaf_index: u32,
    right_leaf_index: u32,
    topology_task_identity_sha256: [32]u8,
    left_leaf_record_identity_sha256: [32]u8,
    right_leaf_record_identity_sha256: [32]u8,
    left_source_authority_sha256: [32]u8,
    right_source_authority_sha256: [32]u8,
    left_source_public_statement_sha256: [32]u8,
    right_source_public_statement_sha256: [32]u8,
    left_statement_sha256: [32]u8,
    right_statement_sha256: [32]u8,
    parent_record_identity_sha256: [32]u8,
    parent_statement_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    identity_sha256: [32]u8,

    pub fn validate(self: *const RealH1TaskV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.reserved != 0 or
            self.ordinal >= REAL_H1_PAIR_COUNT or
            self.parent_index != self.ordinal or
            self.left_leaf_index != self.ordinal * 2 or
            self.right_leaf_index != self.left_leaf_index + 1)
        {
            return error.InvalidEthereumPoseidonH1BatchTask;
        }
        inline for (.{
            self.topology_task_identity_sha256,
            self.left_leaf_record_identity_sha256,
            self.right_leaf_record_identity_sha256,
            self.left_source_authority_sha256,
            self.right_source_authority_sha256,
            self.left_source_public_statement_sha256,
            self.right_source_public_statement_sha256,
            self.left_statement_sha256,
            self.right_statement_sha256,
            self.parent_record_identity_sha256,
            self.parent_statement_sha256,
            self.profile_identity_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        try requireDigest(self.verification_key_id);
        try requireDigest(self.next_parent_vk_id);
        if (!std.mem.eql(u8, &self.identity_sha256, &taskIdentity(self)))
            return error.InvalidEthereumPoseidonH1BatchTask;
    }
};

/// Fixed-size custody for the exact real-H1 prefix of the breadth schedule.
pub const BatchPlanV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    geometry: GeometryV1,
    topology_plan_identity_sha256: [32]u8,
    statement_plan_identity_sha256: [32]u8,
    breadth_schedule_identity_sha256: [32]u8,
    real_h1_profile_identity_sha256: [32]u8,
    tasks: [REAL_H1_PAIR_COUNT]RealH1TaskV1,
    identity_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
    ) !BatchPlanV1 {
        try source.validate();
        try source.profiles.real_h1.requireProductionSecurity();
        const geometry = try auditGeometry(allocator, source.topology);
        var schedule = try topology_mod.BreadthFirstScheduleV1.create(
            allocator,
            source.topology,
        );
        defer schedule.deinit();
        var result = BatchPlanV1{
            .geometry = geometry,
            .topology_plan_identity_sha256 = source.topology.identity,
            .statement_plan_identity_sha256 = source.identity,
            .breadth_schedule_identity_sha256 = schedule.identity,
            .real_h1_profile_identity_sha256 = source.profiles.real_h1.identity,
            .tasks = undefined,
            .identity_sha256 = undefined,
        };
        for (&result.tasks, 0..) |*destination, ordinal|
            destination.* = try taskFromPlan(source, &schedule, ordinal);
        result.identity_sha256 = planIdentity(&result);
        try result.validateAgainst(allocator, source);
        return result;
    }

    pub fn validateCustody(self: *const BatchPlanV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0))
        {
            return error.InvalidEthereumPoseidonH1BatchPlan;
        }
        try self.geometry.validate();
        inline for (.{
            self.topology_plan_identity_sha256,
            self.statement_plan_identity_sha256,
            self.breadth_schedule_identity_sha256,
            self.real_h1_profile_identity_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        for (&self.tasks, 0..) |*task, ordinal| {
            try task.validate();
            if (task.ordinal != @as(u32, @intCast(ordinal)))
                return error.InvalidEthereumPoseidonH1BatchPlan;
        }
        if (!std.mem.eql(u8, &self.identity_sha256, &planIdentity(self)))
            return error.InvalidEthereumPoseidonH1BatchPlan;
    }

    /// Reopens the complete 511-node statement plan and 255-task schedule.
    pub fn validateAgainst(
        self: *const BatchPlanV1,
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
    ) !void {
        try self.validateCustody();
        try source.validate();
        try source.profiles.real_h1.requireProductionSecurity();
        const expected = try BatchPlanV1.initUnchecked(allocator, source);
        if (!std.meta.eql(self.*, expected))
            return error.EthereumPoseidonH1BatchPlanMismatch;
    }

    fn initUnchecked(
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
    ) !BatchPlanV1 {
        const geometry = try auditGeometry(allocator, source.topology);
        var schedule = try topology_mod.BreadthFirstScheduleV1.create(
            allocator,
            source.topology,
        );
        defer schedule.deinit();
        var result = BatchPlanV1{
            .geometry = geometry,
            .topology_plan_identity_sha256 = source.topology.identity,
            .statement_plan_identity_sha256 = source.identity,
            .breadth_schedule_identity_sha256 = schedule.identity,
            .real_h1_profile_identity_sha256 = source.profiles.real_h1.identity,
            .tasks = undefined,
            .identity_sha256 = undefined,
        };
        for (&result.tasks, 0..) |*destination, ordinal|
            destination.* = try taskFromPlan(source, &schedule, ordinal);
        result.identity_sha256 = planIdentity(&result);
        try result.validateCustody();
        return result;
    }
};

/// Pointer-free result of admitting one live verifier-minted pair.
pub const FreshPairAdmissionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    arm_kind: ArmKindV1,
    reserved: [3]u8 = .{ 0, 0, 0 },
    ordinal: u32,
    parent_index: u32,
    batch_identity_sha256: [32]u8,
    task_identity_sha256: [32]u8,
    ingress_identity_sha256: [32]u8,
    h1_profile_identity_sha256: [32]u8,
    left_descriptor_sha256: [32]u8,
    right_descriptor_sha256: [32]u8,
    left_node_public_authority_sha256: [32]u8,
    right_node_public_authority_sha256: [32]u8,
    left_proof_artifact_sha256: [32]u8,
    right_proof_artifact_sha256: [32]u8,
    left_capture_identity_sha256: [32]u8,
    right_capture_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validateAgainst(
        self: *const FreshPairAdmissionV1,
        batch: *const BatchPlanV1,
    ) !void {
        try batch.validateCustody();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.ordinal >= REAL_H1_PAIR_COUNT)
        {
            return error.InvalidEthereumPoseidonH1PairAdmission;
        }
        const task = &batch.tasks[self.ordinal];
        if (self.parent_index != task.parent_index or
            !std.mem.eql(u8, &self.batch_identity_sha256, &batch.identity_sha256) or
            !std.mem.eql(u8, &self.task_identity_sha256, &task.identity_sha256))
        {
            return error.InvalidEthereumPoseidonH1PairAdmission;
        }
        inline for (.{
            self.ingress_identity_sha256,
            self.h1_profile_identity_sha256,
            self.left_descriptor_sha256,
            self.right_descriptor_sha256,
            self.left_node_public_authority_sha256,
            self.right_node_public_authority_sha256,
            self.left_proof_artifact_sha256,
            self.right_proof_artifact_sha256,
            self.left_capture_identity_sha256,
            self.right_capture_identity_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        if (!std.mem.eql(u8, &self.identity_sha256, &pairIdentity(self)))
            return error.InvalidEthereumPoseidonH1PairAdmission;
    }
};

/// Ordered, single-arm closure over all 105 freshly admitted real H1 pairs.
pub const BatchAdmissionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    arm_kind: ArmKindV1,
    production_activation: bool = PRODUCTION_ACTIVATION,
    batch_identity_sha256: [32]u8,
    pairs: [REAL_H1_PAIR_COUNT]FreshPairAdmissionV1,
    identity_sha256: [32]u8,

    pub fn init(
        batch: *const BatchPlanV1,
        pairs: [REAL_H1_PAIR_COUNT]FreshPairAdmissionV1,
    ) !BatchAdmissionV1 {
        try batch.validateCustody();
        const arm_kind = pairs[0].arm_kind;
        var result = BatchAdmissionV1{
            .arm_kind = arm_kind,
            .batch_identity_sha256 = batch.identity_sha256,
            .pairs = pairs,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = admissionIdentity(&result);
        try result.validateAgainst(batch);
        return result;
    }

    pub fn validateAgainst(
        self: *const BatchAdmissionV1,
        batch: *const BatchPlanV1,
    ) !void {
        try batch.validateCustody();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.eql(u8, &self.batch_identity_sha256, &batch.identity_sha256))
        {
            return error.InvalidEthereumPoseidonH1BatchAdmission;
        }
        for (&self.pairs, 0..) |*pair, ordinal| {
            try pair.validateAgainst(batch);
            if (pair.ordinal != @as(u32, @intCast(ordinal)) or
                pair.arm_kind != self.arm_kind)
                return error.InvalidEthereumPoseidonH1BatchAdmission;
        }
        if (!std.mem.eql(u8, &self.identity_sha256, &admissionIdentity(self)))
            return error.InvalidEthereumPoseidonH1BatchAdmission;
    }
};

/// Admits the same generic live pair surface consumed by the H1 cohort.
/// `DefaultPoseidonV4AdapterV1` is the baseline implementation. The future
/// candidate owner must mint its own pair capability from two freshly
/// verified candidate leaves; this function never constructs that type.
pub fn admitVerifierMintedPair(
    allocator: std.mem.Allocator,
    batch: *const BatchPlanV1,
    ordinal: usize,
    verifier_minted: anytype,
) !FreshPairAdmissionV1 {
    const Pair = @TypeOf(verifier_minted);
    validateVerifierMintedSurface(Pair);
    try batch.validateCustody();
    if (ordinal >= REAL_H1_PAIR_COUNT)
        return error.InvalidEthereumPoseidonH1BatchTask;
    try verifier_minted.validateForH1(allocator);
    const custody = verifier_minted.custody();
    try custody.validate();
    _ = verifier_minted.captureViews();
    const freshness = verifier_minted.freshnessKind();
    const arm_kind: ArmKindV1 = switch (freshness) {
        .default_poseidon_v4 => .retained_baseline_poseidon_v4,
        .projected_candidate_v1 => .projected_candidate_v1,
    };
    const task = &batch.tasks[ordinal];
    const profile = &custody.h1_profile;
    const secure_parent = proof_security.ProofSecurityV1
        .recursiveParentSecure();
    if (profile.parent_proof_security_kind != .recursive_parent_secure or
        !std.mem.eql(u8, &profile.parent_proof_security_sha256, &secure_parent.identity) or
        !std.mem.eql(u8, &profile.node_profile_sha256, &task.profile_identity_sha256) or
        !std.meta.eql(profile.verification_key_id, task.verification_key_id) or
        !std.meta.eql(profile.next_parent_vk_id, task.next_parent_vk_id) or
        !std.mem.eql(u8, &custody.parent_statement_sha256, &task.parent_statement_sha256) or
        !childMatchesTask(&custody.children[0], task, true) or
        !childMatchesTask(&custody.children[1], task, false))
    {
        return error.EthereumPoseidonH1PairAdmissionMismatch;
    }
    var result = FreshPairAdmissionV1{
        .arm_kind = arm_kind,
        .ordinal = @intCast(ordinal),
        .parent_index = task.parent_index,
        .batch_identity_sha256 = batch.identity_sha256,
        .task_identity_sha256 = task.identity_sha256,
        .ingress_identity_sha256 = custody.identity_sha256,
        .h1_profile_identity_sha256 = profile.identity_sha256,
        .left_descriptor_sha256 = custody.children[0].descriptor_sha256,
        .right_descriptor_sha256 = custody.children[1].descriptor_sha256,
        .left_node_public_authority_sha256 = custody.children[0].node_public_authority_sha256,
        .right_node_public_authority_sha256 = custody.children[1].node_public_authority_sha256,
        .left_proof_artifact_sha256 = custody.children[0].proof_artifact_sha256,
        .right_proof_artifact_sha256 = custody.children[1].proof_artifact_sha256,
        .left_capture_identity_sha256 = custody.children[0].capture_identity_sha256,
        .right_capture_identity_sha256 = custody.children[1].capture_identity_sha256,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = pairIdentity(&result);
    try result.validateAgainst(batch);
    return result;
}

pub fn auditGeometry(
    allocator: std.mem.Allocator,
    topology: topology_mod.TopologyPlanV1,
) !GeometryV1 {
    try topology.validate();
    var schedule = try topology_mod.BreadthFirstScheduleV1.create(
        allocator,
        topology,
    );
    defer schedule.deinit();
    var real_h1: u16 = 0;
    var empty_h1: u16 = 0;
    var upper: u16 = 0;
    var mixed: u8 = 0;
    for (schedule.tasks) |task| {
        if (task.parent_height == 1) {
            if (task.left_kind == .real and task.right_kind == .real)
                real_h1 += 1
            else if (task.left_kind == .empty and task.right_kind == .empty)
                empty_h1 += 1
            else
                return error.InvalidEthereumPoseidonH1BatchGeometry;
        } else {
            upper += 1;
        }
        if (try topology.nodeKind(task.parent_height, task.parent_index) == .mixed)
            mixed += 1;
    }
    const result = GeometryV1{
        .real_leaf_count = topology.real_leaf_count,
        .padded_leaf_count = @intCast(topology.padded_leaf_count),
        .empty_leaf_count = @intCast(topology.empty_leaf_count),
        .root_height = topology.root_height,
        .real_h1_pair_count = real_h1,
        .empty_h1_pair_count = empty_h1,
        .upper_task_count = upper,
        .mixed_parent_task_count = mixed,
    };
    try result.validate();
    return result;
}

fn taskFromPlan(
    source: *const statement_plan.MaterializedPlanV1,
    schedule: *const topology_mod.BreadthFirstScheduleV1,
    ordinal: usize,
) !RealH1TaskV1 {
    const topology_task = &schedule.tasks[ordinal];
    const parent = &source.parents[ordinal];
    const left_index = ordinal * 2;
    const right_index = left_index + 1;
    const left = &source.leaves[left_index];
    const right = &source.leaves[right_index];
    if (topology_task.ordinal != @as(u64, @intCast(ordinal)) or
        topology_task.parent_height != 1 or
        topology_task.child_height != 0 or
        topology_task.left_kind != .real or topology_task.right_kind != .real or
        parent.ordinal != @as(u32, @intCast(ordinal)) or
        parent.height != 1 or parent.kind != .real or
        left.kind != .real or right.kind != .real)
    {
        return error.InvalidEthereumPoseidonH1BatchTask;
    }
    var result = RealH1TaskV1{
        .ordinal = @intCast(ordinal),
        .parent_index = @intCast(topology_task.parent_index),
        .left_leaf_index = @intCast(left_index),
        .right_leaf_index = @intCast(right_index),
        .topology_task_identity_sha256 = topology_task.identity,
        .left_leaf_record_identity_sha256 = left.identity,
        .right_leaf_record_identity_sha256 = right.identity,
        .left_source_authority_sha256 = left.source_sha_id,
        .right_source_authority_sha256 = right.source_sha_id,
        .left_source_public_statement_sha256 = left.source_public_statement_sha_id,
        .right_source_public_statement_sha256 = right.source_public_statement_sha_id,
        .left_statement_sha256 = left.statement_sha_id,
        .right_statement_sha256 = right.statement_sha_id,
        .parent_record_identity_sha256 = parent.identity,
        .parent_statement_sha256 = parent.statement_sha_id,
        .profile_identity_sha256 = parent.profile_sha_id,
        .verification_key_id = parent.verification_key_id,
        .next_parent_vk_id = parent.next_parent_vk_id,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = taskIdentity(&result);
    try result.validate();
    return result;
}

fn childMatchesTask(
    child: *const ingress_mod.LeafAuthorityV1,
    task: *const RealH1TaskV1,
    left: bool,
) bool {
    const expected_source = if (left)
        task.left_source_authority_sha256
    else
        task.right_source_authority_sha256;
    const expected_public = if (left)
        task.left_source_public_statement_sha256
    else
        task.right_source_public_statement_sha256;
    const expected_statement = if (left)
        task.left_statement_sha256
    else
        task.right_statement_sha256;
    return std.mem.eql(u8, &child.source_authority_sha256, &expected_source) and
        std.mem.eql(u8, &child.source_public_statement_sha256, &expected_public) and
        std.mem.eql(u8, &statement_plan.statementSha256(
            &child.global_statement_words,
        ), &expected_statement);
}

fn validateVerifierMintedSurface(comptime T: type) void {
    inline for (.{
        "validateForH1",
        "custody",
        "freshnessKind",
        "captureViews",
    }) |name| if (!@hasDecl(T, name))
        @compileError("H1 batch verifier-minted pair surface missing " ++ name);
}

fn taskIdentity(value: *const RealH1TaskV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TASK_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.ordinal);
    hashInt(&hash, u32, value.parent_index);
    hashInt(&hash, u32, value.left_leaf_index);
    hashInt(&hash, u32, value.right_leaf_index);
    inline for (.{
        value.topology_task_identity_sha256,
        value.left_leaf_record_identity_sha256,
        value.right_leaf_record_identity_sha256,
        value.left_source_authority_sha256,
        value.right_source_authority_sha256,
        value.left_source_public_statement_sha256,
        value.right_source_public_statement_sha256,
        value.left_statement_sha256,
        value.right_statement_sha256,
        value.parent_record_identity_sha256,
        value.parent_statement_sha256,
        value.profile_identity_sha256,
    }) |item| hash.update(&item);
    hashDigest(&hash, value.verification_key_id);
    hashDigest(&hash, value.next_parent_vk_id);
    return hash.finalResult();
}

fn planIdentity(value: *const BatchPlanV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PLAN_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u32, value.geometry.real_leaf_count);
    hashInt(&hash, u32, value.geometry.padded_leaf_count);
    hashInt(&hash, u32, value.geometry.empty_leaf_count);
    hashInt(&hash, u8, value.geometry.root_height);
    hashInt(&hash, u16, value.geometry.real_h1_pair_count);
    hashInt(&hash, u16, value.geometry.empty_h1_pair_count);
    hashInt(&hash, u16, value.geometry.upper_task_count);
    hashInt(&hash, u8, value.geometry.mixed_parent_task_count);
    hash.update(&value.topology_plan_identity_sha256);
    hash.update(&value.statement_plan_identity_sha256);
    hash.update(&value.breadth_schedule_identity_sha256);
    hash.update(&value.real_h1_profile_identity_sha256);
    for (value.tasks) |task| hash.update(&task.identity_sha256);
    return hash.finalResult();
}

fn pairIdentity(value: *const FreshPairAdmissionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PAIR_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.arm_kind));
    hashInt(&hash, u32, value.ordinal);
    hashInt(&hash, u32, value.parent_index);
    inline for (.{
        value.batch_identity_sha256,
        value.task_identity_sha256,
        value.ingress_identity_sha256,
        value.h1_profile_identity_sha256,
        value.left_descriptor_sha256,
        value.right_descriptor_sha256,
        value.left_node_public_authority_sha256,
        value.right_node_public_authority_sha256,
        value.left_proof_artifact_sha256,
        value.right_proof_artifact_sha256,
        value.left_capture_identity_sha256,
        value.right_capture_identity_sha256,
    }) |item| hash.update(&item);
    return hash.finalResult();
}

fn admissionIdentity(value: *const BatchAdmissionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ADMISSION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.arm_kind));
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.batch_identity_sha256);
    for (value.pairs) |pair| hash.update(&pair.identity_sha256);
    return hash.finalResult();
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidEthereumPoseidonH1BatchAuthority;
}

fn requireDigest(value: channel.Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidEthereumPoseidonH1BatchAuthority;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidEthereumPoseidonH1BatchAuthority;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn resealTask(value: *RealH1TaskV1) void {
        requireTest();
        value.identity_sha256 = taskIdentity(value);
    }

    pub fn resealPlan(value: *BatchPlanV1) void {
        requireTest();
        value.identity_sha256 = planIdentity(value);
    }

    pub fn resealPair(value: *FreshPairAdmissionV1) void {
        requireTest();
        value.identity_sha256 = pairIdentity(value);
    }

    pub fn resealAdmission(value: *BatchAdmissionV1) void {
        requireTest();
        value.identity_sha256 = admissionIdentity(value);
    }

    fn requireTest() void {
        if (!builtin.is_test)
            @panic("Ethereum H1 batch testing helper used outside test build");
    }
};

comptime {
    if (REAL_H1_PAIR_COUNT * 2 != statement_plan.REAL_LEAF_COUNT or
        HEIGHT_ONE_TASK_COUNT != statement_plan.PADDED_LEAF_COUNT / 2 or
        EMPTY_H1_PAIR_COUNT * 2 != statement_plan.EMPTY_LEAF_COUNT or
        HEIGHT_ONE_TASK_COUNT + UPPER_TASK_COUNT != TOTAL_PARENT_TASK_COUNT or
        topology_mod.PRODUCT_REAL_LEAF_COUNT != statement_plan.REAL_LEAF_COUNT or
        topology_mod.PRODUCT_PADDED_LEAF_COUNT != statement_plan.PADDED_LEAF_COUNT or
        PRODUCTION_ACTIVATION or
        @intFromEnum(materializer_mod.FreshnessKindV1.default_poseidon_v4) != 1 or
        @intFromEnum(materializer_mod.FreshnessKindV1.projected_candidate_v1) != 2)
    {
        @compileError("Ethereum Poseidon h1 batch contract drifted");
    }
}
