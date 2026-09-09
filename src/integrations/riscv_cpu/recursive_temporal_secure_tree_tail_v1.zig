//! Exact proof-bearing tail of the 210 -> 256 temporal tree.
//!
//! Real/real height-one tasks are owned by the Ethereum Poseidon H1 batch.
//! This sibling owns the remaining 23 empty/empty height-one tasks and the
//! 127 height-two-through-height-eight product tasks.  Empty leaves remain
//! proofless only at height zero: every record in this plan requires an
//! ordinary secure parent proof and cold fresh verification.
//!
//! The existing empty-parent source can mint `EmptyH1AdmissionV1` today.  An
//! upper proof additionally needs an authenticated composition-program
//! capture for each secure H1/upper child.  The current secure H1 result keeps
//! the PCS capture but not that composition capture, so upper execution and
//! production remain explicitly unavailable rather than reusing the legacy
//! 36-row capture under a new identity.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const empty_source_mod =
    @import("recursive_temporal_empty_parent_source_v1.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const topology_mod = @import("recursive_temporal_topology_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const UPPER_EXECUTION_AVAILABLE = false;
pub const SECURE_CHILD_COMPOSITION_CAPTURE_AVAILABLE = false;
pub const REAL_H1_TASK_COUNT: usize = 105;
pub const EMPTY_H1_TASK_COUNT: usize = 23;
pub const HEIGHT_ONE_TASK_COUNT: usize = 128;
pub const UPPER_TASK_COUNT: usize = 127;
pub const TAIL_TASK_COUNT: usize = EMPTY_H1_TASK_COUNT + UPPER_TASK_COUNT;
pub const TOTAL_PARENT_TASK_COUNT: usize = 255;
pub const FIRST_EMPTY_H1_ORDINAL: usize = REAL_H1_TASK_COUNT;
pub const FIRST_UPPER_ORDINAL: usize = HEIGHT_ONE_TASK_COUNT;
pub const LAST_PARENT_ORDINAL: usize = TOTAL_PARENT_TASK_COUNT - 1;
pub const UPPER_REAL_TASK_COUNT: usize = 101;
pub const UPPER_EMPTY_TASK_COUNT: usize = 19;
pub const UPPER_MIXED_TASK_COUNT: usize = 7;

const TASK_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-secure-tail-task/v1\x00";
const PLAN_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-secure-tail-plan/v1\x00";
const EMPTY_ADMISSION_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-empty-h1-admission/v1\x00";

pub const TaskClassV1 = enum(u8) {
    empty_h1 = 1,
    upper = 2,
};

pub const GeometryV1 = struct {
    real_leaf_count: u32,
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    root_height: u8,
    empty_h1_task_count: u16,
    upper_task_count: u16,
    upper_real_task_count: u16,
    upper_empty_task_count: u16,
    upper_mixed_task_count: u16,
    reserved: [3]u8 = .{ 0, 0, 0 },

    pub fn validate(self: GeometryV1) !void {
        if (self.real_leaf_count != statement_plan.REAL_LEAF_COUNT or
            self.padded_leaf_count != statement_plan.PADDED_LEAF_COUNT or
            self.empty_leaf_count != statement_plan.EMPTY_LEAF_COUNT or
            self.root_height != statement_plan.ROOT_HEIGHT or
            self.empty_h1_task_count != EMPTY_H1_TASK_COUNT or
            self.upper_task_count != UPPER_TASK_COUNT or
            self.upper_real_task_count != UPPER_REAL_TASK_COUNT or
            self.upper_empty_task_count != UPPER_EMPTY_TASK_COUNT or
            self.upper_mixed_task_count != UPPER_MIXED_TASK_COUNT or
            !std.mem.allEqual(u8, &self.reserved, 0))
        {
            return error.InvalidSecureTreeTailGeometry;
        }
    }
};

/// Expected proof product for one task.  Child and parent identities come
/// from `MaterializedPlanV1`; no verifier-minted proof identity is predicted.
pub const ProductTaskV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    task_class: TaskClassV1,
    parent_kind: topology_mod.NodeKindV1,
    left_kind: topology_mod.NodeKindV1,
    right_kind: topology_mod.NodeKindV1,
    parent_height: u8,
    child_height: u8,
    requires_secure_proof: bool = true,
    requires_cold_fresh_verification: bool = true,
    requires_child_composition_capture: bool,
    reserved: [2]u8 = .{ 0, 0 },
    local_ordinal: u16,
    global_ordinal: u16,
    parent_index: u32,
    left_index: u32,
    right_index: u32,
    topology_task_identity_sha256: [32]u8,
    left_record_identity_sha256: [32]u8,
    right_record_identity_sha256: [32]u8,
    left_statement_sha256: [32]u8,
    right_statement_sha256: [32]u8,
    parent_record_identity_sha256: [32]u8,
    parent_statement_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    identity_sha256: [32]u8,

    pub fn validate(self: *const ProductTaskV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !self.requires_secure_proof or
            !self.requires_cold_fresh_verification or
            self.requires_child_composition_capture !=
                (self.task_class == .upper) or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.right_index != self.left_index + 1 or
            self.left_index != self.parent_index * 2)
        {
            return error.InvalidSecureTreeTailTask;
        }
        switch (self.task_class) {
            .empty_h1 => {
                if (self.local_ordinal >= EMPTY_H1_TASK_COUNT or
                    self.global_ordinal !=
                        @as(u16, FIRST_EMPTY_H1_ORDINAL) +
                            self.local_ordinal or
                    self.parent_height != 1 or self.child_height != 0 or
                    self.parent_index != @as(u32, self.global_ordinal) or
                    self.parent_kind != .empty or self.left_kind != .empty or
                    self.right_kind != .empty)
                {
                    return error.InvalidSecureTreeTailTask;
                }
            },
            .upper => {
                const expected = try upperCoordinates(@intCast(
                    self.local_ordinal,
                ));
                if (self.local_ordinal >= UPPER_TASK_COUNT or
                    self.global_ordinal !=
                        @as(u16, FIRST_UPPER_ORDINAL) +
                            self.local_ordinal or
                    self.parent_height != expected.height or
                    self.child_height + 1 != self.parent_height or
                    self.parent_index != expected.index or
                    !validChildKinds(
                        self.parent_kind,
                        self.left_kind,
                        self.right_kind,
                    ))
                {
                    return error.InvalidSecureTreeTailTask;
                }
            },
        }
        inline for (.{
            self.topology_task_identity_sha256,
            self.left_record_identity_sha256,
            self.right_record_identity_sha256,
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
            return error.InvalidSecureTreeTailTask;
    }
};

/// Fixed-size schedule and product contract for all tasks not owned by the
/// real-H1 batch.  It binds the entire canonical topology and statement plan.
pub const TailPlanV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    upper_execution_available: bool = UPPER_EXECUTION_AVAILABLE,
    secure_child_composition_capture_available: bool =
        SECURE_CHILD_COMPOSITION_CAPTURE_AVAILABLE,
    reserved: [3]u8 = .{ 0, 0, 0 },
    geometry: GeometryV1,
    topology_plan_identity_sha256: [32]u8,
    statement_plan_identity_sha256: [32]u8,
    breadth_schedule_identity_sha256: [32]u8,
    empty_authority_identity_sha256: [32]u8,
    empty_h1_profile_identity_sha256: [32]u8,
    upper_profile_identity_sha256: [statement_plan.UPPER_PROFILE_COUNT][32]u8,
    tasks: [TAIL_TASK_COUNT]ProductTaskV1,
    identity_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
    ) !TailPlanV1 {
        try source.validate();
        try source.profiles.empty_h1.requireProductionSecurity();
        for (&source.profiles.upper) |*profile|
            try profile.requireProductionSecurity();
        return initUnchecked(allocator, source);
    }

    pub fn validateCustody(self: *const TailPlanV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.upper_execution_available or
            self.secure_child_composition_capture_available or
            !std.mem.allEqual(u8, &self.reserved, 0))
        {
            return error.InvalidSecureTreeTailPlan;
        }
        try self.geometry.validate();
        inline for (.{
            self.topology_plan_identity_sha256,
            self.statement_plan_identity_sha256,
            self.breadth_schedule_identity_sha256,
            self.empty_authority_identity_sha256,
            self.empty_h1_profile_identity_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        for (self.upper_profile_identity_sha256) |value| try requireSha(value);

        var upper_real: usize = 0;
        var upper_empty: usize = 0;
        var upper_mixed: usize = 0;
        for (&self.tasks, 0..) |*task, local| {
            try task.validate();
            if (local < EMPTY_H1_TASK_COUNT) {
                if (task.task_class != .empty_h1 or
                    task.local_ordinal != @as(u16, @intCast(local)))
                {
                    return error.InvalidSecureTreeTailPlan;
                }
            } else {
                const upper_local = local - EMPTY_H1_TASK_COUNT;
                if (task.task_class != .upper or
                    task.local_ordinal != @as(u16, @intCast(upper_local)))
                {
                    return error.InvalidSecureTreeTailPlan;
                }
                switch (task.parent_kind) {
                    .real => upper_real += 1,
                    .empty => upper_empty += 1,
                    .mixed => upper_mixed += 1,
                }
            }
        }
        if (upper_real != UPPER_REAL_TASK_COUNT or
            upper_empty != UPPER_EMPTY_TASK_COUNT or
            upper_mixed != UPPER_MIXED_TASK_COUNT or
            !std.mem.eql(u8, &self.identity_sha256, &planIdentity(self)))
        {
            return error.InvalidSecureTreeTailPlan;
        }
    }

    pub fn validateAgainst(
        self: *const TailPlanV1,
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
    ) !void {
        try self.validateCustody();
        try source.validate();
        try source.profiles.empty_h1.requireProductionSecurity();
        for (&source.profiles.upper) |*profile|
            try profile.requireProductionSecurity();
        const expected = try initUnchecked(allocator, source);
        if (!std.meta.eql(self.*, expected))
            return error.SecureTreeTailPlanMismatch;
    }

    fn initUnchecked(
        allocator: std.mem.Allocator,
        source: *const statement_plan.MaterializedPlanV1,
    ) !TailPlanV1 {
        var schedule = try topology_mod.BreadthFirstScheduleV1.create(
            allocator,
            source.topology,
        );
        defer schedule.deinit();
        var result = TailPlanV1{
            .geometry = try auditGeometry(&schedule),
            .topology_plan_identity_sha256 = source.topology.identity,
            .statement_plan_identity_sha256 = source.identity,
            .breadth_schedule_identity_sha256 = schedule.identity,
            .empty_authority_identity_sha256 = source.empty_authority.authority_sha_id,
            .empty_h1_profile_identity_sha256 = source.profiles.empty_h1.identity,
            .upper_profile_identity_sha256 = undefined,
            .tasks = undefined,
            .identity_sha256 = undefined,
        };
        for (
            &result.upper_profile_identity_sha256,
            &source.profiles.upper,
        ) |*destination, *profile| destination.* = profile.identity;
        for (0..EMPTY_H1_TASK_COUNT) |local|
            result.tasks[local] = try taskFromPlan(
                source,
                &schedule,
                .empty_h1,
                local,
            );
        for (0..UPPER_TASK_COUNT) |local|
            result.tasks[EMPTY_H1_TASK_COUNT + local] = try taskFromPlan(
                source,
                &schedule,
                .upper,
                local,
            );
        result.identity_sha256 = planIdentity(&result);
        try result.validateCustody();
        return result;
    }
};

/// Live proofless-input authority for one of the 23 empty/empty H1 proofs.
/// It authenticates the existing empty source; it is not a parent proof or a
/// substitute for the secure verifier's future output.
pub const EmptyH1AdmissionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    local_ordinal: u16,
    global_ordinal: u16,
    parent_index: u32,
    tail_plan_identity_sha256: [32]u8,
    task_identity_sha256: [32]u8,
    empty_source_identity_sha256: [32]u8,
    pair_authority_identity_sha256: [32]u8,
    child_authority_identity_sha256: [2][32]u8,
    transcript_authority_identity_sha256: [32]u8,
    parent_statement_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validateAgainst(
        self: *const EmptyH1AdmissionV1,
        plan: *const TailPlanV1,
    ) !void {
        try plan.validateCustody();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.local_ordinal >= EMPTY_H1_TASK_COUNT or
            self.global_ordinal !=
                @as(u16, FIRST_EMPTY_H1_ORDINAL) + self.local_ordinal)
        {
            return error.InvalidEmptyH1Admission;
        }
        const task = &plan.tasks[@as(usize, self.local_ordinal)];
        if (task.task_class != .empty_h1 or
            self.parent_index != task.parent_index or
            !std.mem.eql(
                u8,
                &self.tail_plan_identity_sha256,
                &plan.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.task_identity_sha256,
            &task.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.parent_statement_sha256,
            &task.parent_statement_sha256,
        )) return error.InvalidEmptyH1Admission;
        inline for (.{
            self.empty_source_identity_sha256,
            self.pair_authority_identity_sha256,
            self.child_authority_identity_sha256[0],
            self.child_authority_identity_sha256[1],
            self.transcript_authority_identity_sha256,
            self.identity_sha256,
        }) |value| try requireSha(value);
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &emptyAdmissionIdentity(self),
        )) return error.InvalidEmptyH1Admission;
    }
};

pub fn admitEmptyH1(
    plan: *const TailPlanV1,
    local_ordinal: usize,
    source: *empty_source_mod.SourceV1,
) !EmptyH1AdmissionV1 {
    try plan.validateCustody();
    if (local_ordinal >= EMPTY_H1_TASK_COUNT)
        return error.InvalidEmptyH1Admission;
    try source.validate();
    const task = &plan.tasks[local_ordinal];
    const pair = source.preparedPair();
    const children = source.children();
    try pair.validateAgainst(children[0], children[1]);
    for (children) |child| {
        try child.validate();
        if (child.kind() != .empty) return error.InvalidEmptyH1Admission;
    }
    const left_statement = try children[0].statement();
    const right_statement = try children[1].statement();
    const parent_words = &pair.prepared_root.result.pair.parent_statement_words;
    if (left_statement.slots.first != @as(u64, task.left_index) or
        right_statement.slots.first != @as(u64, task.right_index) or
        !std.mem.eql(u8, &statement_plan.statementSha256(
            &children[0].child().statement_words,
        ), &task.left_statement_sha256) or
        !std.mem.eql(u8, &statement_plan.statementSha256(
            &children[1].child().statement_words,
        ), &task.right_statement_sha256) or
        !std.mem.eql(u8, &statement_plan.statementSha256(
            parent_words,
        ), &task.parent_statement_sha256))
    {
        return error.EmptyH1AdmissionTaskMismatch;
    }
    var result = EmptyH1AdmissionV1{
        .local_ordinal = @intCast(local_ordinal),
        .global_ordinal = task.global_ordinal,
        .parent_index = task.parent_index,
        .tail_plan_identity_sha256 = plan.identity_sha256,
        .task_identity_sha256 = task.identity_sha256,
        .empty_source_identity_sha256 = source.authorityIdentity(),
        .pair_authority_identity_sha256 = pair.authority_sha_id,
        .child_authority_identity_sha256 = .{
            children[0].authority_sha_id,
            children[1].authority_sha_id,
        },
        .transcript_authority_identity_sha256 = source.transcript().authority_sha_id,
        .parent_statement_sha256 = task.parent_statement_sha256,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = emptyAdmissionIdentity(&result);
    try result.validateAgainst(plan);
    return result;
}

pub fn auditGeometry(
    schedule: *const topology_mod.BreadthFirstScheduleV1,
) !GeometryV1 {
    try schedule.validate();
    var empty_h1: u16 = 0;
    var upper: u16 = 0;
    var upper_real: u16 = 0;
    var upper_empty: u16 = 0;
    var upper_mixed: u16 = 0;
    for (schedule.tasks) |task| {
        const parent_kind = try schedule.plan.nodeKind(
            task.parent_height,
            task.parent_index,
        );
        if (task.parent_height == 1) {
            if (task.left_kind == .empty and task.right_kind == .empty)
                empty_h1 += 1;
        } else {
            upper += 1;
            switch (parent_kind) {
                .real => upper_real += 1,
                .empty => upper_empty += 1,
                .mixed => upper_mixed += 1,
            }
        }
    }
    const result = GeometryV1{
        .real_leaf_count = schedule.plan.real_leaf_count,
        .padded_leaf_count = @intCast(schedule.plan.padded_leaf_count),
        .empty_leaf_count = @intCast(schedule.plan.empty_leaf_count),
        .root_height = schedule.plan.root_height,
        .empty_h1_task_count = empty_h1,
        .upper_task_count = upper,
        .upper_real_task_count = upper_real,
        .upper_empty_task_count = upper_empty,
        .upper_mixed_task_count = upper_mixed,
    };
    try result.validate();
    return result;
}

fn taskFromPlan(
    source: *const statement_plan.MaterializedPlanV1,
    schedule: *const topology_mod.BreadthFirstScheduleV1,
    task_class: TaskClassV1,
    local_ordinal: usize,
) !ProductTaskV1 {
    const global = switch (task_class) {
        .empty_h1 => FIRST_EMPTY_H1_ORDINAL + local_ordinal,
        .upper => FIRST_UPPER_ORDINAL + local_ordinal,
    };
    if (global >= schedule.tasks.len or global >= source.parents.len)
        return error.InvalidSecureTreeTailTask;
    const topology_task = &schedule.tasks[global];
    const parent = &source.parents[global];
    const left = try childRecord(source, topology_task.child_height, topology_task.parent_index * 2);
    const right = try childRecord(source, topology_task.child_height, topology_task.parent_index * 2 + 1);
    const parent_kind = try source.topology.nodeKind(
        topology_task.parent_height,
        topology_task.parent_index,
    );
    if (topology_task.ordinal != @as(u64, @intCast(global)) or
        parent.ordinal != @as(u32, @intCast(global)) or
        parent.height != topology_task.parent_height or
        @as(u64, parent.index) != topology_task.parent_index or
        parent.kind != parent_kind or left.kind != topology_task.left_kind or
        right.kind != topology_task.right_kind)
    {
        return error.InvalidSecureTreeTailTask;
    }
    var result = ProductTaskV1{
        .task_class = task_class,
        .parent_kind = parent_kind,
        .left_kind = topology_task.left_kind,
        .right_kind = topology_task.right_kind,
        .parent_height = topology_task.parent_height,
        .child_height = topology_task.child_height,
        .requires_child_composition_capture = task_class == .upper,
        .local_ordinal = @intCast(local_ordinal),
        .global_ordinal = @intCast(global),
        .parent_index = @intCast(topology_task.parent_index),
        .left_index = @intCast(topology_task.parent_index * 2),
        .right_index = @intCast(topology_task.parent_index * 2 + 1),
        .topology_task_identity_sha256 = topology_task.identity,
        .left_record_identity_sha256 = left.identity,
        .right_record_identity_sha256 = right.identity,
        .left_statement_sha256 = left.statement_sha256,
        .right_statement_sha256 = right.statement_sha256,
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

const RecordView = struct {
    kind: topology_mod.NodeKindV1,
    identity: [32]u8,
    statement_sha256: [32]u8,
};

fn childRecord(
    source: *const statement_plan.MaterializedPlanV1,
    height: u8,
    index: u64,
) !RecordView {
    if (height == 0) {
        if (index >= @as(u64, source.leaves.len))
            return error.InvalidSecureTreeTailTask;
        const record = &source.leaves[@intCast(index)];
        return .{
            .kind = record.kind,
            .identity = record.identity,
            .statement_sha256 = record.statement_sha_id,
        };
    }
    const offset = levelOffset(height);
    const at = std.math.add(usize, offset, @intCast(index)) catch
        return error.InvalidSecureTreeTailTask;
    if (at >= source.parents.len) return error.InvalidSecureTreeTailTask;
    const record = &source.parents[at];
    if (record.height != height or @as(u64, record.index) != index)
        return error.InvalidSecureTreeTailTask;
    return .{
        .kind = record.kind,
        .identity = record.identity,
        .statement_sha256 = record.statement_sha_id,
    };
}

fn levelOffset(height: u8) usize {
    std.debug.assert(height >= 1 and height <= statement_plan.ROOT_HEIGHT);
    var result: usize = 0;
    var level: u8 = 1;
    while (level < height) : (level += 1)
        result += statement_plan.PADDED_LEAF_COUNT >>
            @as(u6, @intCast(level));
    return result;
}

const UpperCoordinates = struct { height: u8, index: u32 };

fn upperCoordinates(local_ordinal: usize) !UpperCoordinates {
    if (local_ordinal >= UPPER_TASK_COUNT)
        return error.InvalidSecureTreeTailTask;
    var remaining = local_ordinal;
    var height: u8 = 2;
    while (height <= statement_plan.ROOT_HEIGHT) : (height += 1) {
        const count = statement_plan.PADDED_LEAF_COUNT >>
            @as(u6, @intCast(height));
        if (remaining < count)
            return .{ .height = height, .index = @intCast(remaining) };
        remaining -= count;
    }
    return error.InvalidSecureTreeTailTask;
}

fn validChildKinds(
    parent: topology_mod.NodeKindV1,
    left: topology_mod.NodeKindV1,
    right: topology_mod.NodeKindV1,
) bool {
    return switch (parent) {
        .real => left == .real and right == .real,
        .empty => left == .empty and right == .empty,
        .mixed => (left == .real and right == .empty) or
            (left == .real and right == .mixed) or
            (left == .mixed and right == .empty),
    };
}

fn taskIdentity(value: *const ProductTaskV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TASK_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.task_class));
    hashInt(&hash, u8, @intFromEnum(value.parent_kind));
    hashInt(&hash, u8, @intFromEnum(value.left_kind));
    hashInt(&hash, u8, @intFromEnum(value.right_kind));
    hashInt(&hash, u8, value.parent_height);
    hashInt(&hash, u8, value.child_height);
    hashInt(&hash, u8, @intFromBool(value.requires_secure_proof));
    hashInt(&hash, u8, @intFromBool(value.requires_cold_fresh_verification));
    hashInt(&hash, u8, @intFromBool(value.requires_child_composition_capture));
    hashInt(&hash, u16, value.local_ordinal);
    hashInt(&hash, u16, value.global_ordinal);
    hashInt(&hash, u32, value.parent_index);
    hashInt(&hash, u32, value.left_index);
    hashInt(&hash, u32, value.right_index);
    inline for (.{
        value.topology_task_identity_sha256,
        value.left_record_identity_sha256,
        value.right_record_identity_sha256,
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

fn planIdentity(value: *const TailPlanV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PLAN_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, @intFromBool(value.upper_execution_available));
    hashInt(
        &hash,
        u8,
        @intFromBool(value.secure_child_composition_capture_available),
    );
    hashInt(&hash, u32, value.geometry.real_leaf_count);
    hashInt(&hash, u32, value.geometry.padded_leaf_count);
    hashInt(&hash, u32, value.geometry.empty_leaf_count);
    hashInt(&hash, u8, value.geometry.root_height);
    hashInt(&hash, u16, value.geometry.empty_h1_task_count);
    hashInt(&hash, u16, value.geometry.upper_task_count);
    hashInt(&hash, u16, value.geometry.upper_real_task_count);
    hashInt(&hash, u16, value.geometry.upper_empty_task_count);
    hashInt(&hash, u16, value.geometry.upper_mixed_task_count);
    inline for (.{
        value.topology_plan_identity_sha256,
        value.statement_plan_identity_sha256,
        value.breadth_schedule_identity_sha256,
        value.empty_authority_identity_sha256,
        value.empty_h1_profile_identity_sha256,
    }) |item| hash.update(&item);
    for (value.upper_profile_identity_sha256) |item| hash.update(&item);
    for (value.tasks) |task| hash.update(&task.identity_sha256);
    return hash.finalResult();
}

fn emptyAdmissionIdentity(value: *const EmptyH1AdmissionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(EMPTY_ADMISSION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u16, value.local_ordinal);
    hashInt(&hash, u16, value.global_ordinal);
    hashInt(&hash, u32, value.parent_index);
    inline for (.{
        value.tail_plan_identity_sha256,
        value.task_identity_sha256,
        value.empty_source_identity_sha256,
        value.pair_authority_identity_sha256,
        value.child_authority_identity_sha256[0],
        value.child_authority_identity_sha256[1],
        value.transcript_authority_identity_sha256,
        value.parent_statement_sha256,
    }) |item| hash.update(&item);
    return hash.finalResult();
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidSecureTreeTailAuthority;
}

fn requireDigest(value: channel.Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidSecureTreeTailAuthority;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidSecureTreeTailAuthority;
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
    pub fn resealTask(value: *ProductTaskV1) void {
        requireTest();
        value.identity_sha256 = taskIdentity(value);
    }

    pub fn resealPlan(value: *TailPlanV1) void {
        requireTest();
        value.identity_sha256 = planIdentity(value);
    }

    pub fn resealEmptyAdmission(value: *EmptyH1AdmissionV1) void {
        requireTest();
        value.identity_sha256 = emptyAdmissionIdentity(value);
    }

    fn requireTest() void {
        if (!builtin.is_test)
            @panic("secure tree tail testing helper used outside test build");
    }
};

comptime {
    if (REAL_H1_TASK_COUNT * 2 != statement_plan.REAL_LEAF_COUNT or
        EMPTY_H1_TASK_COUNT * 2 != statement_plan.EMPTY_LEAF_COUNT or
        HEIGHT_ONE_TASK_COUNT != statement_plan.PADDED_LEAF_COUNT / 2 or
        HEIGHT_ONE_TASK_COUNT + UPPER_TASK_COUNT != TOTAL_PARENT_TASK_COUNT or
        TAIL_TASK_COUNT != 150 or LAST_PARENT_ORDINAL != 254 or
        UPPER_REAL_TASK_COUNT + UPPER_EMPTY_TASK_COUNT +
            UPPER_MIXED_TASK_COUNT != UPPER_TASK_COUNT or
        PRODUCTION_ACTIVATION or UPPER_EXECUTION_AVAILABLE or
        SECURE_CHILD_COMPOSITION_CAPTURE_AVAILABLE or
        leaf_mod.PROOFLESS_HIGHER_EMPTY_ACCEPTED)
    {
        @compileError("secure temporal tree tail contract drifted");
    }
}
