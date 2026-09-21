//! Fail-atomic breadth-wise topology authority for temporal recursion.
//!
//! The plan pads only the trailing height-zero slots to `nextPow2`. It never
//! turns a higher empty subtree into a proofless node: every height >= 1 slot
//! is scheduled as an ordinary parent proof, including empty/empty parents.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const recursion = frontend.recursion;
const span = recursion.span_statement;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const SET_SCHEMA_VERSION: u16 = 1;
pub const SCHEDULE_SCHEMA_VERSION: u16 = 1;
pub const EMPTY_SUBTREE_COLLAPSE = false;
pub const PROOFLESS_EMPTY_HEIGHT: u8 = 0;
pub const PRODUCT_REAL_LEAF_COUNT: u32 = 210;
pub const PRODUCT_PADDED_LEAF_COUNT: u64 = 256;
pub const PRODUCT_EMPTY_LEAF_COUNT: u64 = 46;
pub const PRODUCT_ROOT_HEIGHT: u8 = 8;

const PLAN_IDENTITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-topology/v1\x00";
const SET_IDENTITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-padded-leaves/v1\x00";
const TASK_IDENTITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-task/v1\x00";
const SCHEDULE_IDENTITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-breadth-schedule/v1\x00";

pub const NodeKindV1 = enum(u8) {
    real = 0,
    empty = 1,
    mixed = 2,
};

pub const Error = leaf_mod.Error || span.Error || error{
    ArithmeticOverflow,
    DuplicateLeaf,
    EmptyBeforeReal,
    InvalidLeafCount,
    InvalidNode,
    InvalidSchedule,
    InvalidTopology,
    LeafAuthorityMismatch,
    LeafHole,
    LeafOverlap,
    OutOfMemory,
    UnsupportedFormat,
};

pub const PairLocationV1 = struct {
    parent_height: u8,
    parent_index: u64,
    left_first: u64,
    right_first: u64,
    child_height: u8,
    left_kind: NodeKindV1,
    right_kind: NodeKindV1,
};

pub const ParentTaskV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEDULE_SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    ordinal: u64,
    parent_height: u8,
    child_height: u8,
    left_kind: NodeKindV1,
    right_kind: NodeKindV1,
    parent_index: u64,
    left_first: u64,
    right_first: u64,
    plan_identity: [32]u8,
    identity: [32]u8,

    pub fn validateAgainst(
        self: *const ParentTaskV1,
        plan: *const TopologyPlanV1,
    ) Error!void {
        const expected = try plan.task(self.parent_height, self.parent_index);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEDULE_SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            !std.meta.eql(self.*, expected))
        {
            return error.InvalidSchedule;
        }
    }
};

pub const TopologyPlanV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    job: span.JobContext,
    real_leaf_count: u32,
    padded_leaf_count: u64,
    empty_leaf_count: u64,
    root_height: u8,
    proofless_empty_height: u8 = PROOFLESS_EMPTY_HEIGHT,
    empty_subtree_collapse: bool = EMPTY_SUBTREE_COLLAPSE,
    reserved: [5]u8 = [_]u8{0} ** 5,
    identity: [32]u8,

    pub fn init(job: span.JobContext) Error!TopologyPlanV1 {
        try job.validate();
        const padded_leaf_count = job.slotCapacity();
        const real_leaf_count = job.segment_count;
        const empty_leaf_count = padded_leaf_count - real_leaf_count;
        var result = TopologyPlanV1{
            .job = job,
            .real_leaf_count = real_leaf_count,
            .padded_leaf_count = padded_leaf_count,
            .empty_leaf_count = empty_leaf_count,
            .root_height = job.slot_height,
            .identity = undefined,
        };
        result.identity = planIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const TopologyPlanV1) Error!void {
        try self.job.validate();
        const capacity = self.job.slotCapacity();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.real_leaf_count != self.job.segment_count or
            self.padded_leaf_count != capacity or
            self.empty_leaf_count != capacity - self.job.segment_count or
            self.root_height != self.job.slot_height or
            self.proofless_empty_height != PROOFLESS_EMPTY_HEIGHT or
            self.empty_subtree_collapse or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(u8, &self.identity, &planIdentity(self)))
        {
            return error.InvalidTopology;
        }
    }

    pub fn nodeCount(self: *const TopologyPlanV1, height: u8) Error!u64 {
        try self.validate();
        if (height > self.root_height) return error.InvalidNode;
        return self.nodeCountAssumeValid(height);
    }

    pub fn proofCount(self: *const TopologyPlanV1) Error!u64 {
        try self.validate();
        return self.padded_leaf_count - 1;
    }

    pub fn nodeKind(
        self: *const TopologyPlanV1,
        height: u8,
        node_index: u64,
    ) Error!NodeKindV1 {
        const count = try self.nodeCount(height);
        if (node_index >= count) return error.InvalidNode;
        const width = @as(u64, 1) << @as(u6, @intCast(height));
        const first = std.math.mul(u64, node_index, width) catch
            return error.ArithmeticOverflow;
        const end = std.math.add(u64, first, width) catch
            return error.ArithmeticOverflow;
        if (end <= self.real_leaf_count) return .real;
        if (first >= self.real_leaf_count) return .empty;
        return .mixed;
    }

    pub fn pair(
        self: *const TopologyPlanV1,
        parent_height: u8,
        parent_index: u64,
    ) Error!PairLocationV1 {
        try self.validate();
        return self.pairAssumeValid(parent_height, parent_index);
    }

    fn pairAssumeValid(
        self: *const TopologyPlanV1,
        parent_height: u8,
        parent_index: u64,
    ) Error!PairLocationV1 {
        if (parent_height == 0 or parent_height > self.root_height)
            return error.InvalidNode;
        const parent_count = self.nodeCountAssumeValid(parent_height);
        if (parent_index >= parent_count) return error.InvalidNode;
        const child_height = parent_height - 1;
        const child_width = @as(u64, 1) << @as(u6, @intCast(child_height));
        const left_index = std.math.mul(u64, parent_index, 2) catch
            return error.ArithmeticOverflow;
        const right_index = left_index + 1;
        return .{
            .parent_height = parent_height,
            .parent_index = parent_index,
            .left_first = std.math.mul(u64, left_index, child_width) catch
                return error.ArithmeticOverflow,
            .right_first = std.math.mul(u64, right_index, child_width) catch
                return error.ArithmeticOverflow,
            .child_height = child_height,
            .left_kind = try self.nodeKind(child_height, left_index),
            .right_kind = try self.nodeKind(child_height, right_index),
        };
    }

    pub fn task(
        self: *const TopologyPlanV1,
        parent_height: u8,
        parent_index: u64,
    ) Error!ParentTaskV1 {
        try self.validate();
        return self.taskAssumeValid(parent_height, parent_index);
    }

    fn taskAssumeValid(
        self: *const TopologyPlanV1,
        parent_height: u8,
        parent_index: u64,
    ) Error!ParentTaskV1 {
        const location = try self.pairAssumeValid(parent_height, parent_index);
        var ordinal: u64 = 0;
        var height: u8 = 1;
        while (height < parent_height) : (height += 1)
            ordinal = std.math.add(
                u64,
                ordinal,
                self.nodeCountAssumeValid(height),
            ) catch
                return error.ArithmeticOverflow;
        ordinal = std.math.add(u64, ordinal, parent_index) catch
            return error.ArithmeticOverflow;
        var result = ParentTaskV1{
            .ordinal = ordinal,
            .parent_height = parent_height,
            .child_height = location.child_height,
            .left_kind = location.left_kind,
            .right_kind = location.right_kind,
            .parent_index = parent_index,
            .left_first = location.left_first,
            .right_first = location.right_first,
            .plan_identity = self.identity,
            .identity = undefined,
        };
        result.identity = taskIdentity(&result);
        return result;
    }

    fn nodeCountAssumeValid(self: *const TopologyPlanV1, height: u8) u64 {
        std.debug.assert(height <= self.root_height);
        return self.padded_leaf_count >> @as(u6, @intCast(height));
    }

    /// Validates the controller's real-leaf ordinal authority. Exact equality
    /// with `[0, segment_count)` rejects holes, duplicates, reordering, and
    /// overlapping leaf slots before any padded output is allocated.
    pub fn validateRealLeafOrder(
        self: *const TopologyPlanV1,
        indices: []const u32,
    ) Error!void {
        try self.validate();
        if (indices.len != @as(usize, self.real_leaf_count))
            return error.InvalidLeafCount;
        for (indices, 0..) |index, expected_usize| {
            const expected: u32 = @intCast(expected_usize);
            if (index == expected) continue;
            if (expected_usize > 0 and index == indices[expected_usize - 1])
                return error.DuplicateLeaf;
            if (index < expected) return error.LeafOverlap;
            return error.LeafHole;
        }
    }

    pub fn validateLeafKinds(
        self: *const TopologyPlanV1,
        kinds: []const leaf_mod.KindV1,
    ) Error!void {
        try self.validate();
        if (@as(u64, @intCast(kinds.len)) != self.padded_leaf_count)
            return error.InvalidLeafCount;
        for (kinds, 0..) |kind, index| {
            const expected: leaf_mod.KindV1 = if (index < @as(usize, self.real_leaf_count))
                .segment
            else
                .empty;
            if (kind != expected) {
                if (kind == .empty and index < @as(usize, self.real_leaf_count))
                    return error.EmptyBeforeReal;
                return error.InvalidTopology;
            }
        }
    }
};

/// Exact breadth-wise parent schedule intended for the crash journal. The
/// schedule is materialized in one allocation and published only after every
/// task and the whole schedule identity validate.
pub const BreadthFirstScheduleV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEDULE_SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    plan: TopologyPlanV1,
    tasks: []ParentTaskV1,
    identity: [32]u8,

    pub fn create(
        allocator: std.mem.Allocator,
        plan: TopologyPlanV1,
    ) Error!BreadthFirstScheduleV1 {
        try plan.validate();
        const task_count = std.math.cast(usize, try plan.proofCount()) orelse
            return error.InvalidSchedule;
        const tasks = allocator.alloc(ParentTaskV1, task_count) catch
            return error.OutOfMemory;
        errdefer allocator.free(tasks);
        var cursor: usize = 0;
        var height: u8 = 1;
        while (height <= plan.root_height) : (height += 1) {
            const count = plan.nodeCountAssumeValid(height);
            for (0..@as(usize, @intCast(count))) |index| {
                tasks[cursor] = try plan.taskAssumeValid(height, @intCast(index));
                cursor += 1;
            }
        }
        if (cursor != tasks.len) return error.InvalidSchedule;
        var result = BreadthFirstScheduleV1{
            .allocator = allocator,
            .plan = plan,
            .tasks = tasks,
            .identity = undefined,
        };
        result.identity = scheduleIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn deinit(self: *BreadthFirstScheduleV1) void {
        const allocator = self.allocator;
        allocator.free(self.tasks);
        self.* = undefined;
    }

    pub fn validate(self: *const BreadthFirstScheduleV1) Error!void {
        try self.plan.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEDULE_SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            @as(u64, @intCast(self.tasks.len)) != try self.plan.proofCount())
        {
            return error.InvalidSchedule;
        }
        for (self.tasks, 0..) |*task_value, ordinal| {
            if (task_value.ordinal != @as(u64, @intCast(ordinal)))
                return error.InvalidSchedule;
            const expected = try self.plan.taskAssumeValid(
                task_value.parent_height,
                task_value.parent_index,
            );
            if (!std.meta.eql(task_value.*, expected))
                return error.InvalidSchedule;
        }
        if (!std.mem.eql(u8, &self.identity, &scheduleIdentity(self)))
            return error.InvalidSchedule;
    }
};

/// Owned, fail-atomic materialization of the exact padded height-zero layer.
/// Real authorities are copied from verifier custody; every empty authority
/// derives its session/job/VKs from the first real leaf, not detached input.
pub const PaddedLeafSetV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SET_SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    plan: TopologyPlanV1,
    leaves: []leaf_mod.LeafOrEmptyV1,
    identity: [32]u8,

    pub fn create(
        allocator: std.mem.Allocator,
        job: span.JobContext,
        real_leaves: []const leaf_mod.LeafOrEmptyV1,
    ) Error!PaddedLeafSetV1 {
        const plan = try TopologyPlanV1.init(job);
        if (real_leaves.len != @as(usize, plan.real_leaf_count))
            return error.InvalidLeafCount;
        for (real_leaves, 0..) |*leaf, index| {
            try leaf.validate();
            if (leaf.kind() != .segment) return error.EmptyBeforeReal;
            const statement = try leaf.statement();
            if (!std.meta.eql(statement.job, plan.job) or
                statement.slots.height != 0 or
                statement.slots.first != @as(u64, @intCast(index)))
            {
                return error.LeafAuthorityMismatch;
            }
        }
        try validateRealContinuity(&plan, real_leaves);

        const capacity = std.math.cast(usize, plan.padded_leaf_count) orelse
            return error.InvalidLeafCount;
        const leaves = allocator.alloc(leaf_mod.LeafOrEmptyV1, capacity) catch
            return error.OutOfMemory;
        errdefer allocator.free(leaves);
        @memcpy(leaves[0..real_leaves.len], real_leaves);
        const source = &real_leaves[0];
        for (real_leaves.len..capacity) |index| {
            try leaf_mod.admitEmptyInto(
                &leaves[index],
                plan.job,
                @intCast(index),
                source.child().session_id,
                source.segmentLeafVkId(),
                source.child().recursive_parent_vk_id,
            );
        }
        var result = PaddedLeafSetV1{
            .allocator = allocator,
            .plan = plan,
            .leaves = leaves,
            .identity = undefined,
        };
        result.identity = setIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn deinit(self: *PaddedLeafSetV1) void {
        const allocator = self.allocator;
        allocator.free(self.leaves);
        self.* = undefined;
    }

    pub fn validate(self: *const PaddedLeafSetV1) Error!void {
        try self.plan.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SET_SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            @as(u64, @intCast(self.leaves.len)) != self.plan.padded_leaf_count or
            self.leaves.len == 0)
        {
            return error.InvalidTopology;
        }
        const first = &self.leaves[0];
        for (self.leaves, 0..) |*leaf, index| {
            try leaf.validate();
            const statement = try leaf.statement();
            const expected_kind: leaf_mod.KindV1 = if (index < @as(usize, self.plan.real_leaf_count))
                .segment
            else
                .empty;
            if (leaf.kind() != expected_kind or
                !std.meta.eql(statement.job, self.plan.job) or
                statement.slots.height != 0 or
                statement.slots.first != @as(u64, @intCast(index)) or
                !std.meta.eql(leaf.child().session_id, first.child().session_id) or
                !std.meta.eql(leaf.segmentLeafVkId(), first.segmentLeafVkId()) or
                !std.meta.eql(
                    leaf.child().recursive_parent_vk_id,
                    first.child().recursive_parent_vk_id,
                ))
            {
                return error.LeafAuthorityMismatch;
            }
        }
        try validateRealContinuity(
            &self.plan,
            self.leaves[0..@as(usize, self.plan.real_leaf_count)],
        );
        if (!std.mem.eql(u8, &self.identity, &setIdentity(self)))
            return error.InvalidTopology;
    }
};

fn validateRealContinuity(
    plan: *const TopologyPlanV1,
    leaves: []const leaf_mod.LeafOrEmptyV1,
) Error!void {
    if (leaves.len != @as(usize, plan.real_leaf_count))
        return error.InvalidLeafCount;
    var previous: ?span.ExecutedSpan = null;
    for (leaves) |*leaf| {
        const statement = try leaf.statement();
        const current = switch (statement.body) {
            .executed => |value| value,
            .empty => return error.EmptyBeforeReal,
        };
        if (previous) |prior| {
            if (prior.endSegment() != current.first_segment)
                return error.SegmentDiscontinuity;
            if (prior.endCycle() != current.first_cycle)
                return error.CycleDiscontinuity;
            if (!std.meta.eql(prior.exit, current.entry))
                return error.StateDiscontinuity;
            if (prior.output.digest != null) return error.LeftOutputPresent;
            if (current.input.digest != null) return error.RightInputPresent;
        }
        previous = current;
    }
}

fn planIdentity(value: *const TopologyPlanV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PLAN_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashJob(&hash, value.job);
    hashInt(&hash, u32, value.real_leaf_count);
    hashInt(&hash, u64, value.padded_leaf_count);
    hashInt(&hash, u64, value.empty_leaf_count);
    hashInt(&hash, u8, value.root_height);
    hashInt(&hash, u8, value.proofless_empty_height);
    hashInt(&hash, u8, @intFromBool(value.empty_subtree_collapse));
    return hash.finalResult();
}

fn taskIdentity(value: *const ParentTaskV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TASK_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u64, value.ordinal);
    hashInt(&hash, u8, value.parent_height);
    hashInt(&hash, u8, value.child_height);
    hashInt(&hash, u8, @intFromEnum(value.left_kind));
    hashInt(&hash, u8, @intFromEnum(value.right_kind));
    hashInt(&hash, u64, value.parent_index);
    hashInt(&hash, u64, value.left_first);
    hashInt(&hash, u64, value.right_first);
    hash.update(&value.plan_identity);
    return hash.finalResult();
}

fn scheduleIdentity(value: *const BreadthFirstScheduleV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SCHEDULE_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.plan.identity);
    hashInt(&hash, u64, @intCast(value.tasks.len));
    for (value.tasks) |task_value| hash.update(&task_value.identity);
    return hash.finalResult();
}

fn setIdentity(value: *const PaddedLeafSetV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SET_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.plan.identity);
    hashInt(&hash, u64, value.leaves.len);
    for (value.leaves) |leaf| hash.update(&leaf.authority_sha_id);
    return hash.finalResult();
}

fn hashJob(hash: *Sha256, job: span.JobContext) void {
    hashDigest(hash, job.complete.protocol_id);
    hashDigest(hash, job.complete.program);
    hashMachine(hash, job.complete.initial_state);
    hashMachine(hash, job.complete.final_state);
    hashDigest(hash, job.complete.public_input);
    hashDigest(hash, job.complete.public_output);
    hashInt(hash, u64, job.complete.total_cycles);
    hashInt(hash, u32, job.segment_count);
    hashInt(hash, u8, job.slot_height);
}

fn hashMachine(hash: *Sha256, state: span.MachineState) void {
    hashInt(hash, u32, state.pc);
    for (state.registers) |value| hashInt(hash, u32, value);
    hashDigest(hash, state.rw_memory);
    hashDigest(hash, state.public_io_state);
}

fn hashDigest(hash: *Sha256, value: [8]u32) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
