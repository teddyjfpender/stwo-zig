//! Breadth-wise admission for dynamically compiled temporal recursion nodes.
//!
//! The topology and expected folded statements are proof-independent. Real
//! leaves enter only through the fresh-verifier Ethereum descriptor; trailing
//! empty leaves are canonical height-zero statements. Parent admission remains
//! disabled until the dynamic parent verifier can mint the envelope below,
//! and final-root promotion remains independently fail-closed.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const ethereum_leaf =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const proof_security = @import("recursive_temporal_proof_security_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const topology_mod = @import("recursive_temporal_topology_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const VERIFIED_PARENT_ENVELOPE_ACTIVATION = false;
pub const FINAL_ROOT_PROMOTION = false;

const EMPTY_DESCRIPTOR_DOMAIN =
    "stwo-zig/typed-air/recursive-empty-leaf-record/v1\x00";
const PARENT_SUBTREE_DOMAIN =
    "stwo-zig/typed-air/recursive-parent-subtree/v1\x00";
const PARENT_DESCRIPTOR_DOMAIN =
    "stwo-zig/typed-air/recursive-parent-envelope/v1\x00";

pub const NodeRecordV1 = struct {
    height: u8,
    kind: topology_mod.NodeKindV1,
    reserved: [6]u8 = [_]u8{0} ** 6,
    index: u64,
    statement_words: span.StatementWords,
    statement_sha256: [32]u8,
    descriptor_sha256: [32]u8,
    subtree_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    preprocessed_commitment_root: channel.Digest,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,

    pub fn validateAgainstPlan(
        self: *const NodeRecordV1,
        plan: *const topology_mod.TopologyPlanV1,
    ) !void {
        try plan.validate();
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        );
        if (!std.mem.allEqual(u8, &self.reserved, 0) or
            self.height > plan.root_height or
            self.index >= try plan.nodeCount(self.height) or
            statement.slots.height != self.height or
            statement.slots.nodeIndex() != self.index or
            !std.meta.eql(statement.job, plan.job) or
            self.kind != try plan.nodeKind(self.height, self.index) or
            !std.mem.eql(
                u8,
                &self.statement_sha256,
                &statement_plan.statementSha256(&self.statement_words),
            )) return error.InvalidReducerNode;
        try requireSha(self.descriptor_sha256);
        try requireSha(self.subtree_sha256);
        if (self.height == 0 and self.kind == .empty) {
            if (!allProofAuthoritiesZero(self))
                return error.InvalidReducerNode;
        } else {
            try requireSha(self.air_program_identity);
            try requireSha(self.verifier_program_authority);
            try requireDigest(self.preprocessed_commitment_root);
            try requireSha(self.proof_capture_sha256);
            try requireSha(self.capture_identity);
        }
    }

    pub fn fromEthereumLeaf(
        plan: *const topology_mod.TopologyPlanV1,
        descriptor: *const ethereum_leaf.DescriptorV1,
    ) !NodeRecordV1 {
        try descriptor.validate();
        const statement = try span.SpanStatement.fromCanonicalWords(
            &descriptor.statement_words,
        );
        if (!std.meta.eql(statement.job, plan.job) or
            statement.slots.height != 0 or
            statement.slots.first >= plan.real_leaf_count)
        {
            return error.InvalidReducerNode;
        }
        const result = NodeRecordV1{
            .height = 0,
            .kind = .real,
            .index = statement.slots.first,
            .statement_words = descriptor.statement_words,
            .statement_sha256 = descriptor.recursive_statement_sha256,
            .descriptor_sha256 = descriptor.descriptor_sha256,
            .subtree_sha256 = descriptor.subtree_sha256,
            .air_program_identity = descriptor.program.air_program_identity,
            .verifier_program_authority = descriptor.program.verifier_program_authority,
            .preprocessed_commitment_root = descriptor.program.preprocessed_commitment_root,
            .proof_capture_sha256 = descriptor.program.proof_capture_sha256,
            .capture_identity = descriptor.program.capture_identity,
        };
        try result.validateAgainstPlan(plan);
        return result;
    }

    pub fn trailingEmpty(
        plan: *const topology_mod.TopologyPlanV1,
        index: u64,
    ) !NodeRecordV1 {
        try plan.validate();
        if (index < plan.real_leaf_count or index >= plan.padded_leaf_count)
            return error.InvalidReducerNode;
        const leaf_index = std.math.cast(u32, index) orelse
            return error.InvalidReducerNode;
        const statement = try span.SpanStatement.emptyLeaf(
            plan.job,
            leaf_index,
        );
        const words = try statement.canonicalWords();
        var result = NodeRecordV1{
            .height = 0,
            .kind = .empty,
            .index = index,
            .statement_words = words,
            .statement_sha256 = statement_plan.statementSha256(&words),
            .descriptor_sha256 = undefined,
            .subtree_sha256 = undefined,
            .air_program_identity = [_]u8{0} ** 32,
            .verifier_program_authority = [_]u8{0} ** 32,
            .preprocessed_commitment_root = [_]u32{0} ** channel.RATE,
            .proof_capture_sha256 = [_]u8{0} ** 32,
            .capture_identity = [_]u8{0} ** 32,
        };
        result.descriptor_sha256 = emptyDescriptorIdentity(plan, &result);
        result.subtree_sha256 = result.descriptor_sha256;
        try result.validateAgainstPlan(plan);
        return result;
    }
};

/// Future verifier-minted parent result. The current compiler can validate its
/// deterministic statement/program/tree/capture custody, but no production
/// constructor exists until the heterogeneous parent proof verifier lands.
pub const VerifiedParentEnvelopeV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    parent_height: u8,
    parent_kind: topology_mod.NodeKindV1,
    reserved: [2]u8 = .{ 0, 0 },
    parent_index: u64,
    plan_identity: [32]u8,
    task_identity: [32]u8,
    left_descriptor_sha256: [32]u8,
    right_descriptor_sha256: [32]u8,
    left_subtree_sha256: [32]u8,
    right_subtree_sha256: [32]u8,
    statement_words: span.StatementWords,
    statement_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    preprocessed_commitment_root: channel.Digest,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
    proof_artifact_sha256: [32]u8,
    transcript_state_sha256: [32]u8,
    proof_security_identity_sha256: [32]u8,
    verifier_success_sha256: [32]u8,
    subtree_sha256: [32]u8,
    descriptor_sha256: [32]u8,

    pub fn validateAgainst(
        self: *const VerifiedParentEnvelopeV1,
        plan: *const topology_mod.TopologyPlanV1,
        task: *const topology_mod.ParentTaskV1,
        left: *const NodeRecordV1,
        right: *const NodeRecordV1,
    ) !void {
        try task.validateAgainst(plan);
        try left.validateAgainstPlan(plan);
        try right.validateAgainstPlan(plan);
        const left_statement = try span.SpanStatement.fromCanonicalWords(
            &left.statement_words,
        );
        const right_statement = try span.SpanStatement.fromCanonicalWords(
            &right.statement_words,
        );
        const folded = try span.SpanStatement.fold(
            left_statement,
            right_statement,
        );
        const folded_words = try folded.canonicalWords();
        const left_index = task.parent_index * 2;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.parent_height != task.parent_height or
            self.parent_kind != try plan.nodeKind(
                task.parent_height,
                task.parent_index,
            ) or self.parent_index != task.parent_index or
            left.height != task.child_height or
            right.height != task.child_height or
            left.index != left_index or right.index != left_index + 1 or
            left.kind != task.left_kind or right.kind != task.right_kind or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            !std.mem.eql(u8, &self.task_identity, &task.identity) or
            !std.mem.eql(
                u8,
                &self.left_descriptor_sha256,
                &left.descriptor_sha256,
            ) or !std.mem.eql(
            u8,
            &self.right_descriptor_sha256,
            &right.descriptor_sha256,
        ) or !std.mem.eql(
            u8,
            &self.left_subtree_sha256,
            &left.subtree_sha256,
        ) or !std.mem.eql(
            u8,
            &self.right_subtree_sha256,
            &right.subtree_sha256,
        ) or !std.meta.eql(self.statement_words, folded_words) or
            !std.mem.eql(
                u8,
                &self.statement_sha256,
                &statement_plan.statementSha256(&folded_words),
            ) or !std.mem.eql(
            u8,
            &self.proof_security_identity_sha256,
            &parentSecurityIdentity(),
        )) return error.InvalidVerifiedParentEnvelope;
        inline for (.{
            self.air_program_identity,
            self.verifier_program_authority,
            self.proof_capture_sha256,
            self.capture_identity,
            self.proof_artifact_sha256,
            self.transcript_state_sha256,
            self.proof_security_identity_sha256,
            self.verifier_success_sha256,
            self.subtree_sha256,
            self.descriptor_sha256,
        }) |value| try requireSha(value);
        try requireDigest(self.preprocessed_commitment_root);
        if (!std.mem.eql(
            u8,
            &self.subtree_sha256,
            &parentSubtreeIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.descriptor_sha256,
            &parentDescriptorIdentity(self),
        )) return error.InvalidVerifiedParentEnvelope;
    }

    fn nodeRecord(self: *const VerifiedParentEnvelopeV1) NodeRecordV1 {
        return .{
            .height = self.parent_height,
            .kind = self.parent_kind,
            .index = self.parent_index,
            .statement_words = self.statement_words,
            .statement_sha256 = self.statement_sha256,
            .descriptor_sha256 = self.descriptor_sha256,
            .subtree_sha256 = self.subtree_sha256,
            .air_program_identity = self.air_program_identity,
            .verifier_program_authority = self.verifier_program_authority,
            .preprocessed_commitment_root = self.preprocessed_commitment_root,
            .proof_capture_sha256 = self.proof_capture_sha256,
            .capture_identity = self.capture_identity,
        };
    }
};

/// Allocation-owning exact breadth state. No proof-dependent identity enters
/// `create`; only admitted leaf/parent envelopes populate node slots.
pub const ReducerV1 = struct {
    allocator: std.mem.Allocator,
    plan: topology_mod.TopologyPlanV1,
    schedule: topology_mod.BreadthFirstScheduleV1,
    nodes: []?NodeRecordV1,
    next_leaf_index: u64 = 0,
    next_parent_ordinal: u64 = 0,

    pub fn create(
        allocator: std.mem.Allocator,
        plan: topology_mod.TopologyPlanV1,
    ) !ReducerV1 {
        try plan.validate();
        var schedule = try topology_mod.BreadthFirstScheduleV1.create(
            allocator,
            plan,
        );
        errdefer schedule.deinit();
        const node_count = std.math.cast(
            usize,
            std.math.sub(
                u64,
                try std.math.mul(u64, plan.padded_leaf_count, 2),
                1,
            ) catch return error.InvalidReducerTopology,
        ) orelse return error.InvalidReducerTopology;
        const nodes = try allocator.alloc(?NodeRecordV1, node_count);
        errdefer allocator.free(nodes);
        @memset(nodes, null);
        return .{
            .allocator = allocator,
            .plan = plan,
            .schedule = schedule,
            .nodes = nodes,
        };
    }

    pub fn deinit(self: *ReducerV1) void {
        const allocator = self.allocator;
        self.schedule.deinit();
        allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn admitEthereumLeaf(
        self: *ReducerV1,
        descriptor: *const ethereum_leaf.DescriptorV1,
    ) !void {
        if (self.next_leaf_index >= self.plan.real_leaf_count)
            return error.InvalidReducerOrder;
        const record = try NodeRecordV1.fromEthereumLeaf(
            &self.plan,
            descriptor,
        );
        if (record.index != self.next_leaf_index)
            return error.InvalidReducerOrder;
        try self.putLeaf(record);
    }

    pub fn admitTrailingEmpty(self: *ReducerV1) !void {
        if (self.next_leaf_index < self.plan.real_leaf_count or
            self.next_leaf_index >= self.plan.padded_leaf_count)
        {
            return error.InvalidReducerOrder;
        }
        try self.putLeaf(try NodeRecordV1.trailingEmpty(
            &self.plan,
            self.next_leaf_index,
        ));
    }

    /// Production remains unavailable until a fresh heterogeneous parent
    /// verifier owns the constructor for `VerifiedParentEnvelopeV1`.
    pub fn admitVerifiedParent(
        self: *ReducerV1,
        envelope: *const VerifiedParentEnvelopeV1,
    ) !void {
        if (!VERIFIED_PARENT_ENVELOPE_ACTIVATION)
            return error.VerifiedParentEnvelopeUnavailable;
        try self.admitParentAssumeVerifierOwned(envelope);
    }

    pub fn rootCandidate(self: *const ReducerV1) !NodeRecordV1 {
        if (self.next_leaf_index != self.plan.padded_leaf_count or
            self.next_parent_ordinal != self.schedule.tasks.len)
        {
            return error.IncompleteReducer;
        }
        const root = self.node(self.plan.root_height, 0) orelse
            return error.IncompleteReducer;
        try root.validateAgainstPlan(&self.plan);
        return root;
    }

    pub fn promoteFinalRoot(self: *const ReducerV1) !NodeRecordV1 {
        if (!FINAL_ROOT_PROMOTION)
            return error.FinalRootPromotionUnavailable;
        return self.rootCandidate();
    }

    fn putLeaf(self: *ReducerV1, record: NodeRecordV1) !void {
        try record.validateAgainstPlan(&self.plan);
        if (record.height != 0 or record.index != self.next_leaf_index)
            return error.InvalidReducerOrder;
        const at = try self.nodeOffset(0, record.index);
        if (self.nodes[at] != null) return error.DuplicateReducerNode;
        self.nodes[at] = record;
        self.next_leaf_index += 1;
    }

    fn admitParentAssumeVerifierOwned(
        self: *ReducerV1,
        envelope: *const VerifiedParentEnvelopeV1,
    ) !void {
        if (self.next_leaf_index != self.plan.padded_leaf_count or
            self.next_parent_ordinal >= self.schedule.tasks.len)
        {
            return error.InvalidReducerOrder;
        }
        const task = &self.schedule.tasks[self.next_parent_ordinal];
        const left_index = task.parent_index * 2;
        const left = self.node(task.child_height, left_index) orelse
            return error.IncompleteReducer;
        const right = self.node(task.child_height, left_index + 1) orelse
            return error.IncompleteReducer;
        try envelope.validateAgainst(&self.plan, task, &left, &right);
        const node_value = envelope.nodeRecord();
        try node_value.validateAgainstPlan(&self.plan);
        const at = try self.nodeOffset(
            node_value.height,
            node_value.index,
        );
        if (self.nodes[at] != null) return error.DuplicateReducerNode;
        self.nodes[at] = node_value;
        self.next_parent_ordinal += 1;
    }

    fn node(
        self: *const ReducerV1,
        height: u8,
        index: u64,
    ) ?NodeRecordV1 {
        const at = self.nodeOffset(height, index) catch return null;
        return self.nodes[at];
    }

    fn nodeOffset(
        self: *const ReducerV1,
        height: u8,
        index: u64,
    ) !usize {
        if (height > self.plan.root_height or
            index >= try self.plan.nodeCount(height))
        {
            return error.InvalidReducerTopology;
        }
        var offset: u64 = 0;
        var level: u8 = 0;
        while (level < height) : (level += 1)
            offset = try std.math.add(
                u64,
                offset,
                try self.plan.nodeCount(level),
            );
        return std.math.cast(usize, try std.math.add(u64, offset, index)) orelse
            error.InvalidReducerTopology;
    }
};

pub const testing = struct {
    pub fn admitLeafRecord(
        reducer: *ReducerV1,
        record: NodeRecordV1,
    ) !void {
        if (!builtin.is_test) return error.TestOnlyAuthority;
        try reducer.putLeaf(record);
    }

    pub fn mintNextParentEnvelope(
        reducer: *const ReducerV1,
        discriminator: u8,
    ) !VerifiedParentEnvelopeV1 {
        if (!builtin.is_test) return error.TestOnlyAuthority;
        if (reducer.next_leaf_index != reducer.plan.padded_leaf_count or
            reducer.next_parent_ordinal >= reducer.schedule.tasks.len)
        {
            return error.InvalidReducerOrder;
        }
        const task = &reducer.schedule.tasks[reducer.next_parent_ordinal];
        const left_index = task.parent_index * 2;
        const left = reducer.node(task.child_height, left_index) orelse
            return error.IncompleteReducer;
        const right = reducer.node(task.child_height, left_index + 1) orelse
            return error.IncompleteReducer;
        return mintParentEnvelope(
            &reducer.plan,
            task,
            &left,
            &right,
            discriminator,
        );
    }

    pub fn mintParentEnvelope(
        plan: *const topology_mod.TopologyPlanV1,
        task: *const topology_mod.ParentTaskV1,
        left: *const NodeRecordV1,
        right: *const NodeRecordV1,
        discriminator: u8,
    ) !VerifiedParentEnvelopeV1 {
        if (!builtin.is_test) return error.TestOnlyAuthority;
        const left_statement = try span.SpanStatement.fromCanonicalWords(
            &left.statement_words,
        );
        const right_statement = try span.SpanStatement.fromCanonicalWords(
            &right.statement_words,
        );
        const folded = try span.SpanStatement.fold(
            left_statement,
            right_statement,
        );
        const words = try folded.canonicalWords();
        const byte = if (discriminator == 0) @as(u8, 1) else discriminator;
        var result = VerifiedParentEnvelopeV1{
            .parent_height = task.parent_height,
            .parent_kind = try plan.nodeKind(
                task.parent_height,
                task.parent_index,
            ),
            .parent_index = task.parent_index,
            .plan_identity = plan.identity,
            .task_identity = task.identity,
            .left_descriptor_sha256 = left.descriptor_sha256,
            .right_descriptor_sha256 = right.descriptor_sha256,
            .left_subtree_sha256 = left.subtree_sha256,
            .right_subtree_sha256 = right.subtree_sha256,
            .statement_words = words,
            .statement_sha256 = statement_plan.statementSha256(&words),
            .air_program_identity = testSha(byte),
            .verifier_program_authority = testSha(byte +% 1),
            .preprocessed_commitment_root = [_]u32{byte} ** channel.RATE,
            .proof_capture_sha256 = testSha(byte +% 2),
            .capture_identity = testSha(byte +% 3),
            .proof_artifact_sha256 = testSha(byte +% 4),
            .transcript_state_sha256 = testSha(byte +% 5),
            .proof_security_identity_sha256 = parentSecurityIdentity(),
            .verifier_success_sha256 = testSha(byte +% 6),
            .subtree_sha256 = undefined,
            .descriptor_sha256 = undefined,
        };
        result.subtree_sha256 = parentSubtreeIdentity(&result);
        result.descriptor_sha256 = parentDescriptorIdentity(&result);
        try result.validateAgainst(plan, task, left, right);
        return result;
    }

    pub fn admitParent(
        reducer: *ReducerV1,
        envelope: *const VerifiedParentEnvelopeV1,
    ) !void {
        if (!builtin.is_test) return error.TestOnlyAuthority;
        try reducer.admitParentAssumeVerifierOwned(envelope);
    }
};

fn testSha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index + 1));
    return result;
}

fn parentSecurityIdentity() [32]u8 {
    return proof_security.ProofSecurityV1.recursiveParentSecure().identity;
}

fn allProofAuthoritiesZero(value: *const NodeRecordV1) bool {
    return std.mem.allEqual(u8, &value.air_program_identity, 0) and
        std.mem.allEqual(u8, &value.verifier_program_authority, 0) and
        digestIsZero(value.preprocessed_commitment_root) and
        std.mem.allEqual(u8, &value.proof_capture_sha256, 0) and
        std.mem.allEqual(u8, &value.capture_identity, 0);
}

fn emptyDescriptorIdentity(
    plan: *const topology_mod.TopologyPlanV1,
    value: *const NodeRecordV1,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(EMPTY_DESCRIPTOR_DOMAIN);
    hash.update(&plan.identity);
    hashInt(&hash, u64, value.index);
    hash.update(&value.statement_sha256);
    return hash.finalResult();
}

fn parentSubtreeIdentity(value: *const VerifiedParentEnvelopeV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PARENT_SUBTREE_DOMAIN);
    hash.update(&value.plan_identity);
    hash.update(&value.task_identity);
    hash.update(&value.left_subtree_sha256);
    hash.update(&value.right_subtree_sha256);
    hash.update(&value.statement_sha256);
    hash.update(&value.air_program_identity);
    hash.update(&value.verifier_program_authority);
    hashDigest(&hash, value.preprocessed_commitment_root);
    hash.update(&value.proof_capture_sha256);
    hash.update(&value.capture_identity);
    hash.update(&value.proof_artifact_sha256);
    hash.update(&value.transcript_state_sha256);
    hash.update(&value.proof_security_identity_sha256);
    hash.update(&value.verifier_success_sha256);
    return hash.finalResult();
}

fn parentDescriptorIdentity(value: *const VerifiedParentEnvelopeV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PARENT_DESCRIPTOR_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.parent_height);
    hashInt(&hash, u8, @intFromEnum(value.parent_kind));
    hash.update(&value.reserved);
    hashInt(&hash, u64, value.parent_index);
    hash.update(&value.plan_identity);
    hash.update(&value.task_identity);
    hash.update(&value.left_descriptor_sha256);
    hash.update(&value.right_descriptor_sha256);
    hash.update(&value.left_subtree_sha256);
    hash.update(&value.right_subtree_sha256);
    for (value.statement_words) |word| hashInt(&hash, u32, word.toU32());
    hash.update(&value.statement_sha256);
    hash.update(&value.air_program_identity);
    hash.update(&value.verifier_program_authority);
    hashDigest(&hash, value.preprocessed_commitment_root);
    hash.update(&value.proof_capture_sha256);
    hash.update(&value.capture_identity);
    hash.update(&value.proof_artifact_sha256);
    hash.update(&value.transcript_state_sha256);
    hash.update(&value.proof_security_identity_sha256);
    hash.update(&value.verifier_success_sha256);
    hash.update(&value.subtree_sha256);
    return hash.finalResult();
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0)) return error.InvalidReducerNode;
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidReducerNode;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidReducerNode;
}

fn digestIsZero(value: channel.Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        VERIFIED_PARENT_ENVELOPE_ACTIVATION or FINAL_ROOT_PROMOTION)
    {
        @compileError("dynamic temporal reducer activation drifted");
    }
}
