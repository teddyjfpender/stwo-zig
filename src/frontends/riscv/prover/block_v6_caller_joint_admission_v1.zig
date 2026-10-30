//! Independent metadata for the new six-commitment caller protocol. This
//! reconstructs original equation inventories, not a key supplied with a proof.
//! A recursive key/parent compiler is deliberately NOT certified by this type.
const std = @import("std");
const core = @import("stwo_core");
const Joint = @import("block_v6_caller_joint_proof_v1.zig");
const Components = @import("block_v6_caller_joint_components_v1.zig");
const Arithmetic = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Relations = @import("block_v5_caller_fused_recursive_admission_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Bus = @import("block_memory_relation_v2.zig");
pub const Limits = struct { max_columns: usize = 32768, max_claims: usize = 32768, max_samples: usize = 262144, max_capture_bytes: usize = 512 << 20 };
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    arithmetic: Arithmetic.Prepared,
    relations: Relations.Prepared,
    composition_log: u32,
    composition_split: u32,
    mask_log: u32,
    constraint_count: usize,
    template_id: [32]u8,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, expected: Joint.Policy, limits: Limits) !Prepared {
        if (expected.statement.ethereum.localZeroCustody()) return error.UnqualifiedJointCallerLocalZeroRecipe;
        if (limits.max_columns == 0 or limits.max_claims == 0 or limits.max_samples == 0 or limits.max_capture_bytes == 0) return error.InvalidJointCallerLimits;
        var arithmetic = try Arithmetic.Prepared.init(a, expected.statement.*, expected.total_steps, expected.binding, expected.sealed, expected.pins, expected.entries, .{ .max_columns = limits.max_columns, .max_samples = limits.max_samples, .max_capture_bytes = limits.max_capture_bytes });
        errdefer arithmetic.deinit();
        const expected_events = try @import("block_execution_external_trace_v2.zig").expectedEventCountForMode(expected.statement, expected.sealed.register_custody_mode);
        var relations = try Relations.Prepared.init(a, expected.binding.execution_index, .{ .statement = expected.statement, .total_steps = expected.total_steps, .execution_instance_id = expected.binding.execution_instance_id, .expected_key_id = expected.binding.caller_key_id, .expected_caller_instance_id = expected.binding.caller_instance_id, .roots = expected.binding.first_roots, .witness_root = expected.witness_root, .frame = expected.frame, .expected_rw_events = expected_events }, expected.sealed, expected.pins, expected.entries, .{ .max_columns = limits.max_columns, .max_public_claims = limits.max_claims, .max_samples = limits.max_samples, .max_capture_bytes = limits.max_capture_bytes });
        errdefer relations.deinit();
        var result = Prepared{ .allocator = a, .arithmetic = arithmetic, .relations = relations, .composition_log = 0, .composition_split = 0, .mask_log = 0, .constraint_count = 0, .template_id = undefined, .limits = limits };
        const zero_arithmetic = try Profile.ExtensionClaim.zeroForStatement(expected.statement);
        var zero_relations = try zeroClaims(a, &relations.schedule);
        defer zero_relations.deinit(a);
        const equations = try EquationOwner.create(a, &result, &zero_arithmetic, &zero_relations);
        defer equations.destroy();
        result.composition_log = equations.joint.bound;
        result.composition_split = equations.joint.split;
        result.mask_log = result.composition_log - result.composition_split;
        result.constraint_count = equations.joint.constraints;
        result.template_id = result.identity();
        return result;
    }
    pub fn deinit(self: *Prepared) void {
        self.relations.deinit();
        self.arithmetic.deinit();
        self.* = undefined;
    }
    pub fn logs(self: *const Prepared) [5][]const u32 {
        return .{ self.arithmetic.logs[0], self.arithmetic.logs[1], self.relations.logs[2], self.arithmetic.logs[2], self.relations.logs[3] };
    }
    pub fn policy(self: *const Prepared) Joint.Policy {
        return .{ .statement = &self.arithmetic.statement, .total_steps = self.arithmetic.total_steps, .binding = self.arithmetic.binding, .witness_root = self.relations.witness_root, .frame = self.relations.frame, .sealed = self.arithmetic.sealed, .pins = self.arithmetic.pins, .entries = self.arithmetic.entries };
    }
    pub fn identity(self: *const Prepared) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ Joint.TAG, Joint.VERSION, 5, 6, self.composition_log, self.composition_split, self.mask_log });
        channel.mixRoot(self.arithmetic.template_id);
        channel.mixRoot(self.relations.template_id);
        channel.mixU64(self.constraint_count);
        for (self.logs()) |tree| {
            channel.mixU64(tree.len);
            channel.mixU32s(tree);
        }
        return channel.digestBytes();
    }
    /// Rebuild instead of trusting a mutable host metadata checksum.
    pub fn validate(self: *const Prepared) !void {
        var rebuilt = try Prepared.init(self.allocator, self.policy(), self.limits);
        defer rebuilt.deinit();
        if (!std.meta.eql(self.template_id, self.identity()) or !std.meta.eql(self.template_id, rebuilt.template_id)) return error.UntrustedJointCallerGeometry;
        for (self.logs(), rebuilt.logs()) |actual, expected| if (!std.mem.eql(u32, actual, expected)) return error.UntrustedJointCallerGeometry;
    }
};
/// Original equations with independently rebuilt layout and proposed public
/// claims. Their eventual proof verification, not construction, authenticates claims.
pub const EquationOwner = struct {
    allocator: std.mem.Allocator,
    elements: Profile.Relations,
    word: Word.Challenges,
    memory: Bus.Challenges,
    arithmetic: *Profile.Assembly(.verifier),
    relations: Fused.Components,
    handles: []core.air.components.Component,
    joint: *Components.Owner(false),
    pub fn create(a: std.mem.Allocator, admitted: *const Prepared, arithmetic_claims: *const Profile.ExtensionClaim, relation_claims: *const Fused.ClaimFrames) !*EquationOwner {
        try arithmetic_claims.validate(&admitted.arithmetic.statement);
        const schedule = &admitted.relations.schedule;
        // Metadata-only geometry uses zero claims, so it cannot require the
        // live event census here. Lengths must still precede component indexing;
        // complete claim/census admission belongs to the original transcript.
        if (relation_claims.program_claims.len != schedule.program.len or
            relation_claims.state_claims.len != schedule.program.len or
            relation_claims.table_claims.len != schedule.tables.len or
            relation_claims.memory_claims.len != schedule.memory.len)
            return error.InvalidV5CallerCompositeClaims;
        const self = try a.create(EquationOwner);
        errdefer a.destroy(self);
        self.allocator = a;
        self.elements = try Protocol.drawRelations(a, admitted.arithmetic.sealed);
        self.word = try Word.Challenges.draw(a, admitted.arithmetic.sealed);
        self.memory = try Bus.Challenges.draw(a, admitted.arithmetic.sealed);
        self.arithmetic = try Profile.Assembly(.verifier).createBlockV5Standalone(a, &admitted.arithmetic.statement, admitted.arithmetic.total_steps, &self.elements, arithmetic_claims);
        errdefer self.arithmetic.destroy(a);
        self.relations = try Fused.Components.init(a, &admitted.relations.schedule, relation_claims, &self.elements, &self.memory, &self.word, admitted.relations.logs[3], admitted.relations.logs[2], admitted.arithmetic.sealed.register_custody_mode);
        errdefer self.relations.deinit();
        self.handles = try self.relations.verifier();
        errdefer a.free(self.handles);
        self.joint = try Components.Owner(false).create(a, self.arithmetic.active(), self.handles, admitted.logs(), self.relations.memory.len);
        return self;
    }
    pub fn destroy(self: *EquationOwner) void {
        const a = self.allocator;
        self.joint.destroy();
        a.free(self.handles);
        self.relations.deinit();
        self.arithmetic.destroy(a);
        a.destroy(self);
    }
};
pub fn zeroClaims(a: std.mem.Allocator, schedule: *const @import("block_v5_caller_fused_schedule_v1.zig").Schedule) !Fused.ClaimFrames {
    const Program = @import("block_v5_program_extension_proof_v1.zig").Claim;
    const Table = @import("block_v5_precompile_lookup_algebra_v1.zig").Claim;
    const Memory = @import("block_v5_external_memory_sidecar_proof_v1.zig").Claim;
    const Q = core.fields.qm31.QM31;
    var result = Fused.ClaimFrames{ .program_claims = try a.alloc(Program, schedule.program.len), .state_claims = &.{}, .table_claims = &.{}, .memory_claims = &.{} };
    errdefer result.deinit(a);
    result.state_claims = try a.alloc(Program, schedule.program.len);
    result.table_claims = try a.alloc(Table, schedule.tables.len);
    result.memory_claims = try a.alloc(Memory, schedule.memory.len);
    for (schedule.program, result.program_claims, result.state_claims) |slot, *p, *s| {
        p.* = .{ .sum = Q.zero(), .fetch_count = slot.active_calls };
        s.* = p.*;
    }
    for (schedule.tables, result.table_claims) |slot, *claim| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
    for (result.memory_claims) |*claim| claim.* = .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .range_claims = @splat(Q.zero()), .active_count = 0 };
    return result;
}
