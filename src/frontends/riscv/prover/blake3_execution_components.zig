//! Shared native-execution/BLAKE3-commitment component assembly. Both sides use
//! the same universal challenge draw and full-width public-root admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const statement_mod = @import("../air/statement.zig");
const workspace = @import("proof_workspace.zig");
const base = @import("base_component_assembly.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const providers = @import("../recursion/air/universal_provider_relations.zig");
const commitment = @import("blake3_commitment_components.zig");
const columns = @import("blake3_commitment_columns.zig");
const admission_mod = @import("blake3_commitment_plan.zig");
const Prover = engine.air.component_prover.ComponentProver;
const Verifier = core.air.components.Component;
const ProverWorkspace = struct { components: workspace.ComponentTable(Prover) };
const VerifierWorkspace = struct { components: workspace.ComponentTable(Verifier) };
pub const Owner = struct {
    allocator: std.mem.Allocator,
    execution_profile: @import("../isa/execution_profile.zig").ExecutionProfile = .rv32im_zkvm_v1,
    statement: statement_mod.Blake3ExecutionStatement,
    claims: statement_mod.RiscVInteractionClaim,
    relations: universal.UniversalRelations,
    native_relations: providers.SharedProviderRelations,
    proving: ProverWorkspace = undefined,
    verifying: VerifierWorkspace = undefined,
    origin: commitment.Roster.Origin = .{},
    plan_id: [32]u8,
    memory_schedule: []const @import("../recursion/air/blake3_memory_word.zig").Statement,
    pub fn init(a: std.mem.Allocator, statement: *const statement_mod.Blake3ExecutionStatement, claims: *const statement_mod.RiscVInteractionClaim, relations: universal.UniversalRelations, admission: admission_mod.Admission) !*Owner {
        return initWithExternal(a, statement, claims, relations, admission, 0);
    }
    pub fn initWithExternal(a: std.mem.Allocator, statement: *const statement_mod.Blake3ExecutionStatement, claims: *const statement_mod.RiscVInteractionClaim, relations: universal.UniversalRelations, admission: admission_mod.Admission, external_retirements: u32) !*Owner {
        return initWithExternalForProfile(a, statement, claims, relations, admission, external_retirements, .rv32im_zkvm_v1);
    }
    /// The containing proof protocol authenticates this execution profile.
    pub fn initWithExternalForProfile(a: std.mem.Allocator, statement: *const statement_mod.Blake3ExecutionStatement, claims: *const statement_mod.RiscVInteractionClaim, relations: universal.UniversalRelations, admission: admission_mod.Admission, external_retirements: u32, selected_profile: @import("../isa/execution_profile.zig").ExecutionProfile) !*Owner {
        try statement.validateBlake3ExecutionWithExternal(external_retirements);
        try admission.validatePublic(&statement.public_data);
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .execution_profile = selected_profile, .statement = statement.*, .claims = claims.*, .relations = relations, .native_relations = try providers.SharedProviderRelations.init(&relations), .plan_id = admission.expected_id, .memory_schedule = admission.plan.memories };
        self.proving.components.n_handles = 0;
        self.proving.components.n_hash = 0;
        self.verifying.components.n_handles = 0;
        self.verifying.components.n_hash = 0;
        try base.assembleBlake3ExecutionWithExternalInto(.prover, &self.proving, &self.statement, &self.claims, &self.native_relations.native, external_retirements);
        try base.assembleBlake3ExecutionWithExternalInto(.verifier, &self.verifying, &self.statement, &self.claims, &self.native_relations.native, external_retirements);
        if (self.proving.components.active().len != self.verifying.components.active().len) return error.ExecutionComponentMismatch;
        var constraints: u32 = 0;
        for (self.verifying.components.active()) |item| constraints = try std.math.add(u32, constraints, std.math.cast(u32, item.nConstraints()) orelse return error.ExecutionGeometryOverflow);
        self.origin = .{ .columns = .{ self.statement.nPreprocessedColumns(), self.statement.nMainColumns(), self.statement.nInteractionColumns(), constraints }, .claimed_sum_index = std.math.cast(u32, self.verifying.components.active().len) orelse return error.ExecutionGeometryOverflow };
        return self;
    }
    pub fn deinit(self: *Owner) void {
        self.allocator.destroy(self);
    }
    /// The complete transcript must authenticate both component groups and
    /// their PCS geometry. Commitment column storage must outlive these handles.
    pub fn bindCommitments(self: *Owner, target: *columns.Owner, claims: [commitment.Airs.len]core.fields.qm31.QM31) !void {
        if (!std.mem.eql(u8, &target.plan_id, &self.plan_id)) return error.UntrustedCommitmentPlan;
        try self.native_relations.validateAgainst(&self.relations);
        try target.bindAt(self.relations, claims, self.origin);
    }
    pub fn bindCompactCommitments(self: *Owner, target: *columns.Owner, claims: [commitment.Airs.len]core.fields.qm31.QM31, ranges: *@import("compact_range_assembly.zig").Owner, range_claims: [3]core.fields.qm31.QM31) !void {
        if (!std.mem.eql(u8, &target.plan_id, &self.plan_id)) return error.UntrustedCommitmentPlan;
        try self.native_relations.validateAgainst(&self.relations);
        try ranges.bind(self.relations, range_claims);
        if (ranges.proving) try ranges.appendProvers(&self.proving.components);
        try ranges.appendVerifiers(&self.verifying.components);
        const end = try ranges.endOrigin();
        try target.bindAt(self.relations, claims, .{ .columns = end.columns, .claimed_sum_index = end.claimed_sum_index });
    }
    pub fn publicCompensation(self: *const Owner) !core.fields.qm31.QM31 {
        return (try @import("../air/public_logup_arithmetic.zig").blake3ScheduledRelationSumsForProfile(core.fields.qm31.QM31, self.execution_profile, &self.statement.public_data, &self.native_relations.native, self.memory_schedule)).total();
    }
};
