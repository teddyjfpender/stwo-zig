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
    statement: statement_mod.Blake3ExecutionStatement,
    claims: statement_mod.RiscVInteractionClaim,
    relations: universal.UniversalRelations,
    native_relations: providers.SharedProviderRelations,
    proving: ProverWorkspace = undefined,
    verifying: VerifierWorkspace = undefined,
    origin: commitment.Roster.Origin = .{},
    plan_id: [32]u8,
    pub fn init(a: std.mem.Allocator, statement: *const statement_mod.Blake3ExecutionStatement, claims: *const statement_mod.RiscVInteractionClaim, relations: universal.UniversalRelations, admission: admission_mod.Admission) !*Owner {
        try statement.validateBlake3Execution();
        try admission.validatePublic(&statement.public_data);
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .statement = statement.*, .claims = claims.*, .relations = relations, .native_relations = try providers.SharedProviderRelations.init(&relations), .plan_id = admission.expected_id };
        self.proving.components.n_handles = 0;
        self.proving.components.n_hash = 0;
        self.verifying.components.n_handles = 0;
        self.verifying.components.n_hash = 0;
        try base.assembleBlake3ExecutionInto(.prover, &self.proving, &self.statement, &self.claims, &self.native_relations.native);
        try base.assembleBlake3ExecutionInto(.verifier, &self.verifying, &self.statement, &self.claims, &self.native_relations.native);
        if (self.proving.components.active().len != self.verifying.components.active().len) return error.ExecutionComponentMismatch;
        var constraints: u32 = 0;
        for (self.verifying.components.active()) |item| constraints = try std.math.add(u32, constraints, std.math.cast(u32, item.nConstraints()) orelse return error.ExecutionGeometryOverflow);
        self.origin = .{ .columns = .{ self.statement.nPreprocessedColumns(), self.statement.nMainColumns(), self.statement.nInteractionColumns(), constraints }, .claimed_sum_index = std.math.cast(u8, self.verifying.components.active().len) orelse return error.ExecutionGeometryOverflow };
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
    pub fn publicCompensation(self: *const Owner) !core.fields.qm31.QM31 {
        return (try @import("../air/public_logup.zig").blake3RelationSums(&self.statement.public_data, &self.native_relations.native)).total();
    }
};
