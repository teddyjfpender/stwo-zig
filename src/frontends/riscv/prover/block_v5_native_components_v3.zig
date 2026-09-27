//! Native-v5 v3 standalone component owner. No hash-custody columns, old
//! commitment Plan, per-leaf Merkle schedule or scheduled memory compensation.
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
const admission_mod = @import("block_v5_native_public_admission_v1.zig");
const frame = @import("block_v5_native_frame_v1.zig");
const frame_component = @import("block_v5_native_frame_component_v1.zig");
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
    native_frame: frame_component.Component = undefined,
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
        self.* = .{ .allocator = a, .execution_profile = selected_profile, .statement = statement.*, .claims = claims.*, .relations = relations, .native_relations = try providers.SharedProviderRelations.init(&relations), .plan_id = admission.expected_id };
        self.proving.components.n_handles = 0;
        self.proving.components.n_hash = 0;
        self.verifying.components.n_handles = 0;
        self.verifying.components.n_hash = 0;
        try base.assembleBlake3ExecutionWithExternalInto(.prover, &self.proving, &self.statement, &self.claims, &self.native_relations.native, external_retirements);
        try base.assembleBlake3ExecutionWithExternalInto(.verifier, &self.verifying, &self.statement, &self.claims, &self.native_relations.native, external_retirements);
        if (frame.required(&self.statement)) {
            if (self.claims.n_components != 0 or self.claims.n_infra != 0) return error.InvalidNativeV5Claims;
            self.native_frame = .{ .expected = try frame.expected(&self.statement, external_retirements) };
            self.proving.components.push(self.native_frame.asProverComponent());
            self.verifying.components.push(self.native_frame.asVerifierComponent());
        }
        if (self.proving.components.active().len != self.verifying.components.active().len) return error.ExecutionComponentMismatch;
        var constraints: u32 = 0;
        for (self.verifying.components.active()) |item| constraints = try std.math.add(u32, constraints, std.math.cast(u32, item.nConstraints()) orelse return error.ExecutionGeometryOverflow);
        self.origin = .{ .columns = .{ self.statement.nPreprocessedColumns(), self.statement.nMainColumns(), self.statement.nInteractionColumns(), constraints }, .claimed_sum_index = std.math.cast(u32, self.verifying.components.active().len) orelse return error.ExecutionGeometryOverflow };
        if (frame.required(&self.statement)) self.origin.columns = .{ frame.FIXED_COLUMNS, frame.MAIN_COLUMNS, frame.INTERACTION_COLUMNS, constraints };
        return self;
    }
    pub fn deinit(self: *Owner) void {
        self.allocator.destroy(self);
    }
    /// Only the PC/clock state pair is publicly compensated here. Ordinary
    /// register/RW accesses and ROM/table requests remain open for global buses.
    pub fn publicCompensation(self: *const Owner) !core.fields.qm31.QM31 {
        return @import("../air/public_logup_arithmetic.zig").registersStateSumFor(
            core.fields.qm31.QM31,
            &self.statement.public_data,
            &self.native_relations.native,
        );
    }
};
