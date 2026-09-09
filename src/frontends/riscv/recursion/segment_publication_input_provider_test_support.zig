//! Matching synthetic ContextV2 and boundary sources for provider tests.
//! The default is the small 21-claim profile; initWithCore also exercises
//! retained Ethereum geometry. These fixtures do not contain real proofs.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const universal = @import("air/universal_challenges.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary = @import("segment_leaf_outer_authority_v2.zig");
const witness = @import("air/segment_publication_input_provider_witness_v2.zig");
const public_support = @import("segment_public_outer_test_support.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const native_relations = @import("../air/relation_challenges.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const trace_mod = @import("../runner/trace.zig");
const vm_air_profile = @import("vm_air_profile_v2.zig");
const vm_leaf_context = @import("vm_leaf_context_v2.zig");

pub const component_descs = [_]statement_v1.FamilyComponentDesc{
    .{
        .family = .base_alu_imm,
        .log_size = 5,
        .n_rows = 17,
        .n_columns = trace_mod.nColumnsForFamily(.base_alu_imm),
    },
    .{
        .family = .base_alu_reg,
        .log_size = 5,
        .n_rows = 19,
        .n_columns = trace_mod.nColumnsForFamily(.base_alu_reg),
    },
};

pub const infra_descs = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 5,
    .n_rows = 11,
    .n_columns = @import("../air/program/commitment.zig").N_MAIN_COLUMNS,
}};

pub const VerifiedSources = struct {
    vm_context: vm_leaf_context.ContextV2,
    receipt: statement_v2.VerifiedReceipt,

    pub fn init(
        allocator: std.mem.Allocator,
        data: *const public_data_v2.PublicDataV2,
    ) !VerifiedSources {
        return initWithCore(allocator, data, fixtureCore());
    }

    pub fn initWithCore(
        allocator: std.mem.Allocator,
        data: *const public_data_v2.PublicDataV2,
        core: statement_v1.RiscVStatement,
    ) !VerifiedSources {
        var context = try verifiedContextWithCore(allocator, data, core);
        errdefer context.deinit();
        const native = try context.reconstructStatement(data);
        return .{ .vm_context = context, .receipt = try native.verifiedReceipt() };
    }

    pub fn deinit(self: *VerifiedSources) void {
        self.vm_context.deinit();
        self.* = undefined;
    }
};

/// Complete capture/context fixture for focused provider and cohort gates.
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    public_fixture: public_support.Fixture,
    boundary_owner: boundary.AuthorityV2,
    boundary_workspace: boundary.WorkspaceV2,
    boundary_traces: OwnedBoundaryTraces,
    capture: boundary.PreparedNativeVerifierOuterAuthorityV2,
    sources: VerifiedSources,
    outer_relations: universal.UniversalRelations,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        return initWithCore(allocator, fixtureCore());
    }

    pub fn initWithCore(allocator: std.mem.Allocator, core: statement_v1.RiscVStatement) !Fixture {
        var public_fixture = try public_support.Fixture.init(allocator);
        errdefer public_fixture.deinit();
        var sources = try VerifiedSources.initWithCore(
            allocator,
            &public_fixture.owned_public.data,
            core,
        );
        errdefer sources.deinit();
        const shape = try boundary.preflight(
            &public_fixture.owned_public.data,
            &public_fixture.keys,
        );
        var boundary_owner = try boundary.AuthorityV2.init(allocator);
        errdefer boundary_owner.deinit();
        var boundary_workspace = try boundary.WorkspaceV2.init(
            allocator,
            &shape.manifest,
        );
        errdefer boundary_workspace.deinit();
        var boundary_traces = try OwnedBoundaryTraces.init(
            allocator,
            &shape.manifest,
        );
        errdefer boundary_traces.deinit();
        var outer_relations = universal.UniversalRelations.dummy();
        var capture: boundary.PreparedNativeVerifierOuterAuthorityV2 = undefined;
        try boundary.prepareNativeVerifierInto(
            &capture,
            &boundary_workspace,
            &boundary_owner,
            boundary_traces.traces(),
            &public_fixture.owned_public.data,
            &public_fixture.keys,
            &public_fixture.relations,
            &public_fixture.native_sums,
            &sources.receipt,
            sources.vm_context.component_descs,
            sources.vm_context.infra_descs,
            &outer_relations,
        );
        return .{
            .allocator = allocator,
            .public_fixture = public_fixture,
            .boundary_owner = boundary_owner,
            .boundary_workspace = boundary_workspace,
            .boundary_traces = boundary_traces,
            .capture = capture,
            .sources = sources,
            .outer_relations = outer_relations,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.sources.deinit();
        self.boundary_traces.deinit();
        self.boundary_workspace.deinit();
        self.boundary_owner.deinit();
        self.public_fixture.deinit();
        self.* = undefined;
    }

    pub fn inputs(self: *const Fixture) witness.InputsV2 {
        return .{
            .capture = &self.capture,
            .vm_context = &self.sources.vm_context,
        };
    }
};

pub fn verifiedReceipt(data: *const public_data_v2.PublicDataV2) !statement_v2.VerifiedReceipt {
    const core_public = try statement_v2.canonicalCorePublicData(data);
    var core = fixtureCore();
    core.initial_pc = core_public.initial_pc;
    core.final_pc = core_public.final_pc;
    core.total_steps = core_public.clock;
    core.public_data = core_public;
    const native = try statement_v2.RiscVStatementV2.init(core, data.*);
    return native.verifiedReceipt();
}

fn fixtureCore() statement_v1.RiscVStatement {
    var core: statement_v1.RiscVStatement = undefined;
    core.n_components = component_descs.len;
    @memcpy(core.component_descs[0..component_descs.len], &component_descs);
    core.n_infra = infra_descs.len;
    @memcpy(core.infra_descs[0..infra_descs.len], &infra_descs);
    return core;
}

pub fn verifiedContext(
    allocator: std.mem.Allocator,
    data: *const public_data_v2.PublicDataV2,
) !vm_leaf_context.ContextV2 {
    return verifiedContextWithCore(allocator, data, fixtureCore());
}

fn verifiedContextWithCore(
    allocator: std.mem.Allocator,
    data: *const public_data_v2.PublicDataV2,
    core: statement_v1.RiscVStatement,
) !vm_leaf_context.ContextV2 {
    var statement = core;
    const core_public = try statement_v2.canonicalCorePublicData(data);
    statement.initial_pc = core_public.initial_pc;
    statement.final_pc = core_public.final_pc;
    statement.total_steps = core_public.clock;
    statement.public_data = core_public;

    const manifest = lookup.Manifest.native();
    var claim: statement_v1.RiscVInteractionClaim = undefined;
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    var next: u32 = 1;
    for (statement.component_descs[0..statement.n_components], 0..) |descriptor, index| {
        for (claim.opcode_claims[index][0..manifest.entryForFamily(descriptor.family).detailed_claim_count]) |*slot| {
            slot.* = qm31(next);
            next += 4;
        }
    }
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, index| {
        for (0..statement_v1.nClaimedSumsForInfra(descriptor.kind)) |sum| {
            try claim.setInfraClaim(descriptor.kind, index, sum, qm31(next));
            next += 4;
        }
    }
    const native = try statement_v2.RiscVStatementV2.init(statement, data.*);
    const authenticated = try lookup.AuthenticatedStatement.init(&native.core, &manifest);
    const facts = try vm_air_profile.testing.expectedFacts(allocator, &native.core, &manifest);
    defer allocator.free(facts);
    const relations = native_relations.Relations.dummy();
    const sums = try statement_v2.NativePublicSums.init(data, &relations);
    const receipt = try native.verifiedReceipt();
    const sampled_count = try @import("vm_composition_base_geometry_v2.zig").expectedSampledValueCount(&native.core, &manifest);
    return vm_leaf_context.testing.initFromFacts(
        allocator,
        &native,
        &claim,
        &relations,
        &manifest,
        &authenticated,
        facts,
        .{ .full_sampled_value_count = sampled_count, .sha256 = .{0x5a} ** 32 },
        &receipt,
        &sums,
    );
}

const OwnedBoundaryTraces = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    statement_preprocessed: [boundary_air.Statement.PREPROCESSED_COLUMN_COUNT][]M31,
    statement_main: [boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    statement_interaction: [boundary_air.Statement.INTERACTION_COLUMN_COUNT][]M31,
    public_preprocessed: [boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31,
    public_main: [boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    public_interaction: [boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const boundary.OuterManifestV2,
    ) !OwnedBoundaryTraces {
        const statement_rows: usize = manifest.components[0].trace_rows;
        const public_rows: usize = manifest.components[1].trace_rows;
        const statement_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT +
            boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT +
            boundary_air.Statement.INTERACTION_COLUMN_COUNT;
        const public_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT +
            boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT +
            boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT;
        const statement_words = try std.math.mul(
            usize,
            statement_rows,
            statement_columns,
        );
        const public_words = try std.math.mul(
            usize,
            public_rows,
            public_columns,
        );
        const storage = try allocator.alloc(
            M31,
            try std.math.add(usize, statement_words, public_words),
        );
        errdefer allocator.free(storage);
        var at: usize = 0;
        var statement_preprocessed: [boundary_air.Statement.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&statement_preprocessed) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_main: [boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&statement_main) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_interaction: [boundary_air.Statement.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&statement_interaction) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var public_preprocessed: [boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&public_preprocessed) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        var public_main: [boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&public_main) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        var public_interaction: [boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&public_interaction) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        std.debug.assert(at == storage.len);
        return .{
            .allocator = allocator,
            .storage = storage,
            .statement_preprocessed = statement_preprocessed,
            .statement_main = statement_main,
            .statement_interaction = statement_interaction,
            .public_preprocessed = public_preprocessed,
            .public_main = public_main,
            .public_interaction = public_interaction,
        };
    }

    fn deinit(self: *OwnedBoundaryTraces) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn traces(self: *OwnedBoundaryTraces) boundary.TracesV2 {
        return .{
            .statement = .{
                .preprocessed = self.statement_preprocessed,
                .main = self.statement_main,
                .interaction = self.statement_interaction,
            },
            .public_logup = .{
                .preprocessed = self.public_preprocessed,
                .main = self.public_main,
                .interaction = self.public_interaction,
            },
        };
    }
};

fn qm31(seed: u32) QM31 {
    return QM31.fromU32Unchecked(seed, seed + 1, seed + 2, seed + 3);
}
