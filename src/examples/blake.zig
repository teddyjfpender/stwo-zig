//! Exact port of the pinned upstream Stwo Blake AIR.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_engine = @import("stwo_prover_engine").engine;
const stage_profile = @import("stwo_prover_api").stage_profile;
const prover_transaction = @import("common/prover_transaction.zig");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

pub const constants = @import("blake/constants.zig");
pub const geometry = @import("blake/geometry.zig");
pub const round_trace = @import("blake/round_trace.zig");
pub const scheduler_trace = @import("blake/scheduler_trace.zig");
pub const xor_tables = @import("blake/xor_tables.zig");
pub const exact_input = @import("blake/exact_input.zig");
pub const exact_statement = @import("blake/statement.zig");
pub const exact_interaction = @import("blake/interaction.zig");
pub const interaction_builder = @import("blake/interaction_builder.zig");
pub const logup_constraints = @import("blake/logup_constraints.zig");
pub const component_support = @import("blake/component_support.zig");
pub const scheduler_component = @import("blake/scheduler_component.zig");
pub const round_constraints = @import("blake/round_constraints.zig");
pub const round_component = @import("blake/round_component.zig");
pub const xor_component = @import("blake/xor_component.zig");

pub const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);
pub const CpuProverEngine = prover_engine.ProverEngine(
    CpuBackend,
    Hasher,
    MerkleChannel,
    Channel,
);
pub const protocol_name = geometry.PROTOCOL_NAME;

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

comptime {
    @import("stwo_prover_api").assertProverEngine(CpuProverEngine);
}

pub const Request = exact_input.Statement;
pub const Statement = exact_statement.PreparedStatement;
pub const PreparedInput = exact_input.PreparedInput;
pub const prepareInput = exact_input.prepare;

pub const Error = exact_input.Error || error{
    ClaimedSumMismatch,
    InvalidProofShape,
};

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = prover_transaction.Output(Statement, ExtendedProof);

pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
) anyerror!ProveOutput {
    return proveWithEngine(CpuProverEngine, allocator, pcs_config, request, null);
}

pub fn proveEx(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        request,
        include_all_preprocessed_columns,
        null,
    );
}

pub fn proveProfiled(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
    recorder: *stage_profile.Recorder,
) anyerror!ProveOutput {
    return proveWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        request,
        recorder,
    );
}

pub fn proveWithBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    return proveWithEngine(
        ProverEngineForBackend(Backend),
        allocator,
        pcs_config,
        request,
        recorder,
    );
}

pub fn proveWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var output = try proveExWithEngine(
        Engine,
        allocator,
        pcs_config,
        request,
        false,
        recorder,
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn proveExWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    const prepared = blk: {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "trace_generation",
            "Trace generation",
        );
        defer stage.end();
        break :blk try prepareInput(allocator, request);
    };
    return provePreparedExImpl(
        Engine,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        include_all_preprocessed_columns,
        recorder,
    );
}

pub fn provePreparedWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var output = try provePreparedExImpl(
        Engine,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        false,
        recorder,
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn provePreparedExWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return provePreparedExImpl(
        Engine,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        include_all_preprocessed_columns,
        recorder,
    );
}

pub fn provePreparedWithSessionAndEngine(
    comptime Engine: type,
    session: *const Engine.Session,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var output = try provePreparedExImpl(
        Engine,
        true,
        session,
        allocator,
        pcs_config,
        prepared,
        false,
        recorder,
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn provePreparedExWithSessionAndEngine(
    comptime Engine: type,
    session: *const Engine.Session,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return provePreparedExImpl(
        Engine,
        true,
        session,
        allocator,
        pcs_config,
        prepared,
        include_all_preprocessed_columns,
        recorder,
    );
}

fn provePreparedExImpl(
    comptime Engine: type,
    comptime use_session: bool,
    session: if (use_session) *const Engine.Session else void,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return prover_transaction.provePreparedEx(
        Engine,
        ProvingSpec,
        use_session,
        session,
        allocator,
        pcs_config,
        prepared,
        .{
            .include_all_preprocessed_columns = include_all_preprocessed_columns,
            .recorder = recorder,
        },
    );
}

pub fn requiredTwiddleCircleLog(
    request: Request,
    pcs_config: pcs_core.PcsConfig,
) Error!u32 {
    try exact_input.validate(request);
    const max_trace_log = @max(
        request.log_n_rows + constants.ROUND_LOG_SPLIT[0],
        geometry.XOR_TABLES[0].logSize(),
    );
    const commitment_log = std.math.add(
        u32,
        max_trace_log,
        pcs_config.fri_config.log_blowup_factor,
    ) catch return error.InvalidLogNRows;
    return @max(
        @max(try exactCompositionLog(request), commitment_log),
        pcs_config.lifting_log_size orelse 0,
    );
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    exact_statement.verify(statement) catch |err| {
        var proof = proof_in;
        proof.deinit(allocator);
        return err;
    };
    if (proof_in.commitment_scheme_proof.commitments.items.len !=
        geometry.PROOF_COMMITMENTS)
    {
        var proof = proof_in;
        proof.deinit(allocator);
        return error.InvalidProofShape;
    }

    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    var channel = Channel{};
    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(
        Hasher,
        MerkleChannel,
    ).init(allocator, pcs_config);
    defer commitment_scheme.deinit(allocator);

    var logs = try columnLogs(allocator, statement.stmt0.log_size);
    defer logs.deinit(allocator);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        logs.preprocessed,
        &channel,
    );
    exact_statement.mixStatement0(&channel, statement.stmt0);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        logs.main,
        &channel,
    );
    const elements = try exact_statement.AllElements.draw(allocator, &channel);
    exact_statement.mixStatement1(&channel, statement.stmt1);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        logs.interaction,
        &channel,
    );

    var components = initComponents(
        statement.stmt0.log_size,
        elements,
        statement.stmt1,
    );
    const verifier_components = components.verifierComponents();
    proof_moved = true;
    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        &verifier_components,
        &channel,
        &commitment_scheme,
        proof,
    );
}

const ComponentSet = struct {
    scheduler: scheduler_component.Component,
    rounds: [2]round_component.Component,
    xors: [5]xor_component.Component,

    fn verifierComponents(self: *@This()) [geometry.COMPONENT_COUNT]core_air_components.Component {
        return .{
            self.scheduler.asVerifierComponent(),
            self.rounds[0].asVerifierComponent(),
            self.rounds[1].asVerifierComponent(),
            self.xors[0].asVerifierComponent(),
            self.xors[1].asVerifierComponent(),
            self.xors[2].asVerifierComponent(),
            self.xors[3].asVerifierComponent(),
            self.xors[4].asVerifierComponent(),
        };
    }

    fn proverComponents(
        self: *@This(),
    ) [geometry.COMPONENT_COUNT]prover_component.ComponentProver {
        return .{
            self.scheduler.asProverComponent(),
            self.rounds[0].asProverComponent(),
            self.rounds[1].asProverComponent(),
            self.xors[0].asProverComponent(),
            self.xors[1].asProverComponent(),
            self.xors[2].asProverComponent(),
            self.xors[3].asProverComponent(),
            self.xors[4].asProverComponent(),
        };
    }
};

fn initComponents(
    log_size: u32,
    elements: exact_statement.AllElements,
    claims: exact_statement.Statement1,
) ComponentSet {
    var result: ComponentSet = undefined;
    result.scheduler = .{
        .log_size = log_size,
        .main_offset = geometry.SCHEDULER_MAIN_OFFSET,
        .interaction_offset = geometry.SCHEDULER_INTERACTION_OFFSET,
        .elements = elements,
        .claimed_sum = claims.scheduler_claimed_sum,
    };
    for (0..2) |index| {
        result.rounds[index] = .{
            .log_size = log_size + constants.ROUND_LOG_SPLIT[index],
            .main_offset = geometry.ROUND_MAIN_OFFSETS[index],
            .interaction_offset = geometry.ROUND_INTERACTION_OFFSETS[index],
            .elements = elements,
            .claimed_sum = claims.round_claimed_sums[index],
        };
    }
    var preprocessed_offset: usize = 0;
    var main_offset: usize = geometry.XOR_MAIN_OFFSET;
    var interaction_offset: usize = geometry.XOR_INTERACTION_OFFSET;
    for (geometry.XOR_TABLES, 0..) |table, index| {
        result.xors[index] = .{
            .table_index = index,
            .preprocessed_offset = preprocessed_offset,
            .main_offset = main_offset,
            .interaction_offset = interaction_offset,
            .elements = elements.xor[index],
            .claimed_sum = claims.xor_claimed_sums[index],
        };
        preprocessed_offset += 3;
        main_offset += table.multiplicityColumns();
        interaction_offset += 4 * table.interactionSecureColumns();
    }
    return result;
}

const ProvingSpec = struct {
    pub const Statement = exact_statement.PreparedStatement;
    pub const PreparedInput = exact_input.PreparedInput;
    pub const PreparedInteraction = exact_interaction.PreparedInteraction;
    pub const max_components = geometry.COMPONENT_COUNT;
    pub const mix_pcs_config = false;

    pub const ProverContext = struct {
        statement_value: exact_statement.PreparedStatement,
        components: ComponentSet,
    };

    pub fn validateRequest(request: Request) Error!void {
        try exact_input.validate(request);
    }

    pub fn validatePrepared(prepared: *const exact_input.PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        if (preprocessed.len != geometry.PREPROCESSED_COLUMNS or
            main.len != geometry.MAIN_COLUMNS)
        {
            return error.InvalidPreparedGeometry;
        }
    }

    pub fn compositionLog(request: Request) Error!u32 {
        return exactCompositionLog(request);
    }

    pub fn beforeMainCommit(channel: *Channel, request: Request) !void {
        exact_statement.mixStatement0(channel, .{ .log_size = request.log_n_rows });
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *const exact_input.PreparedInput,
    ) !exact_interaction.PreparedInteraction {
        return exact_interaction.generate(allocator, channel, prepared);
    }

    pub fn deinitPreparedInteraction(
        prepared: *exact_interaction.PreparedInteraction,
        allocator: std.mem.Allocator,
    ) void {
        prepared.deinit(allocator);
    }

    pub fn beforeInteractionCommit(
        channel: *Channel,
        _: Request,
        prepared: *const exact_interaction.PreparedInteraction,
    ) !void {
        exact_statement.mixStatement1(channel, prepared.statement.stmt1);
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Channel,
        _: Request,
        prepared: *const exact_interaction.PreparedInteraction,
    ) !void {
        out.* = .{
            .statement_value = prepared.statement,
            .components = initComponents(
                prepared.statement.stmt0.log_size,
                prepared.elements,
                prepared.statement.stmt1,
            ),
        };
    }

    pub fn statement(context: *const ProverContext) exact_statement.PreparedStatement {
        return context.statement_value;
    }

    pub fn proverComponents(
        context: *ProverContext,
        out: []prover_component.ComponentProver,
    ) ![]const prover_component.ComponentProver {
        if (out.len < max_components) return error.InvalidProofShape;
        const components = context.components.proverComponents();
        @memcpy(out[0..max_components], &components);
        return out[0..max_components];
    }
};

fn exactCompositionLog(request: Request) Error!u32 {
    try exact_input.validate(request);
    return @max(
        request.log_n_rows + constants.ROUND_LOG_SPLIT[0] + 1,
        geometry.XOR_TABLES[0].logSize() + 1,
    );
}

const ColumnLogs = struct {
    preprocessed: []u32,
    main: []u32,
    interaction: []u32,

    fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.preprocessed);
        allocator.free(self.main);
        allocator.free(self.interaction);
    }
};

fn columnLogs(allocator: std.mem.Allocator, log_size: u32) !ColumnLogs {
    const preprocessed = try allocator.alloc(u32, geometry.PREPROCESSED_COLUMNS);
    errdefer allocator.free(preprocessed);
    const main = try allocator.alloc(u32, geometry.MAIN_COLUMNS);
    errdefer allocator.free(main);
    const interaction = try allocator.alloc(u32, geometry.INTERACTION_COLUMNS);
    errdefer allocator.free(interaction);

    var pre_index: usize = 0;
    for (geometry.XOR_TABLES) |table| {
        @memset(preprocessed[pre_index .. pre_index + 3], table.logSize());
        pre_index += 3;
    }
    @memset(
        main[geometry.SCHEDULER_MAIN_OFFSET..geometry.ROUND_MAIN_OFFSETS[0]],
        log_size,
    );
    for (0..2) |index| {
        @memset(
            main[geometry.ROUND_MAIN_OFFSETS[index]..][0..geometry.ROUND_MAIN_COLUMNS],
            log_size + constants.ROUND_LOG_SPLIT[index],
        );
    }
    var xor_main = geometry.XOR_MAIN_OFFSET;
    for (geometry.XOR_TABLES) |table| {
        @memset(
            main[xor_main..][0..table.multiplicityColumns()],
            table.logSize(),
        );
        xor_main += table.multiplicityColumns();
    }
    @memset(
        interaction[geometry.SCHEDULER_INTERACTION_OFFSET..geometry.ROUND_INTERACTION_OFFSETS[0]],
        log_size,
    );
    for (0..2) |index| {
        @memset(
            interaction[geometry.ROUND_INTERACTION_OFFSETS[index]..][0 .. 4 * geometry.ROUND_INTERACTION_SECURE_COLUMNS],
            log_size + constants.ROUND_LOG_SPLIT[index],
        );
    }
    var xor_interaction = geometry.XOR_INTERACTION_OFFSET;
    for (geometry.XOR_TABLES) |table| {
        const count = 4 * table.interactionSecureColumns();
        @memset(
            interaction[xor_interaction..][0..count],
            table.logSize(),
        );
        xor_interaction += count;
    }
    return .{
        .preprocessed = preprocessed,
        .main = main,
        .interaction = interaction,
    };
}

test "exact Blake component set concatenates pinned mixed-height geometry" {
    const allocator = std.testing.allocator;
    const relation = exact_statement.RelationElements{
        .z = @import("stwo_core").fields.qm31.QM31.one(),
        .alpha = @import("stwo_core").fields.qm31.QM31.one(),
    };
    const elements = exact_statement.AllElements{
        .blake = relation,
        .round = relation,
        .xor = [_]exact_statement.RelationElements{relation} ** 5,
    };
    const zero = @import("stwo_core").fields.qm31.QM31.zero();
    var set = initComponents(4, elements, .{
        .scheduler_claimed_sum = zero,
        .round_claimed_sums = .{ zero, zero },
        .xor_claimed_sums = .{ zero, zero, zero, zero, zero },
    });
    const values = set.verifierComponents();
    const components = core_air_components.Components{
        .components = &values,
        .n_preprocessed_columns = geometry.PREPROCESSED_COLUMNS,
    };
    var bounds = try components.columnLogSizes(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(geometry.PREPROCESSED_COLUMNS, bounds.items[0].len);
    try std.testing.expectEqual(geometry.MAIN_COLUMNS, bounds.items[1].len);
    try std.testing.expectEqual(geometry.INTERACTION_COLUMNS, bounds.items[2].len);
    try std.testing.expectEqual(@as(u32, 17), components.compositionLogDegreeBound());
}
