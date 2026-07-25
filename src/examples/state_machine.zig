const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const prover_engine = @import("stwo_prover_impl").engine;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const prover_transaction = @import("common/prover_transaction.zig");
const component_mod = @import("state_machine/component.zig");
const trace_input = @import("state_machine/input.zig");
const interaction = @import("state_machine/interaction.zig");
const statement_impl = @import("state_machine/statement.zig");
const CpuBackend = @import("../backends/cpu_scalar/mod.zig").CpuBackend;

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const State = trace_input.State;
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
pub const protocol_name = "raw-stwo-state-machine-v2";
const PROOF_COMMITMENTS: usize = 4;

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

comptime {
    prover_engine.assertProverEngine(CpuProverEngine);
}

pub const Request = trace_input.Request;
pub const PreparedInput = trace_input.PreparedInput;
pub const prepareInput = trace_input.prepare;
pub const genTrace = trace_input.genTrace;
pub const deinitTrace = trace_input.deinitTrace;

pub const Error = trace_input.Error || statement_impl.Error || error{
    InvalidProofShape,
};

pub const TransitionStates = statement_impl.TransitionStates;
pub const Statement0 = statement_impl.Statement0;
pub const Statement1 = statement_impl.Statement1;
pub const PreparedStatement = statement_impl.PreparedStatement;
pub const Elements = statement_impl.Elements;
pub const transitionStates = statement_impl.transitionStates;
pub const claimedSumFromInitial = statement_impl.claimedSumFromInitial;
pub const claimedSumTelescoping = statement_impl.claimedSumTelescoping;
pub const claimsSatisfyStatement = statement_impl.claimsSatisfyStatement;
pub const prepareStatement = statement_impl.prepare;
pub const verifyStatement = statement_impl.verify;
const mixStatement0 = statement_impl.mixStatement0;
const mixStatement1 = statement_impl.mixStatement1;

pub const ProveOutput = struct {
    statement: PreparedStatement,
    proof: Proof,
};

pub const ProveExOutput = prover_transaction.Output(PreparedStatement, ExtendedProof);

/// Proves the state-machine statement using the shared component-driven prover flow.
///
/// Inputs:
/// - `pcs_config`: PCS/FRI configuration.
/// - `log_n_rows`: transition trace size exponent `n`.
/// - `initial_state`: public initial state.
///
/// Output:
/// - `ProveOutput` carrying the prepared statement and generated proof.
///
/// Failure modes:
/// - `Error.InvalidLogSize`/`Error.InvalidIncIndex` from trace/statement setup.
/// - allocator/prover failures from PCS/FRI/prover internals.
pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    log_n_rows: u32,
    initial_state: State,
) anyerror!ProveOutput {
    return proveWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        .{ .log_n_rows = log_n_rows, .initial_state = initial_state },
        null,
    );
}

/// Extended proving wrapper over `prover.proveEx`.
pub fn proveEx(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    log_n_rows: u32,
    initial_state: State,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        .{ .log_n_rows = log_n_rows, .initial_state = initial_state },
        include_all_preprocessed_columns,
        null,
    );
}

pub fn proveProfiled(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    log_n_rows: u32,
    initial_state: State,
    recorder: *stage_profile.Recorder,
) anyerror!ProveOutput {
    return proveWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        .{ .log_n_rows = log_n_rows, .initial_state = initial_state },
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

/// Proves a prepared State Machine trace and consumes it on every path.
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
    try trace_input.validate(request);
    const composition_log = std.math.add(u32, request.log_n_rows, 1) catch
        return error.InvalidLogSize;
    const commitment_log = std.math.add(
        u32,
        request.log_n_rows,
        pcs_config.fri_config.log_blowup_factor,
    ) catch return error.InvalidLogSize;
    return @max(
        @max(composition_log, commitment_log),
        pcs_config.lifting_log_size orelse 0,
    );
}

/// Verifies a state-machine proof generated by `prove`.
///
/// Preconditions:
/// - `statement` and `proof` come from matching execution parameters.
/// - `proof` is consumed by this function.
pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: PreparedStatement,
    proof_in: Proof,
) anyerror!void {
    if (statement.stmt0.n < 5 or statement.stmt0.n >= 31) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogSize;
    }
    if (statement.stmt0.m != statement.stmt0.n - 1) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogSize;
    }
    if (proof_in.commitment_scheme_proof.commitments.items.len != PROOF_COMMITMENTS) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidProofShape;
    }

    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );
    defer commitment_scheme.deinit(allocator);

    const log_n_rows = statement.stmt0.n;
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &.{},
        &channel,
    );
    mixStatement0(&channel, statement.stmt0);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &.{ log_n_rows, log_n_rows, log_n_rows - 1, log_n_rows - 1 },
        &channel,
    );

    const elements = try Elements.draw(allocator, &channel);
    try verifyStatement(statement, elements);
    mixStatement1(&channel, statement.stmt1);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &.{
            log_n_rows,
            log_n_rows,
            log_n_rows,
            log_n_rows,
            log_n_rows - 1,
            log_n_rows - 1,
            log_n_rows - 1,
            log_n_rows - 1,
        },
        &channel,
    );

    const component0 = component_mod.Component{
        .log_size = log_n_rows,
        .coordinate = 0,
        .main_offset = 0,
        .interaction_offset = 0,
        .lookup_elements = elements,
        .claimed_sum = statement.stmt1.x_axis_claimed_sum,
    };
    const component1 = component_mod.Component{
        .log_size = log_n_rows - 1,
        .coordinate = 1,
        .main_offset = 2,
        .interaction_offset = 4,
        .lookup_elements = elements,
        .claimed_sum = statement.stmt1.y_axis_claimed_sum,
    };
    const verifier_components = [_]core_air_components.Component{
        component0.asVerifierComponent(),
        component1.asVerifierComponent(),
    };

    proof_moved = true;
    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        verifier_components[0..],
        &channel,
        &commitment_scheme,
        proof,
    );
}

const ProvingSpec = struct {
    pub const Statement = PreparedStatement;
    pub const PreparedInput = trace_input.PreparedInput;
    pub const PreparedInteraction = interaction.PreparedInteraction;
    pub const max_components: usize = 2;

    pub const ProverContext = struct {
        statement_value: PreparedStatement,
        component0: component_mod.Component,
        component1: component_mod.Component,
    };

    pub fn validateRequest(request: Request) Error!void {
        try trace_input.validate(request);
    }

    pub fn validatePrepared(prepared: *const trace_input.PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        if (preprocessed.len != 0 or main.len != 4)
            return error.InvalidPreparedGeometry;
        if (main[0].log_size != prepared.request.log_n_rows or
            main[1].log_size != prepared.request.log_n_rows or
            main[2].log_size != prepared.request.log_n_rows - 1 or
            main[3].log_size != prepared.request.log_n_rows - 1)
            return error.InvalidPreparedGeometry;
    }

    pub fn compositionLog(request: Request) Error!u32 {
        return std.math.add(u32, request.log_n_rows, 1) catch
            return error.InvalidLogSize;
    }

    pub fn beforeMainCommit(channel: *Channel, request: Request) !void {
        mixStatement0(channel, .{
            .n = request.log_n_rows,
            .m = request.log_n_rows - 1,
        });
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *const trace_input.PreparedInput,
    ) !PreparedInteraction {
        return interaction.generate(allocator, channel, prepared);
    }

    pub fn deinitPreparedInteraction(
        prepared: *PreparedInteraction,
        allocator: std.mem.Allocator,
    ) void {
        prepared.deinit(allocator);
    }

    pub fn beforeInteractionCommit(
        channel: *Channel,
        _: Request,
        prepared: *const PreparedInteraction,
    ) !void {
        mixStatement1(channel, prepared.statement.stmt1);
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Channel,
        request: Request,
        prepared: *const PreparedInteraction,
    ) !void {
        out.* = .{
            .statement_value = prepared.statement,
            .component0 = .{
                .log_size = request.log_n_rows,
                .coordinate = 0,
                .main_offset = 0,
                .interaction_offset = 0,
                .lookup_elements = prepared.lookup_elements,
                .claimed_sum = prepared.statement.stmt1.x_axis_claimed_sum,
            },
            .component1 = .{
                .log_size = request.log_n_rows - 1,
                .coordinate = 1,
                .main_offset = 2,
                .interaction_offset = 4,
                .lookup_elements = prepared.lookup_elements,
                .claimed_sum = prepared.statement.stmt1.y_axis_claimed_sum,
            },
        };
    }

    pub fn statement(context: *const ProverContext) PreparedStatement {
        return context.statement_value;
    }

    pub fn proverComponents(
        context: *const ProverContext,
        out: []prover_component.ComponentProver,
    ) ![]const prover_component.ComponentProver {
        if (out.len < max_components) return error.InvalidProofShape;
        out[0] = context.component0.asProverComponent();
        out[1] = context.component1.asProverComponent();
        return out[0..2];
    }
};

test "examples state_machine: trace generation increments selected coordinate" {
    const alloc = std.testing.allocator;

    var trace = try genTrace(
        alloc,
        4,
        .{
            M31.fromCanonical(17),
            M31.fromCanonical(16),
        },
        1,
    );
    defer deinitTrace(alloc, &trace);

    try std.testing.expectEqual(@as(usize, 16), trace[0].len);
    try std.testing.expectEqual(@as(usize, 16), trace[1].len);
    try std.testing.expect(trace[0][0].eql(M31.fromCanonical(17)));
}

test "examples state_machine: transition states follow upstream formulas" {
    const initial: State = .{
        M31.fromCanonical(5),
        M31.fromCanonical(9),
    };
    const states = try transitionStates(6, initial);

    try std.testing.expect(states.intermediate[0].eql(M31.fromCanonical(5 + 64)));
    try std.testing.expect(states.intermediate[1].eql(M31.fromCanonical(9)));
    try std.testing.expect(states.final[0].eql(M31.fromCanonical(5 + 64)));
    try std.testing.expect(states.final[1].eql(M31.fromCanonical(9 + 32)));
}

test "examples state_machine: rejects invalid log size and coordinate index" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(
        Error.InvalidLogSize,
        prepareInput(alloc, .{
            .log_n_rows = 4,
            .initial_state = .{ M31.zero(), M31.zero() },
        }),
    );
    try std.testing.expectError(
        Error.InvalidLogSize,
        transitionStates(0, .{ M31.zero(), M31.zero() }),
    );
    try std.testing.expectError(
        Error.InvalidLogSize,
        transitionStates(31, .{ M31.zero(), M31.zero() }),
    );
    try std.testing.expectError(
        Error.InvalidIncIndex,
        genTrace(alloc, 4, .{ M31.zero(), M31.zero() }, 2),
    );
}

test "examples state_machine: claimed-sum accumulation equals telescoping form" {
    const elements: Elements = .{
        .z = QM31.fromU32Unchecked(41, 17, 9, 3),
        .alpha = QM31.fromU32Unchecked(5, 8, 13, 21),
    };
    const initial: State = .{
        M31.fromCanonical(7),
        M31.fromCanonical(11),
    };

    const direct = try claimedSumFromInitial(6, initial, 1, elements);
    const telescoping = try claimedSumTelescoping(6, initial, 1, elements);
    try std.testing.expect(direct.eql(telescoping));
}

test "examples state_machine: draw yields distinct lookup elements on successive calls" {
    var channel = Channel{};
    const e0 = try Elements.draw(std.testing.allocator, &channel);
    const e1 = try Elements.draw(std.testing.allocator, &channel);
    try std.testing.expect(!e0.z.eql(e1.z) or !e0.alpha.eql(e1.alpha));
}

test "examples state_machine: claimed sums satisfy public statement equation" {
    const initial: State = .{
        M31.fromCanonical(3),
        M31.fromCanonical(9),
    };
    const elements: Elements = .{
        .z = QM31.fromU32Unchecked(27, 4, 19, 8),
        .alpha = QM31.fromU32Unchecked(2, 7, 11, 13),
    };
    const log_n_rows: u32 = 7;

    const transitions = try transitionStates(log_n_rows, initial);
    const x_claim = try claimedSumTelescoping(log_n_rows, initial, 0, elements);
    const y_claim = try claimedSumTelescoping(log_n_rows - 1, transitions.intermediate, 1, elements);
    const ok = try claimsSatisfyStatement(
        initial,
        transitions.final,
        x_claim,
        y_claim,
        elements,
    );
    try std.testing.expect(ok);
}

test "examples state_machine: prepare/verify statement roundtrip" {
    const elements: Elements = .{
        .z = QM31.fromU32Unchecked(37, 19, 5, 11),
        .alpha = QM31.fromU32Unchecked(7, 3, 13, 17),
    };
    const initial: State = .{
        M31.fromCanonical(12),
        M31.fromCanonical(4),
    };

    const statement = try prepareStatement(8, initial, elements);
    try std.testing.expectEqual(@as(u32, 8), statement.stmt0.n);
    try std.testing.expectEqual(@as(u32, 7), statement.stmt0.m);
    try verifyStatement(statement, elements);

    var bad = statement;
    bad.stmt1.y_axis_claimed_sum = bad.stmt1.y_axis_claimed_sum.add(QM31.one());
    try std.testing.expectError(Error.StatementNotSatisfied, verifyStatement(bad, elements));
}

test "examples state_machine: prove/verify wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    const output = try prove(
        std.testing.allocator,
        config,
        5,
        .{
            M31.fromCanonical(9),
            M31.fromCanonical(3),
        },
    );
    try verify(
        std.testing.allocator,
        config,
        output.statement,
        output.proof,
    );
}

test "examples state_machine: prove_ex wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var output = try proveEx(
        std.testing.allocator,
        config,
        5,
        .{
            M31.fromCanonical(9),
            M31.fromCanonical(3),
        },
        false,
    );
    defer output.proof.aux.deinit(std.testing.allocator);
    try verify(
        std.testing.allocator,
        config,
        output.statement,
        output.proof.proof,
    );
}

test "examples state_machine: prove and prove_ex wrappers emit identical proof bytes" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    var output_prove = try prove(
        alloc,
        config,
        5,
        .{
            M31.fromCanonical(14),
            M31.fromCanonical(6),
        },
    );
    defer output_prove.proof.deinit(alloc);

    var output_prove_ex = try proveEx(
        alloc,
        config,
        5,
        .{
            M31.fromCanonical(14),
            M31.fromCanonical(6),
        },
        false,
    );
    defer output_prove_ex.proof.aux.deinit(alloc);
    defer output_prove_ex.proof.proof.deinit(alloc);

    const proof_wire = @import("../interop/proof_wire.zig");
    const prove_bytes = try proof_wire.encodeProofBytes(alloc, output_prove.proof);
    defer alloc.free(prove_bytes);
    const prove_ex_bytes = try proof_wire.encodeProofBytes(alloc, output_prove_ex.proof.proof);
    defer alloc.free(prove_ex_bytes);

    try std.testing.expectEqualSlices(u8, prove_bytes, prove_ex_bytes);
}

test "examples state_machine: verify wrapper rejects tampered statement" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    const output = try prove(
        std.testing.allocator,
        config,
        5,
        .{
            M31.fromCanonical(14),
            M31.fromCanonical(6),
        },
    );
    var bad_statement = output.statement;
    bad_statement.stmt1.x_axis_claimed_sum = bad_statement.stmt1.x_axis_claimed_sum.add(QM31.one());

    try std.testing.expectError(
        Error.StatementNotSatisfied,
        verify(
            std.testing.allocator,
            config,
            bad_statement,
            output.proof,
        ),
    );
}
