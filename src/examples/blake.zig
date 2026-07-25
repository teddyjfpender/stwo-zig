const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_air_accumulation = @import("stwo_prover_impl").air.accumulation;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const prover_engine = @import("stwo_prover_impl").engine;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const secure_column = @import("stwo_prover_impl").secure_column;
const prover_transaction = @import("common/prover_transaction.zig");
const trace_input = @import("blake/input.zig");
const CpuBackend = @import("../backends/cpu_scalar/mod.zig").CpuBackend;

pub const constants = @import("blake/constants.zig");
pub const exact_input = @import("blake/exact_input.zig");
pub const geometry = @import("blake/geometry.zig");
pub const round_trace = @import("blake/round_trace.zig");
pub const scheduler_trace = @import("blake/scheduler_trace.zig");
pub const xor_tables = @import("blake/xor_tables.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = @import("stwo_core").circle.CirclePointQM31;

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

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

comptime {
    prover_engine.assertProverEngine(CpuProverEngine);
}

pub const Statement = trace_input.Statement;
pub const PreparedInput = trace_input.PreparedInput;
pub const prepareInput = trace_input.prepare;
pub const genTrace = trace_input.genTrace;
pub const deinitTrace = trace_input.deinitTrace;
const validateStatement = trace_input.validate;
const nColumns = trace_input.nColumns;

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = prover_transaction.Output(Statement, ExtendedProof);

pub const Error = trace_input.Error || error{
    InvalidProofShape,
};

pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
) anyerror!ProveOutput {
    return proveWithEngine(CpuProverEngine, allocator, pcs_config, statement, null);
}

pub fn proveEx(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        null,
    );
}

pub fn proveProfiled(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    recorder: *stage_profile.Recorder,
) anyerror!ProveOutput {
    return proveWithEngine(CpuProverEngine, allocator, pcs_config, statement, recorder);
}

pub fn proveExProfiled(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: *stage_profile.Recorder,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        recorder,
    );
}

pub fn proveWithBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    return proveWithEngine(
        ProverEngineForBackend(Backend),
        allocator,
        pcs_config,
        statement,
        recorder,
    );
}

pub fn proveExWithBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        ProverEngineForBackend(Backend),
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        recorder,
    );
}

pub fn proveWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var output = try proveExWithEngine(
        Engine,
        allocator,
        pcs_config,
        statement,
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
    statement: Statement,
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
        break :blk try prepareInput(allocator, statement);
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

/// Proves a prepared Blake trace and consumes it on success or failure.
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
    statement: Statement,
    pcs_config: pcs_core.PcsConfig,
) Error!u32 {
    try trace_input.validate(statement);
    const composition_log = std.math.add(u32, statement.log_n_rows, 1) catch
        return error.InvalidLogNRows;
    const commitment_log = std.math.add(
        u32,
        statement.log_n_rows,
        pcs_config.fri_config.log_blowup_factor,
    ) catch return error.InvalidLogNRows;
    return @max(
        @max(composition_log, commitment_log),
        pcs_config.lifting_log_size orelse 0,
    );
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    validateStatement(statement) catch {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogNRows;
    };
    const n_columns = nColumns(statement) catch {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.ColumnCountOverflow;
    };
    if (proof_in.commitment_scheme_proof.commitments.items.len < 2) {
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

    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{},
        &channel,
    );
    const main_log_sizes = try allocator.alloc(u32, n_columns);
    defer allocator.free(main_log_sizes);
    @memset(main_log_sizes, statement.log_n_rows);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        main_log_sizes,
        &channel,
    );

    mixStatement(&channel, statement);

    const component = BlakeComponent{ .statement = statement };
    const verifier_components = [_]core_air_components.Component{
        component.asVerifierComponent(),
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

const BlakeComponent = struct {
    statement: Statement,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return 1;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.statement.log_n_rows + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const n_columns_local = try nColumns(self.statement);
        const preprocessed = try allocator.alloc(u32, 0);
        const main = try allocator.alloc(u32, n_columns_local);
        @memset(main, self.statement.log_n_rows);

        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{
                preprocessed,
                main,
            }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        _: u32,
    ) !core_air_components.MaskPoints {
        const n_columns_local = try nColumns(self.statement);
        const preprocessed_cols = try allocator.alloc([]CirclePointQM31, 0);

        const main_cols = try allocator.alloc([]CirclePointQM31, n_columns_local);
        errdefer {
            for (main_cols) |col| allocator.free(col);
            allocator.free(main_cols);
        }
        for (main_cols) |*col| {
            col.* = try allocator.alloc(CirclePointQM31, 1);
            col.*[0] = point;
        }

        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
                preprocessed_cols,
                main_cols,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        _: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.alloc(usize, 0);
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        _: CirclePointQM31,
        _: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {
        evaluation_accumulator.accumulate(compositionEval(self.statement));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        _: *const prover_component.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const composition_eval = compositionEval(self.statement);
        const domain_size = @as(usize, 1) << @intCast(self.statement.log_n_rows + 1);
        const values = try evaluation_accumulator.allocator.alloc(QM31, domain_size);
        defer evaluation_accumulator.allocator.free(values);
        @memset(values, composition_eval);

        var col = try secure_column.SecureColumnByCoords.fromSecureSlice(
            evaluation_accumulator.allocator,
            values,
        );
        defer col.deinit(evaluation_accumulator.allocator);
        try evaluation_accumulator.accumulateColumn(self.statement.log_n_rows + 1, &col);
    }
};

const ProvingSpec = struct {
    pub const Statement = trace_input.Statement;
    pub const PreparedInput = trace_input.PreparedInput;
    pub const max_components: usize = 1;

    pub const ProverContext = struct {
        statement_value: trace_input.Statement,
        component: BlakeComponent,
    };

    pub fn validateRequest(request: trace_input.Statement) Error!void {
        try trace_input.validate(request);
    }

    pub fn validatePrepared(prepared: *const trace_input.PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        if (preprocessed.len != 0 or main.len != try nColumns(prepared.request))
            return error.InvalidPreparedGeometry;
        for (main) |column| {
            if (column.log_size != prepared.request.log_n_rows)
                return error.InvalidPreparedGeometry;
        }
    }

    pub fn compositionLog(request: trace_input.Statement) Error!u32 {
        return std.math.add(u32, request.log_n_rows, 1) catch
            return error.InvalidLogNRows;
    }

    pub fn initProverContext(
        out: *ProverContext,
        channel: *Channel,
        request: trace_input.Statement,
    ) !void {
        mixStatement(channel, request);
        out.* = .{
            .statement_value = request,
            .component = .{ .statement = request },
        };
    }

    pub fn statement(context: *const ProverContext) trace_input.Statement {
        return context.statement_value;
    }

    pub fn proverComponents(
        context: *const ProverContext,
        out: []prover_component.ComponentProver,
    ) ![]const prover_component.ComponentProver {
        if (out.len < max_components) return error.InvalidProofShape;
        out[0] = context.component.asProverComponent();
        return out[0..1];
    }
};

fn compositionEval(statement: Statement) QM31 {
    return QM31.fromM31(
        M31.fromCanonical(statement.log_n_rows),
        M31.fromCanonical(statement.n_rounds),
        M31.fromCanonical(@intCast(nColumns(statement) catch 0)),
        M31.one(),
    );
}

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&[_]u32{
        statement.log_n_rows,
        statement.n_rounds,
    });
}

test "examples blake: prove/verify wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_n_rows = 5,
        .n_rounds = 10,
    };

    const output = try prove(std.testing.allocator, config, statement);
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples blake: prove_ex wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_n_rows = 5,
        .n_rounds = 10,
    };

    var output = try proveEx(std.testing.allocator, config, statement, false);
    defer output.proof.aux.deinit(std.testing.allocator);
    try verify(std.testing.allocator, config, output.statement, output.proof.proof);
}

test "examples blake: prove and prove_ex wrappers emit identical proof bytes" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_n_rows = 5,
        .n_rounds = 10,
    };

    var output_prove = try prove(alloc, config, statement);
    defer output_prove.proof.deinit(alloc);

    var output_prove_ex = try proveEx(alloc, config, statement, false);
    defer output_prove_ex.proof.aux.deinit(alloc);
    defer output_prove_ex.proof.proof.deinit(alloc);

    const proof_wire = @import("../interop/proof_wire.zig");
    const prove_bytes = try proof_wire.encodeProofBytes(alloc, output_prove.proof);
    defer alloc.free(prove_bytes);
    const prove_ex_bytes = try proof_wire.encodeProofBytes(alloc, output_prove_ex.proof.proof);
    defer alloc.free(prove_ex_bytes);

    try std.testing.expectEqualSlices(u8, prove_bytes, prove_ex_bytes);
}

test "examples blake: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_n_rows = 5,
        .n_rounds = 10,
    };
    const output = try prove(std.testing.allocator, config, statement);

    var bad_statement = output.statement;
    bad_statement.n_rounds += 1;

    if (verify(std.testing.allocator, config, bad_statement, output.proof)) |_| {
        try std.testing.expect(false);
    } else |err| {
        const verification_error = @import("stwo_core").verifier_types.VerificationError;
        try std.testing.expect(
            err == verification_error.OodsNotMatching or
                err == verification_error.InvalidStructure or
                err == verification_error.ShapeMismatch,
        );
    }
}
