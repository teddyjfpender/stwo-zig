const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const core_air_utils = @import("stwo_core").air.utils;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const m31 = @import("stwo_core").fields.m31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const prover_engine = @import("stwo_prover_impl").engine;
const prover_pcs = @import("stwo_prover_impl").pcs;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const prover_transaction = @import("common/prover_transaction.zig");
const component_mod = @import("wide_fibonacci/component.zig");
const trace_input = @import("wide_fibonacci/trace.zig");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

const M31 = m31.M31;
const WideFibonacciComponent = component_mod.Component;

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

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = prover_transaction.Output(Statement, ExtendedProof);

pub const PreparedInput = trace_input.PreparedInput;

pub const Error = trace_input.Error || error{
    InvalidProofShape,
};

/// Generates a wide-fibonacci trace in bit-reversed circle-domain order.
///
/// For each row `i`, the sequence starts at `(a, b) = (1, i)` and evolves via
/// `c = a^2 + b^2`.
pub const genTrace = trace_input.generate;
pub const deinitTrace = trace_input.deinit;
pub const prepareInput = trace_input.prepare;

pub fn prepareInputForBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    statement: Statement,
) anyerror!PreparedInput {
    return trace_input.prepareForBackend(Backend, allocator, statement);
}

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
    var prove_ex_output = try proveExWithEngine(
        Engine,
        allocator,
        pcs_config,
        statement,
        false,
        recorder,
    );
    const proof = prove_ex_output.proof.proof;
    prove_ex_output.proof.aux.deinit(allocator);
    return .{
        .statement = prove_ex_output.statement,
        .proof = proof,
    };
}

pub fn proveExWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return proveExImpl(
        Engine,
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        recorder,
    );
}

/// Proves a pre-generated trace and consumes `prepared` on success or failure.
pub fn provePreparedWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var prove_ex_output = try provePreparedExImpl(
        Engine,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        false,
        recorder,
    );
    const proof = prove_ex_output.proof.proof;
    prove_ex_output.proof.aux.deinit(allocator);
    return .{ .statement = prove_ex_output.statement, .proof = proof };
}

/// Extended proof route for a pre-generated trace. Consumes `prepared`.
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

/// Proves a pre-generated trace with immutable resources borrowed from
/// `session`. The session must outlive the complete proving transaction.
pub fn provePreparedWithSessionAndEngine(
    comptime Engine: type,
    session: *const Engine.Session,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var prove_ex_output = try provePreparedExImpl(
        Engine,
        true,
        session,
        allocator,
        pcs_config,
        prepared,
        false,
        recorder,
    );
    const proof = prove_ex_output.proof.proof;
    prove_ex_output.proof.aux.deinit(allocator);
    return .{ .statement = prove_ex_output.statement, .proof = proof };
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

fn proveExImpl(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    const prepared = blk: {
        var trace_generation_stage = try stage_profile.StageScope.begin(
            recorder,
            "trace_generation",
            "Trace generation",
        );
        defer trace_generation_stage.end();
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

fn provePreparedExImpl(
    comptime Engine: type,
    comptime use_session: bool,
    session: if (use_session) *const Engine.Session else void,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared_input: PreparedInput,
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
        prepared_input,
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
    const composition_log = std.math.add(u32, statement.log_n_rows, 1) catch
        return Error.InvalidLogSize;
    const commitment_log = std.math.add(
        u32,
        statement.log_n_rows,
        pcs_config.fri_config.log_blowup_factor,
    ) catch return Error.InvalidLogSize;
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
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogSize;
    }
    if (statement.sequence_len < 2) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidSequenceLength;
    }
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

    const n_cols: usize = @intCast(statement.sequence_len);
    const main_log_sizes = try allocator.alloc(u32, n_cols);
    defer allocator.free(main_log_sizes);
    @memset(main_log_sizes, statement.log_n_rows);

    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        main_log_sizes,
        &channel,
    );

    mixStatement(&channel, statement);

    const component = WideFibonacciComponent{
        .statement = statement,
    };
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

const ProvingSpec = struct {
    pub const Statement = trace_input.Statement;
    pub const PreparedInput = trace_input.PreparedInput;
    pub const max_components: usize = 1;

    pub const ProverContext = struct {
        statement_value: trace_input.Statement,
        component: WideFibonacciComponent,
    };

    pub fn validateRequest(request: trace_input.Statement) Error!void {
        if (request.log_n_rows == 0 or request.log_n_rows >= 31)
            return error.InvalidLogSize;
        if (request.sequence_len < 2) return error.InvalidSequenceLength;
    }

    pub fn validatePrepared(prepared: *const trace_input.PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        if (preprocessed.len != 0) return error.InvalidPreparedGeometry;
        if (main.len != @as(usize, prepared.request.sequence_len))
            return error.InvalidSequenceLength;
        for (main) |column| {
            if (column.log_size != prepared.request.log_n_rows)
                return error.InvalidPreparedGeometry;
        }
    }

    pub fn compositionLog(request: trace_input.Statement) Error!u32 {
        return std.math.add(u32, request.log_n_rows, 1) catch
            return error.InvalidLogSize;
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

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&[_]u32{ statement.log_n_rows, statement.sequence_len });
}

test "examples wide_fibonacci: trace generation follows recurrence" {
    const alloc = std.testing.allocator;
    const statement: Statement = .{
        .log_n_rows = 4,
        .sequence_len = 8,
    };

    const trace = try genTrace(alloc, statement);
    defer deinitTrace(alloc, trace);

    try std.testing.expectEqual(@as(usize, 8), trace.len);
    for (trace) |col| try std.testing.expectEqual(@as(usize, 16), col.len);

    const row_index: usize = 5;
    const bit_rev = try core_air_utils.circleBitReversedIndex(statement.log_n_rows, row_index);

    var a = M31.one();
    var b = M31.fromCanonical(@intCast(row_index));
    try std.testing.expect(trace[0][bit_rev].eql(a));
    try std.testing.expect(trace[1][bit_rev].eql(b));

    var col_idx: usize = 2;
    while (col_idx < trace.len) : (col_idx += 1) {
        const c = a.square().add(b.square());
        try std.testing.expect(trace[col_idx][bit_rev].eql(c));
        a = b;
        b = c;
    }
}

test "examples wide_fibonacci: generic CPU engine owns the proving transaction" {
    const CountingEngine = struct {
        pub const Scheme = CpuProverEngine.Scheme;
        pub const Channel = CpuProverEngine.Channel;
        pub const ExtendedProof = CpuProverEngine.ExtendedProof;
        var init_calls: usize = 0;
        var commit_calls: usize = 0;
        var prove_calls: usize = 0;

        pub fn init(allocator: std.mem.Allocator, config: pcs_core.PcsConfig) !Scheme {
            init_calls += 1;
            return CpuProverEngine.init(allocator, config);
        }

        pub fn deinit(scheme: *Scheme, allocator: std.mem.Allocator) void {
            CpuProverEngine.deinit(scheme, allocator);
        }

        pub fn commit(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []prover_pcs.ColumnEvaluation,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            commit_calls += 1;
            return CpuProverEngine.commit(scheme, allocator, columns, recorder, channel);
        }

        pub fn commitWithBacking(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []prover_pcs.ColumnEvaluation,
            backing_buffers: ?[][]M31,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            commit_calls += 1;
            return CpuProverEngine.commitWithBacking(
                scheme,
                allocator,
                columns,
                backing_buffers,
                recorder,
                channel,
            );
        }

        pub fn commitPreparedWithBacking(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []prover_pcs.ColumnEvaluation,
            backing_buffers: ?[][]M31,
            source: prover_pcs.ColumnSource,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            commit_calls += 1;
            return CpuProverEngine.commitPreparedWithBacking(
                scheme,
                allocator,
                columns,
                backing_buffers,
                source,
                recorder,
                channel,
            );
        }

        pub fn prove(
            allocator: std.mem.Allocator,
            components: []const prover_component.ComponentProver,
            channel: anytype,
            scheme: Scheme,
            options: prover_engine.ProveOptions,
        ) !CpuProverEngine.ExtendedProof {
            prove_calls += 1;
            return CpuProverEngine.prove(allocator, components, channel, scheme, options);
        }
    };

    CountingEngine.init_calls = 0;
    CountingEngine.commit_calls = 0;
    CountingEngine.prove_calls = 0;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement = Statement{ .log_n_rows = 5, .sequence_len = 8 };
    const output = try proveWithEngine(
        CountingEngine,
        std.testing.allocator,
        config,
        statement,
        null,
    );

    try std.testing.expectEqual(@as(usize, 1), CountingEngine.init_calls);
    try std.testing.expectEqual(@as(usize, 2), CountingEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 1), CountingEngine.prove_calls);
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples wide_fibonacci: prepared CPU backend route verifies" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement = Statement{ .log_n_rows = 5, .sequence_len = 8 };
    const prepared = try prepareInput(std.testing.allocator, statement);
    const output = try provePreparedWithEngine(
        ProverEngineForBackend(CpuBackend),
        std.testing.allocator,
        config,
        prepared,
        null,
    );
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples wide_fibonacci: corrupted recurrence trace is rejected" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement = Statement{ .log_n_rows = 5, .sequence_len = 8 };
    const prepared = try prepareInput(std.testing.allocator, statement);
    const main = prepared.trace.main.columns.?;
    const corrupted = @constCast(main[2].values);
    corrupted[0] = corrupted[0].add(M31.one());

    if (provePreparedWithEngine(
        ProverEngineForBackend(CpuBackend),
        std.testing.allocator,
        config,
        prepared,
        null,
    )) |output| {
        var proof = output.proof;
        proof.deinit(std.testing.allocator);
        try std.testing.expect(false);
    } else |err| {
        try std.testing.expectEqual(
            @import("stwo_prover_impl").prove.ProvingError.ConstraintsNotSatisfied,
            err,
        );
    }
}

test "examples wide_fibonacci: prove/verify wrapper roundtrip" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    const statement: Statement = .{
        .log_n_rows = 5,
        .sequence_len = 16,
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

test "examples wide_fibonacci: coefficient fallback verifies with two-bit blowup" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 2, 3),
    };
    const output = try prove(
        std.testing.allocator,
        config,
        .{ .log_n_rows = 5, .sequence_len = 8 },
    );
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples wide_fibonacci: two-column trace has zero constraints" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const output = try prove(
        std.testing.allocator,
        config,
        .{ .log_n_rows = 5, .sequence_len = 2 },
    );
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples wide_fibonacci: traces narrower than two columns are rejected" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    try std.testing.expectError(
        error.InvalidSequenceLength,
        prove(
            std.testing.allocator,
            config,
            .{ .log_n_rows = 5, .sequence_len = 0 },
        ),
    );
    try std.testing.expectError(
        error.InvalidSequenceLength,
        prove(
            std.testing.allocator,
            config,
            .{ .log_n_rows = 5, .sequence_len = 1 },
        ),
    );
}

test "examples wide_fibonacci: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };

    const statement: Statement = .{
        .log_n_rows = 5,
        .sequence_len = 16,
    };
    const output = try prove(std.testing.allocator, config, statement);

    var bad_statement = output.statement;
    bad_statement.sequence_len += 1;

    if (verify(std.testing.allocator, config, bad_statement, output.proof)) |_| {
        try std.testing.expect(false);
    } else |err| {
        const verification_error = @import("stwo_core").verifier_types.VerificationError;
        try std.testing.expect(
            err == verification_error.OodsNotMatching or
                err == verification_error.InvalidStructure or
                err == verification_error.ShapeMismatch or
                err == verification_error.ColumnIndexOutOfBounds or
                err == Error.InvalidProofShape,
        );
    }
}
