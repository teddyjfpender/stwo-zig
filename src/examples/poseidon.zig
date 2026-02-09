const std = @import("std");
const core_air_accumulation = @import("../core/air/accumulation.zig");
const core_air_components = @import("../core/air/components.zig");
const core_air_derive = @import("../core/air/derive.zig");
const channel_blake2s = @import("../core/channel/blake2s.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const pcs_core = @import("../core/pcs/mod.zig");
const pcs_verifier = @import("../core/pcs/verifier.zig");
const core_proof = @import("../core/proof.zig");
const core_verifier = @import("../core/verifier.zig");
const blake2_merkle = @import("../core/vcs_lifted/blake2_merkle.zig");
const prover_air_accumulation = @import("../prover/air/accumulation.zig");
const prover_component = @import("../prover/air/component_prover.zig");
const prover_pcs = @import("../prover/pcs/mod.zig");
const prover_prove = @import("../prover/prove.zig");
const secure_column = @import("../prover/secure_column.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = @import("../core/circle.zig").CirclePointQM31;

pub const Hasher = blake2_merkle.Blake2sMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);

const N_LOG_INSTANCES_PER_ROW: u32 = 3;
const N_INSTANCES_PER_ROW: usize = 1 << N_LOG_INSTANCES_PER_ROW;
const N_STATE: usize = 16;
const N_PARTIAL_ROUNDS: usize = 14;
const N_HALF_FULL_ROUNDS: usize = 4;
const N_FULL_ROUNDS: usize = N_HALF_FULL_ROUNDS * 2;
const N_COLUMNS_PER_REP: usize = N_STATE * (1 + N_FULL_ROUNDS) + N_PARTIAL_ROUNDS;
const N_COLUMNS: usize = N_COLUMNS_PER_REP * N_INSTANCES_PER_ROW;

pub const Statement = struct {
    log_n_instances: u32,
};

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = struct {
    statement: Statement,
    proof: ExtendedProof,
};

pub const Error = error{
    InvalidLogNInstances,
    InvalidProofShape,
};

pub fn genTrace(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)![][]M31 {
    const log_n_rows = try logNRows(statement);
    const n = checkedPow2(log_n_rows) catch return Error.InvalidLogNInstances;

    const trace = try allocator.alloc([]M31, N_COLUMNS);
    errdefer allocator.free(trace);

    var initialized: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized) : (i += 1) {
            allocator.free(trace[i]);
        }
    }

    for (trace) |*col| {
        col.* = try allocator.alloc(M31, n);
        @memset(col.*, M31.zero());
        initialized += 1;
    }

    for (0..n) |row| {
        var col_index: usize = 0;
        for (0..N_INSTANCES_PER_ROW) |rep_i| {
            var state: [N_STATE]M31 = undefined;
            for (0..N_STATE) |state_i| {
                state[state_i] = M31.fromU64(@as(u64, @intCast(row * N_STATE + state_i + rep_i)));
                trace[col_index][row] = state[state_i];
                col_index += 1;
            }

            for (0..N_HALF_FULL_ROUNDS) |round| {
                for (0..N_STATE) |state_i| {
                    state[state_i] = state[state_i].add(externalRoundConst(round, state_i));
                }
                applyExternalRoundMatrix(&state);
                for (0..N_STATE) |state_i| {
                    state[state_i] = pow5(state[state_i]);
                    trace[col_index][row] = state[state_i];
                    col_index += 1;
                }
            }

            for (0..N_PARTIAL_ROUNDS) |round| {
                state[0] = state[0].add(internalRoundConst(round));
                applyInternalRoundMatrix(&state);
                state[0] = pow5(state[0]);
                trace[col_index][row] = state[0];
                col_index += 1;
            }

            for (0..N_HALF_FULL_ROUNDS) |half_round| {
                const round = half_round + N_HALF_FULL_ROUNDS;
                for (0..N_STATE) |state_i| {
                    state[state_i] = state[state_i].add(externalRoundConst(round, state_i));
                }
                applyExternalRoundMatrix(&state);
                for (0..N_STATE) |state_i| {
                    state[state_i] = pow5(state[state_i]);
                    trace[col_index][row] = state[state_i];
                    col_index += 1;
                }
            }
        }
        std.debug.assert(col_index == N_COLUMNS);
    }

    return trace;
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: [][]M31) void {
    for (trace) |col| allocator.free(col);
    allocator.free(trace);
}

pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
) anyerror!ProveOutput {
    var prove_ex_output = try proveEx(allocator, pcs_config, statement, false);
    const proof = prove_ex_output.proof.proof;
    prove_ex_output.proof.aux.deinit(allocator);
    return .{
        .statement = prove_ex_output.statement,
        .proof = proof,
    };
}

pub fn proveEx(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    const log_n_rows = try logNRows(statement);

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var scheme = try prover_pcs.CommitmentSchemeProver(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );

    const preprocessed = [_]prover_pcs.ColumnEvaluation{};
    try scheme.commit(allocator, preprocessed[0..], &channel);

    const trace = try genTrace(allocator, statement);
    var trace_moved = false;
    defer if (!trace_moved) deinitTrace(allocator, trace);

    const owned_columns = try allocator.alloc(prover_pcs.ColumnEvaluation, N_COLUMNS);
    errdefer allocator.free(owned_columns);
    for (trace, 0..) |col, i| {
        owned_columns[i] = .{
            .log_size = log_n_rows,
            .values = col,
        };
    }
    allocator.free(trace);
    trace_moved = true;
    try scheme.commitOwned(allocator, owned_columns, &channel);

    mixStatement(&channel, statement);

    const component = PoseidonComponent{ .statement = statement };
    const components = [_]prover_component.ComponentProver{
        component.asProverComponent(),
    };

    const proof = try prover_prove.proveEx(
        Hasher,
        MerkleChannel,
        allocator,
        components[0..],
        &channel,
        scheme,
        include_all_preprocessed_columns,
    );
    return .{
        .statement = statement,
        .proof = proof,
    };
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    const log_n_rows = logNRows(statement) catch {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogNInstances;
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

    const main_log_sizes = try allocator.alloc(u32, N_COLUMNS);
    defer allocator.free(main_log_sizes);
    @memset(main_log_sizes, log_n_rows);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        main_log_sizes,
        &channel,
    );

    mixStatement(&channel, statement);

    const component = PoseidonComponent{ .statement = statement };
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

const PoseidonComponent = struct {
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
        return (logNRows(self.statement) catch unreachable) + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        const main = try allocator.alloc(u32, N_COLUMNS);
        @memset(main, logNRows(self.statement) catch unreachable);

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
        _ = self;
        const preprocessed_cols = try allocator.alloc([]CirclePointQM31, 0);

        const main_cols = try allocator.alloc([]CirclePointQM31, N_COLUMNS);
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
        const log_n_rows = logNRows(self.statement) catch unreachable;
        const composition_eval = compositionEval(self.statement);
        const domain_size = @as(usize, 1) << @intCast(log_n_rows + 1);
        const values = try evaluation_accumulator.allocator.alloc(QM31, domain_size);
        defer evaluation_accumulator.allocator.free(values);
        @memset(values, composition_eval);

        var col = try secure_column.SecureColumnByCoords.fromSecureSlice(
            evaluation_accumulator.allocator,
            values,
        );
        defer col.deinit(evaluation_accumulator.allocator);
        try evaluation_accumulator.accumulateColumn(log_n_rows + 1, &col);
    }
};

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogNInstances;
    return @as(usize, 1) << @intCast(log_size);
}

fn logNRows(statement: Statement) Error!u32 {
    if (statement.log_n_instances < N_LOG_INSTANCES_PER_ROW) return Error.InvalidLogNInstances;
    const log_n_rows = statement.log_n_instances - N_LOG_INSTANCES_PER_ROW;
    if (log_n_rows >= 31) return Error.InvalidLogNInstances;
    return log_n_rows;
}

fn compositionEval(statement: Statement) QM31 {
    return QM31.fromM31(
        M31.fromCanonical(statement.log_n_instances),
        M31.fromCanonical(@intCast(N_COLUMNS_PER_REP)),
        M31.fromCanonical(@intCast(N_COLUMNS)),
        M31.one(),
    );
}

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&[_]u32{statement.log_n_instances});
}

fn pow5(x: M31) M31 {
    const x2 = x.mul(x);
    const x4 = x2.mul(x2);
    return x4.mul(x);
}

fn externalRoundConst(round: usize, state_i: usize) M31 {
    return M31.fromU64(1234 + (@as(u64, @intCast(round)) * 37) + @as(u64, @intCast(state_i)));
}

fn internalRoundConst(round: usize) M31 {
    return M31.fromU64(9876 + (@as(u64, @intCast(round)) * 17));
}

fn applyM4(x: [4]M31) [4]M31 {
    const t0 = x[0].add(x[1]);
    const t02 = t0.add(t0);
    const t1 = x[2].add(x[3]);
    const t12 = t1.add(t1);
    const t2 = x[1].add(x[1]).add(t1);
    const t3 = x[3].add(x[3]).add(t0);
    const t4 = t12.add(t12).add(t3);
    const t5 = t02.add(t02).add(t2);
    const t6 = t3.add(t5);
    const t7 = t2.add(t4);
    return .{ t6, t5, t7, t4 };
}

fn applyExternalRoundMatrix(state: *[N_STATE]M31) void {
    for (0..4) |i| {
        const offset = i * 4;
        const mixed = applyM4(.{
            state[offset + 0],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        });
        state[offset + 0] = mixed[0];
        state[offset + 1] = mixed[1];
        state[offset + 2] = mixed[2];
        state[offset + 3] = mixed[3];
    }

    for (0..4) |j| {
        const s = state[j].add(state[j + 4]).add(state[j + 8]).add(state[j + 12]);
        for (0..4) |i| {
            const idx = i * 4 + j;
            state[idx] = state[idx].add(s);
        }
    }
}

fn applyInternalRoundMatrix(state: *[N_STATE]M31) void {
    var sum = state[0];
    for (1..N_STATE) |i| {
        sum = sum.add(state[i]);
    }
    for (0..N_STATE) |i| {
        const coeff = M31.fromU64(@as(u64, 1) << @intCast(i + 1));
        state[i] = state[i].mul(coeff).add(sum);
    }
}

test "examples poseidon: prove/verify wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };

    const output = try prove(std.testing.allocator, config, statement);
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples poseidon: prove_ex wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };

    var output = try proveEx(std.testing.allocator, config, statement, false);
    defer output.proof.aux.deinit(std.testing.allocator);
    try verify(std.testing.allocator, config, output.statement, output.proof.proof);
}

test "examples poseidon: prove and prove_ex wrappers emit identical proof bytes" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };

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

test "examples poseidon: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };
    const output = try prove(std.testing.allocator, config, statement);

    var bad_statement = output.statement;
    bad_statement.log_n_instances += 1;

    if (verify(std.testing.allocator, config, bad_statement, output.proof)) |_| {
        try std.testing.expect(false);
    } else |err| {
        const verification_error = @import("../core/verifier_types.zig").VerificationError;
        try std.testing.expect(
            err == verification_error.OodsNotMatching or
                err == verification_error.InvalidStructure or
                err == verification_error.ShapeMismatch,
        );
    }
}
