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

const N_STATE: usize = 16;
const N_MESSAGE_WORDS: usize = 16;
const N_FELTS_IN_U32: usize = 2;
const N_ROUND_INPUT_FELTS: usize = (N_STATE + N_STATE + N_MESSAGE_WORDS) * N_FELTS_IN_U32;

pub const Statement = struct {
    log_n_rows: u32,
    n_rounds: u32,
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
    InvalidLogNRows,
    InvalidNRounds,
    InvalidProofShape,
    ColumnCountOverflow,
};

pub fn genTrace(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)![][]M31 {
    validateStatement(statement) catch |err| return err;
    const n = checkedPow2(statement.log_n_rows) catch return Error.InvalidLogNRows;
    const n_columns = nColumns(statement) catch return Error.ColumnCountOverflow;

    const trace = try allocator.alloc([]M31, n_columns);
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
        var seed: u64 = @as(u64, @intCast(row)) + 1;
        for (0..statement.n_rounds) |round| {
            for (0..N_ROUND_INPUT_FELTS) |cell| {
                seed = nextSeed(seed);
                const mixed = seed ^
                    (@as(u64, @intCast(round)) *% 0x9e37_79b9_7f4a_7c15) ^
                    (@as(u64, @intCast(cell + 1)) *% 0x517c_c1b7_2722_0a95);
                trace[col_index][row] = M31.fromU64(mixed);
                col_index += 1;
            }
        }
        std.debug.assert(col_index == n_columns);
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
    try validateStatement(statement);
    const n_columns = try nColumns(statement);

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

    const owned_columns = try allocator.alloc(prover_pcs.ColumnEvaluation, n_columns);
    errdefer allocator.free(owned_columns);
    for (trace, 0..) |col, i| {
        owned_columns[i] = .{
            .log_size = statement.log_n_rows,
            .values = col,
        };
    }
    allocator.free(trace);
    trace_moved = true;
    try scheme.commitOwned(allocator, owned_columns, &channel);

    mixStatement(&channel, statement);

    const component = BlakeComponent{ .statement = statement };
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

fn validateStatement(statement: Statement) Error!void {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) {
        return Error.InvalidLogNRows;
    }
    if (statement.n_rounds == 0) {
        return Error.InvalidNRounds;
    }
    _ = try nColumns(statement);
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogNRows;
    return @as(usize, 1) << @intCast(log_size);
}

fn nColumns(statement: Statement) Error!usize {
    return std.math.mul(usize, @as(usize, @intCast(statement.n_rounds)), N_ROUND_INPUT_FELTS) catch {
        return Error.ColumnCountOverflow;
    };
}

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

fn nextSeed(seed: u64) u64 {
    var x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

test "examples blake: prove/verify wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        const verification_error = @import("../core/verifier_types.zig").VerificationError;
        try std.testing.expect(
            err == verification_error.OodsNotMatching or
                err == verification_error.InvalidStructure or
                err == verification_error.ShapeMismatch,
        );
    }
}
