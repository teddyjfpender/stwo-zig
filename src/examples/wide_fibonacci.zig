const std = @import("std");
const core_air_accumulation = @import("../core/air/accumulation.zig");
const core_air_components = @import("../core/air/components.zig");
const core_air_derive = @import("../core/air/derive.zig");
const core_air_utils = @import("../core/air/utils.zig");
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

pub const Statement = struct {
    log_n_rows: u32,
    sequence_len: u32,
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
    InvalidLogSize,
    InvalidSequenceLength,
    InvalidProofShape,
};

/// Generates a wide-fibonacci trace in bit-reversed circle-domain order.
///
/// For each row `i`, the sequence starts at `(a, b) = (1, i)` and evolves via
/// `c = a^2 + b^2`.
pub fn genTrace(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)![][]M31 {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) return Error.InvalidLogSize;
    if (statement.sequence_len < 2) return Error.InvalidSequenceLength;

    const n = checkedPow2(statement.log_n_rows) catch return Error.InvalidLogSize;
    const n_cols: usize = @intCast(statement.sequence_len);

    const trace = try allocator.alloc([]M31, n_cols);
    errdefer allocator.free(trace);

    var initialized: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized) : (i += 1) allocator.free(trace[i]);
    }

    for (trace) |*col| {
        col.* = try allocator.alloc(M31, n);
        @memset(col.*, M31.zero());
        initialized += 1;
    }

    for (0..n) |row| {
        const bit_rev = core_air_utils.circleBitReversedIndex(statement.log_n_rows, row) catch {
            return Error.InvalidLogSize;
        };

        var a = M31.one();
        var b = M31.fromCanonical(@intCast(row));
        trace[0][bit_rev] = a;
        trace[1][bit_rev] = b;

        var col_idx: usize = 2;
        while (col_idx < n_cols) : (col_idx += 1) {
            const c = a.square().add(b.square());
            trace[col_idx][bit_rev] = c;
            a = b;
            b = c;
        }
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
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) return Error.InvalidLogSize;
    if (statement.sequence_len < 2) return Error.InvalidSequenceLength;

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var scheme = try prover_pcs.CommitmentSchemeProver(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );

    const preprocessed = [_]prover_pcs.ColumnEvaluation{};
    try scheme.commit(allocator, preprocessed[0..], &channel);

    const trace = try genTrace(allocator, statement);
    defer deinitTrace(allocator, trace);

    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, trace.len);
    defer allocator.free(columns);
    for (trace, 0..) |col, i| {
        columns[i] = .{
            .log_size = statement.log_n_rows,
            .values = col,
        };
    }
    try scheme.commit(allocator, columns, &channel);

    mixStatement(&channel, statement);

    const component = WideFibonacciComponent{
        .statement = statement,
    };
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

const WideFibonacciComponent = struct {
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

    pub fn nConstraints(self: *const @This()) usize {
        _ = self;
        return 1;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.statement.log_n_rows + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        const main = try allocator.alloc(u32, @intCast(self.statement.sequence_len));
        @memset(main, self.statement.log_n_rows);

        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        _: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed_cols = try allocator.alloc([]CirclePointQM31, 0);

        const n_cols: usize = @intCast(self.statement.sequence_len);
        const main_cols = try allocator.alloc([]CirclePointQM31, n_cols);
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

fn compositionEval(statement: Statement) QM31 {
    return QM31.fromM31(
        M31.fromU64(statement.log_n_rows),
        M31.fromU64(statement.sequence_len),
        M31.zero(),
        M31.one(),
    );
}

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&[_]u32{ statement.log_n_rows, statement.sequence_len });
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
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

test "examples wide_fibonacci: prove/verify wrapper roundtrip" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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

test "examples wide_fibonacci: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        const verification_error = @import("../core/verifier_types.zig").VerificationError;
        try std.testing.expect(
            err == verification_error.OodsNotMatching or
                err == verification_error.InvalidStructure or
                err == verification_error.ShapeMismatch,
        );
    }
}
