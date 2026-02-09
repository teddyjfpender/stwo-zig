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

pub const Statement = struct {
    log_n_rows: u32,
};

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = struct {
    statement: Statement,
    proof: ExtendedProof,
};

pub const Trace = struct {
    preprocessed: [4][]M31,
    main: [4][]M31,
};

pub const Error = error{
    InvalidLogSize,
    InvalidProofShape,
};

pub fn genTrace(
    allocator: std.mem.Allocator,
    statement: Statement,
) (std.mem.Allocator.Error || Error)!Trace {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) return Error.InvalidLogSize;
    const n = checkedPow2(statement.log_n_rows) catch return Error.InvalidLogSize;

    var preprocessed = try allocColumnSet(allocator, n);
    errdefer freeColumnSet(allocator, preprocessed);
    var main = try allocColumnSet(allocator, n);
    errdefer freeColumnSet(allocator, main);

    var fib = try allocator.alloc(M31, n + 2);
    defer allocator.free(fib);
    fib[0] = M31.one();
    fib[1] = M31.one();
    for (2..fib.len) |i| {
        fib[i] = fib[i - 1].add(fib[i - 2]);
    }

    for (0..n) |i| {
        preprocessed[0][i] = M31.fromU64(i);
        preprocessed[1][i] = M31.fromU64(i + 1);
        preprocessed[2][i] = M31.fromU64(i + 2);
        preprocessed[3][i] = M31.one();

        main[0][i] = M31.one();
        main[1][i] = fib[i];
        main[2][i] = fib[i + 1];
        main[3][i] = fib[i + 2];
    }

    if (n >= 2) {
        main[0][n - 1] = M31.zero();
        main[0][n - 2] = M31.one();
    }

    return .{ .preprocessed = preprocessed, .main = main };
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: *Trace) void {
    freeColumnSet(allocator, trace.preprocessed);
    freeColumnSet(allocator, trace.main);
    trace.* = undefined;
}

pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
) anyerror!ProveOutput {
    var output = try proveEx(allocator, pcs_config, statement, false);
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn proveEx(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) return Error.InvalidLogSize;

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var scheme = try prover_pcs.CommitmentSchemeProver(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );

    const trace = try genTrace(allocator, statement);
    var preprocessed_moved = false;
    var main_moved = false;
    defer {
        if (!preprocessed_moved) freeColumnSet(allocator, trace.preprocessed);
        if (!main_moved) freeColumnSet(allocator, trace.main);
    }

    const preprocessed_owned = try allocator.alloc(prover_pcs.ColumnEvaluation, trace.preprocessed.len);
    errdefer allocator.free(preprocessed_owned);
    for (trace.preprocessed, 0..) |col, i| {
        preprocessed_owned[i] = .{
            .log_size = statement.log_n_rows,
            .values = col,
        };
    }
    preprocessed_moved = true;
    try scheme.commitOwned(allocator, preprocessed_owned, &channel);

    const main_owned = try allocator.alloc(prover_pcs.ColumnEvaluation, trace.main.len);
    errdefer allocator.free(main_owned);
    for (trace.main, 0..) |col, i| {
        main_owned[i] = .{
            .log_size = statement.log_n_rows,
            .values = col,
        };
    }
    main_moved = true;
    try scheme.commitOwned(allocator, main_owned, &channel);

    mixStatement(&channel, statement);

    const component = PlonkComponent{ .statement = statement };
    const components = [_]prover_component.ComponentProver{component.asProverComponent()};

    const proof = try prover_prove.proveEx(
        Hasher,
        MerkleChannel,
        allocator,
        components[0..],
        &channel,
        scheme,
        include_all_preprocessed_columns,
    );

    return .{ .statement = statement, .proof = proof };
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31) {
        var p = proof_in;
        p.deinit(allocator);
        return Error.InvalidLogSize;
    }
    if (proof_in.commitment_scheme_proof.commitments.items.len < 2) {
        var p = proof_in;
        p.deinit(allocator);
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
        &[_]u32{
            statement.log_n_rows,
            statement.log_n_rows,
            statement.log_n_rows,
            statement.log_n_rows,
        },
        &channel,
    );
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &[_]u32{
            statement.log_n_rows,
            statement.log_n_rows,
            statement.log_n_rows,
            statement.log_n_rows,
        },
        &channel,
    );

    mixStatement(&channel, statement);

    const component = PlonkComponent{ .statement = statement };
    const verifier_components = [_]core_air_components.Component{component.asVerifierComponent()};

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

const PlonkComponent = struct {
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
        const preprocessed = try allocator.dupe(u32, &[_]u32{
            self.statement.log_n_rows,
            self.statement.log_n_rows,
            self.statement.log_n_rows,
            self.statement.log_n_rows,
        });
        const main = try allocator.dupe(u32, &[_]u32{
            self.statement.log_n_rows,
            self.statement.log_n_rows,
            self.statement.log_n_rows,
            self.statement.log_n_rows,
        });
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
        );
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        _: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed_cols = try allocMaskCols(allocator, 4, point);
        const main_cols = try allocMaskCols(allocator, 4, point);
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
        return allocator.dupe(usize, &[_]usize{ 0, 1, 2, 3 });
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
        M31.fromCanonical(statement.log_n_rows),
        M31.fromCanonical(4),
        M31.fromCanonical(1),
        M31.one(),
    );
}

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&[_]u32{statement.log_n_rows});
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn allocColumnSet(allocator: std.mem.Allocator, n: usize) ![4][]M31 {
    var cols: [4][]M31 = undefined;
    var init_count: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < init_count) : (i += 1) allocator.free(cols[i]);
    }
    for (&cols) |*col| {
        col.* = try allocator.alloc(M31, n);
        @memset(col.*, M31.zero());
        init_count += 1;
    }
    return cols;
}

fn freeColumnSet(allocator: std.mem.Allocator, cols: [4][]M31) void {
    for (cols) |col| allocator.free(col);
}

fn allocMaskCols(
    allocator: std.mem.Allocator,
    n_cols: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const cols = try allocator.alloc([]CirclePointQM31, n_cols);

    var init_count: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < init_count) : (i += 1) allocator.free(cols[i]);
        allocator.free(cols);
    }

    for (cols) |*col| {
        col.* = try allocator.alloc(CirclePointQM31, 1);
        col.*[0] = point;
        init_count += 1;
    }
    return cols;
}

test "examples plonk: trace generation" {
    const alloc = std.testing.allocator;
    const statement: Statement = .{ .log_n_rows = 5 };
    var trace = try genTrace(alloc, statement);
    defer deinitTrace(alloc, &trace);

    try std.testing.expectEqual(@as(usize, 32), trace.preprocessed[0].len);
    try std.testing.expectEqual(@as(usize, 32), trace.main[0].len);
    try std.testing.expect(trace.main[1][0].eql(M31.one()));
    try std.testing.expect(trace.main[2][0].eql(M31.one()));
    try std.testing.expect(trace.main[3][0].eql(M31.fromCanonical(2)));
}

test "examples plonk: prove/verify wrapper roundtrip" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_rows = 5 };

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

test "examples plonk: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_rows = 5 };
    const output = try prove(std.testing.allocator, config, statement);

    var bad_statement = output.statement;
    bad_statement.log_n_rows += 1;

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
