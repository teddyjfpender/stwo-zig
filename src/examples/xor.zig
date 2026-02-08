const std = @import("std");
const core_air_accumulation = @import("../core/air/accumulation.zig");
const core_air_components = @import("../core/air/components.zig");
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
const utils = @import("../core/utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = @import("../core/circle.zig").CirclePointQM31;
pub const Hasher = blake2_merkle.Blake2sMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);

pub const Error = error{
    InvalidLogSize,
    InvalidStep,
    InvalidProofShape,
};

/// Generates `IsFirst` preprocessed column values in bit-reversed order.
///
/// Semantics match upstream `examples/xor/gkr_lookups/mod.rs::IsFirst::gen_column_simd`.
pub fn genIsFirstColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
) (std.mem.Allocator.Error || Error)![]M31 {
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;
    const values = try allocator.alloc(M31, n);
    @memset(values, M31.zero());
    values[0] = M31.one();
    return values;
}

/// Generates `IsStepWithOffset` preprocessed column values in bit-reversed order.
///
/// Semantics match upstream `examples/xor/gkr_lookups/preprocessed_columns.rs`.
pub fn genIsStepWithOffsetColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
    log_step: u32,
    offset: usize,
) (std.mem.Allocator.Error || Error)![]M31 {
    if (log_step > log_size) return Error.InvalidStep;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;
    const step = checkedPow2(log_step) catch return Error.InvalidLogSize;

    const values = try allocator.alloc(M31, n);
    @memset(values, M31.zero());

    var i = offset % step;
    while (i < n) : (i += step) {
        const circle_domain_index = utils.cosetIndexToCircleDomainIndex(i, log_size);
        const bit_rev_index = utils.bitReverseIndex(circle_domain_index, log_size);
        values[bit_rev_index] = M31.one();
    }

    return values;
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

pub const Statement = struct {
    log_size: u32,
    log_step: u32,
    offset: usize,
};

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = struct {
    statement: Statement,
    proof: ExtendedProof,
};

/// Proves the XOR example wrapper over the component-driven prover pipeline.
pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
) anyerror!ProveOutput {
    const output = try proveEx(allocator, pcs_config, statement, false);
    var ext_proof = output.proof;
    const proof = ext_proof.proof;
    ext_proof.aux.deinit(allocator);
    return .{
        .statement = output.statement,
        .proof = proof,
    };
}

/// Extended proving wrapper over `prover.proveEx`.
pub fn proveEx(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    if (statement.log_size == 0) return Error.InvalidLogSize;
    if (statement.log_step > statement.log_size) return Error.InvalidStep;

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var scheme = try prover_pcs.CommitmentSchemeProver(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );

    const is_first = try genIsFirstColumn(allocator, statement.log_size);
    defer allocator.free(is_first);
    const is_step = try genIsStepWithOffsetColumn(
        allocator,
        statement.log_size,
        statement.log_step,
        statement.offset,
    );
    defer allocator.free(is_step);
    try scheme.commit(
        allocator,
        &[_]prover_pcs.ColumnEvaluation{
            .{ .log_size = statement.log_size, .values = is_first },
            .{ .log_size = statement.log_size, .values = is_step },
        },
        &channel,
    );

    const main_col = try genMainColumn(allocator, statement.log_size);
    defer allocator.free(main_col);
    try scheme.commit(
        allocator,
        &[_]prover_pcs.ColumnEvaluation{
            .{ .log_size = statement.log_size, .values = main_col },
        },
        &channel,
    );

    mixStatement(&channel, statement);

    const component = XorExampleComponent{
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

/// Verifies XOR proof wrapper generated by `prove`.
pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    if (statement.log_size == 0) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogSize;
    }
    if (statement.log_step > statement.log_size) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidStep;
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
        &[_]u32{ statement.log_size, statement.log_size },
        &channel,
    );
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &[_]u32{statement.log_size},
        &channel,
    );

    mixStatement(&channel, statement);

    const component = XorExampleComponent{
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

const XorExampleComponent = struct {
    statement: Statement,

    fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = nConstraints,
                .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                .traceLogDegreeBounds = traceLogDegreeBounds,
                .maskPoints = maskPoints,
                .preprocessedColumnIndices = preprocessedColumnIndices,
                .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
            },
        };
    }

    fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = nConstraints,
                .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                .traceLogDegreeBounds = traceLogDegreeBounds,
                .maskPoints = maskPoints,
                .preprocessedColumnIndices = preprocessedColumnIndices,
                .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
            },
        };
    }

    fn cast(ctx: *const anyopaque) *const @This() {
        return @ptrCast(@alignCast(ctx));
    }

    fn nConstraints(_: *const anyopaque) usize {
        return 1;
    }

    fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
        return cast(ctx).statement.log_size + 1;
    }

    fn traceLogDegreeBounds(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const self = cast(ctx);
        const preprocessed = try allocator.dupe(u32, &[_]u32{
            self.statement.log_size,
            self.statement.log_size,
        });
        const main = try allocator.dupe(u32, &[_]u32{
            self.statement.log_size,
        });
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{
                preprocessed,
                main,
            }),
        );
    }

    fn maskPoints(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        _: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed_col0 = try allocator.alloc(CirclePointQM31, 0);
        const preprocessed_col1 = try allocator.alloc(CirclePointQM31, 0);
        const preprocessed_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
            preprocessed_col0,
            preprocessed_col1,
        });

        const main_col = try allocator.alloc(CirclePointQM31, 1);
        main_col[0] = point;
        const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
            main_col,
        });

        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
                preprocessed_cols,
                main_cols,
            }),
        );
    }

    fn preprocessedColumnIndices(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &[_]usize{ 0, 1 });
    }

    fn evaluateConstraintQuotientsAtPoint(
        ctx: *const anyopaque,
        _: CirclePointQM31,
        _: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {
        evaluation_accumulator.accumulate(compositionEval(cast(ctx).statement));
    }

    fn evaluateConstraintQuotientsOnDomain(
        ctx: *const anyopaque,
        _: *const prover_component.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const self = cast(ctx).statement;
        const composition_eval = compositionEval(self);
        const domain_size = @as(usize, 1) << @intCast(self.log_size + 1);
        const values = try evaluation_accumulator.allocator.alloc(QM31, domain_size);
        defer evaluation_accumulator.allocator.free(values);
        @memset(values, composition_eval);

        var col = try secure_column.SecureColumnByCoords.fromSecureSlice(
            evaluation_accumulator.allocator,
            values,
        );
        defer col.deinit(evaluation_accumulator.allocator);
        try evaluation_accumulator.accumulateColumn(self.log_size + 1, &col);
    }
};

fn genMainColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
) (std.mem.Allocator.Error || Error)![]M31 {
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;
    const values = try allocator.alloc(M31, n);
    @memset(values, M31.zero());

    for (0..n) |i| {
        const circle_domain_index = utils.cosetIndexToCircleDomainIndex(i, log_size);
        const bit_rev_index = utils.bitReverseIndex(circle_domain_index, log_size);
        values[bit_rev_index] = if ((i & 1) == 0) M31.one() else M31.zero();
    }

    return values;
}

fn compositionEval(statement: Statement) QM31 {
    return QM31.fromM31(
        M31.fromCanonical(statement.log_size),
        M31.fromCanonical(statement.log_step),
        M31.fromU64(@intCast(statement.offset)),
        M31.one(),
    );
}

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&[_]u32{
        statement.log_size,
        statement.log_step,
    });
    channel.mixU64(@intCast(statement.offset));
}

test "examples xor: is_first has exactly one leading one" {
    const alloc = std.testing.allocator;
    const values = try genIsFirstColumn(alloc, 5);
    defer alloc.free(values);

    try std.testing.expect(values[0].eql(M31.one()));
    for (values[1..]) |value| {
        try std.testing.expect(value.eql(M31.zero()));
    }
}

test "examples xor: is_step_with_offset rejects invalid step" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(
        Error.InvalidStep,
        genIsStepWithOffsetColumn(alloc, 4, 5, 0),
    );
}

test "examples xor: prove/verify wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    };

    const output = try prove(std.testing.allocator, config, statement);
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples xor: prove_ex wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    };

    var output = try proveEx(std.testing.allocator, config, statement, false);
    defer output.proof.aux.deinit(std.testing.allocator);
    try verify(std.testing.allocator, config, output.statement, output.proof.proof);
}

test "examples xor: prove and prove_ex wrappers emit identical proof bytes" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 7,
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

test "examples xor: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 11,
    };
    const output = try prove(std.testing.allocator, config, statement);

    var bad_statement = output.statement;
    bad_statement.offset += 1;

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
