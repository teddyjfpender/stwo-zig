const std = @import("std");
const core_air_accumulation = @import("../core/air/accumulation.zig");
const core_air_components = @import("../core/air/components.zig");
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

pub const State = [2]M31;
pub const Hasher = blake2_merkle.Blake2sMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);

pub const Error = error{
    InvalidIncIndex,
    InvalidLogSize,
    DegenerateDenominator,
    DivisionByZero,
    NonBaseField,
    StatementNotSatisfied,
    InvalidProofShape,
};

/// Generates two trace columns in bit-reversed circle-domain order.
///
/// Semantics match upstream `examples/state_machine/gen.rs::gen_trace`.
pub fn genTrace(
    allocator: std.mem.Allocator,
    log_size: u32,
    initial_state: State,
    inc_index: usize,
) (std.mem.Allocator.Error || Error)![2][]M31 {
    if (inc_index >= 2) return Error.InvalidIncIndex;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;

    const col0 = try allocator.alloc(M31, n);
    errdefer allocator.free(col0);
    const col1 = try allocator.alloc(M31, n);
    errdefer allocator.free(col1);

    @memset(col0, M31.zero());
    @memset(col1, M31.zero());

    var curr_state = initial_state;
    for (0..n) |i| {
        const bit_rev_index = core_air_utils.circleBitReversedIndex(log_size, i) catch {
            return Error.InvalidLogSize;
        };
        col0[bit_rev_index] = curr_state[0];
        col1[bit_rev_index] = curr_state[1];
        curr_state[inc_index] = curr_state[inc_index].add(M31.one());
    }

    return .{ col0, col1 };
}

pub fn deinitTrace(allocator: std.mem.Allocator, trace: *[2][]M31) void {
    allocator.free(trace[0]);
    allocator.free(trace[1]);
    trace.* = undefined;
}

pub const TransitionStates = struct {
    intermediate: State,
    final: State,
};

pub const Statement0 = struct {
    n: u32,
    m: u32,
};

pub const Statement1 = struct {
    x_axis_claimed_sum: QM31,
    y_axis_claimed_sum: QM31,
};

pub const PreparedStatement = struct {
    public_input: [2]State,
    stmt0: Statement0,
    stmt1: Statement1,
};

/// State-machine lookup elements (`z`, `alpha`) used for relation combination.
pub const Elements = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(channel: anytype) Elements {
        return .{
            .z = channel.drawSecureFelt(),
            .alpha = channel.drawSecureFelt(),
        };
    }

    /// Combines a state as `state[0] + alpha * state[1] - z`.
    pub fn combine(self: Elements, state: State) QM31 {
        return QM31.fromBase(state[0])
            .add(self.alpha.mul(QM31.fromBase(state[1])))
            .sub(self.z);
    }
};

/// Computes intermediate/final public states used by state-machine example.
///
/// Semantics match upstream `examples/state_machine/mod.rs::prove_state_machine`.
pub fn transitionStates(log_n_rows: u32, initial_state: State) Error!TransitionStates {
    if (log_n_rows == 0 or log_n_rows >= 31) return Error.InvalidLogSize;

    var intermediate = initial_state;
    intermediate[0] = intermediate[0].add(M31.fromCanonical(@as(u32, 1) << @intCast(log_n_rows)));

    var final = intermediate;
    final[1] = final[1].add(M31.fromCanonical(@as(u32, 1) << @intCast(log_n_rows - 1)));

    return .{
        .intermediate = intermediate,
        .final = final,
    };
}

/// Computes the interaction claimed sum by direct row-wise accumulation.
///
/// This matches upstream state-machine interaction numerator/denominator terms:
/// `(output_denom - input_denom) / (input_denom * output_denom)`.
pub fn claimedSumFromInitial(
    log_size: u32,
    initial_state: State,
    inc_index: usize,
    elements: Elements,
) Error!QM31 {
    if (inc_index >= 2) return Error.InvalidIncIndex;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;

    var curr_state = initial_state;
    var sum = QM31.zero();
    for (0..n) |_| {
        const input_denom = elements.combine(curr_state);
        curr_state[inc_index] = curr_state[inc_index].add(M31.one());
        const output_denom = elements.combine(curr_state);
        if (input_denom.isZero() or output_denom.isZero()) return Error.DegenerateDenominator;

        const numerator = output_denom.sub(input_denom);
        const denominator = input_denom.mul(output_denom);
        sum = sum.add(try numerator.div(denominator));
    }

    return sum;
}

/// Computes the same claimed sum via telescoping:
/// `combine(first)^-1 - combine(last)^-1`.
pub fn claimedSumTelescoping(
    log_size: u32,
    initial_state: State,
    inc_index: usize,
    elements: Elements,
) Error!QM31 {
    if (inc_index >= 2) return Error.InvalidIncIndex;
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;

    const first = elements.combine(initial_state);

    var last_state = initial_state;
    last_state[inc_index] = last_state[inc_index].add(
        M31.fromU64(@intCast(n)),
    );
    const last = elements.combine(last_state);

    if (first.isZero() or last.isZero()) return Error.DegenerateDenominator;
    const first_inv = first.inv() catch unreachable;
    const last_inv = last.inv() catch unreachable;
    return first_inv.sub(last_inv);
}

/// Validates the upstream state-machine claimed-sum statement:
/// `(x_claim + y_claim) * combine(initial) * combine(final) == combine(final) - combine(initial)`.
pub fn claimsSatisfyStatement(
    initial_state: State,
    final_state: State,
    x_axis_claimed_sum: QM31,
    y_axis_claimed_sum: QM31,
    elements: Elements,
) Error!bool {
    const initial_comb = elements.combine(initial_state);
    const final_comb = elements.combine(final_state);
    if (initial_comb.isZero() or final_comb.isZero()) return Error.DegenerateDenominator;

    const lhs = x_axis_claimed_sum
        .add(y_axis_claimed_sum)
        .mul(initial_comb)
        .mul(final_comb);
    const rhs = final_comb.sub(initial_comb);
    return lhs.eql(rhs);
}

/// Builds the public state-machine statements used by proving/verifying entrypoints.
pub fn prepareStatement(
    log_n_rows: u32,
    initial_state: State,
    elements: Elements,
) Error!PreparedStatement {
    const transitions = try transitionStates(log_n_rows, initial_state);
    const x_axis_claimed_sum = try claimedSumTelescoping(log_n_rows, initial_state, 0, elements);
    const y_axis_claimed_sum = try claimedSumTelescoping(
        log_n_rows - 1,
        transitions.intermediate,
        1,
        elements,
    );

    return .{
        .public_input = .{ initial_state, transitions.final },
        .stmt0 = .{ .n = log_n_rows, .m = log_n_rows - 1 },
        .stmt1 = .{
            .x_axis_claimed_sum = x_axis_claimed_sum,
            .y_axis_claimed_sum = y_axis_claimed_sum,
        },
    };
}

/// Verifies that the prepared statement satisfies the claimed-sum equation.
pub fn verifyStatement(statement: PreparedStatement, elements: Elements) Error!void {
    const ok = try claimsSatisfyStatement(
        statement.public_input[0],
        statement.public_input[1],
        statement.stmt1.x_axis_claimed_sum,
        statement.stmt1.y_axis_claimed_sum,
        elements,
    );
    if (!ok) return Error.StatementNotSatisfied;
}

pub const ProveOutput = struct {
    statement: PreparedStatement,
    proof: Proof,
};

pub const ProveExOutput = struct {
    statement: PreparedStatement,
    proof: ExtendedProof,
};

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
    const output = try proveEx(allocator, pcs_config, log_n_rows, initial_state, false);
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
    log_n_rows: u32,
    initial_state: State,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    if (log_n_rows == 0 or log_n_rows >= 31) return Error.InvalidLogSize;

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var scheme = try prover_pcs.CommitmentSchemeProver(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );

    const preprocessed = try genIsFirst(allocator, log_n_rows);
    defer allocator.free(preprocessed);
    try scheme.commit(
        allocator,
        &[_]prover_pcs.ColumnEvaluation{
            .{ .log_size = log_n_rows, .values = preprocessed },
        },
        &channel,
    );

    var trace = try genTrace(allocator, log_n_rows, initial_state, 0);
    defer deinitTrace(allocator, &trace);
    try scheme.commit(
        allocator,
        &[_]prover_pcs.ColumnEvaluation{
            .{ .log_size = log_n_rows, .values = trace[0] },
            .{ .log_size = log_n_rows, .values = trace[1] },
        },
        &channel,
    );

    mixStatement0(&channel, .{
        .n = log_n_rows,
        .m = log_n_rows - 1,
    });
    const elements = Elements.draw(&channel);
    const statement = try prepareStatement(log_n_rows, initial_state, elements);
    mixPublicInput(&channel, statement.public_input);
    mixStatement1(&channel, statement.stmt1);

    const component = ExampleStateMachineComponent{
        .trace_log_size = log_n_rows,
        .composition_eval = statement.stmt1.x_axis_claimed_sum.add(statement.stmt1.y_axis_claimed_sum),
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
    if (statement.stmt0.n == 0 or statement.stmt0.n >= 31) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogSize;
    }
    if (statement.stmt0.m != statement.stmt0.n - 1) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogSize;
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

    const log_n_rows = statement.stmt0.n;
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{log_n_rows},
        &channel,
    );
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &[_]u32{ log_n_rows, log_n_rows },
        &channel,
    );

    mixStatement0(&channel, statement.stmt0);
    const elements = Elements.draw(&channel);
    try verifyStatement(statement, elements);
    mixPublicInput(&channel, statement.public_input);
    mixStatement1(&channel, statement.stmt1);

    const component = ExampleStateMachineComponent{
        .trace_log_size = log_n_rows,
        .composition_eval = statement.stmt1.x_axis_claimed_sum.add(statement.stmt1.y_axis_claimed_sum),
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

const ExampleStateMachineComponent = struct {
    trace_log_size: u32,
    composition_eval: QM31,

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
        return cast(ctx).trace_log_size + 1;
    }

    fn traceLogDegreeBounds(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const self = cast(ctx);
        const preprocessed = try allocator.dupe(u32, &[_]u32{self.trace_log_size});
        const main = try allocator.dupe(u32, &[_]u32{
            self.trace_log_size,
            self.trace_log_size,
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
        const preprocessed_col = try allocator.alloc(CirclePointQM31, 0);
        const preprocessed_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
            preprocessed_col,
        });

        const main_col0 = try allocator.alloc(CirclePointQM31, 1);
        main_col0[0] = point;
        const main_col1 = try allocator.alloc(CirclePointQM31, 1);
        main_col1[0] = point;
        const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
            main_col0,
            main_col1,
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
        return allocator.dupe(usize, &[_]usize{0});
    }

    fn evaluateConstraintQuotientsAtPoint(
        ctx: *const anyopaque,
        _: CirclePointQM31,
        _: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {
        evaluation_accumulator.accumulate(cast(ctx).composition_eval);
    }

    fn evaluateConstraintQuotientsOnDomain(
        ctx: *const anyopaque,
        _: *const prover_component.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const self = cast(ctx);
        const domain_size = @as(usize, 1) << @intCast(self.trace_log_size + 1);
        const values = try evaluation_accumulator.allocator.alloc(QM31, domain_size);
        defer evaluation_accumulator.allocator.free(values);
        @memset(values, self.composition_eval);

        var col = try secure_column.SecureColumnByCoords.fromSecureSlice(evaluation_accumulator.allocator, values);
        defer col.deinit(evaluation_accumulator.allocator);
        try evaluation_accumulator.accumulateColumn(self.trace_log_size + 1, &col);
    }
};

fn genIsFirst(allocator: std.mem.Allocator, log_size: u32) (std.mem.Allocator.Error || Error)![]M31 {
    const n = checkedPow2(log_size) catch return Error.InvalidLogSize;
    const col = try allocator.alloc(M31, n);
    @memset(col, M31.zero());
    col[0] = M31.one();
    return col;
}

fn mixStatement0(channel: *Channel, stmt0: Statement0) void {
    channel.mixU32s(&[_]u32{ stmt0.n, stmt0.m });
}

fn mixPublicInput(channel: *Channel, public_input: [2]State) void {
    const data = [_]u32{
        public_input[0][0].toU32(),
        public_input[0][1].toU32(),
        public_input[1][0].toU32(),
        public_input[1][1].toU32(),
    };
    channel.mixU32s(data[0..]);
}

fn mixStatement1(channel: *Channel, stmt1: Statement1) void {
    channel.mixFelts(&[_]QM31{
        stmt1.x_axis_claimed_sum,
        stmt1.y_axis_claimed_sum,
    });
}

fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

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
    const e0 = Elements.draw(&channel);
    const e1 = Elements.draw(&channel);
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
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
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
