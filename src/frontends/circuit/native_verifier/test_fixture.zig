//! A prover-backed native proof for the verifier tests: the wide-Fibonacci
//! AIR of `src/examples/wide_fibonacci` (columns `c_j = c_{j-2}^2 + c_{j-1}^2`
//! per row, no preprocessed or interaction tree) proved with the generic
//! prover engine over a minimal host backend (the one of
//! `src/prover/pcs/owned_source_admission_test.zig`), then verified natively
//! with `verifyBorrowedExWithProofCapture`. The package cannot depend on the
//! example or CPU-backend packages (layer rules), so the AIR is restated
//! here; its transcript is the example's `verify`: `PcsConfig.mixInto`, the
//! empty preprocessed root, the main root, `mixU32s(log_n_rows, sequence_len)`,
//! then the core verifier.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const shape_mod = @import("shape.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const air_components = core.air.components;
const air_accumulation = core.air.accumulation;
const prover_component = prover.air.component_prover;
const prover_accumulation = prover.air.accumulation;
const work = prover.work_profile;

pub const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
pub const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
pub const Channel = core.channel.blake2s.Blake2sChannel;
pub const Proof = core.proof.StarkProof(Hasher);
pub const Capture = core.pcs.verifier.VerifiedProofCapture(Hasher);
pub const PcsConfig = core.pcs.PcsConfig;

pub const Statement = struct {
    log_n_rows: u32,
    sequence_len: u32,
};

/// The host backend: real scalar Merkle hashing and FFTs from the prover
/// engine, no device policies.
pub const TestBackend = struct {
    pub const adopts_source_trace_arena = false;
    pub const combined_base_in_place = false;
    pub const combined_commit_min_columns: usize = 65;
    pub const resident_column_arena_alignment = std.mem.Alignment.fromByteUnits(64);

    pub fn MerkleTree(comptime H: type) type {
        return prover.vcs_lifted.prover.MerkleProverLifted(H);
    }

    pub fn commitMerkle(comptime H: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(H) {
        return MerkleTree(H).commit(allocator, columns);
    }

    pub fn interpolateAndEvaluateCircleBuffers(
        allocator: std.mem.Allocator,
        source_values: []const []const M31,
        base_values: []const []M31,
        extended_values: []const []M31,
        transform_buffer: []M31,
        extended_start: usize,
        extended_stride: usize,
        base_domain: anytype,
        base_twiddles: anytype,
        extended_domain: anytype,
        extended_twiddles: anytype,
    ) !work.M31CircleLdeExecution {
        _ = allocator;
        _ = transform_buffer;
        _ = extended_start;
        _ = extended_stride;
        const poly = prover.poly.circle.poly;
        for (source_values, base_values, extended_values) |source, base, extended| {
            if (source.ptr != base.ptr) @memcpy(base, source);
            var base_batch = [_][]M31{base};
            try poly.interpolateBuffersWithTwiddles(&base_batch, base_domain, base_twiddles);
            @memcpy(extended[0..base.len], base);
            @memset(extended[base.len..], M31.zero());
            var extended_batch = [_][]M31{extended};
            try poly.evaluateBuffersWithTwiddles(&extended_batch, extended_domain, extended_twiddles);
        }
        return .{
            .interpolation = .{ .log_size = base_domain.logSize(), .column_count = @intCast(source_values.len), .batch_count = @intCast(source_values.len) },
            .forward = .{ .log_size = extended_domain.logSize(), .column_count = @intCast(source_values.len), .skipped_layers = 0 },
        };
    }
};

pub const Engine = prover.engine.ProverEngine(TestBackend, Hasher, MerkleChannel, Channel);

/// The wide-Fibonacci component, verifier and prover halves.
pub const FibComponent = struct {
    statement: Statement,

    const Adapter = core.air.derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(self: *const @This()) air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return @as(usize, self.statement.sequence_len) - 2;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.statement.log_n_rows + 1;
    }

    pub fn traceLogDegreeBounds(self: *const @This(), allocator: std.mem.Allocator) !air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, self.statement.sequence_len);
        errdefer allocator.free(main);
        @memset(main, self.statement.log_n_rows);
        return air_components.TraceLogDegreeBounds.initOwned(try allocator.dupe([]u32, &.{ preprocessed, main }));
    }

    pub fn maskPoints(self: *const @This(), allocator: std.mem.Allocator, point: CirclePointQM31, _: u32) !air_components.MaskPoints {
        const preprocessed = try allocator.alloc([]CirclePointQM31, 0);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc([]CirclePointQM31, self.statement.sequence_len);
        var initialized: usize = 0;
        errdefer {
            for (main[0..initialized]) |column| allocator.free(column);
            allocator.free(main);
        }
        for (main) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{point});
            initialized += 1;
        }
        return air_components.MaskPoints.initOwned(try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main }));
    }

    pub fn preprocessedColumnIndices(_: *const @This(), allocator: std.mem.Allocator) ![]usize {
        return allocator.alloc(usize, 0);
    }

    /// `sum_j alpha^(n-1-j) (c_j - a_j^2 - b_j^2) / Z_trace(point)`, the
    /// example's `evaluateConstraintQuotientsAtPoint`.
    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const air_components.MaskValues,
        accumulator: *air_accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {
        const main = mask.items[1];
        if (main.len != self.statement.sequence_len) return error.InvalidProofShape;
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(self.statement.log_n_rows).coset(), point);
        const denominator_inv = try denominator.inv();
        var a = main[0][0];
        var b = main[1][0];
        for (main[2..]) |column| {
            const c = column[0];
            accumulator.accumulate(c.sub(a.square().add(b.square())).mul(denominator_inv));
            a = b;
            b = c;
        }
    }

    /// The example's domain evaluation for one bit of blowup: the committed
    /// columns are already on the composition domain.
    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const allocator = accumulator.allocator;
        const main = trace.polys.items[1];
        const eval_log_size = self.statement.log_n_rows + 1;
        for (main) |poly| {
            try poly.validate();
            if (poly.log_size != eval_log_size) return error.UnsupportedBlowup;
        }
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const trace_coset = canonic.CanonicCoset.new(self.statement.log_n_rows).coset();
        const denominator_inv = [_]M31{
            try core.constraints.cosetVanishing(M31, trace_coset, eval_domain.at(0)).inv(),
            try core.constraints.cosetVanishing(M31, trace_coset, eval_domain.at(1)).inv(),
        };
        const accumulators = try accumulator.columns(allocator, &.{.{ .log_size = eval_log_size, .n_cols = self.nConstraints() }});
        defer allocator.free(accumulators);
        var column_accumulator = &accumulators[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.statement.log_n_rows);
        for (0..eval_domain.size()) |row| {
            var a = main[0].values[row];
            var b = main[1].values[row];
            var row_evaluation = QM31.zero();
            for (main[2..], 0..) |column, constraint| {
                const c = column.values[row];
                const value = c.sub(a.square().add(b.square()));
                row_evaluation = row_evaluation.add(column_accumulator.random_coeff_powers[self.nConstraints() - 1 - constraint].mulM31(value));
                a = b;
                b = c;
            }
            column_accumulator.accumulate(row, row_evaluation.mulM31(denominator_inv[row >> shift]));
        }
    }
};

/// The main trace: every storage position is its own recurrence instance
/// `(1, position, ...)`, as the example's generator.
fn mainColumns(allocator: std.mem.Allocator, statement: Statement) ![]prover.pcs.ColumnEvaluation {
    const n = @as(usize, 1) << @intCast(statement.log_n_rows);
    const columns = try allocator.alloc(prover.pcs.ColumnEvaluation, statement.sequence_len);
    for (columns) |*column| column.* = .{ .log_size = statement.log_n_rows, .values = try allocator.alloc(M31, n) };
    for (0..n) |row| {
        var a = M31.one();
        var b = M31.fromCanonical(@intCast(row + 3));
        @constCast(columns[0].values)[row] = a;
        @constCast(columns[1].values)[row] = b;
        for (columns[2..]) |column| {
            const c = a.square().add(b.square());
            @constCast(column.values)[row] = c;
            a = b;
            b = c;
        }
    }
    return columns;
}

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&.{ statement.log_n_rows, statement.sequence_len });
}

/// Proves `statement` (the example's transcript).
pub fn prove(allocator: std.mem.Allocator, config: PcsConfig, statement: Statement) !Proof {
    var channel = Channel{};
    config.mixInto(&channel);
    var scheme = try Engine.init(allocator, config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    try Engine.commit(&scheme, allocator, try allocator.alloc(prover.pcs.ColumnEvaluation, 0), null, &channel);
    try Engine.commit(&scheme, allocator, try mainColumns(allocator, statement), null, &channel);
    mixStatement(&channel, statement);
    const component = FibComponent{ .statement = statement };
    scheme_owned = false;
    var extended = try Engine.prove(allocator, &.{component.asProverComponent()}, &channel, scheme, .{});
    extended.aux.deinit(allocator);
    return extended.proof;
}

/// Verifies natively with proof capture; returns the final channel.
pub fn verifyNative(allocator: std.mem.Allocator, config: PcsConfig, statement: Statement, proof: *const Proof, capture: *Capture) !Channel {
    var channel = Channel{};
    config.mixInto(&channel);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(allocator, config);
    defer verifier.deinit(allocator);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != 3) return error.InvalidProofShape;
    try verifier.commit(allocator, commitments[0], &.{}, &channel);
    const main_logs = try allocator.alloc(u32, statement.sequence_len);
    defer allocator.free(main_logs);
    @memset(main_logs, statement.log_n_rows);
    try verifier.commit(allocator, commitments[1], main_logs, &channel);
    mixStatement(&channel, statement);
    const component = FibComponent{ .statement = statement };
    try core.verifier.verifyBorrowedExWithProofCapture(Hasher, MerkleChannel, allocator, &.{component.asVerifierComponent()}, &channel, &verifier, proof, false, capture);
    return channel;
}

/// The shape of the fixture's proofs: an empty preprocessed tree, the main
/// tree sampled at offset 0, the composition tree.
pub fn makeShape(allocator: std.mem.Allocator, config: PcsConfig, statement: Statement) !shape_mod.Shape {
    const n_main: usize = statement.sequence_len;
    const main_logs = try allocator.alloc(u32, n_main);
    @memset(main_logs, statement.log_n_rows);
    const composition_logs = try allocator.alloc(u32, 8);
    @memset(composition_logs, statement.log_n_rows);
    const at_oods = try allocator.dupe(i32, &.{0});
    const main_offsets = try allocator.alloc([]const i32, n_main);
    @memset(main_offsets, at_oods);
    const composition_offsets = try allocator.alloc([]const i32, 8);
    @memset(composition_offsets, at_oods);
    return .{
        .tree_column_log_sizes = try allocator.dupe([]const u32, &.{ &.{}, main_logs, composition_logs }),
        .mask_offsets = try allocator.dupe([]const []const i32, &.{ &.{}, main_offsets, composition_offsets }),
        .global_log = statement.log_n_rows,
        .composition_log_split = 1,
        .pcs = config,
    };
}

/// A proved and natively verified statement with everything the circuit
/// tests need.
pub const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    config: PcsConfig,
    statement: Statement,
    proof: Proof,
    capture: Capture,
    final_channel: Channel,
    shape: shape_mod.Shape,

    pub fn init(gpa: std.mem.Allocator, config: PcsConfig, statement: Statement) !Fixture {
        var proof = try prove(gpa, config, statement);
        errdefer proof.deinit(gpa);
        var capture: Capture = undefined;
        const final_channel = try verifyNative(gpa, config, statement, &proof, &capture);
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        // Allocate before the arena state is copied into the fixture.
        const shape = try makeShape(arena.allocator(), config, statement);
        return .{
            .arena = arena,
            .config = config,
            .statement = statement,
            .proof = proof,
            .capture = capture,
            .final_channel = final_channel,
            .shape = shape,
        };
    }

    pub fn deinit(self: *Fixture, gpa: std.mem.Allocator) void {
        // The empty preprocessed tree is never decommitted natively, so
        // `verifyWithPathCapture` leaves its capture slot unwritten
        // (`vcs_lifted/verifier.zig` returns before `capture_out`).
        self.capture.trace_paths[0] = .{ .positions = &.{}, .path_depth = 0, .siblings = &.{} };
        self.capture.deinit(gpa);
        self.proof.deinit(gpa);
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn allocator(self: *Fixture) std.mem.Allocator {
        return self.arena.allocator();
    }
};

/// The default fixture: 16 rows of 5 columns, 7 queries, 4 bits of work.
pub const default_config = PcsConfig{ .pow_bits = 4, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 7, .fold_step = 1 } };
pub const default_statement = Statement{ .log_n_rows = 4, .sequence_len = 5 };

test "fixture: the wide-Fibonacci proof verifies natively with capture" {
    var fixture = try Fixture.init(std.testing.allocator, default_config, default_statement);
    defer fixture.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 7), fixture.capture.queries.raw.len);
    try std.testing.expectEqual(@as(usize, 3), fixture.capture.commitments.len);
    try std.testing.expectEqual(@as(usize, 4), fixture.capture.fri.layers.len);
    try fixture.shape.validate();
    try std.testing.expectEqual(@as(u32, 5), fixture.shape.liftingLogSize());
}
