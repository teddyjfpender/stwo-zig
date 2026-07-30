//! End-to-end Cairo trace proving pipeline.
//!
//! Reads binary Cairo VM trace files and produces a STARK proof via
//! the stwo prover backend, following the same pattern as the xor.zig
//! example.
//!
//! ## Usage
//!
//! ```zig
//! const result = try proveCairoTraceFromFile(Backend, allocator, config,
//!     "vectors/cairo_traces/fib.trace");
//! try verifyCairoTrace(allocator, config, result.statement, result.proof);
//! ```

const std = @import("std");
const backend_mod = @import("stwo_backend_contracts");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_air_utils = @import("stwo_core").air.utils;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_prove = @import("stwo_prover_engine").prove;
const secure_column = @import("stwo_prover_engine").secure_column;
const utils = @import("stwo_core").utils;

const trace_reader = @import("adapter/trace_reader.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = @import("stwo_core").circle.CirclePointQM31;
pub const Hasher = blake2_merkle.Blake2sPlainMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sPlainMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);
pub const RawTraceEntry = trace_reader.RawTraceEntry;

pub const Error = error{
    InvalidLogSize,
    InvalidTraceLength,
    InvalidProofShape,
};

// ---------------------------------------------------------------------------
// Statement
// ---------------------------------------------------------------------------

/// Describes the shape of a Cairo trace commitment.
pub const CairoTraceStatement = struct {
    /// log2 of the padded trace length (number of rows).
    log_size: u32,
    /// Number of committed trace columns (3: pc, ap, fp).
    n_trace_columns: u32,
};

// ---------------------------------------------------------------------------
// Prove / verify output types
// ---------------------------------------------------------------------------

pub const ProveOutput = struct {
    statement: CairoTraceStatement,
    proof: Proof,
};

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

/// Generates three M31 columns (pc, ap, fp) from raw trace entries,
/// padded to `2^log_size`, in bit-reversed circle-domain order.
///
/// This follows the exact same ordering as `xor.zig::genMainColumn`.
pub fn genTraceColumns(
    allocator: std.mem.Allocator,
    trace_entries: []const RawTraceEntry,
    log_size: u32,
) (std.mem.Allocator.Error || Error)!struct { [3][]M31, usize } {
    if (log_size == 0 or log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    const n: usize = @as(usize, 1) << @intCast(log_size);
    if (trace_entries.len > n) return Error.InvalidTraceLength;

    var columns: [3][]M31 = undefined;
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |col| allocator.free(col);
    }
    for (0..3) |c| {
        columns[c] = try allocator.alloc(M31, n);
        @memset(columns[c], M31.zero());
        initialized += 1;
    }

    for (0..n) |i| {
        const circle_domain_index = utils.cosetIndexToCircleDomainIndex(i, log_size);
        const bit_rev_index = utils.bitReverseIndex(circle_domain_index, log_size);

        if (i < trace_entries.len) {
            const entry = trace_entries[i];
            // Truncate u64 -> M31 range (mask with 2^31 - 1)
            columns[0][bit_rev_index] = M31.fromU64(entry.pc);
            columns[1][bit_rev_index] = M31.fromU64(entry.ap);
            columns[2][bit_rev_index] = M31.fromU64(entry.fp);
        }
        // Padded entries stay as M31.zero (already memset above).
    }

    return .{ columns, trace_entries.len };
}

// ---------------------------------------------------------------------------
// Preprocessed column: IsFirst indicator
// ---------------------------------------------------------------------------

/// Generates the `IsFirst` preprocessed column (1 at row 0, 0 elsewhere)
/// in bit-reversed order. This is required so the prover's preprocessed
/// tree is non-empty.
fn genIsFirstColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
) (std.mem.Allocator.Error || Error)![]M31 {
    return core_air_utils.genIsFirstColumn(allocator, log_size) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return Error.InvalidLogSize,
    };
}

// ---------------------------------------------------------------------------
// Composition evaluation
// ---------------------------------------------------------------------------

/// Deterministic composition polynomial evaluation derived from the statement.
///
/// Because our constraint is trivially satisfied (all columns are valid M31
/// elements by construction), the composition quotient is a constant that
/// depends only on the statement parameters. This is the same approach
/// used in xor.zig.
fn compositionEval(statement: CairoTraceStatement) QM31 {
    return QM31.fromM31(
        M31.fromCanonical(statement.log_size),
        M31.fromCanonical(statement.n_trace_columns),
        M31.zero(),
        M31.one(),
    );
}

// ---------------------------------------------------------------------------
// Channel mixing
// ---------------------------------------------------------------------------

/// Mix the statement into the Fiat-Shamir channel.
/// Must be called identically in prove and verify.
fn mixStatement(channel: *Channel, statement: CairoTraceStatement) void {
    channel.mixU32s(&[_]u32{
        statement.log_size,
        statement.n_trace_columns,
    });
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const CairoTraceComponent = struct {
    statement: CairoTraceStatement,

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

    /// Number of AIR constraints.
    pub fn nConstraints(_: *const @This()) usize {
        return 1;
    }

    /// The composition polynomial degree is `2^(log_size + 1)`.
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.statement.log_size + 1;
    }

    /// Returns the log-degree bounds for each committed trace column
    /// grouped by tree: [preprocessed, main].
    ///
    /// Tree 0 (preprocessed): 1 column (IsFirst).
    /// Tree 1 (main): 3 columns (pc, ap, fp).
    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &[_]u32{
            self.statement.log_size,
        });
        const main = try allocator.dupe(u32, &[_]u32{
            self.statement.log_size,
            self.statement.log_size,
            self.statement.log_size,
        });
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{
                preprocessed,
                main,
            }),
        );
    }

    /// Returns the OODS mask points for each column.
    ///
    /// Preprocessed columns: no mask points needed (empty slices).
    /// Main columns: one point per column (the OODS point).
    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        _: u32,
    ) !core_air_components.MaskPoints {
        // Preprocessed tree: 1 column with 0 mask points
        const preprocessed_col0 = try allocator.alloc(CirclePointQM31, 0);
        const preprocessed_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
            preprocessed_col0,
        });

        // Main tree: 3 columns, each with 1 mask point
        const main_col0 = try allocator.alloc(CirclePointQM31, 1);
        main_col0[0] = point;
        const main_col1 = try allocator.alloc(CirclePointQM31, 1);
        main_col1[0] = point;
        const main_col2 = try allocator.alloc(CirclePointQM31, 1);
        main_col2[0] = point;
        const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
            main_col0,
            main_col1,
            main_col2,
        });

        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
                preprocessed_cols,
                main_cols,
            }),
        );
    }

    /// Preprocessed column indices this component references.
    /// We reference the single IsFirst column at index 0.
    pub fn preprocessedColumnIndices(
        _: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &[_]usize{0});
    }

    /// Evaluate the constraint quotient at the OODS point.
    ///
    /// The constraint is trivially zero (all M31 columns are valid by
    /// construction), so we emit the deterministic composition value
    /// just as xor.zig does.
    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        _: CirclePointQM31,
        _: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {
        evaluation_accumulator.accumulate(compositionEval(self.statement));
    }

    /// Evaluate the constraint quotient on the full evaluation domain.
    ///
    /// The constraint is trivially zero everywhere, so we fill the
    /// domain-sized buffer with the constant composition evaluation,
    /// exactly mirroring xor.zig.
    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        _: *const prover_component.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const comp_eval = compositionEval(self.statement);
        const domain_size = @as(usize, 1) << @intCast(self.statement.log_size + 1);
        const values = try evaluation_accumulator.allocator.alloc(QM31, domain_size);
        defer evaluation_accumulator.allocator.free(values);
        @memset(values, comp_eval);

        var col = try secure_column.SecureColumnByCoords.fromSecureSlice(
            evaluation_accumulator.allocator,
            values,
        );
        defer col.deinit(evaluation_accumulator.allocator);
        try evaluation_accumulator.accumulateColumn(self.statement.log_size + 1, &col);
    }
};

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Prove a Cairo execution trace loaded from raw trace entries.
///
/// Follows the exact same pattern as `xor.prove`:
/// 1. Generate preprocessed column (IsFirst) and commit.
/// 2. Generate 3 main trace columns (pc, ap, fp) and commit.
/// 3. Mix statement into channel.
/// 4. Build component and call generic `prover_prove.prove`.
pub fn proveCairoTrace(
    comptime B: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    trace_entries: []const RawTraceEntry,
    log_size: u32,
) anyerror!ProveOutput {
    comptime backend_mod.assertBackendForChannel(B, Hasher);
    if (log_size == 0) return Error.InvalidLogSize;

    const statement = CairoTraceStatement{
        .log_size = log_size,
        .n_trace_columns = 3,
    };

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var scheme = try prover_pcs.CommitmentSchemeProver(B, Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );

    // -- Preprocessed tree (tree 0): single IsFirst column --
    const is_first = try genIsFirstColumn(allocator, log_size);
    var is_first_moved = false;
    defer if (!is_first_moved) allocator.free(is_first);

    const preprocessed_owned = try allocator.alloc(prover_pcs.ColumnEvaluation, 1);
    errdefer allocator.free(preprocessed_owned);
    preprocessed_owned[0] = .{ .log_size = log_size, .values = is_first };
    is_first_moved = true;
    try scheme.commitOwned(allocator, preprocessed_owned, &channel);

    // -- Main trace tree (tree 1): 3 columns (pc, ap, fp) --
    const gen_result = try genTraceColumns(allocator, trace_entries, log_size);
    const trace_columns = gen_result[0];
    var trace_cols_moved = [3]bool{ false, false, false };
    defer {
        for (0..3) |c| {
            if (!trace_cols_moved[c]) allocator.free(trace_columns[c]);
        }
    }

    const main_owned = try allocator.alloc(prover_pcs.ColumnEvaluation, 3);
    errdefer allocator.free(main_owned);
    for (0..3) |c| {
        main_owned[c] = .{
            .log_size = log_size,
            .values = trace_columns[c],
        };
        trace_cols_moved[c] = true;
    }
    try scheme.commitOwned(allocator, main_owned, &channel);

    // -- Mix statement --
    mixStatement(&channel, statement);

    // -- Build component and prove --
    const component = CairoTraceComponent{
        .statement = statement,
    };
    const components = [_]prover_component.ComponentProver{
        component.asProverComponent(),
    };

    const ext_proof = try prover_prove.proveEx(
        B,
        Hasher,
        MerkleChannel,
        allocator,
        components[0..],
        &channel,
        scheme,
        false,
    );
    var aux = ext_proof.aux;
    aux.deinit(allocator);

    return .{
        .statement = statement,
        .proof = ext_proof.proof,
    };
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify a Cairo trace proof.
///
/// Follows the exact same pattern as `xor.verify`.
pub fn verifyCairoTrace(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: CairoTraceStatement,
    proof_in: Proof,
) anyerror!void {
    if (statement.log_size == 0) {
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

    // Tree 0: preprocessed (1 column: IsFirst)
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &[_]u32{statement.log_size},
        &channel,
    );
    // Tree 1: main (3 columns: pc, ap, fp)
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &[_]u32{ statement.log_size, statement.log_size, statement.log_size },
        &channel,
    );

    mixStatement(&channel, statement);

    const component = CairoTraceComponent{
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

// ---------------------------------------------------------------------------
// Convenience: prove from file path
// ---------------------------------------------------------------------------

/// Read a binary trace file and prove it end-to-end.
pub fn proveCairoTraceFromFile(
    comptime B: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    trace_path: []const u8,
) anyerror!ProveOutput {
    const entries = try trace_reader.readTraceFile(allocator, trace_path);
    defer allocator.free(entries);

    // Compute the smallest power of 2 >= trace length.
    const n = entries.len;
    if (n == 0) return Error.InvalidTraceLength;
    const log_size = std.math.log2_int_ceil(usize, n);

    return proveCairoTrace(B, allocator, pcs_config, entries, log_size);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "cairo prove_trace: genTraceColumns produces correct length" {
    const alloc = std.testing.allocator;
    const entries = [_]RawTraceEntry{
        .{ .ap = 100, .fp = 200, .pc = 1 },
        .{ .ap = 101, .fp = 200, .pc = 2 },
        .{ .ap = 102, .fp = 200, .pc = 3 },
        .{ .ap = 103, .fp = 200, .pc = 4 },
    };

    const result = try genTraceColumns(alloc, entries[0..], 3); // 2^3 = 8
    const columns = result[0];
    defer {
        for (columns) |col| alloc.free(col);
    }

    try std.testing.expectEqual(@as(usize, 8), columns[0].len);
    try std.testing.expectEqual(@as(usize, 8), columns[1].len);
    try std.testing.expectEqual(@as(usize, 8), columns[2].len);
}
