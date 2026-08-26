//! Isolated command for the H-010 authenticated Poseidon layout experiment.
//!
//! `check` is an untimed admission pass over all arms at logs 4 and 6.
//! `sample` measures one arm in one fresh process and emits exactly one JSON
//! line.  It executes no proof, commitment, interaction, verifier, or Metal
//! path and cannot promote a candidate layout.

const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const core_utils = @import("stwo_core").utils;
const process_usage = @import("stwo_prover_engine").measurement.process_usage;
const reviewed = @import("typed_air_h009_artifacts");
const checked_vectors = @import("typed_air_h010_artifacts");
const compat = @import("typed_poseidon2_compat.zig");
const cut_set = @import("materialization_cut_set.zig");
const direct_benchmark = @import("materialization_direct_benchmark.zig");
const direct_program = @import("materialization_direct_program.zig");
const frontier = @import("materialization_frontier_manifest.zig");
const layout_executor = @import("typed_poseidon2_layout_executor.zig");
const poseidon = @import("typed_poseidon2.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const proof_authority = @import("typed_poseidon2_proof_authority.zig");
const protocol = @import("poseidon_layout_benchmark_protocol.zig");
const rss = @import("poseidon_layout_benchmark_rss.zig");
const types = @import("types.zig");
const vector_artifact = @import("poseidon_layout_benchmark_artifact.zig");
const vector_mod = @import("poseidon_layout_benchmark_vector.zig");

const usage =
    "usage: riscv-poseidon-layout-benchmark check | " ++
    "sample <compat-seed|removed-q0|removed-q50|removed-q100> <10|14|18> | " ++
    "vector-artifacts <check|update> <directory>\n";
const direct_result_domain = "stwo-zig/typed-air/h010/direct-result/v1";
const target_label = @tagName(builtin.cpu.arch) ++ "-" ++
    @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.abi);

pub fn main() void {
    run() catch |err| {
        std.debug.print("H-010 Poseidon layout benchmark failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    // ReleaseFast timing uses the libc allocator rather than retaining debug
    // allocator metadata in the measured process high-water mark.
    const allocator = std.heap.c_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 2 and std.mem.eql(u8, args[1], "check")) {
        try runCheck(allocator);
        return;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "sample")) {
        const arm = protocol.Arm.parse(args[2]) orelse return invalidArguments();
        const log_size = std.fmt.parseInt(u8, args[3], 10) catch
            return invalidArguments();
        if (!protocol.isMeasurementLog(log_size)) return invalidArguments();
        try runSample(allocator, arm, log_size);
        return;
    }
    if (args.len == 4 and std.mem.eql(u8, args[1], "vector-artifacts")) {
        const mode = std.meta.stringToEnum(vector_artifact.Mode, args[2]) orelse
            return invalidArguments();
        try vector_artifact.execute(allocator, mode, args[3]);
        return;
    }
    return invalidArguments();
}

fn invalidArguments() error{InvalidArguments} {
    std.debug.print("{s}", .{usage});
    return error.InvalidArguments;
}

fn requireReleaseFast() !void {
    if (builtin.mode != .ReleaseFast) return error.ReleaseFastRequired;
}

fn runCheck(allocator: std.mem.Allocator) !void {
    try requireReleaseFast();
    const rss_probe = try rss.checkAdapter(allocator);
    inline for (.{ @as(u8, 10), @as(u8, 14) }) |log_size| {
        var vector = try measurementVector(allocator, log_size);
        defer vector.deinit();
        inline for (std.meta.tags(protocol.Arm)) |arm| {
            try checkFullVector(allocator, arm, &vector);
        }
    }
    inline for (std.meta.tags(protocol.Arm)) |arm| {
        inline for (.{ @as(u8, 4), @as(u8, 6) }) |log_size| {
            try checkOne(allocator, arm, log_size);
        }
    }
    try writeJsonLine(.{
        .schema = protocol.schema,
        .schema_version = protocol.schema_version,
        .benchmark = protocol.benchmark_id,
        .command = "check",
        .status = "passed",
        .arms = protocol.arm_pins.len,
        .correctness_log_sizes = &[_]u16{ 4, 6 },
        .measurement_logs_checked = &[_]u16{ 10, 14 },
        .direct_roots_checked_per_row = protocol.root_count,
        .rss_probe_allocated_bytes = rss_probe.allocated_bytes,
        .rss_probe_delta_bytes = rss_probe.delta_bytes,
        .rss_probe_source = rss_probe.source,
        .proof_executed = false,
        .metal_candidate_execution_supported = false,
        .production_layout_changed = false,
    });
}

fn checkFullVector(
    allocator: std.mem.Allocator,
    arm: protocol.Arm,
    vector: *vector_mod.Owned,
) !void {
    var prepared = try Prepared.init(
        allocator,
        arm,
        vector.identity.log_size,
        vector.calls,
    );
    defer prepared.deinit();
    const execution = try prepared.execute();
    try prepared.validateExecution(execution);
    try validateVectorExecution(vector.identity, execution, arm);
}

fn checkOne(allocator: std.mem.Allocator, arm: protocol.Arm, log_size: u8) !void {
    var vector = try vector_mod.Owned.generate(allocator, log_size, false);
    defer vector.deinit();
    var prepared = try Prepared.init(allocator, arm, log_size, vector.calls);
    defer prepared.deinit();
    const execution = try prepared.execute();
    try prepared.validateExecution(execution);
    if (protocol.vectorPin(log_size) != null)
        try validateVectorExecution(vector.identity, execution, arm);
    try prepared.checkBoundaryAndMutations();
}

fn runSample(
    allocator: std.mem.Allocator,
    arm: protocol.Arm,
    log_size: u8,
) !void {
    try requireReleaseFast();
    var vector = try measurementVector(allocator, log_size);
    defer vector.deinit();
    var setup_timer = try std.time.Timer.start();
    var prepared = try Prepared.init(allocator, arm, log_size, vector.calls);
    defer prepared.deinit();
    const witness_capability = try prepared.layout.prepareMain(
        &prepared.trace.mutable,
        prepared.calls,
        log_size,
    );
    const direct_capability = try prepared.direct.prepareTrace(
        &prepared.trace.readonly,
    );
    const setup_ns = setup_timer.read();

    var witness_timer = try std.time.Timer.start();
    witness_capability.execute();
    const witness_ns = witness_timer.read();

    var direct_timer = try std.time.Timer.start();
    const direct = direct_capability.execute();
    const direct_ns = direct_timer.read();
    const execution = try prepared.observe(direct);
    try prepared.validateExecution(execution);
    try validateVectorExecution(vector.identity, execution, arm);

    const resources = try process_usage.sample();
    if (resources.source != .unsupported and
        (resources.lifetime_peak_physical_footprint_bytes orelse 0) == 0)
    {
        return error.ResourceUsageUnavailable;
    }
    const peak_rss = try rss.sample();
    try writeSampleJson(
        prepared,
        execution,
        peak_rss,
        vector.identity,
        vector.storage_class,
        setup_ns,
        witness_ns,
        direct_ns,
    );
}

fn measurementVector(
    allocator: std.mem.Allocator,
    log_size: u8,
) !vector_mod.Owned {
    return switch (log_size) {
        10 => vector_mod.Owned.decodeChecked(
            allocator,
            checked_vectors.poseidon_layout_vector_log10,
            10,
        ),
        14 => vector_mod.Owned.decodeChecked(
            allocator,
            checked_vectors.poseidon_layout_vector_log14,
            14,
        ),
        18 => vector_mod.Owned.generate(allocator, 18, true),
        else => error.UnsupportedVectorLog,
    };
}

const Execution = struct {
    call_digest: [32]u8,
    output_digest: [32]u8,
    trace_digest: [32]u8,
    direct_result_digest: [32]u8,
    direct: direct_benchmark.TraceResult,
};

const Prepared = struct {
    allocator: std.mem.Allocator,
    arm: protocol.Arm,
    log_size: u8,
    authority: proof_authority.Authority,
    decoded: frontier.Decoded,
    cut: cut_set.CutSet,
    layout: layout_executor.Executor,
    program: direct_program.Program,
    direct: direct_benchmark.Evaluator,
    calls: []production.Call,
    trace: OwnedTrace,

    fn init(
        allocator: std.mem.Allocator,
        arm: protocol.Arm,
        log_size: u8,
        calls: []production.Call,
    ) !Prepared {
        var authority = try proof_authority.Authority.init(allocator);
        errdefer authority.deinit();
        const canonical_identity = try authority.programIdentity();
        if (!canonical_identity.isCanonical()) return error.ProgramIdentityMismatch;
        try expectDigest(canonical_identity.semantic_digest, protocol.semantic_digest_hex);

        var decoded = try frontier.decodeAlloc(
            allocator,
            reviewed.h009_poseidon2_frontier,
        );
        errdefer decoded.deinit();
        try protocol.authenticateArtifact(
            reviewed.h009_poseidon2_frontier,
            decoded.view(),
        );
        const fixed_digest = try poseidon_fixed.program.digestValue(allocator);
        try protocol.authenticateFixedProgramDigest(
            fixed_digest,
            decoded.view().cost_model.fixed_program_digest,
        );
        const proposal = selectProposal(decoded.view(), arm);
        var selected: [protocol.materialization_count]types.ValueId = undefined;
        for (proposal.selected_values, &selected) |raw, *value| {
            value.* = try types.idFromIndex(types.ValueId, raw);
        }
        const roots = poseidon.values(authority.definition.outputs);
        var cut = try cut_set.build(allocator, &authority.arena, .{
            .roots = &roots,
            .gate = authority.gate,
            .policy = authority.plan.policy,
        }, &selected);
        errdefer cut.deinit();
        var layout = try layout_executor.Executor.init(
            allocator,
            &authority.arena,
            authority.definition,
            authority.spans,
            &authority.plan,
            &authority.binding,
            &cut,
            decoded.view(),
            if (arm == .compat_seed)
                .baseline
            else
                .{ .frontier = arm.frontierOrdinal().? },
        );
        errdefer layout.deinit();
        var program = try direct_program.extract(allocator, &authority.arena, .{
            .gate = authority.gate,
            .policy = authority.plan.policy,
            .selected = &selected,
            .materialization_column_start = poseidon_fixed.main_prefix_columns,
            .fixed_direct_program = poseidon_fixed.program,
        });
        errdefer program.deinit();
        try validateProgram(&program, proposal);

        var base: [poseidon.WIDTH + 1]direct_benchmark.ValueColumn = undefined;
        base[0] = .{ .value = authority.gate, .physical_column = 0 };
        for (poseidon.values(authority.definition.inputs), 0..) |value, lane| {
            base[lane + 1] = .{ .value = value, .physical_column = lane + 1 };
        }
        var direct = try direct_benchmark.Evaluator.init(
            allocator,
            &program,
            &base,
            layout_executor.N_MAIN_COLUMNS,
        );
        errdefer direct.deinit();
        const rows = @as(usize, 1) << @intCast(log_size);
        if (calls.len != rows) return error.VectorGeometryMismatch;
        var trace = try OwnedTrace.init(allocator, rows);
        errdefer trace.deinit();
        return .{
            .allocator = allocator,
            .arm = arm,
            .log_size = log_size,
            .authority = authority,
            .decoded = decoded,
            .cut = cut,
            .layout = layout,
            .program = program,
            .direct = direct,
            .calls = calls,
            .trace = trace,
        };
    }

    fn deinit(self: *Prepared) void {
        self.trace.deinit();
        self.direct.deinit();
        self.program.deinit();
        self.layout.deinit();
        self.cut.deinit();
        self.decoded.deinit();
        self.authority.deinit();
        self.* = undefined;
    }

    fn execute(self: *Prepared) !Execution {
        try self.layout.generateMainInto(
            &self.trace.mutable,
            self.calls,
            self.log_size,
        );
        return self.observe(try self.direct.evaluateTrace(&self.trace.readonly));
    }

    fn observe(
        self: *Prepared,
        direct_result: direct_benchmark.TraceResult,
    ) !Execution {
        return .{
            .call_digest = vector_mod.callsDigest(self.calls, self.log_size),
            .output_digest = try self.outputsDigest(),
            .trace_digest = traceDigest(&self.trace.readonly, self.log_size),
            .direct_result_digest = try directResultDigest(
                &self.direct,
                direct_result,
            ),
            .direct = direct_result,
        };
    }

    fn validateExecution(self: *Prepared, execution: Execution) !void {
        if (!execution.direct.allRootsZero() or
            execution.direct.rows != self.calls.len or
            execution.direct.root_evaluations !=
                @as(u64, @intCast(self.calls.len)) * protocol.root_count)
        {
            return error.DirectConstraintFailure;
        }
        _ = try self.layout.identity();
        _ = try self.direct.identityDigest();
        try validateProgram(&self.program, selectProposal(self.decoded.view(), self.arm));
    }

    fn outputsDigest(self: *Prepared) ![32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(protocol.output_digest_domain);
        hashInt(&hash, u8, self.log_size);
        hashInt(&hash, u64, self.calls.len);
        for (self.calls, 0..) |call, logical_row| {
            const committed = committedRow(logical_row, self.log_size);
            var row: [layout_executor.N_MAIN_COLUMNS]M31 = undefined;
            for (self.trace.readonly, &row) |column, *value| {
                value.* = column[committed];
            }
            const actual = try self.layout.outputs(&row);
            const expected = production.output(production.fill(call));
            if (!equalM31(&actual, &expected))
                return error.SemanticOutputMismatch;
            for (actual) |value| hashInt(&hash, u32, value.toU32());
        }
        return hash.finalResult();
    }

    fn checkBoundaryAndMutations(self: *Prepared) !void {
        const calls = boundaryCalls();
        try self.layout.generateMainInto(
            &self.trace.mutable,
            &calls,
            self.log_size,
        );
        const direct_result = try self.direct.evaluateTrace(&self.trace.readonly);
        if (!direct_result.allRootsZero() or
            direct_result.root_evaluations !=
                @as(u64, self.trace.rows) * protocol.root_count)
        {
            return error.PaddingOrModeFailure;
        }
        for (calls) |call| {
            var row: [layout_executor.N_MAIN_COLUMNS]M31 = undefined;
            try self.layout.fillRow(&row, call);
            const actual = try self.layout.outputs(&row);
            if (!equalM31(&actual, &production.output(production.fill(call))))
                return error.SemanticOutputMismatch;
        }

        var canary: [layout_executor.N_MAIN_COLUMNS]M31 = undefined;
        const narrow = production.Call.narrow(7, 11);
        try self.layout.fillRow(&canary, narrow);
        for (self.program.selectedColumns(), 0..) |column, ordinal| {
            const physical: usize = @intCast(column.physical_column);
            const saved = canary[physical];
            canary[physical] = saved.add(M31.one());
            const result = try self.direct.evaluateRow(&canary);
            if (result.first_nonzero_root != @as(u32, @intCast(ordinal + 1)))
                return error.MaterializationMutationEscaped;
            canary[physical] = saved;
        }
        try expectMutationRoot(&self.direct, &canary, compat.ENABLER_COLUMN, 2, 0);
        try expectMutationRoot(&self.direct, &canary, compat.WIDE_COLUMN, 2, 427);
        try expectMutationRoot(&self.direct, &canary, compat.IO_COLUMN, 2, 428);
        canary[compat.WIDE_COLUMN] = M31.one();
        canary[compat.IO_COLUMN] = M31.one();
        const exclusion = try self.direct.evaluateRow(&canary);
        if (exclusion.first_nonzero_root != 429)
            return error.FixedRoleMutationEscaped;
    }
};

const OwnedTrace = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    mutable: [layout_executor.N_MAIN_COLUMNS][]M31,
    readonly: [layout_executor.N_MAIN_COLUMNS][]const M31,
    rows: usize,

    fn init(allocator: std.mem.Allocator, rows: usize) !OwnedTrace {
        const cells = try std.math.mul(usize, layout_executor.N_MAIN_COLUMNS, rows);
        const storage = try allocator.alloc(M31, cells);
        var mutable: [layout_executor.N_MAIN_COLUMNS][]M31 = undefined;
        var readonly: [layout_executor.N_MAIN_COLUMNS][]const M31 = undefined;
        for (&mutable, &readonly, 0..) |*write_view, *read_view, column| {
            write_view.* = storage[column * rows ..][0..rows];
            read_view.* = write_view.*;
        }
        return .{
            .allocator = allocator,
            .storage = storage,
            .mutable = mutable,
            .readonly = readonly,
            .rows = rows,
        };
    }

    fn deinit(self: *OwnedTrace) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

fn selectProposal(manifest: frontier.Manifest, arm: protocol.Arm) frontier.Proposal {
    return if (arm.frontierOrdinal()) |ordinal|
        manifest.frontier[ordinal]
    else
        manifest.baseline;
}

fn validateProgram(
    program: *const direct_program.Program,
    proposal: frontier.Proposal,
) !void {
    const counts = program.counts;
    const cost = proposal.cost;
    if (counts.nodes != cost.canonical_direct_nodes or
        counts.root_uses != cost.direct_roots or
        counts.additions != cost.canonical_direct_additions or
        counts.subtractions != cost.canonical_direct_subtractions or
        counts.negations != cost.canonical_direct_negations or
        counts.multiplications != cost.canonical_direct_multiplications or
        counts.unique_committed_column_reads != cost.unique_committed_column_reads or
        counts.streaming_peak_live_nodes != cost.canonical_streaming_peak_live_nodes or
        program.selectedColumns().len != proposal.selected_values.len)
    {
        return error.DirectProgramCostMismatch;
    }
    for (program.selectedColumns(), proposal.selected_values, 0..) |column, raw, ordinal| {
        if (@intFromEnum(column.source_value) != raw or
            column.physical_column != poseidon_fixed.main_prefix_columns + ordinal)
        {
            return error.DirectProgramLayoutMismatch;
        }
    }
}

fn validateVectorExecution(
    identity: protocol.VectorIdentity,
    execution: Execution,
    arm: protocol.Arm,
) !void {
    try protocol.authenticateVector(identity);
    if (!std.mem.eql(u8, &identity.call_digest, &execution.call_digest) or
        !std.mem.eql(u8, &identity.output_digest, &execution.output_digest))
    {
        return error.VectorIdentityMismatch;
    }
    try protocol.authenticateTrace(arm, identity.log_size, execution.trace_digest);
}

fn boundaryCalls() [5]production.Call {
    return .{
        production.Call.narrow(0, 0),
        production.Call.narrowWithOutput(7, 11, 19),
        .{ .input = .{1} ** poseidon.WIDTH, .wide = true },
        .{ .input = .{2} ** poseidon.WIDTH, .io = true },
        .{ .input = .{0x7fff_fffe} ** poseidon.WIDTH },
    };
}

fn expectMutationRoot(
    evaluator: *direct_benchmark.Evaluator,
    row: *[layout_executor.N_MAIN_COLUMNS]M31,
    column: usize,
    value: u32,
    expected_root: u32,
) !void {
    const saved = row[column];
    row[column] = M31.fromCanonical(value);
    const result = try evaluator.evaluateRow(row);
    row[column] = saved;
    if (result.first_nonzero_root != expected_root)
        return error.FixedRoleMutationEscaped;
}

fn equalM31(lhs: *const [poseidon.WIDTH]M31, rhs: *const [poseidon.WIDTH]M31) bool {
    for (lhs, rhs) |left, right| {
        if (left.toU32() != right.toU32()) return false;
    }
    return true;
}

fn traceDigest(
    columns: *const [layout_executor.N_MAIN_COLUMNS][]const M31,
    log_size: u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(protocol.trace_digest_domain);
    hashInt(&hash, u8, log_size);
    hashInt(&hash, u32, columns.len);
    hashInt(&hash, u64, columns[0].len);
    for (columns) |column| for (column) |value| {
        hashInt(&hash, u32, value.toU32());
    };
    return hash.finalResult();
}

fn directResultDigest(
    evaluator: *const direct_benchmark.Evaluator,
    result: direct_benchmark.TraceResult,
) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(direct_result_domain);
    hash.update(&(try evaluator.identityDigest()));
    hashInt(&hash, u64, result.rows);
    hashInt(&hash, u64, result.root_evaluations);
    hashInt(&hash, u64, result.nonzero_roots);
    hashInt(&hash, u32, result.sink.toU32());
    return hash.finalResult();
}

fn committedRow(logical_row: usize, log_size: u8) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

fn writeSampleJson(
    prepared: Prepared,
    execution: Execution,
    peak_rss: rss.Peak,
    vector_identity: protocol.VectorIdentity,
    vector_storage_class: vector_mod.StorageClass,
    setup_ns: u64,
    witness_ns: u64,
    direct_ns: u64,
) !void {
    const proposal = selectProposal(prepared.decoded.view(), prepared.arm);
    const layout_identity = try prepared.layout.identity();
    const program_digest = prepared.program.programDigest();
    const evaluator_digest = try prepared.direct.identityDigest();
    const storage_profile = prepared.layout.storageProfile();
    const semantic_retained_scratch = std.math.mul(
        u64,
        @intCast(storage_profile.semantic_scratch_elements),
        @intCast(storage_profile.field_element_bytes),
    ) catch return error.ScratchSizeOverflow;
    const retained_scratch = try prepared.direct.retainedScratchBytes();
    const proposal_hex = std.fmt.bytesToHex(proposal.proposal_digest, .lower);
    const cut_hex = std.fmt.bytesToHex(proposal.cut_digest, .lower);
    const semantic_execution_hex = std.fmt.bytesToHex(
        layout_identity.semantic_execution_digest,
        .lower,
    );
    const layout_hex = std.fmt.bytesToHex(layout_identity.layout_digest, .lower);
    const program_hex = std.fmt.bytesToHex(program_digest, .lower);
    const evaluator_hex = std.fmt.bytesToHex(evaluator_digest, .lower);
    const calls_hex = std.fmt.bytesToHex(execution.call_digest, .lower);
    const outputs_hex = std.fmt.bytesToHex(execution.output_digest, .lower);
    const trace_hex = std.fmt.bytesToHex(execution.trace_digest, .lower);
    const direct_hex = std.fmt.bytesToHex(execution.direct_result_digest, .lower);
    const vector_seal_hex = std.fmt.bytesToHex(
        vector_identity.vector_seal,
        .lower,
    );
    const vector_artifact_sha256_hex = std.fmt.bytesToHex(
        vector_identity.vector_artifact_sha256,
        .lower,
    );
    try writeJsonLine(.{
        .schema = protocol.schema,
        .schema_version = protocol.schema_version,
        .classification = "experimental_uncommitted_timing",
        .benchmark_id = protocol.benchmark_id,
        .evaluator = protocol.evaluator,
        .backend = protocol.backend,
        .measurement_scope = protocol.measurement_scope,
        .optimization_mode = @tagName(builtin.mode),
        .zig_version = builtin.zig_version_string,
        .target = target_label,
        .allocator = "libc-c-allocator",
        .monotonic_clock = "std.time.Timer",
        .arm = prepared.arm.id(),
        .frontier_ordinal = prepared.arm.frontierOrdinal(),
        .log_size = prepared.log_size,
        .rows = prepared.calls.len,
        .setup_ns = setup_ns,
        .witness_ns = witness_ns,
        .direct_ns = direct_ns,
        .peak_rss_native_value = peak_rss.native_value,
        .peak_rss_native_unit = peak_rss.unit.label(),
        .peak_rss_bytes = peak_rss.bytes,
        .resource_source = peak_rss.source,
        .vector_storage_class = vector_storage_class.id(),
        .vector_seal = vector_seal_hex[0..],
        .vector_artifact_sha256 = vector_artifact_sha256_hex[0..],
        .vector_bytes = vector_identity.artifact_bytes,
        .root_evaluations = execution.direct.root_evaluations,
        .nonzero_roots = execution.direct.nonzero_roots,
        .direct_sink = execution.direct.sink.toU32(),
        .artifact_digest = protocol.artifact_sha256_hex,
        .cut_digest = cut_hex[0..],
        .proposal_digest = proposal_hex[0..],
        .layout_digest = layout_hex[0..],
        .direct_program_digest = program_hex[0..],
        .evaluator_digest = evaluator_hex[0..],
        .output_digest = outputs_hex[0..],
        .trace_digest = trace_hex[0..],
        .trace_digest_class = "candidate_layout_regression_pin_not_correctness_oracle",
        .call_schedule = protocol.call_schedule,
        .call_digest = calls_hex[0..],
        .semantic_execution_digest = semantic_execution_hex[0..],
        .direct_result_digest = direct_hex[0..],
        .main_columns = layout_executor.N_MAIN_COLUMNS,
        .materializations = layout_executor.N_MATERIALIZATIONS,
        .direct_nodes = prepared.program.counts.nodes,
        .direct_roots = prepared.program.counts.root_uses,
        .semantic_retained_scratch_bytes = semantic_retained_scratch,
        .direct_retained_scratch_bytes = retained_scratch,
        .allocation_free_timed_row_loops = true,
        .valid = true,
        .proof_executed = false,
        .verification_executed = false,
        .hash_component_shell_executed = false,
        .logup_executed = false,
        .commitment_executed = false,
        .pcs_executed = false,
        .metal_candidate_execution_supported = false,
        .production_layout_changed = false,
        .promotion_authority = false,
        .status = "pass",
    });
}

fn writeJsonLine(value: anytype) !void {
    var buffer: [16 * 1024]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    try std.json.Stringify.value(value, .{}, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn expectDigest(actual: [32]u8, expected_hex: []const u8) !void {
    const actual_hex = std.fmt.bytesToHex(actual, .lower);
    if (!std.mem.eql(u8, &actual_hex, expected_hex))
        return error.ArtifactIdentityMismatch;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
