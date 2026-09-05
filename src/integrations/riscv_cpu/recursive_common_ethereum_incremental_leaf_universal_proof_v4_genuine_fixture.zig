//! Self-contained two-leaf Stage-101 fixture for the genuine role-0 proof.
//!
//! One segmented Ethereum execution retires recovery in leaf zero and Keccak
//! in leaf one. Leaf zero closes through the authenticated kind-3 program
//! fetch; leaf one reaches the declared self-loop. The two Stage-101 proofs
//! are produced sequentially and cross canonical decode plus independent q193
//! verification only when the caller opens their returned bytes.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");
const authority_v1 = @import("ethereum_incremental_boundary_authority_v1.zig");
const boundary_capture = @import("ethereum_incremental_boundary_capture_v2.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const full_leaf = @import("ethereum_incremental_full_leaf_proof_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");
const runtime_mod =
    @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const public_data = frontend.air.public_data;
const recovery_abi = frontend.isa.ethereum_signer_recovery;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const span = frontend.recursion.span_statement;
pub const Stage101ExecutionOptions = frontend.testing
    .incremental_ethereum_orchestration_v4_internal.ExecutionOptions;
const ExecutionOptions = Stage101ExecutionOptions;

pub const LEAF_COUNT: usize = 2;
pub const THREE_LEAF_COUNT: usize = 3;
pub const FIRST_SEGMENT_STEP_BUDGET: usize = 3;
pub const MIDDLE_SEGMENT_STEP_BUDGET: usize = 1;
pub const FINAL_SEGMENT_STEP_BUDGET: usize = 16;

const input_bytes = [_]u8{ 0, 0, 0, 0 };
const input_address: u32 = 0x0010_0274;

pub fn OwnedArtifactsV4(comptime Engine: type) type {
    comptime {
        _ = Engine;
    }
    return struct {
        allocator: std.mem.Allocator,
        bytes: [LEAF_COUNT][]u8,
        execution_receipt: ?runtime_mod.Stage101ExecutionReceiptV4,

        pub fn deinit(self: *@This()) void {
            for (self.bytes) |bytes| self.allocator.free(bytes);
            self.* = undefined;
        }
    };
}

pub fn OwnedThreeArtifactsV4(comptime Engine: type) type {
    comptime {
        _ = Engine;
    }
    return struct {
        allocator: std.mem.Allocator,
        bytes: [THREE_LEAF_COUNT][]u8,
        execution_receipt: ?runtime_mod.Stage101ExecutionReceiptV4,

        pub fn deinit(self: *@This()) void {
            for (self.bytes) |bytes| self.allocator.free(bytes);
            self.* = undefined;
        }
    };
}

/// Produces two independent Stage-101 proof artifacts. No Stage-102 input,
/// campaign authority, or verifier capability is synthesized here.
pub fn buildArtifacts(
    comptime Engine: type,
    allocator: std.mem.Allocator,
) !OwnedArtifactsV4(Engine) {
    return buildArtifactsInternal(Engine, allocator, .{}, null);
}

pub fn buildArtifactsWithExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    proof_execution: ExecutionOptions,
) !OwnedArtifactsV4(Engine) {
    const receipt = try runtime_mod.Stage101ExecutionReceiptV4.mint(
        proof_execution.cpu orelse
            return error.InvalidRole0GenuineExecutionReceipt,
        LEAF_COUNT,
    );
    return buildArtifactsInternal(
        Engine,
        allocator,
        proof_execution,
        receipt,
    );
}

/// Produces three independent Stage-101 proof artifacts from one canonical
/// Ethereum execution. The middle leaf retires only the ADDI between recovery
/// and Keccak, so it exercises the authenticated kind-3 program-fetch
/// completion without inventing an opcode row or rewriting declared ROM.
pub fn buildThreeArtifacts(
    comptime Engine: type,
    allocator: std.mem.Allocator,
) !OwnedThreeArtifactsV4(Engine) {
    return buildThreeArtifactsInternal(Engine, allocator, .{}, null);
}

pub fn buildThreeArtifactsWithExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    proof_execution: ExecutionOptions,
) !OwnedThreeArtifactsV4(Engine) {
    const receipt = try runtime_mod.Stage101ExecutionReceiptV4.mint(
        proof_execution.cpu orelse
            return error.InvalidRole0GenuineExecutionReceipt,
        THREE_LEAF_COUNT,
    );
    return buildThreeArtifactsInternal(
        Engine,
        allocator,
        proof_execution,
        receipt,
    );
}

fn buildArtifactsInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    proof_execution: ExecutionOptions,
    execution_receipt: ?runtime_mod.Stage101ExecutionReceiptV4,
) !OwnedArtifactsV4(Engine) {
    comptime requireEngine(Engine);
    var elf = ethereumWithUntouchedInput();
    var session = try runner.EthereumExecutionSession.init(
        allocator,
        &elf,
        .{
            .input = &input_bytes,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
        },
    );
    defer session.deinit();
    var first = try session.startSegment(FIRST_SEGMENT_STEP_BUDGET);
    defer first.deinit();
    const continuation = first.base.continuation orelse
        return error.InvalidRole0GenuineFixture;
    var second = try session.resumeSegment(
        continuation,
        FINAL_SEGMENT_STEP_BUDGET,
    );
    defer second.deinit();
    try validateExecutionPair(&first, &second);

    var program = try frontend.air.program.commitment
        .buildDeclaredForProfileSources(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{
            first.base.execution_trace.rows.items,
            second.base.execution_trace.rows.items,
            first.keccakf_execution_rows.rows(),
            second.keccakf_execution_rows.rows(),
            first.signer_recovery_execution_rows.rows(),
            second.signer_recovery_execution_rows.rows(),
        },
        first.base.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);

    const roots = [LEAF_COUNT]RootPair{
        try rootsForSegment(allocator, &first.base),
        try rootsForSegment(allocator, &second.base),
    };
    if (roots[0].exit != roots[1].entry)
        return error.InvalidRole0GenuineFixture;
    const input_digest = digest("role0-genuine-campaign-input");
    const output_digest = digest("role0-genuine-campaign-output");
    const states = [LEAF_COUNT + 1]span.MachineState{
        try machineState(
            first.base.entry_cpu,
            scalarDigest(roots[0].entry),
            digest("role0-genuine-io-entry"),
        ),
        try machineState(
            first.base.exit_cpu,
            scalarDigest(roots[0].exit),
            digest("role0-genuine-io-shared"),
        ),
        try machineState(
            second.base.exit_cpu,
            scalarDigest(roots[1].exit),
            digest("role0-genuine-io-exit"),
        ),
    };
    const total_cycles = std.math.add(
        u64,
        @intCast(first.base.cycle_count),
        @intCast(second.base.cycle_count),
    ) catch return error.InvalidRole0GenuineFixture;
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            states[0],
            states[2],
            input_digest,
            output_digest,
            total_cycles,
        ),
        LEAF_COUNT,
    );

    var capture = try boundary_capture.SessionCaptureV2.init(
        allocator,
        digestBytes("role0-genuine-boundary-session"),
        0,
        &first.base.rw_memory,
        roots[0].entry,
    );
    defer capture.deinit();

    const first_bytes = try proveSegment(
        Engine,
        allocator,
        &first,
        job,
        states[0],
        states[1],
        try span.EdgeClaim.present(input_digest),
        span.EdgeClaim.absent(),
        &capture,
        roots[0],
        proof_execution,
    );
    errdefer allocator.free(first_bytes);
    const second_bytes = try proveSegment(
        Engine,
        allocator,
        &second,
        job,
        states[1],
        states[2],
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(output_digest),
        &capture,
        roots[1],
        proof_execution,
    );
    errdefer allocator.free(second_bytes);
    if (capture.nextSegmentIndex() != LEAF_COUNT)
        return error.InvalidRole0GenuineFixture;
    return .{
        .allocator = allocator,
        .bytes = .{ first_bytes, second_bytes },
        .execution_receipt = execution_receipt,
    };
}

fn buildThreeArtifactsInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    proof_execution: ExecutionOptions,
    execution_receipt: ?runtime_mod.Stage101ExecutionReceiptV4,
) !OwnedThreeArtifactsV4(Engine) {
    comptime requireEngine(Engine);
    var elf = ethereumWithUntouchedInput();
    var session = try runner.EthereumExecutionSession.init(
        allocator,
        &elf,
        .{
            .input = &input_bytes,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
        },
    );
    defer session.deinit();
    var first = try session.startSegment(FIRST_SEGMENT_STEP_BUDGET);
    defer first.deinit();
    const first_continuation = first.base.continuation orelse
        return error.InvalidRole0GenuineFixture;
    var middle = try session.resumeSegment(
        first_continuation,
        MIDDLE_SEGMENT_STEP_BUDGET,
    );
    defer middle.deinit();
    const middle_continuation = middle.base.continuation orelse
        return error.InvalidRole0GenuineFixture;
    var final = try session.resumeSegment(
        middle_continuation,
        FINAL_SEGMENT_STEP_BUDGET,
    );
    defer final.deinit();
    try validateExecutionTriple(&first, &middle, &final);

    var program = try frontend.air.program.commitment
        .buildDeclaredForProfileSources(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{
            first.base.execution_trace.rows.items,
            middle.base.execution_trace.rows.items,
            final.base.execution_trace.rows.items,
            first.keccakf_execution_rows.rows(),
            middle.keccakf_execution_rows.rows(),
            final.keccakf_execution_rows.rows(),
            first.signer_recovery_execution_rows.rows(),
            middle.signer_recovery_execution_rows.rows(),
            final.signer_recovery_execution_rows.rows(),
        },
        first.base.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);

    const roots = [THREE_LEAF_COUNT]RootPair{
        try rootsForSegment(allocator, &first.base),
        try rootsForSegment(allocator, &middle.base),
        try rootsForSegment(allocator, &final.base),
    };
    if (roots[0].exit != roots[1].entry or
        roots[1].exit != roots[2].entry)
    {
        return error.InvalidRole0GenuineFixture;
    }
    const input_digest = digest("role0-genuine-three-campaign-input");
    const output_digest = digest("role0-genuine-three-campaign-output");
    const states = [THREE_LEAF_COUNT + 1]span.MachineState{
        try machineState(
            first.base.entry_cpu,
            scalarDigest(roots[0].entry),
            digest("role0-genuine-three-io-entry"),
        ),
        try machineState(
            first.base.exit_cpu,
            scalarDigest(roots[0].exit),
            digest("role0-genuine-three-io-after-recovery"),
        ),
        try machineState(
            middle.base.exit_cpu,
            scalarDigest(roots[1].exit),
            digest("role0-genuine-three-io-before-keccak"),
        ),
        try machineState(
            final.base.exit_cpu,
            scalarDigest(roots[2].exit),
            digest("role0-genuine-three-io-exit"),
        ),
    };
    const first_two_cycles = std.math.add(
        u64,
        @intCast(first.base.cycle_count),
        @intCast(middle.base.cycle_count),
    ) catch return error.InvalidRole0GenuineFixture;
    const total_cycles = std.math.add(
        u64,
        first_two_cycles,
        @intCast(final.base.cycle_count),
    ) catch return error.InvalidRole0GenuineFixture;
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            states[0],
            states[3],
            input_digest,
            output_digest,
            total_cycles,
        ),
        THREE_LEAF_COUNT,
    );

    var capture = try boundary_capture.SessionCaptureV2.init(
        allocator,
        digestBytes("role0-genuine-three-boundary-session"),
        0,
        &first.base.rw_memory,
        roots[0].entry,
    );
    defer capture.deinit();

    const first_bytes = try proveSegment(
        Engine,
        allocator,
        &first,
        job,
        states[0],
        states[1],
        try span.EdgeClaim.present(input_digest),
        span.EdgeClaim.absent(),
        &capture,
        roots[0],
        proof_execution,
    );
    errdefer allocator.free(first_bytes);
    const middle_bytes = try proveSegment(
        Engine,
        allocator,
        &middle,
        job,
        states[1],
        states[2],
        span.EdgeClaim.absent(),
        span.EdgeClaim.absent(),
        &capture,
        roots[1],
        proof_execution,
    );
    errdefer allocator.free(middle_bytes);
    const final_bytes = try proveSegment(
        Engine,
        allocator,
        &final,
        job,
        states[2],
        states[3],
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(output_digest),
        &capture,
        roots[2],
        proof_execution,
    );
    errdefer allocator.free(final_bytes);
    if (capture.nextSegmentIndex() != THREE_LEAF_COUNT)
        return error.InvalidRole0GenuineFixture;
    return .{
        .allocator = allocator,
        .bytes = .{ first_bytes, middle_bytes, final_bytes },
        .execution_receipt = execution_receipt,
    };
}

fn proveSegment(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    configured: *const runner.EthereumSegmentResult,
    job: span.JobContext,
    entry_state: span.MachineState,
    exit_state: span.MachineState,
    input_edge: span.EdgeClaim,
    output_edge: span.EdgeClaim,
    capture: *boundary_capture.SessionCaptureV2,
    roots: RootPair,
    proof_execution: ExecutionOptions,
) ![]u8 {
    const global_leaf = try leafStatement(
        job,
        &configured.base,
        entry_state,
        exit_state,
        input_edge,
        output_edge,
    );
    const global_source = try global_v3.SourceV3.fromSegmentResult(
        global_leaf,
        &configured.base,
    );
    var projection = try projection_v3.ProjectionV3.init(&global_source);
    const source = try projection.sourceV2(
        &global_source,
        digest("role0-genuine-segment-session"),
    );
    try validateLocalRegisterClocks(&projection.local_result);
    try rejectOutOfRangeRegisterClock(&projection, &global_source);
    var local_configured = configured.*;
    local_configured.base = projection.local_result;
    const local = &local_configured;
    const execution = &local.base;
    const canonical_words = try encodeSegment(allocator, &source);
    defer allocator.free(canonical_words);
    const public_wire = try frontend.air.public_data_v2.PublicDataV2
        .authenticate(canonical_words);
    const metadata = try public_wire.metadata();
    if (metadata.entry_continuation_root != roots.entry or
        metadata.exit_continuation_root != roots.exit)
    {
        return error.InvalidRole0GenuineFixture;
    }

    var role_public = try OwnedRolePublic.init(
        allocator,
        &public_wire,
        execution,
    );
    defer role_public.deinit();
    const public_authority = boundary_v4.SegmentPublicAuthorityV4{
        .coordinate = .{
            .segment_index = metadata.segment_index,
            .segment_count = metadata.segment_count,
        },
        .segment_role = execution.segment_role,
        .layout = execution.rw_memory.layout,
        .public_data = &role_public.value,
        .continuation_roots = .{ .entry = roots.entry, .exit = roots.exit },
    };
    try public_authority.validate();

    var boundary_artifact = try buildBoundaryArtifact(
        allocator,
        local,
        capture,
        &public_wire,
        public_authority,
        roots,
    );
    defer boundary_artifact.deinit();
    const completion = role_public.value.completion orelse
        return error.InvalidRole0GenuineFixture;
    var prepared = try full_leaf.prepareFullWitnessFromColdArtifact(
        allocator,
        .{
            execution.execution_trace.rows.items,
            local.keccakf_execution_rows.rows(),
            local.signer_recovery_execution_rows.rows(),
        },
        &execution.rw_memory,
        completion,
        &boundary_artifact,
        &public_wire,
        public_authority,
        artifact_v4.default_limits,
    );
    defer prepared.deinit(allocator);

    const external_count = std.math.add(
        usize,
        local.keccakf_calls.len(),
        local.signer_recovery_calls.len(),
    ) catch return error.InvalidRole0GenuineFixture;
    const native = try full_leaf.prepareStatement(
        allocator,
        &execution.execution_trace,
        &execution.state_chain_tracker,
        &prepared,
        public_wire,
        @intCast(external_count),
    );
    const core_public = try frontend.air.statement_v2
        .canonicalCorePublicData(&native.public_data);
    var ethereum_witness = try prover.guest_precompile.ethereum_witness.Witness
        .init(
        allocator,
        local.keccakf_calls.records(),
        local.keccakf_execution_rows.rows(),
        local.signer_recovery_calls.records(),
        local.signer_recovery_execution_rows.rows(),
        core_public.clock,
    );
    defer ethereum_witness.deinit();
    const extension = try frontend.air.guest_precompile.ethereum_statement
        .Statement.canonicalV2(
        &native,
        @intCast(local.keccakf_calls.len()),
        @intCast(local.signer_recovery_calls.len()),
        ethereum_witness.shapes(),
    );
    const profile = try prepared.mintProfile(
        &boundary_artifact,
        public_authority,
        &native,
        &extension,
    );
    try profile.validateAgainstInputs(
        allocator,
        &boundary_artifact,
        &public_wire,
        public_authority,
        &native,
        &extension,
        artifact_v4.default_limits,
    );

    var prove_channel = Engine.Channel{};
    var output = try full_leaf.proveWithEngineUsingChannel(
        Engine,
        allocator,
        &execution.execution_trace,
        &execution.state_chain_tracker,
        &prepared,
        &native,
        &role_public.value,
        &local.keccakf_calls,
        &local.keccakf_execution_rows,
        &local.signer_recovery_calls,
        &local.signer_recovery_execution_rows,
        &profile,
        null,
        &prove_channel,
        proof_execution,
    );
    defer output.deinit(allocator);
    return proof_artifact.encodeAlloc(
        Engine,
        allocator,
        .{
            .statement = &output.statement,
            .role_aware_public = &role_public.value,
            .extension = &output.extension,
            .profile = &profile,
            .base_claim = output.claims.base,
            .extension_claim = &output.claims.ethereum,
            .bridge_claim = output.claims.bridge,
            .proof = &output.proof,
        },
        .{},
    );
}

/// The global span remains in `global_source`; only the existing V3 adapter
/// may project its AIR-visible clocks into the bounded local V2 frame.
fn validateLocalRegisterClocks(
    result: *const runner.SegmentResult,
) !void {
    const cycle_count = std.math.cast(u32, result.cycle_count) orelse
        return error.InvalidRole0GenuineFixture;
    if (result.clock_frame != .global_continuous or
        result.global_first_cycle != 1 or cycle_count == 0)
    {
        return error.InvalidRole0GenuineFixture;
    }
    for (result.entry_access_clocks.register_clocks) |clock|
        if (clock != 0) return error.InvalidRole0GenuineFixture;
    for (result.exit_access_clocks.register_clocks) |clock|
        if (!frontend.access_clock.isWithinExecution(clock, cycle_count, true))
            return error.InvalidRole0GenuineFixture;
}

/// Mutation pin: a globally-carried predecessor clock must not be accepted as
/// a local V2 boundary simply because the CPU/register values still match.
fn rejectOutOfRangeRegisterClock(
    projection: *const projection_v3.ProjectionV3,
    global_source: *const global_v3.SourceV3,
) !void {
    var mutated = projection.local_result;
    const cycle_count = std.math.cast(u32, mutated.cycle_count) orelse
        return error.InvalidRole0GenuineFixture;
    const next_cycle = std.math.add(u32, cycle_count, 1) catch
        return error.InvalidRole0GenuineFixture;
    mutated.exit_access_clocks.register_clocks[31] =
        frontend.access_clock.encode(next_cycle, .first);
    if (segment_v2.SourceV2.fromSegmentResult(
        digest("role0-genuine-clock-mutation"),
        projection.local_statement,
        &mutated,
    )) |_| {
        return error.InvalidRole0GenuineFixture;
    } else |err| {
        if (err != error.BoundaryClockOutOfRange) return err;
    }
    try projection.validateAgainst(global_source);
}

const OwnedRolePublic = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,

    fn init(
        allocator: std.mem.Allocator,
        native: *const frontend.air.public_data_v2.PublicDataV2,
        execution: *const runner.SegmentResult,
    ) !OwnedRolePublic {
        const input = execution.input orelse &.{};
        const input_words = try public_data.packInputWords(allocator, input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(
            public_data.OutputWord,
            execution.output_words.len,
        );
        errdefer allocator.free(output_words);
        for (output_words, execution.output_words) |*destination, source|
            destination.* = .{
                .addr = source.addr,
                .value = source.value,
                .clock = source.clock,
            };
        var value = try frontend.air.statement_v2.canonicalCorePublicData(native);
        value.completion = try completionFor(execution, value.final_pc);
        value.io_entries = .{
            .input_start = execution.input_start,
            .input_len = @intCast(input.len),
            .input_words = input_words,
            .output_len = execution.output_len,
            .output_len_addr = execution.output_len_addr,
            .output_data_addr = execution.output_data_addr,
            .output_words = output_words,
        };
        try frontend.air.incremental_public_logup_v4.validateSharedAuthority(
            native,
            &value,
        );
        return .{
            .allocator = allocator,
            .input_words = input_words,
            .output_words = output_words,
            .value = value,
        };
    }

    fn deinit(self: *OwnedRolePublic) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }
};

fn completionFor(
    execution: *const runner.SegmentResult,
    final_pc: u32,
) !public_data.Completion {
    if (execution.segment_role.is_last) {
        const retained = execution.completion_reason orelse
            return error.InvalidRole0GenuineFixture;
        if (retained != .self_loop)
            return error.InvalidRole0GenuineFixture;
        return public_data.Completion.canonicalSelfLoop(final_pc);
    }
    if (execution.completion_reason != null or execution.continuation == null)
        return error.InvalidRole0GenuineFixture;
    for (execution.rw_memory.program_words) |word| {
        if (word.addr != final_pc) continue;
        return public_data.Completion.unretiredProgramFetch(
            final_pc,
            word.initial_word,
        );
    }
    return error.InvalidRole0GenuineFixture;
}

fn buildBoundaryArtifact(
    allocator: std.mem.Allocator,
    configured: *const runner.EthereumSegmentResult,
    capture: *boundary_capture.SessionCaptureV2,
    public_wire: *const frontend.air.public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    roots: RootPair,
) !artifact_v4.OwnedArtifactV4 {
    const addresses = try replayTouchedAddresses(allocator, configured);
    defer allocator.free(addresses);
    var transition = try capture.apply(
        configured.base.segment_index,
        &configured.base.rw_memory,
        addresses,
        roots.entry,
        roots.exit,
    );
    defer transition.deinit();
    const transition_bytes = try artifact_v2.encodeAlloc(
        allocator,
        &transition,
        artifact_v2.default_limits,
    );
    defer allocator.free(transition_bytes);
    const bytes = try artifact_v4.encodeAlloc(
        allocator,
        transition_bytes,
        public_wire,
        public_authority,
        artifact_v4.default_limits,
    );
    defer allocator.free(bytes);
    return artifact_v4.decodeAlloc(
        allocator,
        bytes,
        artifact_v4.default_limits,
    );
}

fn replayTouchedAddresses(
    allocator: std.mem.Allocator,
    configured: *const runner.EthereumSegmentResult,
) ![]u32 {
    var unique = std.AutoHashMap(u32, void).init(allocator);
    defer unique.deinit();
    for (configured.base.execution_trace.rows.items) |row| {
        if (row.is_load or row.is_store)
            try unique.put(row.mem_addr & ~@as(u32, 3), {});
    }
    for (configured.keccakf_calls.records()) |record|
        try putWordRange(&unique, record.state_ptr, 0, record.input.len);
    for (configured.signer_recovery_calls.records()) |record| {
        try putWordRange(
            &unique,
            record.io_ptr,
            0,
            recovery_abi.input_word_count,
        );
        try putWordRange(
            &unique,
            record.io_ptr,
            recovery_abi.public_key_offset,
            recovery_abi.output_word_count,
        );
    }
    const result = try allocator.alloc(u32, unique.count());
    errdefer allocator.free(result);
    var iterator = unique.keyIterator();
    var at: usize = 0;
    while (iterator.next()) |address| : (at += 1) result[at] = address.*;
    if (at != result.len) return error.InvalidRole0GenuineFixture;
    std.mem.sort(u32, result, {}, std.sort.asc(u32));
    return result;
}

fn putWordRange(
    addresses: *std.AutoHashMap(u32, void),
    base: u32,
    byte_offset: u32,
    count: usize,
) !void {
    const start = std.math.add(u32, base, byte_offset) catch
        return error.InvalidRole0GenuineFixture;
    for (0..count) |index| {
        const word_offset = std.math.mul(
            u32,
            @intCast(index),
            @sizeOf(u32),
        ) catch return error.InvalidRole0GenuineFixture;
        const address = std.math.add(u32, start, word_offset) catch
            return error.InvalidRole0GenuineFixture;
        try addresses.put(address, {});
    }
}

const RootPair = struct { entry: u32, exit: u32 };

fn rootsForSegment(
    allocator: std.mem.Allocator,
    execution: *const runner.SegmentResult,
) !RootPair {
    return .{
        .entry = try snapshotRoot(allocator, execution.rw_memory.words, .entry),
        .exit = try snapshotRoot(allocator, execution.rw_memory.words, .exit),
    };
}

const SnapshotSide = enum { entry, exit };

fn snapshotRoot(
    allocator: std.mem.Allocator,
    words: []const runner.memory_state.WordState,
    side: SnapshotSide,
) !u32 {
    var sparse: std.ArrayList(authority_v1.SparseWordV1) = .empty;
    defer sparse.deinit(allocator);
    for (words) |word| {
        const value = if (side == .entry)
            word.initial_word
        else
            word.final_word;
        if (value != 0) try sparse.append(allocator, .{
            .address = word.addr,
            .value = value,
        });
    }
    return artifact_v2.testing.fullRoot(allocator, sparse.items);
}

fn validateExecutionPair(
    first: *const runner.EthereumSegmentResult,
    second: *const runner.EthereumSegmentResult,
) !void {
    if (first.base.segment_index != 0 or second.base.segment_index != 1 or
        first.base.clock_frame != .leaf_local or
        second.base.clock_frame != .leaf_local or
        first.base.segment_role.is_last or !second.base.segment_role.is_last or
        first.base.isComplete() or !second.base.isComplete() or
        first.signer_recovery_calls.len() != 1 or
        first.keccakf_calls.len() != 0 or
        second.signer_recovery_calls.len() != 0 or
        second.keccakf_calls.len() != 1 or
        !std.meta.eql(first.base.exit_cpu, second.base.entry_cpu))
    {
        return error.InvalidRole0GenuineFixture;
    }
    var found_untouched = false;
    for (first.base.rw_memory.words) |word| {
        if (word.addr != input_address) continue;
        found_untouched = word.role.is_public_input and
            word.initial_word == 0 and word.final_word == 0 and
            word.final_clock == 0;
    }
    if (!found_untouched) return error.InvalidRole0GenuineFixture;
}

fn validateExecutionTriple(
    first: *const runner.EthereumSegmentResult,
    middle: *const runner.EthereumSegmentResult,
    final: *const runner.EthereumSegmentResult,
) !void {
    if (first.base.segment_index != 0 or
        middle.base.segment_index != 1 or
        final.base.segment_index != 2 or
        first.base.clock_frame != .leaf_local or
        middle.base.clock_frame != .leaf_local or
        final.base.clock_frame != .leaf_local or
        first.base.segment_role.is_last or
        middle.base.segment_role.is_first or
        middle.base.segment_role.is_last or
        !final.base.segment_role.is_last or
        first.base.isComplete() or middle.base.isComplete() or
        !final.base.isComplete() or
        first.signer_recovery_calls.len() != 1 or
        first.keccakf_calls.len() != 0 or
        middle.signer_recovery_calls.len() != 0 or
        middle.keccakf_calls.len() != 0 or
        final.signer_recovery_calls.len() != 0 or
        final.keccakf_calls.len() != 1 or
        !std.meta.eql(first.base.exit_cpu, middle.base.entry_cpu) or
        !std.meta.eql(middle.base.exit_cpu, final.base.entry_cpu))
    {
        return error.InvalidRole0GenuineFixture;
    }
    if (middle.base.execution_trace.rows.items.len !=
        MIDDLE_SEGMENT_STEP_BUDGET)
    {
        return error.InvalidRole0GenuineFixture;
    }
    var found_untouched = false;
    for (first.base.rw_memory.words) |word| {
        if (word.addr != input_address) continue;
        found_untouched = word.role.is_public_input and
            word.initial_word == 0 and word.final_word == 0 and
            word.final_clock == 0;
    }
    if (!found_untouched) return error.InvalidRole0GenuineFixture;
}

fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit_state: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
) !span.SpanStatement {
    if (result.global_first_cycle == 0)
        return error.InvalidRole0GenuineFixture;
    return span.SpanStatement.segmentLeaf(
        job,
        result.segment_index,
        try span.ExecutedSpan.init(
            result.segment_index,
            1,
            result.global_first_cycle - 1,
            @intCast(result.cycle_count),
            entry,
            exit_state,
            input,
            output,
        ),
    );
}

fn machineState(
    cpu: runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

fn encodeSegment(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn ethereumWithUntouchedInput() [frontend.testing.guest_precompile_test_elf.ethereum_elf_size]u8 {
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    const strings_offset: usize = 480;
    const symbols_offset: usize = 560;
    const program_offset: usize = 640;
    const completion_offset = program_offset +
        (frontend.testing.guest_precompile_test_elf.ethereum_instructions.len - 1) *
            @sizeOf(u32);
    std.mem.writeInt(
        u32,
        elf[completion_offset..][0..4],
        public_data.CANONICAL_SELF_LOOP_WORD,
        .little,
    );
    const prior_strings: usize = std.mem.readInt(u32, elf[308..312], .little);
    const extra = "__input_start\x00__input_end\x00";
    @memcpy(elf[strings_offset + prior_strings ..][0..extra.len], extra);
    std.mem.writeInt(
        u32,
        elf[308..312],
        @intCast(prior_strings + extra.len),
        .little,
    );
    std.mem.writeInt(u32, elf[268..272], 5 * 16, .little);
    writeSymbol(
        &elf,
        symbols_offset + 3 * 16,
        @intCast(prior_strings),
        input_address,
    );
    writeSymbol(
        &elf,
        symbols_offset + 4 * 16,
        @intCast(prior_strings + "__input_start\x00".len),
        input_address + input_bytes.len,
    );
    return elf;
}

fn writeSymbol(
    elf: []u8,
    offset: usize,
    name_offset: u32,
    value: u32,
) void {
    @memset(elf[offset..][0..16], 0);
    std.mem.writeInt(u32, elf[offset..][0..4], name_offset, .little);
    std.mem.writeInt(u32, elf[offset + 4 ..][0..4], value, .little);
}

fn digest(label: []const u8) span.Digest {
    return frontend.recursion.poseidon2_channel.hashBytes(label, 0x3446_4549);
}

fn digestBytes(label: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &result, .{});
    return result;
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} **
        frontend.recursion.poseidon2_channel.RATE;
    result[0] = value;
    return result;
}

fn requireEngine(comptime Engine: type) void {
    if (Engine.Hasher.Hash != frontend.recursion.poseidon2_channel.Digest or
        Engine.Channel != frontend.recursion.poseidon2_channel.Channel)
    {
        @compileError("role0 genuine fixture requires q193 Poseidon2 engine");
    }
}

comptime {
    if (LEAF_COUNT != 2 or FIRST_SEGMENT_STEP_BUDGET != 3 or
        THREE_LEAF_COUNT != 3 or MIDDLE_SEGMENT_STEP_BUDGET != 1 or
        FINAL_SEGMENT_STEP_BUDGET < 3)
    {
        @compileError("role0 genuine fixture topology drifted");
    }
}
