//! VM-free producer for one full Ethereum + incremental-memory V4 leaf.
//!
//! The compact tape reconstructs every base/Keccak/recovery execution row.
//! Program words come from an independently admitted ELF, while STWIMT04 and
//! the canonical public wire reconstruct the incremental memory bridge.  The
//! caller supplies plan-owned source/CPU/completion authority explicitly;
//! those values are never copied from the resealable tape being admitted.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const stage_profile = @import("stwo_prover_api").stage_profile;

const boundary_artifact =
    @import("ethereum_incremental_boundary_artifact_v4.zig");
const boundary_authority =
    @import("ethereum_incremental_boundary_authority_v4.zig");
const full_leaf = @import("ethereum_incremental_full_leaf_proof_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");

const minimal = frontend.runner.minimal_trace;
const memory_state = frontend.runner.memory_state;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const prover = frontend.prover_mod;

pub const FORMAT_VERSION: u16 = 4;
pub const PRODUCTION_ACTIVE = false;

/// Process-local timing evidence for the six transaction stages owned here.
/// It is deliberately excluded from every proof/artifact codec and may only
/// be populated after a successful canonical encode.
pub const TimingReceiptV1 = struct {
    transaction_ns: u64,
    input_admission_ns: u64,
    compact_replay_ns: u64,
    witness_prepare_ns: u64,
    statement_profile_prepare_ns: u64,
    prove_ns: u64,
    encode_ns: u64,
};

/// Immutable program custody reconstructed from the admitted ELF.  Both
/// representations share the same canonical address ordering: `minimal_words`
/// feeds replay, while `statement_words` feeds the program commitment.
pub const ProgramV4 = struct {
    allocator: std.mem.Allocator,
    layout: memory_state.MemoryLayout,
    minimal_words: []minimal.ProgramWord,
    statement_words: []memory_state.WordState,
    program: minimal.SliceProgram,

    pub fn init(
        allocator: std.mem.Allocator,
        elf_bytes: []const u8,
    ) !ProgramV4 {
        var memory = try frontend.runner.Memory.initFallible(allocator);
        defer memory.deinit();
        const elf = try frontend.runner.elf_loader.loadElfForProfile(
            elf_bytes,
            &memory,
            .rv32im_zkvm_ethereum_v1,
        );
        const initialized = try memory.canonicalAlignedWordAddresses();
        var count: usize = 0;
        for (initialized) |address|
            count += @intFromBool(elf.memory_layout.isProgramAddr(address));
        if (count == 0) return error.EmptyProgram;

        const minimal_words = try allocator.alloc(minimal.ProgramWord, count);
        errdefer allocator.free(minimal_words);
        const statement_words = try allocator.alloc(memory_state.WordState, count);
        errdefer allocator.free(statement_words);
        var at: usize = 0;
        for (initialized) |address| {
            if (!elf.memory_layout.isProgramAddr(address)) continue;
            const word = memory.readU32(address);
            minimal_words[at] = .{ .address = address, .word = word };
            statement_words[at] = .{
                .addr = address,
                .initial_word = word,
                .final_word = word,
                .final_clock = 0,
            };
            at += 1;
        }
        if (at != count) return error.InvalidProgramInventory;
        const program = try minimal.SliceProgram.init(minimal_words);
        return .{
            .allocator = allocator,
            .layout = elf.memory_layout,
            .minimal_words = minimal_words,
            .statement_words = statement_words,
            .program = program,
        };
    }

    pub fn deinit(self: *ProgramV4) void {
        self.allocator.free(self.statement_words);
        self.allocator.free(self.minimal_words);
        self.* = undefined;
    }

    /// Derive the proof-role completion from the separately admitted ELF.
    /// Nonfinal SegmentV2 leaves deliberately carry no completion.  Older
    /// retained role projections use the self-loop placeholder; the V4
    /// postprocessor already supplies the exact role-only program fetch.  In
    /// either case, admit only the word fetched from the separately opened ELF.
    /// Final runner completions remain untouched.
    pub fn completionForProof(
        self: *const ProgramV4,
        role: memory_state.SegmentRole,
        retained: public_data.Completion,
    ) !public_data.Completion {
        if (role.is_last) {
            if (retained.kind == .unretired_program_fetch)
                return error.InvalidIncrementalLeafCompletionProgramV4;
            return retained;
        }
        const word = self.program.source().fetch(retained.address) catch
            return error.InvalidIncrementalLeafCompletionProgramV4;
        return switch (retained.kind) {
            .unretired_self_loop => public_data.Completion
                .unretiredProgramFetch(retained.address, word),
            .unretired_program_fetch => if (retained.value == word and
                retained.clock == 0)
                retained
            else
                error.InvalidIncrementalLeafCompletionProgramV4,
            .halt_flag => error.InvalidIncrementalLeafCompletionProgramV4,
        };
    }

    /// Build the declared-program view used by this leaf proof. Completion
    /// fetches are exact reads of the admitted ELF; this function never
    /// overlays or relabels a declared word, including when the same address
    /// was already fetched earlier in the segment.
    pub fn snapshotForCompletion(
        self: *const ProgramV4,
        allocator: std.mem.Allocator,
        role: memory_state.SegmentRole,
        completion: public_data.Completion,
    ) !OwnedProgramSnapshotV4 {
        switch (completion.kind) {
            .halt_flag => {},
            .unretired_self_loop, .unretired_program_fetch => {
                const declared = self.program.source().fetch(
                    completion.address,
                ) catch return error.InvalidIncrementalLeafCompletionProgramV4;
                if (declared != completion.value)
                    return error.InvalidIncrementalLeafCompletionProgramV4;
            },
        }
        const words = try allocator.dupe(
            memory_state.WordState,
            self.statement_words,
        );
        errdefer allocator.free(words);
        return .{
            .allocator = allocator,
            .program_words = words,
            .value = .{
                .layout = self.layout,
                .segment_role = role,
                .words = &.{},
                .program_words = words,
            },
        };
    }
};

pub const OwnedProgramSnapshotV4 = struct {
    allocator: std.mem.Allocator,
    program_words: []memory_state.WordState,
    value: memory_state.Snapshot,

    pub fn deinit(self: *OwnedProgramSnapshotV4) void {
        self.allocator.free(self.program_words);
        self.* = undefined;
    }
};

/// Plan-owned authority for replay.  It is intentionally distinct from the
/// compact leaf: validating a tape against values copied out of that same tape
/// would make a content checksum masquerade as execution admission.
pub const ReplayAuthorityV4 = struct {
    source: minimal.ethereum_types.SourceIdentityV1,
    global_first_cycle: u64,
    entry_cpu_sha256: [32]u8,
    exit_cpu_sha256: [32]u8,
    completion: ?minimal.ethereum_types.CompletionV1,

    pub fn validate(self: ReplayAuthorityV4) !void {
        try self.source.validate();
        if (self.global_first_cycle == 0 or
            allZero(&self.entry_cpu_sha256) or
            allZero(&self.exit_cpu_sha256))
            return error.InvalidIncrementalReplayAuthorityV4;
    }
};

/// Borrowed, already-opened inputs for one proof transaction.  Every durable
/// object is revalidated here or by `prepareFullWitnessFromColdArtifact`.
pub const ColdInputV4 = struct {
    compact: *const minimal.EthereumMinimalArtifactV1,
    public_wire: *const public_data_v2.PublicDataV2,
    role_aware_public: *const public_data.PublicData,
    public_authority: boundary_authority.SegmentPublicAuthorityV4,
    boundary: *const boundary_artifact.OwnedArtifactV4,
    program: *const ProgramV4,
    replay_authority: ReplayAuthorityV4,
    validation_counters: ?*public_data_v2.PublicDataV2.ValidationCountersV2 =
        null,

    pub fn validate(self: ColdInputV4) !void {
        // Validate the value-only plan authority before touching any borrowed
        // transport. This also gives malformed requests deterministic error
        // precedence at the process boundary.
        try self.replay_authority.validate();
        try self.compact.validate();
        try self.public_wire.validate();
        try self.role_aware_public.validate();
        try self.public_authority.validate();
        try self.boundary.validateCanonical(boundary_artifact.default_limits);
        try frontend.air.incremental_public_logup_v4.validateSharedAuthority(
            self.public_wire,
            self.role_aware_public,
        );
        if (self.public_authority.public_data != self.role_aware_public)
            return invalidReplayInput("public-authority-owner");
        if (!std.meta.eql(self.public_authority.layout, self.program.layout))
            return invalidReplayInput("memory-layout");
        if (!std.mem.eql(
            u8,
            &self.compact.leaf.source.program,
            &self.program.program.identity,
        )) return invalidReplayInput("program-identity");
        if (!std.meta.eql(
            self.compact.leaf.source,
            self.replay_authority.source,
        )) return invalidReplayInput("source-authority");
        if (!std.meta.eql(
            self.compact.leaf.completion,
            self.replay_authority.completion,
        )) return invalidReplayInput("completion-authority");

        const metadata = try self.public_wire.metadata();
        const local_cycles = std.math.sub(
            u32,
            metadata.global_cycle_end,
            metadata.global_cycle_start,
        ) catch return invalidReplayInput("cycle-range");
        if (self.compact.leaf.segment_index != metadata.segment_index)
            return invalidReplayInput("segment-index");
        if (self.compact.leaf.global_first_cycle !=
            self.replay_authority.global_first_cycle)
            return invalidReplayInput("global-first-cycle");
        if (self.compact.leaf.cycle_count != local_cycles)
            return invalidReplayInput("cycle-count");
        if (self.public_authority.coordinate.segment_index !=
            metadata.segment_index) return invalidReplayInput("coordinate-index");
        if (self.public_authority.coordinate.segment_count !=
            metadata.segment_count) return invalidReplayInput("coordinate-count");
        if (!cpuMatches(self.compact.leaf.entry_cpu, metadata.entry_cpu))
            return invalidReplayInput("entry-cpu-wire");
        if (!cpuMatches(self.compact.leaf.exit_cpu, metadata.exit_cpu))
            return invalidReplayInput("exit-cpu-wire");
        if (!std.mem.eql(
            u8,
            &minimal.ethereumCpuIdentity(self.compact.leaf.entry_cpu),
            &self.replay_authority.entry_cpu_sha256,
        )) return invalidReplayInput("entry-cpu-authority");
        if (!std.mem.eql(
            u8,
            &minimal.ethereumCpuIdentity(self.compact.leaf.exit_cpu),
            &self.replay_authority.exit_cpu_sha256,
        )) return invalidReplayInput("exit-cpu-authority");
    }
};

fn invalidReplayInput(
    comptime stage: []const u8,
) error{InvalidIncrementalFullLeafReplayInputV4} {
    std.debug.print("INCREMENTAL_FULL_LEAF_REPLAY_INPUT_STAGE={s}\n", .{stage});
    return error.InvalidIncrementalFullLeafReplayInputV4;
}

/// Replay, prove, and return the sole canonical durable result.  Producer
/// state and proof ownership are destroyed before the returned bytes can be
/// admitted by a separate cold verifier.
pub fn produceAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    source_input: ColdInputV4,
    proof_limits: proof_artifact.Limits,
    execution: frontend.testing.incremental_ethereum_orchestration_v4_internal
        .ExecutionOptions,
) ![]u8 {
    return produceAllocWithRecorder(
        Engine,
        allocator,
        source_input,
        proof_limits,
        execution,
        null,
    );
}

/// Diagnostic twin of `produceAlloc`. The recorder is process-local telemetry:
/// it neither enters the transcript nor changes canonical artifact bytes.
pub fn produceAllocWithRecorder(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    source_input: ColdInputV4,
    proof_limits: proof_artifact.Limits,
    execution: frontend.testing.incremental_ethereum_orchestration_v4_internal
        .ExecutionOptions,
    recorder: ?*stage_profile.Recorder,
) ![]u8 {
    return produceAllocWithRecorderAndTiming(
        Engine,
        allocator,
        source_input,
        proof_limits,
        execution,
        recorder,
        null,
    );
}

/// Measured diagnostic sibling used by the isolated Stage101 autoresearch
/// command. Timing is observational only: the same producer path and the same
/// canonical encoder are used, and no clock value enters transcript state.
pub fn produceAllocWithRecorderAndTiming(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    source_input: ColdInputV4,
    proof_limits: proof_artifact.Limits,
    execution: frontend.testing.incremental_ethereum_orchestration_v4_internal
        .ExecutionOptions,
    recorder: ?*stage_profile.Recorder,
    timing_out: ?*TimingReceiptV1,
) ![]u8 {
    var transaction_timer = try std.time.Timer.start();
    var transaction_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_leaf_transaction",
        "Stage101 leaf transaction",
    );
    defer transaction_stage.end();

    // Preserve the trust-boundary error order promised by `ColdInputV4`:
    // reject the value-only replay authority before observing any borrowed
    // transport pointer. The validated-wire fast path must not make an
    // invalid request dereference otherwise-untrusted custody.
    var admission_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_input_admission",
        "Stage101 input admission",
    );
    var admission_timer = try std.time.Timer.start();
    errdefer admission_stage.end();
    try source_input.replay_authority.validate();
    var public_lease: ?public_data_v2.PublicDataV2.OwnedValidatedLeaseV2 = null;
    defer if (public_lease) |*lease| lease.deinit();
    var input = source_input;
    if (source_input.public_wire.validated_lease != null) {
        // The caller already owns an immutable, process-local frontend lease.
        // Keep borrowing that authority; copying it would cross the same
        // producer trust boundary a second time.
    } else if (source_input.public_wire.retained_snapshots) |retained| {
        public_lease = try public_data_v2.PublicDataV2.OwnedValidatedLeaseV2
            .initRetained(
            allocator,
            source_input.public_wire,
            retained,
            source_input.validation_counters,
        );
        input.public_wire = public_lease.?.data();
    } else if (source_input.validation_counters) |counters| {
        counters.recordLegacyFullAuthentication();
    }
    try input.validate();
    admission_stage.end();
    const admission_ns = admission_timer.read();

    var replay_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_compact_replay",
        "Stage101 compact replay",
    );
    var replay_timer = try std.time.Timer.start();
    errdefer replay_stage.end();
    var replay_boundary = try minimal.SliceBoundary.init(
        input.compact.boundary_words,
    );
    var replay = try minimal.replayEthereumLeaf(allocator, .{
        .leaf = &input.compact.leaf,
        .program = input.program.program.source(),
        .boundary = replay_boundary.source(),
        .expected_memory_layout = input.program.layout,
        .expected_source = input.replay_authority.source,
        .expected_entry_cpu_sha256 = input.replay_authority.entry_cpu_sha256,
        .expected_exit_cpu_sha256 = input.replay_authority.exit_cpu_sha256,
        .expected_completion = input.replay_authority.completion,
    });
    defer replay.deinit();
    replay_stage.end();
    const replay_ns = replay_timer.read();

    var witness_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_witness_prepare",
        "Stage101 witness preparation",
    );
    var witness_timer = try std.time.Timer.start();
    errdefer witness_stage.end();
    const completion = input.role_aware_public.completion orelse
        return error.MissingIncrementalFullLeafCompletionV4;
    var snapshot = try input.program.snapshotForCompletion(
        allocator,
        input.public_authority.segment_role,
        completion,
    );
    defer snapshot.deinit();
    var prepared = try full_leaf.prepareFullWitnessFromColdArtifact(
        allocator,
        .{
            replay.execution_trace.rows.items,
            replay.keccakf_execution_rows.rows(),
            replay.signer_recovery_execution_rows.rows(),
        },
        &snapshot.value,
        completion,
        input.boundary,
        input.public_wire,
        input.public_authority,
        boundary_artifact.default_limits,
    );
    defer prepared.deinit(allocator);
    witness_stage.end();
    const witness_ns = witness_timer.read();

    var profile_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_statement_profile_prepare",
        "Stage101 statement and profile preparation",
    );
    var profile_timer = try std.time.Timer.start();
    errdefer profile_stage.end();
    const external_count = std.math.add(
        usize,
        replay.keccakf_calls.records().len,
        replay.signer_recovery_calls.records().len,
    ) catch return error.IncrementalFullLeafReplayResourceOverflowV4;
    const native = try full_leaf.prepareStatement(
        allocator,
        &replay.execution_trace,
        &replay.state_chain_tracker,
        &prepared,
        input.public_wire.*,
        std.math.cast(u32, external_count) orelse
            return error.IncrementalFullLeafReplayResourceOverflowV4,
    );
    try native.validate();
    const core_public = try frontend.air.statement_v2.canonicalCorePublicData(
        &native.public_data,
    );
    var ethereum_witness = try prover.guest_precompile.ethereum_witness.Witness
        .init(
        allocator,
        replay.keccakf_calls.records(),
        replay.keccakf_execution_rows.rows(),
        replay.signer_recovery_calls.records(),
        replay.signer_recovery_execution_rows.rows(),
        core_public.clock,
    );
    defer ethereum_witness.deinit();
    const extension = try ethereum_statement.Statement.canonicalV2(
        &native,
        std.math.cast(u32, replay.keccakf_calls.records().len) orelse
            return error.IncrementalFullLeafReplayResourceOverflowV4,
        std.math.cast(u32, replay.signer_recovery_calls.records().len) orelse
            return error.IncrementalFullLeafReplayResourceOverflowV4,
        ethereum_witness.shapes(),
    );
    const profile = try prepared.mintProfile(
        input.boundary,
        input.public_authority,
        &native,
        &extension,
    );
    try profile.validateAgainstInputs(
        allocator,
        input.boundary,
        input.public_wire,
        input.public_authority,
        &native,
        &extension,
        boundary_artifact.default_limits,
    );
    profile_stage.end();
    const profile_ns = profile_timer.read();

    var prove_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_prove",
        "Stage101 prove",
    );
    var prove_timer = try std.time.Timer.start();
    errdefer prove_stage.end();
    var prove_channel = Engine.Channel{};
    var output = try full_leaf.proveWithEngineUsingChannel(
        Engine,
        allocator,
        &replay.execution_trace,
        &replay.state_chain_tracker,
        &prepared,
        &native,
        input.role_aware_public,
        &replay.keccakf_calls,
        &replay.keccakf_execution_rows,
        &replay.signer_recovery_calls,
        &replay.signer_recovery_execution_rows,
        &profile,
        recorder,
        &prove_channel,
        execution,
    );
    defer output.deinit(allocator);
    prove_stage.end();
    const prove_ns = prove_timer.read();

    var encode_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_encode",
        "Stage101 canonical encode",
    );
    var encode_timer = try std.time.Timer.start();
    errdefer encode_stage.end();
    const encoded = try proof_artifact.encodeAlloc(
        Engine,
        allocator,
        .{
            .statement = &output.statement,
            .role_aware_public = input.role_aware_public,
            .extension = &output.extension,
            .profile = &profile,
            .base_claim = output.claims.base,
            .extension_claim = &output.claims.ethereum,
            .bridge_claim = output.claims.bridge,
            .proof = &output.proof,
        },
        proof_limits,
    );
    encode_stage.end();
    if (timing_out) |timing| timing.* = .{
        .transaction_ns = transaction_timer.read(),
        .input_admission_ns = admission_ns,
        .compact_replay_ns = replay_ns,
        .witness_prepare_ns = witness_ns,
        .statement_profile_prepare_ns = profile_ns,
        .prove_ns = prove_ns,
        .encode_ns = encode_timer.read(),
    };
    return encoded;
}

fn cpuMatches(
    cpu: frontend.runner.Cpu,
    retained: public_data_v2.CpuBoundary,
) bool {
    return cpu.pc == retained.pc and
        std.mem.eql(u32, &cpu.regs, &retained.registers);
}

fn allZero(value: []const u8) bool {
    return std.mem.allEqual(u8, value, 0);
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 4)
        @compileError("VM-free incremental full-leaf producer activated");
}
