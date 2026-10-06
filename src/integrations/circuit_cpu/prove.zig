//! The circuit prover: `prove_circuit_assignment_with_channel` and
//! `prove_circuit_with_precompute` of `crates/circuit_prover/src/prover.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) on the CPU backend.
//!
//! This is the only place that sequences the circuit transcript (design
//! §4.4, map §1.3):
//!
//!  1. `mix_felts([0])`, the channel salt;
//!  2. `FriConfig::mix_into` (two felts);
//!  3. commit the preprocessed tree (the commit mixes its root);
//!  4. write the base trace, then `mix_hash(circuit_hash)` with
//!     `circuit_hash = H(config_words || preprocessed_root)`;
//!  5. `CircuitClaim::mix_into` (the output values), commit the base trace;
//!  6. the 20-bit interaction grind in Rust `SimdBackend` order, `mix_u64`,
//!     draw `CommonLookupElements`;
//!  7. mix the eleven claimed sums, commit the interaction trace;
//!  8. `prove_ex` with every preprocessed column sampled, which runs the
//!     FRI grind at the FRI config's PoW bits.
//!
//! The Merkle channel `MC` is one of the two `proving_5a7c5ed` channel
//! profiles (`core.vcs_lifted.channel_profile`): `Blake2sM31MerkleChannel`
//! for leaves and internal folds, `Blake2sMerkleChannel` for the root. Both
//! commit with the plain Blake2s Merkle hasher and grind in Rust order; only
//! the Fiat-Shamir channel and `mix_hash` differ.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
/// The CPU backend with the Cairo product's wide LDE preparation: fused
/// per-column extension jobs in a product-bounded batch, so a 2^23-row
/// tree's FFTs occupy every worker. Commitment bytes are unchanged.
const CpuBackend = @import("stwo_cpu_backend").configured(.{ .wide_preparation = true });
const air = @import("air.zig");
const repeated_step_chip = @import("repeated_step_chip.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const lookup_transcript = core.channel.lookup_transcript;
const component_list = circuit.common.component_list;
const preprocessed = circuit.common.preprocessed;
const circuit_hash = circuit.common.circuit_hash;
const witness = circuit.witness.trace;
const PerComponent = component_list.PerComponent;
/// Stage timing scope; a null recorder makes it a no-op.
pub const StageScope = prover.stage_profile.StageScope;
const CapturedComponent = cairo.proving.air.component.Component;
const NativeExecutor = cairo.proving.air.native_evaluator.Executor;
const composition_aot = @import("circuit_composition_cpu_aot");

/// The circuit AIR's generated native composition kernels
/// (`composition_aot_build.zig`), one per recorded program.
pub fn nativeCompositionExecutor() NativeExecutor {
    return composition_aot.executor();
}

pub const profiles = core.vcs_lifted.channel_profile.proving_5a7c5ed;

/// The transcript steps an observer sees, in order (the oracle's
/// `prove-small` step names).
pub const Step = enum {
    mix_channel_salt,
    mix_fri_config,
    commit_preprocessed,
    mix_circuit_hash,
    mix_claim,
    commit_base_trace,
    mix_interaction_pow_nonce,
    draw_interaction_elements,
    mix_interaction_claim,
    commit_interaction_trace,
    prove_ex,
};

/// Execution choices that never change proof bytes.
pub const Options = struct {
    /// Stage timings (`proof_of_work` is the FRI grind).
    recorder: ?*prover.stage_profile.Recorder = null,
    /// Drop each tree's blown-up evaluations after hashing, keeping the
    /// polynomial coefficients, for columns of at least this log size
    /// (`CommitmentSchemeProver.setCompactPolynomialStorage`).
    compact_polynomial_min_log: ?u32 = null,
    /// Called once the base trace is written, the value table's last read:
    /// a caller that owns `values` can free it there instead of holding it
    /// through the proof. `values` must not be read after the call.
    release_values: ?ReleaseValues = null,
    /// Keep each tree's committed (blown-up) evaluations only, without the
    /// second, coefficient-form copy (`CoefficientRetentionPolicy.never`):
    /// sampled values are evaluated from the evaluations, and composition,
    /// quotients and decommitment read the committed columns instead of
    /// re-extending coefficients. Excludes compact storage, which keeps the
    /// coefficients instead.
    evaluations_only: bool = false,
    /// The preprocessed tree of this proof's topology, already committed
    /// (design §9.2 item 1): step 3 appends a lease on it instead of
    /// interpolating, extending and hashing the preprocessed columns again.
    /// It must be `PreprocessedCommitment.build` of the same preprocessed
    /// circuit under the same `pcs_config`; its storage policy is its own
    /// (a proof never compacts a lease).
    preprocessed_commitment: ?*const PreprocessedCommitment = null,
    /// Canonical twiddles shared by consecutive proofs (`twiddleTower`);
    /// null precomputes them per proof.
    twiddle_tower: ?*const TwiddleTower = null,
    /// Optional whole-stage device evaluator for the captured circuit AIR.
    composition_device: ?DeviceStage.Device = null,
    /// Evaluates composition with generated native kernels; null uses the
    /// SIMD interpreter. Both produce the same field values.
    composition_executor: ?NativeExecutor = nativeCompositionExecutor(),
    /// S31 hybrid-step-v2 extension. It adds one AIR component to the same
    /// base, interaction, composition and FRI commitments as the circuit.
    chip: ?ChipRequest = null,
};

pub const ChipRequest = struct {
    source_digest: [32]u8,
    rounds: u32,
    constant: M31,
    initial: [4]M31,
    final: [4]M31,
};

const DeviceStage = cairo.proving.air.device_stage;

pub const ReleaseValues = struct {
    context: *anyopaque,
    release: *const fn (context: *anyopaque) void,
};

pub const TwiddleTower = prover.poly.twiddle_tower.M31TwiddleTower;

/// The tower that covers every circle domain a proof under `pcs_config`
/// requests: the committed heights and the composition domain.
pub fn twiddleTower(allocator: std.mem.Allocator, pcs_config: PcsConfigV2) !TwiddleTower {
    return TwiddleTower.init(allocator, twiddleTowerLog(pcs_config), std.math.maxInt(usize));
}

fn twiddleTowerLog(pcs_config: PcsConfigV2) u32 {
    // The composition polynomial is evaluated on its own domain, one above
    // the trace bound (`COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND`), then
    // extended by the blowup.
    return pcs_config.trace_lifting_log_size + composition_log_degree_bound;
}

/// A committed preprocessed tree shared by every proof of one topology.
///
/// Upstream re-interpolates, re-extends and re-hashes the preprocessed
/// columns in every proof (`prove_circuit_assignment_with_channel`); the tree
/// is a function of the columns and the commitment height alone, so one
/// commitment serves every proof of the key, on both channel profiles (they
/// share the plain Blake2s Merkle hasher). Each proof appends a lease
/// (`retainShared`), which the scheme releases with the proof.
pub const PreprocessedCommitment = struct {
    tree: Tree,
    pcs_config: PcsConfigV2,
    /// `(log_size)` of each column, in layout order.
    log_sizes: [preprocessed.N_PREPROCESSED_COLUMNS]u32,

    pub const Tree = Internal.Engine.Scheme.CommitmentTree;
    comptime {
        std.debug.assert(Tree == Root.Engine.Scheme.CommitmentTree);
    }

    /// Commits `pp`'s columns as tree 0 of a `pcs_config` proof, exactly as
    /// step 3 of `prove` does, and keeps the tree, stored as `options` says
    /// (compact, evaluations only, or both); every lease shares that storage.
    pub fn build(
        allocator: std.mem.Allocator,
        pp: *const preprocessed.PreprocessedCircuit,
        pcs_config: PcsConfigV2,
        options: Options,
    ) !PreprocessedCommitment {
        var scheme = try initScheme(Internal.Engine, allocator, pcs_config, options);
        defer Internal.Engine.deinit(&scheme, allocator);
        // The root is mixed into a throwaway channel; a proof mixes the
        // lease's root into its own.
        var channel = Internal.Channel{};
        try Internal.commitColumns(&scheme, allocator, try preprocessedColumns(allocator, pp), options.recorder, &channel);
        if (scheme.trees.items.len != 1) return error.PreprocessedCommitmentShape;
        try scheme.trees.items[0].share(allocator);
        var log_sizes: [preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
        for (pp.columns, &log_sizes) |column, *log_size| log_size.* = column.logSize();
        return .{
            .tree = scheme.trees.pop().?,
            .pcs_config = pcs_config,
            .log_sizes = log_sizes,
        };
    }

    pub fn deinit(self: *PreprocessedCommitment, allocator: std.mem.Allocator) void {
        self.tree.deinit(allocator);
        self.* = undefined;
    }

    pub fn root(self: *const PreprocessedCommitment) Internal.Hash {
        return self.tree.root();
    }

    /// Retained host bytes: evaluations, coefficients and Merkle layers.
    pub fn byteSize(self: *const PreprocessedCommitment) usize {
        var bytes: usize = 0;
        for (self.tree.columns) |column| bytes += column.values.len * @sizeOf(M31);
        if (self.tree.coefficients) |coefficients| {
            for (coefficients) |coefficient| bytes += coefficient.coefficients().len * @sizeOf(M31);
        }
        // The Merkle layers: at most one hash per leaf and per inner node.
        bytes += (@as(usize, 2) << @intCast(self.tree.commitment.maxLogSize())) * @sizeOf(Internal.Hash);
        return bytes;
    }

    /// Whether a proof of `pp` under `pcs_config` may use this commitment.
    /// The caller vouches that `pp` is the circuit it was built from (a
    /// topology-cache hit); the shape and every commitment parameter are
    /// checked here. The storage policy is the commitment's own: a proof
    /// never compacts a lease, and residency never changes the bytes.
    fn check(self: *const PreprocessedCommitment, pp: *const preprocessed.PreprocessedCircuit, pcs_config: PcsConfigV2) !void {
        if (!std.meta.eql(self.pcs_config, pcs_config))
            return error.PreprocessedCommitmentMismatch;
        for (pp.columns, self.log_sizes) |column, log_size|
            if (column.logSize() != log_size) return error.PreprocessedCommitmentMismatch;
    }
};

fn initScheme(comptime Engine: type, allocator: std.mem.Allocator, pcs_config: PcsConfigV2, options: Options) !Engine.Scheme {
    var scheme = if (options.twiddle_tower) |tower|
        try Engine.initRevisionWithTwiddleTower(pcs_config, tower)
    else
        try Engine.initRevision(allocator, pcs_config);
    errdefer Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    if (options.compact_polynomial_min_log) |min_log| {
        if (options.evaluations_only) return error.ConflictingStorageOptions;
        scheme.setCompactPolynomialStorage(min_log);
    } else if (options.evaluations_only) {
        scheme.setCoefficientRetentionPolicy(.never);
    }
    return scheme;
}

/// `COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND`.
pub const composition_log_degree_bound: u32 = 1;

/// `default_circuit_pcs_config` of `crates/circuit_prover/src/test_utils.rs`:
/// `FriConfig::default()` lifted to the trace.
pub fn defaultPcsConfig(trace_log_size: u32) PcsConfigV2 {
    const fri = FriConfigV2.init(10, 0, 1, 3, 1) catch unreachable;
    return PcsConfigV2.fromFriAndTraceSize(fri, trace_log_size);
}

/// `CircuitProof<MC::H>`: its stark proof depends only on the Merkle
/// hasher, so the CPU and device provers of a profile share this type.
pub fn CircuitProofOf(comptime MC: type) type {
    const Hash = MC.MerkleHasher.Hash;
    return struct {
        allocator: std.mem.Allocator,
        pcs_config: PcsConfigV2,
        /// `CircuitClaim::output_values`.
        output_values: []QM31,
        interaction_pow_nonce: u64,
        /// `CircuitInteractionClaim::claimed_sums`.
        claimed_sums: PerComponent(QM31),
        stark_proof: core.proof.ExtendedStarkProof(MC.MerkleHasher),
        channel_salt: u32,
        circuit_hash: Hash,
        /// Not a proof field: the committed log sizes the circuit hash
        /// binds, for callers that re-derive it.
        component_log_sizes: PerComponent(u32),
        /// Present only for the hybrid-step-v2 profile. The v1 serializer
        /// ignores this field and retains its original byte format.
        chip_claimed_sum: ?QM31 = null,

        pub fn deinit(self: *@This()) void {
            self.stark_proof.deinit(self.allocator);
            self.allocator.free(self.output_values);
            self.* = undefined;
        }
    };
}

pub fn Prover(comptime MC: type) type {
    return ProverOn(CpuBackend, MC);
}

/// The circuit prover on the PCS backend `B` (design §4.6): the CPU backend
/// is the parity oracle; a device backend (`circuit_metal`) reuses this
/// transcript unchanged, so the two can differ only in where the work runs.
/// A backend may supply the §4.7 interaction grind
/// (`prover.pcs.proof_of_work.grindForBackend`); the CPU grinds on the
/// channel, which walks the same `(hi, lo < 2^20)` order.
pub fn ProverOn(comptime B: type, comptime MC: type) type {
    comptime std.debug.assert(MC.protocol_revision == .proving_5a7c5ed);
    return struct {
        pub const Backend = B;
        pub const MerkleChannel = MC;
        pub const Channel = MC.Channel;
        pub const Hasher = MC.MerkleHasher;
        pub const Engine = prover.engine.ProverEngine(B, Hasher, MC, Channel);
        pub const Hash = Hasher.Hash;

        comptime {
            @import("stwo_prover_api").assertProverEngine(Engine);
        }

        /// `CircuitProof<MC::H>`; one type per channel profile, whichever
        /// backend proved it.
        pub const CircuitProof = CircuitProofOf(MC);

        /// `prove_circuit_assignment_with_channel`. `values` is the finalized
        /// context's value table, `pp` its preprocessed circuit and
        /// `air_template` the parsed circuit AIR bundle (`air.parse`).
        /// `observer` is `{}` or a pointer to a type with any of
        /// `onStep(Step, digest: [32]u8)`, `onLookupElements(z, alpha)` and
        /// `onTraces(preprocessed, base, interaction: []const ColumnEvaluation)`;
        /// `onTraces` sees the committed (blown-up) evaluations, which compact
        /// storage has already dropped.
        pub fn prove(
            allocator: std.mem.Allocator,
            values: []const QM31,
            pp: *const preprocessed.PreprocessedCircuit,
            air_template: *const air.Bundle,
            pcs_config: PcsConfigV2,
            options: Options,
            observer: anytype,
        ) !CircuitProof {
            const channel_salt: u32 = 0;
            var channel = Channel{};
            if (options.chip) |request|
                repeated_step_chip.mixProfile(&channel, request.source_digest, request.rounds, request.constant);
            lookup_transcript.mixChannelSalt(&channel, channel_salt);
            step(observer, .mix_channel_salt, &channel);
            pcs_config.fri_config.mixInto(&channel);
            step(observer, .mix_fri_config, &channel);

            var scheme = try initScheme(Engine, allocator, pcs_config, options);
            var scheme_owned = true;
            errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);

            const recorder = options.recorder;
            // Preprocessed tree: lease the topology's commitment when present.
            {
                var stage = try StageScope.begin(recorder, "circuit_commit_preprocessed", "commit preprocessed tree");
                defer stage.end();
                if (comptime B == CpuBackend) {
                    if (options.preprocessed_commitment) |cached| {
                        try cached.check(pp, pcs_config);
                        var lease = cached.tree.retainShared();
                        errdefer lease.deinit(allocator);
                        try scheme.appendCommittedTree(allocator, lease, &channel);
                    } else if (scheme.compact_polynomial_storage) {
                        var views: [preprocessed.N_PREPROCESSED_COLUMNS]prover.pcs.ColumnEvaluation = undefined;
                        preprocessedViews(pp, &views);
                        try commitBorrowed(&scheme, allocator, &views, &channel);
                    } else try commit(&scheme, allocator, try preprocessedColumns(allocator, pp), recorder, &channel);
                } else {
                    if (options.preprocessed_commitment != null) return error.CpuCommitmentOnDevice;
                    // Device tree representations are backend-specific.
                    // The canonical CPU commitment cannot be leased here.
                    try commit(&scheme, allocator, try preprocessedColumns(allocator, pp), recorder, &channel);
                }
            }
            const preprocessed_root = scheme.trees.items[0].commitment.root();
            step(observer, .commit_preprocessed, &channel);

            // Base trace.
            var base = blk: {
                var stage = try StageScope.begin(recorder, "circuit_base_witness", "base trace witness");
                defer stage.end();
                break :blk try witness.writeTrace(allocator, values, pp);
            };
            defer base.deinit();
            var chip_base: ?repeated_step_chip.Base = null;
            defer if (chip_base) |*owned| owned.deinit();
            if (options.chip) |request| {
                chip_base = try repeated_step_chip.writeBase(
                    allocator,
                    request.initial,
                    request.constant,
                    request.rounds,
                );
                if (!std.meta.eql(chip_base.?.final, request.final))
                    return error.InvalidChipBoundary;
                if (base.output_values.len != 8) return error.InvalidChipBoundary;
                for (0..4) |lane| {
                    const input_word = QM31.fromU32Unchecked(
                        request.initial[lane].toU32() & 0xffff,
                        request.initial[lane].toU32() >> 16,
                        0,
                        0,
                    );
                    const output_word = QM31.fromU32Unchecked(
                        request.final[lane].toU32() & 0xffff,
                        request.final[lane].toU32() >> 16,
                        0,
                        0,
                    );
                    if (!base.output_values[lane].eql(input_word) or
                        !base.output_values[4 + lane].eql(output_word))
                        return error.InvalidChipBoundary;
                }
            }
            // The value table's last reader was the base trace.
            if (options.release_values) |release| release.release(release.context);
            const hash = try circuit_hash.hostCircuitHash(
                base.log_sizes,
                pcs_config.fri_config.log_blowup_factor,
                preprocessed_root,
            );
            MC.mixRoot(&channel, hash);
            step(observer, .mix_circuit_hash, &channel);
            channel.mixFelts(base.output_values);
            step(observer, .mix_claim, &channel);
            // The commitment owns (and extends) what it commits; the base
            // columns stay here for the interaction pass. A compact commitment
            // streams bounded batches out of them instead of copying the tree.
            {
                var stage = try StageScope.begin(recorder, "circuit_commit_base", "commit base trace");
                defer stage.end();
                if (chip_base) |*chip| {
                    const joined = try joinedViews(allocator, base.columns, chip.columns);
                    defer allocator.free(joined);
                    if (B == CpuBackend and scheme.compact_polynomial_storage)
                        try commitBorrowed(&scheme, allocator, joined, &channel)
                    else
                        try commit(&scheme, allocator, try dupColumns(allocator, joined), recorder, &channel);
                } else if (B == CpuBackend and scheme.compact_polynomial_storage)
                    try commitBorrowed(&scheme, allocator, base.columns, &channel)
                else
                    try commit(&scheme, allocator, try dupColumns(allocator, base.columns), recorder, &channel);
            }
            step(observer, .commit_base_trace, &channel);

            // Interaction elements.
            const nonce = blk: {
                var stage = try StageScope.begin(recorder, "circuit_interaction_pow", "interaction grind");
                defer stage.end();
                break :blk if (comptime B == CpuBackend)
                    channel.grind(component_list.INTERACTION_POW_BITS)
                else
                    try prover.pcs.proof_of_work.grindForBackend(B, &channel, component_list.INTERACTION_POW_BITS);
            };
            channel.mixU64(nonce);
            step(observer, .mix_interaction_pow_nonce, &channel);
            const elements = try lookup_transcript.drawLookupElements(allocator, &channel);
            if (comptime hasObserver(@TypeOf(observer), "onLookupElements")) observer.onLookupElements(elements.z, elements.alpha);
            step(observer, .draw_interaction_elements, &channel);

            // Interaction trace.
            // Each component's base columns are freed once its LogUp columns
            // exist; the committed tree holds the base coefficients.
            var interaction = blk: {
                var stage = try StageScope.begin(recorder, "circuit_interaction_witness", "interaction trace witness");
                defer stage.end();
                break :blk try witness.writeInteractionTraceReleasing(
                    allocator,
                    &base,
                    pp,
                    elements.z,
                    elements.alpha,
                );
            };
            defer interaction.deinit();
            var chip_interaction: ?repeated_step_chip.Interaction = null;
            defer if (chip_interaction) |*owned| owned.deinit();
            if (chip_base) |*chip| {
                chip_interaction = try repeated_step_chip.writeInteraction(
                    allocator,
                    chip.columns,
                    elements.z,
                    elements.alpha,
                );
                const request = options.chip.?;
                const closure = try repeated_step_chip.endpointSum(
                    chip_interaction.?.claimed_sum,
                    .init(elements.z, elements.alpha),
                    request.rounds,
                    request.initial,
                    request.final,
                );
                if (!closure.isZero()) return error.InvalidChipLookupSum;
            }
            const sum = try witness.lookupSum(base.output_values, interaction.claimed_sums, elements.z, elements.alpha);
            if (!sum.isZero()) return error.InvalidLookupSum;
            // The interaction pass was the base columns' last reader; the
            // commitment holds its own copy.
            witness.freeColumns(allocator, base.takeColumns());
            const claimed_sums = interaction.claimed_sums.toArray();
            if (chip_interaction) |chip|
                lookup_transcript.mixInteractionClaim(&channel, &.{
                    claimed_sums[0], claimed_sums[1],  claimed_sums[2],
                    claimed_sums[3], claimed_sums[4],  claimed_sums[5],
                    claimed_sums[6], claimed_sums[7],  claimed_sums[8],
                    claimed_sums[9], claimed_sums[10], chip.claimed_sum,
                })
            else
                lookup_transcript.mixInteractionClaim(&channel, &claimed_sums);
            step(observer, .mix_interaction_claim, &channel);
            {
                var stage = try StageScope.begin(recorder, "circuit_commit_interaction", "commit interaction trace");
                defer stage.end();
                if (chip_interaction) |*chip| {
                    const joined = try joinedViews(allocator, interaction.columns, chip.columns);
                    defer allocator.free(joined);
                    try commit(&scheme, allocator, try dupColumns(allocator, joined), recorder, &channel);
                } else try commit(&scheme, allocator, interaction.takeColumns(), recorder, &channel);
            }
            step(observer, .commit_interaction_trace, &channel);
            // The committed trees hold the blown-up evaluations
            // (`CommitmentSchemeProver::evaluations`).
            if (comptime hasObserver(@TypeOf(observer), "onTraces"))
                try observer.onTraces(scheme.trees.items[0].columns, scheme.trees.items[1].columns, scheme.trees.items[2].columns);

            // Components.
            const layout = pp.layout();
            var bind_stage = try StageScope.begin(recorder, "circuit_bind_components", "bind circuit components");
            var bound = air.bind(allocator, air_template, base.log_sizes, &layout) catch |err| {
                bind_stage.end();
                return err;
            };
            bind_stage.end();
            defer bound.deinit();
            var preprocessed_logs: [preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
            for (layout.entries, &preprocessed_logs) |entry, *log_size| log_size.* = entry.log_size;
            // `prove_ex`'s `max_log_degree_bound`: the lifted trace height
            // minus the blowup, one above the components' trace bound.
            const lifting_bound = pcs_config.trace_lifting_log_size - pcs_config.fri_config.log_blowup_factor + 1;
            var captured: [component_list.N_COMPONENTS]CapturedComponent = undefined;
            var components: [component_list.N_COMPONENTS + 1]prover.air.component_prover.ComponentProver = undefined;
            for (bound.components, &captured, components[0..component_list.N_COMPONENTS], claimed_sums) |*template, *runtime, *component, claimed_sum| {
                runtime.* = CapturedComponent.init(
                    allocator,
                    template,
                    &preprocessed_logs,
                    lifting_bound,
                    elements.z,
                    elements.alpha,
                    claimed_sum,
                );
                runtime.native_executor = options.composition_executor;
                runtime.recorder = if (options.composition_executor != null) options.recorder else null;
                component.* = runtime.asProverComponent();
                // Every circuit component is a 2^20..2^23-row domain: give
                // each the whole pool in turn, row-split, instead of leaving
                // all but the largest on one core. Rows are written
                // independently into per-component accumulators, so the
                // composition is byte-identical.
                component.pool_exclusive_domain = true;
            }
            var chip_component: repeated_step_chip.Component = undefined;
            var component_count: usize = component_list.N_COMPONENTS;
            if (chip_interaction) |chip| {
                const request = options.chip.?;
                const main_widths = witness.traceWidths();
                const interaction_widths = witness.interactionWidths();
                var main_offset: usize = 0;
                var interaction_offset: usize = 0;
                for (main_widths) |width| main_offset += width;
                for (interaction_widths) |width| interaction_offset += width;
                chip_component = .{
                    .log_size = try repeated_step_chip.validateRounds(request.rounds),
                    .constant = request.constant,
                    .main_offset = main_offset,
                    .interaction_offset = interaction_offset,
                    .elements = .init(elements.z, elements.alpha),
                    .claimed_sum = chip.claimed_sum,
                };
                components[component_list.N_COMPONENTS] = chip_component.asProverComponent();
                component_count += 1;
            }

            // `STWO_CIRCUIT_STAGE_PROFILE` prints `prove_ex`'s stage tree when
            // the caller brought no recorder. Timing only; no byte changes.
            var local_recorder: ?prover.stage_profile.Recorder = if (options.recorder == null and
                std.process.hasEnvVarConstant("STWO_CIRCUIT_STAGE_PROFILE"))
                prover.stage_profile.Recorder.initWithOptions(allocator, "circuit_cpu", "prove", .{ .capture_tasks = false })
            else
                null;
            defer if (local_recorder) |*owned| owned.deinit();
            // Not handed to the captured components: they may be evaluated
            // concurrently, and the recorder's stage stack is single-threaded.
            const engine_recorder = options.recorder orelse if (local_recorder) |*owned| owned else null;

            // The device composition stage is admitted before `prove_ex`,
            // exactly as the Cairo transaction does it.
            var stage: ?DeviceStage.Bound = null;
            defer if (stage) |*owned| owned.close();
            if (chip_interaction != null and options.composition_device != null)
                return error.HybridDeviceCompositionUnsupported;
            if (options.composition_device) |device| {
                var committed_logs = try scheme.columnLogSizes(allocator);
                defer committed_logs.deinitDeep(allocator);
                const opened = try device.open(device.context, allocator, bound.components, committed_logs.items);
                if (opened) |session| {
                    stage = .{
                        .allocator = allocator,
                        .components = &captured,
                        .captured = bound.components,
                        .session = session,
                        .recorder = options.recorder,
                    };
                    for (session.accepts) |accepted| {
                        if (!accepted) try admitHostComposition(B);
                    }
                } else try admitHostComposition(B);
            }

            scheme_owned = false;
            var stark_proof = try Engine.prove(allocator, components[0..component_count], &channel, scheme, .{
                .include_all_preprocessed_columns = true,
                .recorder = engine_recorder,
                .composition_stage = if (stage) |*ready| ready.asStage() else null,
            });
            if (local_recorder) |*owned| printStageProfile(allocator, owned);
            errdefer stark_proof.deinit(allocator);
            // A device error mid-stage recomposes that component on the host;
            // the bytes are the same, but a strict device run must not claim it.
            if (stage) |owned| if (owned.counts.device_fallbacks != 0) try admitHostComposition(B);
            step(observer, .prove_ex, &channel);
            return .{
                .allocator = allocator,
                .pcs_config = pcs_config,
                .output_values = try allocator.dupe(QM31, base.output_values),
                .interaction_pow_nonce = nonce,
                .claimed_sums = interaction.claimed_sums,
                .stark_proof = stark_proof,
                .channel_salt = channel_salt,
                .circuit_hash = hash,
                .component_log_sizes = base.log_sizes,
                .chip_claimed_sum = if (chip_interaction) |chip| chip.claimed_sum else null,
            };
        }

        pub const commitColumns = commit;

        /// Commits owned columns as the next tree and mixes its root.
        ///
        /// Under compact storage the tree keeps only coefficients (and the
        /// extended evaluations of columns below the compact threshold), so
        /// nothing needs every column's extension at once. The commitment is
        /// row-tiled (`pcs.tiled_commit`): coefficients once, then one row tile
        /// of every column's extension, its leaves and its subtree at a time.
        /// Shapes it does not cover stream bounded column batches instead
        /// (`StreamingTreeBuilder`'s compact committer). The Merkle tree, and
        /// so the root, is the same either way; only the transient peak changes.
        fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []prover.pcs.ColumnEvaluation, recorder: ?*prover.stage_profile.Recorder, channel: *Channel) !void {
            if (comptime B != CpuBackend) {
                try Engine.commit(scheme, allocator, columns, recorder, channel);
            } else if (!scheme.compact_polynomial_storage)
                try Engine.commit(scheme, allocator, columns, recorder, channel)
            else if (tiles(scheme, columns))
                try prover.pcs.tiled_commit.commit(CpuBackend, Hasher, scheme, allocator, columns, .owned, .{}, channel)
            else
                try scheme.commitOwnedStreamingWithRecorder(allocator, columns, 0, null, channel);
            try Engine.flushPendingCommit(scheme, allocator, channel);
        }

        /// `commit` for columns the caller keeps (compact storage only).
        fn commitBorrowed(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const prover.pcs.ColumnEvaluation, channel: *Channel) !void {
            std.debug.assert(scheme.compact_polynomial_storage);
            if (tiles(scheme, columns)) {
                // The tiled commit copies each column once into its coefficients.
                const descriptors = try allocator.dupe(prover.pcs.ColumnEvaluation, columns);
                defer allocator.free(descriptors);
                try prover.pcs.tiled_commit.commit(CpuBackend, Hasher, scheme, allocator, descriptors, .borrowed, .{}, channel);
            } else try scheme.commitBorrowedStreamingWithRecorder(allocator, columns, 0, null, channel);
            try Engine.flushPendingCommit(scheme, allocator, channel);
        }

        fn tiles(scheme: *const Engine.Scheme, columns: []const prover.pcs.ColumnEvaluation) bool {
            return prover.pcs.tiled_commit.applies(columns, scheme.config.fri_config.log_blowup_factor, scheme.compact_polynomial_min_log_size);
        }

        fn step(observer: anytype, comptime which: Step, channel: *const Channel) void {
            prover.measurement.process_usage.reportStage("circuit." ++ @tagName(which));
            if (comptime hasObserver(@TypeOf(observer), "onStep")) observer.onStep(which, channel.digestBytes());
        }
    };
}

fn printStageProfile(allocator: std.mem.Allocator, recorder: *const prover.stage_profile.Recorder) void {
    var profile = recorder.snapshot(allocator) catch return;
    defer profile.deinit(allocator);
    for (profile.stages) |node| printStageNode(node, 0);
}

fn printStageNode(node: prover.stage_profile.StageNode, depth: usize) void {
    std.debug.print("CIRCUIT_STAGE {d} {s} {d:.3}s ({s})\n", .{ depth, node.id, node.seconds, node.label });
    if (node.children) |children| for (children) |child| printStageNode(child, depth + 1);
}

/// The backend's host-work policy for composition (Metal:
/// `STWO_ZIG_METAL_REQUIRE_GPU=1` forbids it); a backend without one admits.
fn admitHostComposition(comptime B: type) !void {
    if (comptime @hasDecl(B, "admitHostProving")) try B.admitHostProving(.composition);
}

fn hasObserver(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .pointer => |pointer| @hasDecl(pointer.child, name),
        else => false,
    };
}

/// Owned copies of the preprocessed columns, in layout order, for the
/// commitment (which takes ownership of what it commits).
fn preprocessedColumns(
    allocator: std.mem.Allocator,
    pp: *const preprocessed.PreprocessedCircuit,
) ![]prover.pcs.ColumnEvaluation {
    var views: [preprocessed.N_PREPROCESSED_COLUMNS]prover.pcs.ColumnEvaluation = undefined;
    preprocessedViews(pp, &views);
    return dupColumns(allocator, &views);
}

/// Borrowed views of the preprocessed columns, in layout order.
fn preprocessedViews(
    pp: *const preprocessed.PreprocessedCircuit,
    views: *[preprocessed.N_PREPROCESSED_COLUMNS]prover.pcs.ColumnEvaluation,
) void {
    for (pp.columns, views) |column, *view| view.* = .{ .log_size = column.logSize(), .values = column.values };
}

fn dupColumns(
    allocator: std.mem.Allocator,
    source: []const prover.pcs.ColumnEvaluation,
) ![]prover.pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover.pcs.ColumnEvaluation, source.len);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (source, columns) |column, *out| {
        out.* = .{ .log_size = column.log_size, .values = try allocator.dupe(M31, column.values) };
        initialized += 1;
    }
    return columns;
}

/// Concatenate descriptors only. Both source owners stay alive through the
/// commitment; callers either duplicate the values or use a borrowed commit.
fn joinedViews(
    allocator: std.mem.Allocator,
    left: []const prover.pcs.ColumnEvaluation,
    right: []const prover.pcs.ColumnEvaluation,
) ![]prover.pcs.ColumnEvaluation {
    const joined = try allocator.alloc(prover.pcs.ColumnEvaluation, left.len + right.len);
    @memcpy(joined[0..left.len], left);
    @memcpy(joined[left.len..], right);
    return joined;
}

/// The circuit prover on the internal (leaf and internal-fold) profile.
pub const Internal = Prover(profiles.Blake2sM31MerkleChannel);
/// The circuit prover on the root profile.
pub const Root = Prover(profiles.Blake2sMerkleChannel);

/// The two profiles' provers bound to one backend, for the recursion
/// drivers (leaf wrap, fold): the CPU set is the default, a device
/// integration supplies its own (`circuit_metal.provers`). Both sets return
/// the same proof types, so the drivers do not depend on the backend.
pub const Provers = struct {
    backend_name: []const u8,
    internal: *const fn (
        std.mem.Allocator,
        []const QM31,
        *const preprocessed.PreprocessedCircuit,
        *const air.Bundle,
        PcsConfigV2,
        Options,
    ) anyerror!Internal.CircuitProof,
    root: *const fn (
        std.mem.Allocator,
        []const QM31,
        *const preprocessed.PreprocessedCircuit,
        *const air.Bundle,
        PcsConfigV2,
        Options,
    ) anyerror!Root.CircuitProof,

    /// The set of `ProverOn(B, ·)` for both profiles.
    pub fn of(comptime I: type, comptime R: type) Provers {
        comptime std.debug.assert(I.CircuitProof == Internal.CircuitProof and R.CircuitProof == Root.CircuitProof);
        return .{
            .backend_name = if (I.Backend == CpuBackend) "cpu" else @typeName(I.Backend),
            .internal = Unobserved(I).prove,
            .root = Unobserved(R).prove,
        };
    }

    fn Unobserved(comptime P: type) type {
        return struct {
            fn prove(
                allocator: std.mem.Allocator,
                values: []const QM31,
                pp: *const preprocessed.PreprocessedCircuit,
                bundle: *const air.Bundle,
                pcs_config: PcsConfigV2,
                options: Options,
            ) anyerror!P.CircuitProof {
                var effective = options;
                if (comptime P.Backend != CpuBackend) {
                    // The topology's leased tree and twiddles belong to the
                    // CPU PCS. A device builds its own tree; its current
                    // storage policy is compact coefficients, not the CPU
                    // fold's evaluations-only policy.
                    effective.preprocessed_commitment = null;
                    effective.twiddle_tower = null;
                    if (effective.evaluations_only) {
                        effective.evaluations_only = false;
                        effective.compact_polynomial_min_log = 18;
                    }
                }
                return P.prove(allocator, values, pp, bundle, pcs_config, effective, {});
            }
        };
    }
};

/// The CPU scalar provers: the parity oracle.
pub const cpu_provers = Provers.of(Internal, Root);
