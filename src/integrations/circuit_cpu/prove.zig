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
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const air = @import("air.zig");

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
const CapturedComponent = cairo.proving.air.component.Component;

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
};

pub const ReleaseValues = struct {
    context: *anyopaque,
    release: *const fn (context: *anyopaque) void,
};

/// A caller-owned value table handed to the prover for release: frees it
/// after the base trace (`releaseOption`) or when the caller is done.
pub const OwnedValues = struct {
    allocator: std.mem.Allocator,
    values: ?[]QM31,

    pub fn release(self: *OwnedValues) void {
        if (self.values) |values| self.allocator.free(values);
        self.values = null;
    }

    /// `Options.release_values` for this table.
    pub fn releaseOption(self: *OwnedValues) ReleaseValues {
        return .{ .context = self, .release = releaseErased };
    }

    fn releaseErased(context: *anyopaque) void {
        const self: *OwnedValues = @ptrCast(@alignCast(context));
        self.release();
    }
};

/// `COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND`.
pub const composition_log_degree_bound: u32 = 1;

/// `default_circuit_pcs_config` of `crates/circuit_prover/src/test_utils.rs`:
/// `FriConfig::default()` lifted to the trace.
pub fn defaultPcsConfig(trace_log_size: u32) PcsConfigV2 {
    const fri = FriConfigV2.init(10, 0, 1, 3, 1) catch unreachable;
    return PcsConfigV2.fromFriAndTraceSize(fri, trace_log_size);
}

pub fn Prover(comptime MC: type) type {
    comptime std.debug.assert(MC.protocol_revision == .proving_5a7c5ed);
    return struct {
        pub const MerkleChannel = MC;
        pub const Channel = MC.Channel;
        pub const Hasher = MC.MerkleHasher;
        pub const Engine = prover.engine.ProverEngine(CpuBackend, Hasher, MC, Channel);
        pub const Hash = Hasher.Hash;

        comptime {
            @import("stwo_prover_api").assertProverEngine(Engine);
        }

        /// `CircuitProof<MC::H>`.
        pub const CircuitProof = struct {
            allocator: std.mem.Allocator,
            pcs_config: PcsConfigV2,
            /// `CircuitClaim::output_values`.
            output_values: []QM31,
            interaction_pow_nonce: u64,
            /// `CircuitInteractionClaim::claimed_sums`.
            claimed_sums: PerComponent(QM31),
            stark_proof: Engine.ExtendedProof,
            channel_salt: u32,
            circuit_hash: Hash,
            /// Not a proof field: the committed log sizes the circuit hash
            /// binds, for callers that re-derive it.
            component_log_sizes: PerComponent(u32),

            pub fn deinit(self: *CircuitProof) void {
                self.stark_proof.deinit(self.allocator);
                self.allocator.free(self.output_values);
                self.* = undefined;
            }
        };

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
            lookup_transcript.mixChannelSalt(&channel, channel_salt);
            step(observer, .mix_channel_salt, &channel);
            pcs_config.fri_config.mixInto(&channel);
            step(observer, .mix_fri_config, &channel);

            var scheme = try Engine.initRevision(allocator, pcs_config);
            var scheme_owned = true;
            errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
            scheme.setStorePolynomialsCoefficients();
            if (options.compact_polynomial_min_log) |min_log| scheme.setCompactPolynomialStorage(min_log);
            const scheme_compact = scheme.compact_polynomial_storage;

            // Preprocessed tree.
            if (scheme.compact_polynomial_storage) {
                var views: [preprocessed.N_PREPROCESSED_COLUMNS]prover.pcs.ColumnEvaluation = undefined;
                preprocessedViews(pp, &views);
                try commitBorrowed(&scheme, allocator, &views, &channel);
            } else try commit(&scheme, allocator, try preprocessedColumns(allocator, pp), &channel);
            const preprocessed_root = scheme.trees.items[0].commitment.root();
            step(observer, .commit_preprocessed, &channel);

            // Base trace.
            var base = try witness.writeTrace(allocator, values, pp);
            defer base.deinit();
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
            if (scheme.compact_polynomial_storage)
                try commitBorrowed(&scheme, allocator, base.columns, &channel)
            else
                try commit(&scheme, allocator, try dupColumns(allocator, base.columns), &channel);
            step(observer, .commit_base_trace, &channel);

            // Interaction elements.
            const nonce = channel.grind(component_list.INTERACTION_POW_BITS);
            channel.mixU64(nonce);
            step(observer, .mix_interaction_pow_nonce, &channel);
            const elements = try lookup_transcript.drawLookupElements(allocator, &channel);
            if (comptime hasObserver(@TypeOf(observer), "onLookupElements")) observer.onLookupElements(elements.z, elements.alpha);
            step(observer, .draw_interaction_elements, &channel);

            // Interaction trace.
            // Each component's base columns are freed once its LogUp columns
            // exist; the committed tree holds the base coefficients.
            var interaction = try witness.writeInteractionTraceReleasing(
                allocator,
                &base,
                pp,
                elements.z,
                elements.alpha,
            );
            defer interaction.deinit();
            const sum = try witness.lookupSum(base.output_values, interaction.claimed_sums, elements.z, elements.alpha);
            if (!sum.isZero()) return error.InvalidLookupSum;
            // The interaction pass was the base columns' last reader; the
            // commitment holds its own copy.
            witness.freeColumns(allocator, base.takeColumns());
            const claimed_sums = interaction.claimed_sums.toArray();
            lookup_transcript.mixInteractionClaim(&channel, &claimed_sums);
            step(observer, .mix_interaction_claim, &channel);
            try commit(&scheme, allocator, interaction.takeColumns(), &channel);
            step(observer, .commit_interaction_trace, &channel);
            debugTrees(&scheme);
            // The committed trees hold the blown-up evaluations
            // (`CommitmentSchemeProver::evaluations`).
            if (comptime hasObserver(@TypeOf(observer), "onTraces"))
                try observer.onTraces(scheme.trees.items[0].columns, scheme.trees.items[1].columns, scheme.trees.items[2].columns);

            // Components.
            const layout = pp.layout();
            var bound = try air.bind(allocator, air_template, base.log_sizes, &layout);
            defer bound.deinit();
            var preprocessed_logs: [preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
            for (layout.entries, &preprocessed_logs) |entry, *log_size| log_size.* = entry.log_size;
            // `prove_ex`'s `max_log_degree_bound`: the lifted trace height
            // minus the blowup, one above the components' trace bound.
            const lifting_bound = pcs_config.trace_lifting_log_size - pcs_config.fri_config.log_blowup_factor + 1;
            var captured: [component_list.N_COMPONENTS]CapturedComponent = undefined;
            var components: [component_list.N_COMPONENTS]prover.air.component_prover.ComponentProver = undefined;
            for (bound.components, &captured, &components, claimed_sums) |*template, *runtime, *component, claimed_sum| {
                runtime.* = CapturedComponent.init(
                    allocator,
                    template,
                    &preprocessed_logs,
                    lifting_bound,
                    elements.z,
                    elements.alpha,
                    claimed_sum,
                );
                component.* = runtime.asProverComponent();
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
            const recorder = options.recorder orelse if (local_recorder) |*owned| owned else null;

            scheme_owned = false;
            var stark_proof = try Engine.prove(allocator, &components, &channel, scheme, .{
                .include_all_preprocessed_columns = true,
                .recorder = recorder,
                .cpu_composition_execution = if (scheme_compact) sequentialComposition() else null,
            });
            if (local_recorder) |*owned| printStageProfile(allocator, owned);
            errdefer stark_proof.deinit(allocator);
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
            };
        }

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
        fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []prover.pcs.ColumnEvaluation, channel: *Channel) !void {
            if (!scheme.compact_polynomial_storage)
                try Engine.commit(scheme, allocator, columns, null, channel)
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

        fn debugTrees(scheme: *const Engine.Scheme) void {
            if (!std.process.hasEnvVarConstant("STWO_DEBUG_TREES")) return;
            for (scheme.trees.items, 0..) |tree, index| {
                var values: usize = 0;
                var coeffs: usize = 0;
                var logs: [40]usize = .{0} ** 40;
                for (tree.columns) |column| {
                    values += column.values.len * 4;
                    if (column.coefficient_values) |c| coeffs += c.len * 4;
                    logs[column.log_size] += 1;
                }
                var merkle: usize = 0;
                for (tree.commitment.layers) |layer| merkle += layer.len * 32;
                var poly: usize = 0;
                if (tree.coefficients) |cs| for (cs) |c| {
                    poly += c.coeffs.len * 4;
                };
                std.debug.print("TREE {d}: columns {d} values {d} MB coeffs {d} MB polys {d} MB merkle {d} MB logs", .{ index, tree.columns.len, values >> 20, coeffs >> 20, poly >> 20, merkle >> 20 });
                for (logs, 0..) |count, log| if (count != 0) std.debug.print(" {d}x{d}", .{ count, log });
                std.debug.print("\n", .{});
            }
        }

        fn step(observer: anytype, comptime which: Step, channel: *const Channel) void {
            prover.measurement.process_usage.reportStage("circuit." ++ @tagName(which));
            if (comptime hasObserver(@TypeOf(observer), "onStep")) observer.onStep(which, channel.digestBytes());
        }
    };
}

/// The low-memory composition schedule: the components one after another
/// into one accumulator (each still row-parallel on the global pool), rather
/// than all at once, each with its own accumulator and trace lease. Field
/// addition is exact, so the composition evaluation is the same.
fn sequentialComposition() prover.engine.CpuCompositionExecutionRequest {
    const workers = if (prover.work_pool.getGlobalPool()) |pool| pool.workerCount() else 1;
    return .{
        .worker_count = @max(1, workers),
        .host_byte_budget = std.math.maxInt(usize),
        .contention_policy = .compatibility,
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

/// The circuit prover on the internal (leaf and internal-fold) profile.
pub const Internal = Prover(profiles.Blake2sM31MerkleChannel);
/// The circuit prover on the root profile.
pub const Root = Prover(profiles.Blake2sMerkleChannel);
