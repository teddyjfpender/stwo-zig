//! The leaf wrap: a Cairo proof verified by the leaf verifier circuit, and
//! that circuit's execution proved (design §7.1).
//!
//! Ports steps 4-8 of `prove_leaf` (`crates/leaf_prover/src/prove_leaf.rs`,
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) and
//! `prepare_cairo_proof_for_circuit_verifier`
//! (`crates/cairo_verifier/src/verify.rs`), in upstream order:
//!
//!  1. read the trace log size off the Cairo proof's (equal) lifting
//!     heights and look up the registry's leaf verifier and circuit config;
//!  2. `leaf_verifier_config` for the registry's preprocessed-trace variant,
//!     and the proof's column counts checked against it;
//!  3. the Cairo proof converted for the in-circuit verifier
//!     (`proof_from_stark_proof`, `serialize_aux_data`) and the output
//!     digest read off the output cells;
//!  4. the leaf circuit built with values, padded to the registry's shared
//!     target and required to be satisfied;
//!  5. the circuit proved on the `.internal` profile, its circuit hash
//!     required to equal the registry's, and the proof emitted as
//!     `SerializedLeafProof` (`CircuitSerialize` bytes).
//!
//! The preprocessed circuit depends only on the topology (`topology_key.zig`),
//! so it is built on the first wrap of a key and reused from the cache after
//! that (`topology_cache.zig`). A new entry is published only once its proof
//! has passed the registry check, so a failed wrap caches nothing. Every wrap,
//! hit or miss, checks the proof's circuit hash against the registry, as
//! upstream does, and a hit also requires the rebuilt circuit to have the
//! cached variable count.
//!
//! The input is the Cairo lane's in-memory proof (`proveLeafCairo` of the
//! Cairo CPU integration) with the execution it proves; design §6.4 admits it
//! because the lane's proofs are byte-identical to upstream `prove_cairo`
//! (rung R10c).

const std = @import("std");
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const prove = @import("../prove.zig");
const air = @import("../air.zig");
const verifier_proof = @import("../verifier_proof.zig");
const topology_key = @import("topology_key.zig");
const topology_cache = @import("topology_cache.zig");
const circuit_params = @import("circuit_params.zig");
const proof_source = @import("proof_source.zig");
const stage_profile = @import("stage_profile.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const layout = core.cairo_air_layout;
const finalize = circuit.common.finalize;
const circuit_hash = circuit.common.circuit_hash;
const PreprocessedCircuit = circuit.common.preprocessed.PreprocessedCircuit;
const component_table = circuit.air_eval.component_table;
const cairo_verifier = circuit.statements.cairo_verifier;
const cairo_leaf_config = circuit.statements.cairo_leaf_config;
const cairo_statement = circuit.statements.cairo_statement;
const circuit_leaf = cairo.statement.circuit_leaf;
const CircuitRegistry = wire.registry.CircuitRegistry;
const DigestHex = wire.leaf_proof_json.DigestHex;

const StageScope = prove.StageScope;

const log = std.log.scoped(.circuit_recursion);

pub const Error = error{
    /// The registry's `cairo_prover_params` do not set
    /// `include_all_preprocessed_columns` (the leaf circuit expects a
    /// constant number of preprocessed columns).
    IncludeAllPreprocessedColumnsRequired,
    /// The registry's lifting policy is not `AtLeastPreprocessed`.
    AtLeastPreprocessedRequired,
    /// The Cairo proof was made with another preprocessed trace.
    VariantMismatch,
    /// The Cairo proof carries no explicit lifting heights.
    MissingLiftingHeights,
    /// The Cairo proof's trees are not all lifted to one height.
    UnequalLiftingHeights,
    LiftingBelowBlowup,
    /// The proof's components are not the leaf's enabled set.
    EnabledComponentsMismatch,
    /// A trace of the proof has another width than the leaf circuit expects
    /// (the program does not use every component).
    ColumnCountMismatch,
    /// `serialize_aux_data` has another length than the leaf config's.
    AuxDataLengthMismatch,
    /// The leaf circuit rejects the proof.
    CircuitRejectsProof,
    /// A cached topology does not match the rebuilt circuit.
    TopologyMismatch,
    /// The proven circuit is not the registry's leaf verifier.
    CircuitHashMismatch,
};

/// The per-topology artifacts every proof of a leaf key shares.
pub const LeafTopology = struct {
    preprocessed: PreprocessedCircuit,
    n_vars: usize,
    /// Eight little-endian words of the committed root and the circuit hash.
    preprocessed_root: [8]u32,
    circuit_hash: [8]u32,
    /// The committed preprocessed tree and the twiddles every wrap of the
    /// key shares (design §7.1, §9.2 item 1).
    commitment: ?prove.PreprocessedCommitment,
    twiddles: ?prove.TwiddleTower,

    pub fn deinit(self: *LeafTopology, allocator: std.mem.Allocator) void {
        if (self.commitment) |*item| item.deinit(allocator);
        if (self.twiddles) |*item| item.deinit(allocator);
        self.preprocessed.deinit(allocator);
    }

    pub fn byteSize(self: *const LeafTopology) usize {
        var bytes: usize = 0;
        for (self.preprocessed.columns) |column| bytes += column.values.len * @sizeOf(M31);
        if (self.commitment) |*item| bytes += item.byteSize();
        if (self.twiddles) |*item| bytes += item.retainedBytes();
        return bytes;
    }

    /// `options` with this topology's commitment and twiddles.
    fn proveOptions(self: *const LeafTopology, options: prove.Options) prove.Options {
        var out = options;
        if (self.commitment) |*item| out.preprocessed_commitment = item;
        if (self.twiddles) |*item| out.twiddle_tower = item;
        return out;
    }
};

pub const Cache = topology_cache.TopologyCache(LeafTopology);

/// What every wrap of a process shares. Borrowed; built once.
pub const LeafWrap = struct {
    registry: *const CircuitRegistry,
    /// The 83-slot Cairo evaluator table (`cairo_components.build`).
    cairo_table: *const component_table.Table,
    /// The circuit AIR bundle (`air.parse`).
    bundle: *const air.Bundle,
    /// The leaf program's felts (`programFeltsFromCompiledJson`).
    program: []const layout.ProgramFelt,
    cache: *Cache,
    options: prove.Options = .{},
    /// The backend that proves the wrap; never changes bytes.
    provers: *const prove.Provers = &prove.cpu_provers,
    /// Verified device circuit proof; bypasses the CPU circuit prover.
    source: ?proof_source.Source = null,

    /// The statement constants: the Cairo relation ids and the projection's
    /// memory constants.
    pub fn constants(self: *const LeafWrap) cairo_statement.Constants {
        return circuit_params.cairoConstants(self.cairo_table);
    }
};

/// A wrapped leaf: the fields of `SerializedLeafProof`.
pub const LeafProof = struct {
    allocator: std.mem.Allocator,
    circuit_preprocessed_root: DigestHex,
    circuit_hash: DigestHex,
    /// `CircuitSerialize` bytes of the circuit proof.
    proof: []u8,
    /// Whether the topology came from the cache.
    cache_hit: bool,

    pub fn deinit(self: *LeafProof) void {
        self.allocator.free(self.proof);
        self.* = undefined;
    }

    pub fn serialized(self: *const LeafProof) wire.leaf_proof_json.SerializedLeafProof {
        return .{
            .circuit_preprocessed_root = self.circuit_preprocessed_root,
            .circuit_hash = self.circuit_hash,
            .proof = self.proof,
        };
    }

    /// The leaf prover's output file: pretty JSON, no trailing newline.
    pub fn writeJson(self: *const LeafProof, out: *std.Io.Writer) std.Io.Writer.Error!void {
        try wire.leaf_proof_json.writeSerializedLeafProof(out, self.serialized());
    }
};

/// A cache miss's entry: the preprocessed circuit of `circuit`, committed
/// once under `options` (the root and hash are set after the proof passes).
fn buildTopology(
    allocator: std.mem.Allocator,
    circuit_ctx: anytype,
    circuit_fri: core.pcs.config_v2.FriConfigV2,
    options: prove.Options,
    commit_on_host: bool,
) !LeafTopology {
    var pp = try PreprocessedCircuit.fromBuilderCircuit(allocator, circuit_ctx);
    errdefer pp.deinit(allocator);
    if (!commit_on_host) return .{
        .preprocessed = pp,
        .n_vars = circuit_ctx.n_vars,
        .preprocessed_root = undefined,
        .circuit_hash = undefined,
        .commitment = null,
        .twiddles = null,
    };
    const pcs_config = PcsConfigV2.fromFriAndTraceSize(circuit_fri, pp.traceLogSize());
    var twiddles = try prove.twiddleTower(allocator, pcs_config);
    errdefer twiddles.deinit(allocator);
    var commit_options = options;
    commit_options.twiddle_tower = &twiddles;
    const commitment = try prove.PreprocessedCommitment.build(allocator, &pp, pcs_config, commit_options);
    return .{
        .preprocessed = pp,
        .n_vars = circuit_ctx.n_vars,
        .preprocessed_root = undefined,
        .circuit_hash = undefined,
        .commitment = commitment,
        .twiddles = twiddles,
    };
}

/// Wraps `cairo_proof`, the Cairo lane's `Result` for the leaf engine, of
/// the execution `input`.
pub fn wrapCairoProof(
    allocator: std.mem.Allocator,
    wrap: *const LeafWrap,
    cairo_proof: anytype,
    input: *const cairo.adapter.ProverInput,
) !LeafProof {
    return wrapCairoProofImpl(allocator, wrap, cairo_proof, input, false, {});
}

/// The resident Cairo prover retains only its verified, compressed STARK
/// proof and opening capture. This explicit view is the handoff from a CUDA
/// leaf proof to the recursive verifier circuit; no CPU Cairo re-proving or
/// host prover auxiliary tree is required.
pub const VerifiedCairoLeaf = struct {
    proof: *const core.proof.StarkProof(cairo.witness.resident_verifier.Hasher),
    composition: *const cairo.witness.composition_bundle.Bundle,
    claimed_sums: []const QM31,
    interaction_pow: u64,
    channel_salt: u32,
    preprocessed_variant: cairo.preprocessed.trace.Variant,
    capture: *const core.verifier.ProofCapture(cairo.witness.resident_verifier.Hasher),
};

pub fn wrapVerifiedCairoLeaf(
    allocator: std.mem.Allocator,
    wrap: *const LeafWrap,
    leaf: VerifiedCairoLeaf,
    input: *const cairo.adapter.ProverInput,
) !LeafProof {
    return wrapCairoProofImpl(allocator, wrap, leaf, input, true, leaf.capture);
}

fn wrapCairoProofImpl(
    allocator: std.mem.Allocator,
    wrap: *const LeafWrap,
    cairo_proof: anytype,
    input: *const cairo.adapter.ProverInput,
    comptime verified_capture: bool,
    capture: anytype,
) !LeafProof {
    const registry = wrap.registry;
    const params = registry.cairo_prover_params;
    if (!params.include_all_preprocessed_columns) return error.IncludeAllPreprocessedColumnsRequired;
    if (params.lifting_size_policy != .at_least_preprocessed) return error.AtLeastPreprocessedRequired;
    const variant = params.preprocessed_trace;
    if (!std.mem.eql(u8, @tagName(cairo_proof.preprocessed_variant), @tagName(variant))) return error.VariantMismatch;

    // 1. The trace log size and the registry entry.
    const proof = if (comptime verified_capture) cairo_proof.proof else &cairo_proof.proof.proof;
    const stark = &proof.commitment_scheme_proof;
    const pcs = stark.revision_config orelse return error.MissingLiftingHeights;
    if (pcs.trace_lifting_log_size != pcs.preprocessed_lifting_log_size) return error.UnequalLiftingHeights;
    const trace_log_size = std.math.sub(u32, pcs.trace_lifting_log_size, pcs.fri_config.log_blowup_factor) catch
        return error.LiftingBelowBlowup;
    const entry = try registry.leafVerifier(trace_log_size);
    const circuit_config = try registry.config(entry.config);
    const circuit_fri = circuit_config.fri_config;
    const target = finalize.ComponentSizes.fromLogSizes(circuit_config.component_log_sizes);

    // 2. `leaf_verifier_config` and the proof's widths.
    var leaf_config = try cairo_leaf_config.leafVerifierConfig(allocator, wrap.cairo_table, variant, pcs.fri_config, trace_log_size);
    defer leaf_config.deinit(allocator);
    if (stark.commitments.items.len == 0) return error.ColumnCountMismatch;
    const cairo_root = blake2_hash.digestToU32s(stark.commitments.items[0]);
    const config = leaf_config.verifierConfig(wrap.program, cairo_root, circuit_params.zkBlindingAmount(entry.zk_blinding, circuit_fri));

    const wire_config = config.proof_config.shape();
    const widths = wire_config.nColumnsPerTrace();
    if (stark.queried_values.items.len != widths.len) return error.ColumnCountMismatch;
    for (stark.queried_values.items[0..3], widths[0..3]) |columns, width|
        if (columns.len != width) return error.ColumnCountMismatch;

    const recorder = wrap.options.recorder;
    var build_stage = try StageScope.begin(recorder, "leaf_wrap_build", "convert the Cairo proof and build the leaf circuit");
    defer build_stage.end();

    // 3. `prepare_cairo_proof_for_circuit_verifier` and the output digest.
    const composition = if (comptime verified_capture) cairo_proof.composition else &cairo_proof.composition;
    var geometry = try cairo.statement_bootstrap.deriveFlatClaimGeometry(allocator, composition);
    defer geometry.deinit();
    if (!std.mem.eql(bool, geometry.component_enable_bits, config.enabled_bits)) return error.EnabledComponentsMismatch;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var converted = if (comptime verified_capture)
        try verifier_proof.fromVerifiedCapture(
            allocator,
            proof,
            capture,
            wire_config,
            cairo_proof.claimed_sums,
            cairo_proof.interaction_pow,
            cairo_proof.channel_salt,
        )
    else
        try verifier_proof.fromStarkProof(
            allocator,
            &cairo_proof.proof,
            wire_config,
            cairo_proof.claimed_sums,
            cairo_proof.interaction_pow,
            cairo_proof.channel_salt,
        );
    defer converted.deinit();
    const proof_values = try verifier_proof.circuitVerifierValues(arena, &converted.proof, converted.config);

    const aux_words = try circuit_leaf.serializeAuxData(allocator, input, geometry.component_log_sizes);
    defer allocator.free(aux_words);
    if (aux_words.len != config.auxDataLen()) return error.AuxDataLengthMismatch;
    const aux = try arena.alloc(M31, aux_words.len);
    for (aux, aux_words) |*out, word| out.* = M31.fromCanonical(word);
    const output_hash = try circuit_leaf.outputHash(input);

    const key = (topology_key.LeafKey{
        .config_name = entry.config,
        .circuit_fri = circuit_fri,
        .target = target,
        .variant = variant,
        .enabled_bits = config.enabled_bits,
        .cairo_fri = pcs.fri_config,
        .trace_log_size = trace_log_size,
        .zk_blinding = entry.zk_blinding,
        .cairo_preprocessed_root = cairo_root,
        .program = wrap.program,
    }).key();
    const cached = wrap.cache.get(key);
    // A resident source proves against the authenticated cached topology and
    // independently verifies the resulting proof. Its witness builder needs
    // the values and row counts, but not another full set of gate records.
    const record_gates = wrap.source == null or cached == null;

    // 4. The leaf circuit with values, padded to the shared target.
    var stages = stage_profile.Profile.init("leaf");
    var ctx = try cairo_verifier.buildCairoVerifierCircuitWithGateRecordingAndCapacity(QM31, allocator, wrap.cairo_table, &config, wrap.constants(), .{
        .proof = &proof_values,
        .serialized_aux_data = aux,
        .output_hash = output_hash,
    }, record_gates, if (cached) |hit| hit.n_vars else null, &stages);
    var ctx_owned = true;
    defer if (ctx_owned) ctx.deinit();
    stages.report(&ctx, "raw");
    try finalize.padToTargets(QM31, &ctx, target);
    stages.report(&ctx, "padded");
    if (record_gates and !try ctx.isCircuitValid()) return error.CircuitRejectsProof;
    build_stage.end();

    var fresh: ?LeafTopology = null;
    defer if (fresh) |*topology| topology.deinit(wrap.cache.allocator);
    const topology: *const LeafTopology = if (cached) |hit| blk: {
        if (hit.n_vars != ctx.circuit.n_vars) return error.TopologyMismatch;
        break :blk hit;
    } else blk: {
        var preprocess_stage = try StageScope.begin(recorder, "leaf_wrap_preprocess", "preprocess the leaf circuit (topology miss)");
        defer preprocess_stage.end();
        fresh = try buildTopology(wrap.cache.allocator, &ctx.circuit, circuit_fri, wrap.options, wrap.source == null);
        break :blk &fresh.?;
    };
    log.info("leaf topology {f}: {s}, {d} variables", .{ key, if (fresh == null) "cached" else "built", ctx.circuit.n_vars });

    // 5. Prove, check against the registry, serialize. The prover reads
    // only the values and the preprocessed circuit; the gates go first.
    const values = try ctx.intoValues();
    ctx_owned = false;
    defer allocator.free(values);
    const pcs_config = PcsConfigV2.fromFriAndTraceSize(circuit_fri, topology.preprocessed.traceLogSize());
    var produced: ?proof_source.Produced = if (wrap.source) |source| try source.run(allocator, .{
        .values = values,
        .preprocessed = &topology.preprocessed,
        .air = wrap.bundle,
        .config = pcs_config,
        .profile = .internal,
        .expected_preprocessed_root = entry.preprocessed_root.words,
    }) else null;
    defer if (produced) |*item| item.deinit();
    var circuit_proof: ?prove.Internal.CircuitProof = if (produced == null) try wrap.provers.internal(allocator, values, &topology.preprocessed, wrap.bundle, pcs_config, topology.proveOptions(wrap.options)) else null;
    defer if (circuit_proof) |*item| item.deinit();
    const root = if (produced) |item| item.preprocessed_root else blake2_hash.digestToU32s(circuit_proof.?.stark_proof.proof.commitment_scheme_proof.commitments.items[0]);
    const hash = if (produced) |item| item.circuit_hash else blake2_hash.digestToU32s(circuit_proof.?.circuit_hash);
    if (!std.mem.eql(u32, &root, &entry.preprocessed_root.words)) return error.PreprocessedRootMismatch;
    if (!std.mem.eql(u32, &hash, &entry.circuit_hash.words)) return error.CircuitHashMismatch;
    if (fresh == null and !std.mem.eql(u32, &hash, &topology.circuit_hash)) return error.TopologyMismatch;

    const bytes = blk: {
        var serialize_stage = try StageScope.begin(recorder, "leaf_wrap_serialize", "prepare and serialize the leaf proof");
        defer serialize_stage.end();
        if (produced) |*item| {
            const internal_proof = switch (item.proof) {
                .internal => |*internal| internal,
                .root => return error.WrongProofProfile,
            };
            const config_shape = try verifier_proof.proofConfig(topology.preprocessed.columns.len, pcs_config);
            break :blk try wire.circuit_serialize.serializeProofAlloc(allocator, internal_proof, config_shape);
        }
        var prepared = try verifier_proof.prepare(allocator, &circuit_proof.?);
        defer prepared.deinit();
        break :blk try prepared.serialize(allocator);
    };
    errdefer allocator.free(bytes);

    const cache_hit = fresh == null;
    if (fresh) |*topology_entry| {
        topology_entry.preprocessed_root = root;
        topology_entry.circuit_hash = hash;
        if (wrap.cache.publish(key, topology_entry.*)) |_| {
            fresh = null;
        } else |err| switch (err) {
            // Too large to keep: the wrap succeeded, the entry is dropped.
            error.EntryExceedsLimits => log.warn("leaf topology {f} exceeds the cache limits; not cached", .{key}),
            else => return err,
        }
    }
    return .{
        .allocator = allocator,
        .circuit_preprocessed_root = .{ .words = root },
        .circuit_hash = .{ .words = hash },
        .proof = bytes,
        .cache_hit = cache_hit,
    };
}
