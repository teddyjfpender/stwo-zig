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

    pub fn deinit(self: *LeafTopology, allocator: std.mem.Allocator) void {
        self.preprocessed.deinit(allocator);
    }

    pub fn byteSize(self: *const LeafTopology) usize {
        var bytes: usize = 0;
        for (self.preprocessed.columns) |column| bytes += column.values.len * @sizeOf(M31);
        return bytes;
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

/// Wraps `cairo_proof`, the Cairo lane's `Result` for the leaf engine, of
/// the execution `input`.
pub fn wrapCairoProof(
    allocator: std.mem.Allocator,
    wrap: *const LeafWrap,
    cairo_proof: anytype,
    input: *const cairo.adapter.ProverInput,
) !LeafProof {
    const registry = wrap.registry;
    const params = registry.cairo_prover_params;
    if (!params.include_all_preprocessed_columns) return error.IncludeAllPreprocessedColumnsRequired;
    if (params.lifting_size_policy != .at_least_preprocessed) return error.AtLeastPreprocessedRequired;
    const variant = params.preprocessed_trace;
    if (!std.mem.eql(u8, @tagName(cairo_proof.preprocessed_variant), @tagName(variant))) return error.VariantMismatch;

    // 1. The trace log size and the registry entry.
    const stark = &cairo_proof.proof.proof.commitment_scheme_proof;
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

    // 3. `prepare_cairo_proof_for_circuit_verifier` and the output digest.
    var geometry = try cairo.statement_bootstrap.deriveFlatClaimGeometry(allocator, &cairo_proof.composition);
    defer geometry.deinit();
    if (!std.mem.eql(bool, geometry.component_enable_bits, config.enabled_bits)) return error.EnabledComponentsMismatch;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var converted = try verifier_proof.fromStarkProof(
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

    // 4. The leaf circuit with values, padded to the shared target.
    var ctx = try cairo_verifier.buildCairoVerifierCircuit(QM31, allocator, wrap.cairo_table, &config, wrap.constants(), .{
        .proof = &proof_values,
        .serialized_aux_data = aux,
        .output_hash = output_hash,
    }, circuit.stark_verifier.verify.NoStages{});
    var ctx_owned = true;
    defer if (ctx_owned) ctx.deinit();
    try finalize.padToTargets(QM31, &ctx, target);
    if (!try ctx.isCircuitValid()) return error.CircuitRejectsProof;

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
    var fresh: ?LeafTopology = null;
    defer if (fresh) |*topology| topology.deinit(wrap.cache.allocator);
    const topology: *const LeafTopology = if (wrap.cache.get(key)) |hit| blk: {
        if (hit.n_vars != ctx.circuit.n_vars) return error.TopologyMismatch;
        break :blk hit;
    } else blk: {
        fresh = .{
            .preprocessed = try PreprocessedCircuit.fromBuilderCircuit(wrap.cache.allocator, &ctx.circuit),
            .n_vars = ctx.circuit.n_vars,
            .preprocessed_root = undefined,
            .circuit_hash = undefined,
        };
        break :blk &fresh.?;
    };
    log.info("leaf topology {f}: {s}, {d} variables", .{ key, if (fresh == null) "cached" else "built", ctx.circuit.n_vars });

    // 5. Prove, check against the registry, serialize. The prover reads
    // only the values and the preprocessed circuit; the gates go first.
    // The prover frees the value table once the base trace is written.
    var owned_values = prove.OwnedValues{ .allocator = allocator, .values = try ctx.intoValues() };
    ctx_owned = false;
    defer owned_values.release();
    var options = wrap.options;
    options.release_values = owned_values.releaseOption();
    const pcs_config = PcsConfigV2.fromFriAndTraceSize(circuit_fri, topology.preprocessed.traceLogSize());
    var circuit_proof = try prove.Internal.prove(allocator, owned_values.values.?, &topology.preprocessed, wrap.bundle, pcs_config, options, {});
    defer circuit_proof.deinit();
    const root = blake2_hash.digestToU32s(circuit_proof.stark_proof.proof.commitment_scheme_proof.commitments.items[0]);
    const hash = blake2_hash.digestToU32s(circuit_proof.circuit_hash);
    if (!std.mem.eql(u32, &hash, &entry.circuit_hash.words)) return error.CircuitHashMismatch;
    if (fresh == null and !std.mem.eql(u32, &hash, &topology.circuit_hash)) return error.TopologyMismatch;

    var prepared = try verifier_proof.prepare(allocator, &circuit_proof);
    defer prepared.deinit();
    const bytes = try prepared.serialize(allocator);
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
