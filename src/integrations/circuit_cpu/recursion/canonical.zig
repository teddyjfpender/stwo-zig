//! The one circuit shape that verifies every layer of a recursive tree.
//!
//! Ports `CanonicalCircuit::build` of
//! `crates/stwo_run_and_prove_recursive_tree/src/canonical.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). The leaf and multiverifier
//! circuits of a registry are padded to its shared target, so they share one
//! preprocessed layout and one `trace_log_size`: a single multiverifier shape
//! verifies leaf proofs (layer 1) and multiverifier proofs (every layer
//! above), and an unpaired entry can be carried up unchanged.
//!
//! The shape depends only on the registry's target sizes and circuit FRI
//! config (design §3.5), so it is built once per process in topology mode
//! and its circuit hash is checked against the registry once, here, before
//! any proving (design §7.2).

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const verifier_proof = @import("../verifier_proof.zig");
const prove = @import("../prove.zig");
const circuit_params = @import("circuit_params.zig");
const topology_key = @import("topology_key.zig");
const topology_cache = @import("topology_cache.zig");

const builder = circuit.builder;
const finalize = circuit.common.finalize;
const preprocessed = circuit.common.preprocessed;
const circuit_hash = circuit.common.circuit_hash;
const multiverifier = circuit.statements.multiverifier;
const component_table = circuit.air_eval.component_table;
const ComponentSizes = finalize.ComponentSizes;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

pub const Hash = [32]u8;

pub const Error = error{
    /// `RecursiveTreeError::PaddingParity`: the multiverifier padded to the
    /// registry's target does not have the layout it was built to verify.
    PaddingParity,
    /// `RecursiveTreeError::MultiverifierCircuitHash`: the built multiverifier
    /// does not hash to the registry's entry.
    MultiverifierCircuitHash,
    UnsupportedCompactTerminalRegistry,
    TerminalCircuitHashMismatch,
};

/// Production registry's homogeneous child key and the compact terminal key
/// derived from that exact two-child verifier topology. The terminal root
/// was independently committed by the resident prover and extracted from its
/// verified proof; its hash was also recorded in the packed root. A change to
/// the child registry requires deriving and qualifying a new terminal key.
const terminal_key = struct {
    const child_root = [_]u32{ 0xe479ab39, 0xc55be4ac, 0x9f98c322, 0xd73b0254, 0xb7ae54fb, 0xe78a54c5, 0xb0486f13, 0x66e91045 };
    const child_hash = [_]u32{ 0xa5989715, 0x2377c07a, 0xc6d1e844, 0x54f0a04d, 0x8be65a7d, 0xfd73c261, 0x9078e728, 0x973f680f };
    const root = [_]u32{ 2417389210, 2999989152, 2684763732, 3436300829, 3428327508, 3680076162, 2468850231, 399589778 };
    const hash = [_]u32{ 708715752, 3519296436, 620525775, 1567930826, 4247635046, 1011846141, 340946107, 538352252 };
};

pub const CanonicalCircuit = struct {
    /// The configuration shared by every proof the multiverifier verifies.
    shared: multiverifier.SharedConfig,
    /// The registry's padding target.
    target_sizes: ComponentSizes,
    /// Exact padded witness length of the authenticated outer topology.
    n_vars: u32,
    /// The outer proof's configuration. A terminal circuit can be smaller
    /// than the child proofs it verifies, so this need not equal `shared`.
    prover_config: PcsConfigV2,
    /// The padded multiverifier, preprocessed: the shape every fold proves.
    preprocessed: preprocessed.PreprocessedCircuit,
    /// Its preprocessed root at the circuit blowup and its circuit hash,
    /// equal to the registry's multiverifier entry.
    preprocessed_root: Hash,
    circuit_hash: Hash,
    /// The committed preprocessed tree every fold leases (design §7.2), and
    /// the twiddles every fold borrows; set by `commitPreprocessed`.
    commitment: ?prove.PreprocessedCommitment = null,
    twiddles: ?prove.TwiddleTower = null,

    /// `CanonicalCircuit::build`. `table` is the circuit AIR's in-circuit
    /// evaluator table (`air_eval.circuit_components.build`).
    pub fn build(
        gpa: std.mem.Allocator,
        table: *const component_table.Table,
        registry: wire.registry.CircuitRegistry,
    ) !CanonicalCircuit {
        return buildWithMode(gpa, table, registry, .canonical_host);
    }

    /// The resident prover commits the preprocessed columns on the device and
    /// its independent verifier checks that commitment against the registry.
    /// Avoid committing the same columns on the CPU merely to discover a root
    /// that the authenticated registry already supplies.
    pub fn buildForDevice(
        gpa: std.mem.Allocator,
        table: *const component_table.Table,
        registry: wire.registry.CircuitRegistry,
    ) !CanonicalCircuit {
        return buildWithMode(gpa, table, registry, .canonical_device);
    }

    /// A terminal-only multiverifier. Its child proof configuration remains
    /// canonical, but its own AIR is padded only to the rows it actually uses.
    /// This circuit is intentionally not a homogeneous internal tree node.
    pub fn buildTerminal(
        gpa: std.mem.Allocator,
        table: *const component_table.Table,
        registry: wire.registry.CircuitRegistry,
    ) !CanonicalCircuit {
        return buildWithMode(gpa, table, registry, .terminal_compact);
    }

    const BuildMode = enum { canonical_host, canonical_device, terminal_compact };

    fn buildWithMode(
        gpa: std.mem.Allocator,
        table: *const component_table.Table,
        registry: wire.registry.CircuitRegistry,
        mode: BuildMode,
    ) !CanonicalCircuit {
        const entry = try registry.multiverifier();
        if (mode == .terminal_compact and
            (!std.mem.eql(u32, &entry.preprocessed_root.words, &terminal_key.child_root) or
                !std.mem.eql(u32, &entry.circuit_hash.words, &terminal_key.child_hash)))
            return error.UnsupportedCompactTerminalRegistry;
        const config = try registry.config(entry.config);
        const target = ComponentSizes.fromLogSizes(config.component_log_sizes);

        // 1. The shared config of a child proof, derived from the target.
        var shared = try multiverifier.foldSharedConfig(gpa, target, config.fri_config);
        errdefer shared.deinit(gpa);

        // 2. The multiverifier shape, padded to the target.
        var outer_target = target;
        var n_vars: u32 = undefined;
        var pp = blk: {
            var ctx = try multiverifier.buildMultiverifierTopology(gpa, table, &shared, circuit.stark_verifier.verify.NoStages{});
            defer ctx.deinit();
            if (mode == .terminal_compact)
                outer_target = finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
            try finalize.padToTargets(builder.NoValue, &ctx, outer_target);
            n_vars = ctx.circuit.n_vars;
            break :blk try preprocessed.PreprocessedCircuit.fromBuilderCircuit(gpa, &ctx.circuit);
        };
        errdefer pp.deinit(gpa);

        // 3. Homogeneity: it has the layout it verifies.
        const layout = pp.layout();
        if (mode != .terminal_compact and (!layout.eql(&shared.preprocessed_column_log_sizes) or
            layout.traceLogSize() != shared.preprocessed_column_log_sizes.traceLogSize()))
            return error.PaddingParity;

        // 4. The registry's trust anchor.
        const identity = if (mode != .canonical_host) blk: {
            const root = if (mode == .terminal_compact)
                core.vcs.blake2_hash.digestFromU32s(terminal_key.root)
            else
                entry.preprocessed_root.toBytes();
            const log_sizes = try circuit.statements.circuit_statement.circuitComponentLogSizes(&layout);
            break :blk circuit_params.Identity{
                .preprocessed_root = root,
                .circuit_hash = try circuit_hash.hostCircuitHash(log_sizes, shared.pcs_config.fri_config.log_blowup_factor, root),
            };
        } else try circuit_params.identity(gpa, &pp, shared.pcs_config.fri_config.log_blowup_factor);
        if (mode == .terminal_compact and
            !std.mem.eql(u8, &identity.circuit_hash, &core.vcs.blake2_hash.digestFromU32s(terminal_key.hash)))
            return error.TerminalCircuitHashMismatch;
        if (mode != .terminal_compact and !std.mem.eql(u8, &identity.circuit_hash, &entry.circuit_hash.toBytes()))
            return error.MultiverifierCircuitHash;

        return .{
            .shared = shared,
            .target_sizes = outer_target,
            .n_vars = n_vars,
            .prover_config = PcsConfigV2.fromFriAndTraceSize(config.fri_config, layout.traceLogSize()),
            .preprocessed = pp,
            .preprocessed_root = identity.preprocessed_root,
            .circuit_hash = identity.circuit_hash,
        };
    }

    /// Commits the preprocessed tree once, as every fold under `options`
    /// would, and keeps it with the twiddle tower it was extended with. The
    /// root must equal the identity's, which `build` checked against the
    /// registry. The tree is stored as `options` says, for every fold.
    pub fn commitPreprocessed(self: *CanonicalCircuit, gpa: std.mem.Allocator, options: prove.Options) !void {
        if (self.commitment != null) return error.AlreadyCommitted;
        const pcs_config = self.prover_config;
        var twiddles = try prove.twiddleTower(gpa, pcs_config);
        errdefer twiddles.deinit(gpa);
        var commit_options = options;
        commit_options.twiddle_tower = &twiddles;
        commit_options.preprocessed_commitment = null;
        var commitment = try prove.PreprocessedCommitment.build(gpa, &self.preprocessed, pcs_config, commit_options);
        errdefer commitment.deinit(gpa);
        if (!std.mem.eql(u8, &commitment.root(), &self.preprocessed_root)) return error.PreprocessedRootMismatch;
        self.twiddles = twiddles;
        self.commitment = commitment;
    }

    /// `options` with this circuit's committed tree and twiddles, when
    /// `commitPreprocessed` ran. The tower lives in `self`, so the result
    /// must not outlive it (nor the circuit move).
    pub fn proveOptions(self: *const CanonicalCircuit, options: prove.Options) prove.Options {
        var out = options;
        if (self.commitment) |*commitment| out.preprocessed_commitment = commitment;
        if (self.twiddles) |*twiddles| out.twiddle_tower = twiddles;
        return out;
    }

    /// Retained bytes, for the topology cache's budget.
    pub fn byteSize(self: *const CanonicalCircuit) usize {
        var bytes: usize = 0;
        for (self.preprocessed.columns) |column| bytes += column.values.len * @sizeOf(core.fields.m31.M31);
        if (self.commitment) |*commitment| bytes += commitment.byteSize();
        if (self.twiddles) |*twiddles| bytes += twiddles.retainedBytes();
        return bytes;
    }

    pub fn deinit(self: *CanonicalCircuit, gpa: std.mem.Allocator) void {
        if (self.commitment) |*commitment| commitment.deinit(gpa);
        if (self.twiddles) |*twiddles| twiddles.deinit(gpa);
        self.preprocessed.deinit(gpa);
        self.shared.deinit(gpa);
        self.* = undefined;
    }

    /// The `CircuitSerialize` layout of every proof in the tree
    /// (`shared_config.proof_config`).
    pub fn proofConfig(self: *const CanonicalCircuit) wire.circuit_serialize.ProofConfig {
        return self.shared.proof_config.shape();
    }
};

/// Canonical circuits by fold topology (design §3.5): a fold's topology
/// depends on the registry config alone (`topology_key.FoldKey`), so one
/// entry serves every tree of every registry with that config.
pub const Cache = topology_cache.TopologyCache(CanonicalCircuit);

/// The fold `TopologyKey` of `registry`'s multiverifier.
pub fn foldKey(registry: wire.registry.CircuitRegistry) !topology_key.TopologyKey {
    const entry = try registry.multiverifier();
    const config = try registry.config(entry.config);
    return (topology_key.FoldKey{
        .config_name = entry.config,
        .circuit_fri = config.fri_config,
        .target = ComponentSizes.fromLogSizes(config.component_log_sizes),
    }).key();
}

/// The canonical circuit of `registry`: from `cache` on a hit, else built,
/// checked against the registry, committed under `options` and published.
/// A hit still checks the registry's multiverifier circuit hash, which the
/// key does not cover. `cache` must use `gpa`. The pointer is valid until the
/// cache's next publish or deinit.
pub fn acquire(
    gpa: std.mem.Allocator,
    cache: *Cache,
    table: *const component_table.Table,
    registry: wire.registry.CircuitRegistry,
    options: prove.Options,
) !*const CanonicalCircuit {
    const key = try foldKey(registry);
    const expected = (try registry.multiverifier()).circuit_hash.toBytes();
    if (cache.get(key)) |hit| {
        if (!std.mem.eql(u8, &hit.circuit_hash, &expected)) return error.MultiverifierCircuitHash;
        return hit;
    }
    var built = try CanonicalCircuit.build(gpa, table, registry);
    var owned = true;
    defer if (owned) built.deinit(gpa);
    try built.commitPreprocessed(gpa, options);
    const published = try cache.publish(key, built);
    owned = false;
    return published;
}
