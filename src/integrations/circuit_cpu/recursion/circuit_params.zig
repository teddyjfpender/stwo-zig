//! Circuit registry generation: `circuit-params --registry`.
//!
//! Ports `crates/circuit_params/src/{lib,main}.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 (design §7.3). A registry
//! definition fixes the verified Cairo proofs' parameters, the circuit FRI
//! config, the program and a range of Cairo trace log sizes; the registry
//! holds one leaf (Cairo verifier) circuit per trace size and the
//! multiverifier over them, all padded to one shared target:
//!
//! 1. every leaf circuit's padded sizes, built with a zero Cairo root (the
//!    root is a constant *value*, never topology);
//! 2. the target: the leaves' elementwise max (raised to
//!    `pad_to_component_log_sizes` when given), closed under the
//!    multiverifier fixpoint;
//! 3. the multiverifier padded to the target, preprocessed and hashed;
//! 4. every leaf rebuilt with its real Cairo preprocessed root (the Cairo
//!    preprocessed trace committed at `trace_log_size + log_blowup_factor`
//!    under `Blake2sM31MerkleChannel`), padded, checked to share the
//!    multiverifier's layout, preprocessed and hashed.
//!
//! Only one circuit is alive at a time, as upstream.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const prove = @import("../prove.zig");

const builder = circuit.builder;
const finalize = circuit.common.finalize;
const preprocessed = circuit.common.preprocessed;
const circuit_hash = circuit.common.circuit_hash;
const multiverifier = circuit.statements.multiverifier;
const cairo_verifier = circuit.statements.cairo_verifier;
const cairo_leaf_config = circuit.statements.cairo_leaf_config;
const component_table = circuit.air_eval.component_table;
const layout = core.cairo_air_layout;
const registry_format = wire.registry;
const ComponentSizes = finalize.ComponentSizes;
const FriConfig = core.pcs.config_v2.FriConfigV2;

pub const Error = error{
    /// The padding target a definition names is not the fixpoint its leaves
    /// and multiverifier converge to (upstream asserts).
    PadToTargetNotFixpoint,
    /// A padded leaf circuit does not have the multiverifier's layout.
    LeafLayoutMismatch,
};

/// The one config id every circuit of a generated registry shares.
pub const config_id = "default";

/// `DUMMY_PREPROCESSED_ROOT`.
pub const dummy_preprocessed_root: [8]u32 = @splat(0);

/// A definition with its three files read.
pub const Inputs = struct {
    definition: wire.registry_definition.RegistryDefinition,
    cairo_params: registry_format.ProverParameters,
    circuit_fri_config: FriConfig,
    program: []const layout.ProgramFelt,
};

/// The in-circuit evaluator tables of both AIRs.
pub const Tables = struct {
    cairo: *const component_table.Table,
    circuit: *const component_table.Table,
};

/// A generated registry; its slices live in `arena`.
pub const Generated = struct {
    arena: std.heap.ArenaAllocator,
    registry: registry_format.CircuitRegistry,

    pub fn deinit(self: *Generated) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// `serde_json::to_string_pretty(&registry)` and a newline, the bytes
    /// `circuit-params --registry --output-path` writes.
    pub fn write(self: *const Generated, out: *std.Io.Writer) std.Io.Writer.Error!void {
        try registry_format.writeRegistry(out, self.registry);
    }
};

/// `CircuitBuilder`: builds the leaf circuits of one definition.
pub const LeafBuilder = struct {
    table: *const component_table.Table,
    variant: layout.Variant,
    cairo_fri_config: FriConfig,
    circuit_fri_config: FriConfig,
    program: []const layout.ProgramFelt,
    add_zk_blinding: bool,

    pub fn init(tables: Tables, inputs: Inputs) LeafBuilder {
        return .{
            .table = tables.cairo,
            .variant = variantOf(inputs.cairo_params.preprocessed_trace),
            .cairo_fri_config = inputs.cairo_params.fri_config,
            .circuit_fri_config = inputs.circuit_fri_config,
            .program = inputs.program,
            .add_zk_blinding = inputs.definition.add_zk_blinding,
        };
    }

    /// `CircuitBuilder::build_context`: the leaf verifier topology for a
    /// Cairo proof of `trace_log_size`, with `cairo_root` baked in.
    pub fn buildTopology(self: *const LeafBuilder, gpa: std.mem.Allocator, trace_log_size: u32, cairo_root: [8]u32) !builder.Context(builder.NoValue) {
        var leaf_config = try cairo_leaf_config.leafVerifierConfig(gpa, self.table, self.variant, self.cairo_fri_config, trace_log_size);
        defer leaf_config.deinit(gpa);
        const zk_blinding_amount: ?usize = if (self.add_zk_blinding)
            @as(usize, self.circuit_fri_config.n_queries) + cairo_verifier.NON_QUERY_INFO_LEAK
        else
            null;
        const config = leaf_config.verifierConfig(self.program, cairo_root, zk_blinding_amount);
        return cairo_verifier.buildCairoVerifierTopology(gpa, self.table, &config, cairoConstants(self.table), circuit.stark_verifier.verify.NoStages{});
    }

    /// `CircuitBuilder::cairo_preprocessed_root`: the Cairo preprocessed
    /// trace committed at `trace_log_size + log_blowup_factor` under
    /// `Blake2sM31MerkleChannel`, as eight little-endian words.
    pub fn cairoPreprocessedRoot(self: *const LeafBuilder, gpa: std.mem.Allocator, trace_log_size: u32) ![8]u32 {
        const cairo_preprocessed = cairo.preprocessed;
        var spec = try cairo_preprocessed.trace.Spec.init(gpa, self.variant);
        defer spec.deinit();
        var pedersen: ?cairo_preprocessed.pedersen_table.Table = switch (self.variant) {
            .canonical_without_pedersen => null,
            .canonical => try cairo_preprocessed.pedersen_table.Table.init(gpa, .standard),
            .canonical_small => try cairo_preprocessed.pedersen_table.Table.init(gpa, .small),
        };
        defer if (pedersen) |*table| table.deinit();
        const binding = cairo_preprocessed.product_cache.Binding{
            .variant = self.variant,
            .spec_digest = cairo_preprocessed.product_cache.specDigest(spec),
            .pcs_digest = cairo_preprocessed.product_cache.pcsDigestRevision(self.cairo_fri_config),
        };
        const Engine = prove.Internal.Engine;
        const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndLiftingSize(self.cairo_fri_config, trace_log_size + self.cairo_fri_config.log_blowup_factor);
        var scheme = try Engine.initRevision(gpa, pcs);
        defer scheme.deinit(gpa);
        var channel = prove.Internal.Channel{};
        try cairo.proving.preprocessed_commit.commit(Engine, gpa, &spec, if (pedersen) |*table| table else null, binding, &scheme, &channel, null);
        var roots = try scheme.roots(gpa);
        defer roots.deinit(gpa);
        return circuit_hash.leU32sFromBytes(8, &roots.items[0]);
    }
};

/// The Cairo facts the leaf statement reads: relation ids from the Cairo
/// claim registry, memory constants from the projection.
fn cairoConstants(table: *const component_table.Table) circuit.statements.cairo_statement.Constants {
    const relation_ids = cairo.air.claims.relation_ids;
    return .{
        .opcodes_relation_id = relation_ids.OPCODES.v,
        .memory_address_to_id_relation_id = relation_ids.MEMORY_ADDRESS_TO_ID.v,
        .memory_id_to_big_relation_id = relation_ids.MEMORY_ID_TO_BIG.v,
        .memory = table.constants,
    };
}

fn variantOf(variant: registry_format.PreprocessedTraceVariant) layout.Variant {
    return switch (variant) {
        .canonical => .canonical,
        .canonical_without_pedersen => .canonical_without_pedersen,
        .canonical_small => .canonical_small,
    };
}

fn log2(n: usize) usize {
    return std.math.log2_int(usize, n);
}

fn logSizes(sizes: ComponentSizes) registry_format.LogSizes {
    const logs = sizes.map(log2);
    return .{
        .eq = @intCast(logs.eq),
        .qm31_ops = @intCast(logs.qm31_ops),
        .m31_to_u32 = @intCast(logs.m31_to_u32),
        .triple_xor = @intCast(logs.triple_xor),
        .blake_g_gate = @intCast(logs.blake_g_gate),
    };
}

/// `shared_target_fixpoint`: grows `start` until the multiverifier over
/// proofs of the target-padded layout fits the target. Returns the target
/// and the multiverifier topology built at it (not yet padded).
pub fn sharedTargetFixpoint(
    gpa: std.mem.Allocator,
    circuit_table: *const component_table.Table,
    start: ComponentSizes,
    fri: FriConfig,
) !struct { target: ComponentSizes, multiverifier: builder.Context(builder.NoValue) } {
    var target = start;
    while (true) {
        var shared = try multiverifier.foldSharedConfig(gpa, target, fri);
        defer shared.deinit(gpa);
        var ctx = try multiverifier.buildMultiverifierTopology(gpa, circuit_table, &shared, circuit.stark_verifier.verify.NoStages{});
        const grown = target.elementwiseMax(finalize.computePaddedSizes(&ctx.circuit));
        if (std.meta.eql(grown, target)) return .{ .target = target, .multiverifier = ctx };
        ctx.deinit();
        target = grown;
    }
}

/// `padded_preprocessed_circuit`: pads `ctx` (consumed) to `target` and
/// preprocesses it.
fn paddedPreprocessed(gpa: std.mem.Allocator, ctx: *builder.Context(builder.NoValue), target: ComponentSizes) !preprocessed.PreprocessedCircuit {
    defer ctx.deinit();
    try finalize.padToTargets(builder.NoValue, ctx, target);
    return preprocessed.PreprocessedCircuit.fromBuilderCircuit(gpa, &ctx.circuit);
}

/// `circuit_hash_and_preprocessed_root`.
fn identity(gpa: std.mem.Allocator, pp: *const preprocessed.PreprocessedCircuit, log_blowup_factor: u32) !struct { circuit_hash: [32]u8, preprocessed_root: [32]u8 } {
    const pp_layout = pp.layout();
    const root = try pp.preprocessedRoot(gpa, log_blowup_factor);
    const log_sizes = try circuit.statements.circuit_statement.circuitComponentLogSizes(&pp_layout);
    return .{ .circuit_hash = try circuit_hash.hostCircuitHash(log_sizes, log_blowup_factor, root), .preprocessed_root = root };
}

/// `circuit-params --registry`.
pub fn generate(gpa: std.mem.Allocator, tables: Tables, inputs: Inputs) !Generated {
    const definition = inputs.definition;
    const circuit_fri = inputs.circuit_fri_config;
    const leaf_builder = LeafBuilder.init(tables, inputs);

    // Pass 1: the leaves' padded sizes, one circuit at a time.
    var leaves_max: ?ComponentSizes = null;
    var trace_log_size = definition.min_trace_log_size;
    while (trace_log_size <= definition.max_trace_log_size) : (trace_log_size += 1) {
        var ctx = try leaf_builder.buildTopology(gpa, trace_log_size, dummy_preprocessed_root);
        defer ctx.deinit();
        const padded = finalize.computePaddedSizes(&ctx.circuit);
        leaves_max = if (leaves_max) |max| max.elementwiseMax(padded) else padded;
    }

    // The shared target and the multiverifier padded to it.
    var start = leaves_max.?;
    if (definition.pad_to_component_log_sizes) |pad_to| start = start.elementwiseMax(ComponentSizes.fromLogSizes(pad_to));
    var fixpoint = try sharedTargetFixpoint(gpa, tables.circuit, start, circuit_fri);
    const target = fixpoint.target;
    if (definition.pad_to_component_log_sizes) |pad_to| {
        if (!std.meta.eql(logSizes(target), pad_to)) {
            fixpoint.multiverifier.deinit();
            return error.PadToTargetNotFixpoint;
        }
    }
    var multiverifier_pp = try paddedPreprocessed(gpa, &fixpoint.multiverifier, target);
    const shared_layout = multiverifier_pp.layout();
    const multiverifier_identity = identity(gpa, &multiverifier_pp, circuit_fri.log_blowup_factor) catch |err| {
        multiverifier_pp.deinit(gpa);
        return err;
    };
    multiverifier_pp.deinit(gpa);

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    // Pass 2: each leaf's identity, with its real Cairo root.
    const n_leaves = definition.max_trace_log_size - definition.min_trace_log_size + 1;
    const leaf_verifiers = try a.alloc(registry_format.LeafVerifier, n_leaves);
    for (leaf_verifiers, definition.min_trace_log_size..) |*leaf, size| {
        const leaf_trace_log_size: u32 = @intCast(size);
        const cairo_root = try leaf_builder.cairoPreprocessedRoot(gpa, leaf_trace_log_size);
        var ctx = try leaf_builder.buildTopology(gpa, leaf_trace_log_size, cairo_root);
        var pp = try paddedPreprocessed(gpa, &ctx, target);
        defer pp.deinit(gpa);
        const pp_layout = pp.layout();
        if (!pp_layout.eql(&shared_layout) or pp_layout.traceLogSize() != shared_layout.traceLogSize())
            return error.LeafLayoutMismatch;
        const leaf_identity = try identity(gpa, &pp, circuit_fri.log_blowup_factor);
        leaf.* = .{
            .config = config_id,
            .trace_log_size = leaf_trace_log_size,
            .preprocessed_root = .fromBytes(leaf_identity.preprocessed_root),
            .circuit_hash = .fromBytes(leaf_identity.circuit_hash),
            .zk_blinding = definition.add_zk_blinding,
        };
    }

    const configs = try a.alloc(registry_format.NamedProofConfig, 1);
    configs[0] = .{ .name = config_id, .config = .{ .fri_config = circuit_fri, .component_log_sizes = logSizes(target) } };
    const multiverifiers = try a.alloc(registry_format.Multiverifier, 1);
    multiverifiers[0] = .{
        .config = config_id,
        .input_configs = .{ config_id, config_id },
        .preprocessed_root = .fromBytes(multiverifier_identity.preprocessed_root),
        .circuit_hash = .fromBytes(multiverifier_identity.circuit_hash),
    };
    return .{ .arena = arena, .registry = .{
        .cairo_prover_params = inputs.cairo_params,
        .circuit_proof_configs = configs,
        .leaf_verifiers = leaf_verifiers,
        .multiverifiers = multiverifiers,
    } };
}

test "circuit params: log sizes of a padded target" {
    const sizes = ComponentSizes{ .eq = 1 << 20, .qm31_ops = 1 << 23, .m31_to_u32 = 1 << 21, .triple_xor = 1 << 20, .blake_g_gate = 1 << 23 };
    try std.testing.expectEqual(registry_format.LogSizes{ .eq = 20, .qm31_ops = 23, .m31_to_u32 = 21, .triple_xor = 20, .blake_g_gate = 23 }, logSizes(sizes));
}
