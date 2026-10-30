//! Instance-derived RISC circuit registry and CPU/backend-neutral handoff.
//! This is deliberately not the Cairo registry: no Cairo leaf hash, program,
//! target size, or preprocessed commitment authorizes a RISC theorem here.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const Prove = @import("../prove.zig");
const Air = @import("../air.zig");
const Verifier = @import("../verify.zig");
const VerifierProof = @import("../verifier_proof.zig");
const ProofSource = @import("../recursion/proof_source.zig");
const Authority = @import("authority_v1.zig");
const Material = @import("proof_material_v1.zig");
const Leaf = @import("leaf_wrap_v1.zig");
const Statement = circuit.statements.riscv_native_parent_v1;
const Receiver = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Q = core.fields.qm31.QM31;
const finalize = circuit.common.finalize;
const Preprocessed = circuit.common.preprocessed.PreprocessedCircuit;
const D = core.vcs.blake2_hash;
pub const production_active = false;
pub const qualification_status = "source-only; no complete RISC circuit wrapper proof qualified";
pub const Options = struct {
    /// Explicit separate outer protocol: proving_5a7c5ed + Blake2sM31.
    fri: core.pcs.config_v2.FriConfigV2 = .{ .pow_bits = 26, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 },
    prover: Prove.Options = .{},
    source: ?ProofSource.Source = null,
};

/// Both outer circuit equation authorities are pinned canonical artifacts,
/// parsed here instead of accepting a caller-nominated evaluator or AIR.
pub const BackendAuthority = struct {
    allocator: std.mem.Allocator,
    air_bytes: []u8,
    projection_bytes: []u8,
    projection: circuit.air_eval.projection.Projection,
    table: circuit.air_eval.component_table.Table,
    bundle: Air.Bundle,
    pub const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";
    pub fn load(a: std.mem.Allocator, air_bytes: []const u8, projection_bytes: []const u8) !*BackendAuthority {
        try requireSha256(air_bytes, Air.bundle_sha256);
        try requireSha256(projection_bytes, projection_sha256);
        const out = try a.create(BackendAuthority);
        errdefer a.destroy(out);
        out.allocator = a;
        out.air_bytes = try a.dupe(u8, air_bytes);
        errdefer a.free(out.air_bytes);
        out.projection_bytes = try a.dupe(u8, projection_bytes);
        errdefer a.free(out.projection_bytes);
        out.projection = try circuit.air_eval.projection.parse(a, out.projection_bytes);
        errdefer out.projection.deinit();
        out.table = try circuit.air_eval.circuit_components.build(a, &out.projection);
        errdefer out.table.deinit();
        out.bundle = try Air.parse(a, out.air_bytes);
        return out;
    }
    pub fn deinit(v: *BackendAuthority) void {
        const a = v.allocator;
        v.bundle.deinit();
        v.table.deinit();
        v.projection.deinit();
        a.free(v.air_bytes);
        a.free(v.projection_bytes);
        a.destroy(v);
    }
};

pub const Entry = struct {
    allocator: std.mem.Allocator,
    authority_id: [32]u8,
    preprocessed: Preprocessed,
    commitment: Prove.PreprocessedCommitment,
    config: core.pcs.config_v2.PcsConfigV2,
    target: finalize.ComponentSizes,
    n_vars: u32,
    preprocessed_root: [32]u8,
    circuit_hash: [32]u8,
    output_digest: [32]u8,

    /// This factory receives no proof/capture. Independent NoValue rendering
    /// derives the expected circuit key from metadata and canonical equations.
    pub fn derive(a: std.mem.Allocator, authority: *const Authority.Owned, options: Options) !Entry {
        try authority.validate();
        try requireProfile(options.fri);
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const dummy = try Material.Owned.zeroForTopologyLeaky(scratch.allocator(), authority.geometry);
        var ctx = try circuit.builder.Context(circuit.builder.NoValue).init(a, Leaf.OUTPUTS);
        defer ctx.deinit();
        _ = try Leaf.build(circuit.builder.NoValue, &ctx, authority, &dummy);
        return deriveFromTopology(a, &ctx, authority.seal, try Statement.digest(a, authority.statement), options);
    }
    /// Mechanical key compilation. This is not an admission API: public
    /// receivers always reconstruct this topology from typed RISC metadata.
    pub fn deriveFromTopology(a: std.mem.Allocator, ctx: *circuit.builder.Context(circuit.builder.NoValue), authority_id: [32]u8, output_digest: [32]u8, options: Options) !Entry {
        try requireProfile(options.fri);
        try finalizeStrict(circuit.builder.NoValue, ctx);
        const target = finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
        try finalize.padToTargets(circuit.builder.NoValue, ctx, target);
        var pp = try Preprocessed.fromBuilderCircuit(a, &ctx.circuit);
        errdefer pp.deinit(a);
        const config = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(options.fri, pp.traceLogSize());
        var commitment = try Prove.PreprocessedCommitment.build(a, &pp, config, options.prover);
        errdefer commitment.deinit(a);
        const root = commitment.root();
        const layout = pp.layout();
        const log_sizes = try circuit.statements.circuit_statement.circuitComponentLogSizes(&layout);
        return .{ .allocator = a, .authority_id = authority_id, .preprocessed = pp, .commitment = commitment, .config = config, .target = target, .n_vars = @intCast(ctx.circuit.n_vars), .preprocessed_root = root, .circuit_hash = try circuit.common.circuit_hash.hostCircuitHash(log_sizes, config.fri_config.log_blowup_factor, root), .output_digest = output_digest };
    }
    pub fn deinit(v: *Entry) void {
        v.commitment.deinit(v.allocator);
        v.preprocessed.deinit(v.allocator);
        v.* = undefined;
    }
    fn request(v: *const Entry, a: std.mem.Allocator) !Verifier.Request {
        const layout = v.preprocessed.layout();
        const columns = try a.alloc(wire.verify_request.Column, layout.entries.len);
        for (columns, layout.entries) |*column, entry| column.* = .{ .id = entry.id, .log_size = entry.log_size };
        return .{ .pcs_config = v.config, .preprocessed_column_log_sizes = columns, .preprocessed_root = D.digestToU32s(v.preprocessed_root), .output_digest = D.digestToU32s(v.output_digest) };
    }
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    statement: Statement.Statement,
    pub fn deinit(v: *Artifact) void {
        v.allocator.free(v.bytes);
        v.* = undefined;
    }
};

/// Returns only serialized outer proof and its typed statement. Native proof,
/// expanded paths, row values and both producer/registry keys are destroyed
/// before the fresh receiver independently recompiles the expected key.
pub fn produce(a: std.mem.Allocator, metadata: Receiver.Tree, native_bytes: []const u8, backend: *const BackendAuthority, options: Options) !Artifact {
    const result = blk: {
        var authority = try Authority.Owned.derive(a, metadata);
        defer authority.deinit();
        var material = try Material.Owned.fromBytes(a, native_bytes, &authority);
        defer material.deinit();
        var entry = try Entry.derive(a, &authority, options);
        defer entry.deinit();
        var ctx = try circuit.builder.Context(Q).init(a, Leaf.OUTPUTS);
        var ctx_owned = true;
        defer if (ctx_owned) ctx.deinit();
        _ = try Leaf.build(Q, &ctx, &authority, &material);
        try finalizeStrict(Q, &ctx);
        try finalize.padToTargets(Q, &ctx, entry.target);
        if (ctx.circuit.n_vars != entry.n_vars or !try ctx.isCircuitValid()) return error.RiscCircuitRejectsNativeProof;
        ctx_owned = false; // proveFinalized consumes ctx, including on error.
        const bytes = try proveFinalized(a, &ctx, &entry, backend, options);
        break :blk Artifact{ .allocator = a, .bytes = bytes, .statement = authority.statement };
    };
    errdefer a.free(result.bytes);
    try verifyBytes(a, metadata, result.bytes, backend, options);
    return result;
}

/// The received proof never supplies its expected key, circuit hash or output
/// statement. Metadata/checkpoints are still required for instance admission.
pub fn verifyBytes(a: std.mem.Allocator, metadata: Receiver.Tree, bytes: []const u8, backend: *const BackendAuthority, options: Options) !void {
    if (bytes.len == 0 or bytes.len > 128 << 20) return error.RiscCircuitProofResourceLimit;
    var authority = try Authority.Owned.derive(a, metadata);
    defer authority.deinit();
    var entry = try Entry.derive(a, &authority, options);
    defer entry.deinit();
    try verifyWithEntry(a, &entry, bytes, backend);
}
/// Mechanical byte verification; high-level receiving reconstructs Entry from
/// metadata and does not accept a proof-supplied key, hash, layout or receipt.
pub fn verifyWithEntry(a: std.mem.Allocator, entry: *const Entry, bytes: []const u8, backend: *const BackendAuthority) !void {
    const shape = try VerifierProof.proofConfig(entry.preprocessed.columns.len, entry.config);
    if (bytes.len == 0 or bytes.len > 128 << 20 or bytes.len != shape.serializedLen()) return error.NonCanonicalRiscCircuitProof;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const request = try entry.request(arena.allocator());
    const verdict = try Verifier.verifyProofBytes(a, &backend.table, &request, bytes);
    if (!verdict.isAccepted()) return error.RiscCircuitOuterProofRejected;
}
fn requireProfile(fri: core.pcs.config_v2.FriConfigV2) !void {
    if (fri.pow_bits != 26 or fri.n_queries != 70 or fri.log_blowup_factor != 1 or fri.log_last_layer_degree_bound != 0 or fri.fold_step != 1) return error.UnsupportedRiscCircuitOuterProfile;
}
fn requireSha256(bytes: []const u8, expected: []const u8) !void {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    const actual = std.fmt.bytesToHex(hash, .lower);
    if (!std.mem.eql(u8, &actual, expected)) return error.UntrustedRiscCircuitEquationArtifact;
}

/// Diagnostics do not relax use checking or change the circuit. Only report
/// variable identities and producer kinds; request values are never printed.
pub fn finalizeStrict(comptime V: type, ctx: *circuit.builder.Context(V)) !void {
    ctx.finalize(true) catch |err| {
        if (err == error.UnusedVarNotMarked or err == error.UsedVarMarkedUnused)
            diagnoseVariableUse(ctx) catch {};
        return err;
    };
}
fn diagnoseVariableUse(ctx: anytype) !void {
    var counts = try ctx.circuit.computeMultiplicities(ctx.gpa);
    defer counts.deinit(ctx.gpa);
    var missing: usize = 0;
    var illegal: usize = 0;
    for (counts.n_uses, 0..) |uses, index| {
        const marked = ctx.unused_vars.contains(@intCast(index));
        if (uses != 0 and marked) illegal += 1;
        if (uses == 0 and !marked and !ctx.maybe_unused_vars.contains(@intCast(index))) {
            if (missing < 8) std.debug.print("RISC_CIRCUIT_UNUSED var={d} producer={s}\n", .{ index, producerKind(ctx, @intCast(index)) });
            missing += 1;
        }
    }
    std.debug.print("RISC_CIRCUIT_VARIABLE_USE vars={d} marked={d} missing={d} used_but_marked={d}\n", .{ counts.n_uses.len, ctx.unused_vars.count(), missing, illegal });
}
fn producerKind(ctx: anytype, index: u32) []const u8 {
    for (ctx.circuit.triple_xor.items) |gate| if (gate.out == index) return "triple_xor";
    for (ctx.circuit.blake_g_gate.items) |gate| if (index >= gate.out_base and index - gate.out_base < 4) return "blake_g";
    inline for (.{ "add", "sub", "mul", "pointwise_mul" }) |field| {
        for (@field(ctx.circuit, field).items) |gate| if (gate.out == index) return field;
    }
    for (ctx.circuit.m31_to_u32.items) |gate| if (gate.out == index) return "m31_to_u32";
    return "reserved_guess_or_constant";
}

/// Backend-neutral mechanical proving, never an expected-key authority.
/// Consumes ctx on every path. Entry must come from metadata-only compilation.
pub fn proveFinalized(a: std.mem.Allocator, ctx: *circuit.builder.Context(Q), entry: *const Entry, backend: *const BackendAuthority, options: Options) ![]u8 {
    var owns_ctx = true;
    defer if (owns_ctx) ctx.deinit();
    if (!ctx.finalized or ctx.circuit.n_vars != entry.n_vars or !try ctx.isCircuitValid()) return error.RiscCircuitRejectsProof;
    const values = try ctx.intoValues();
    owns_ctx = false;
    defer a.free(values);
    const bytes = if (options.source) |source| source_bytes: {
        var proof = try source.run(a, .{ .values = values, .preprocessed = &entry.preprocessed, .air = &backend.bundle, .config = entry.config, .profile = .internal, .expected_preprocessed_root = D.digestToU32s(entry.preprocessed_root) });
        defer proof.deinit();
        if (!std.meta.eql(proof.preprocessed_root, D.digestToU32s(entry.preprocessed_root)) or !std.meta.eql(proof.circuit_hash, D.digestToU32s(entry.circuit_hash)) or !std.meta.eql(proof.output_digest, D.digestToU32s(entry.output_digest))) return error.UntrustedRiscCircuitBackend;
        const internal = switch (proof.proof) {
            .internal => |*p| p,
            .root => return error.UnsupportedRiscCircuitOuterProfile,
        };
        break :source_bytes try wire.circuit_serialize.serializeProofAlloc(a, internal, try VerifierProof.proofConfig(entry.preprocessed.columns.len, entry.config));
    } else cpu_bytes: {
        var effective = options.prover;
        effective.preprocessed_commitment = &entry.commitment;
        var proof = try Prove.cpu_provers.internal(a, values, &entry.preprocessed, &backend.bundle, entry.config, effective);
        defer proof.deinit();
        if (!std.meta.eql(proof.circuit_hash, entry.circuit_hash)) return error.UntrustedRiscCircuitBackend;
        var prepared = try VerifierProof.prepare(a, &proof);
        defer prepared.deinit();
        break :cpu_bytes try prepared.serialize(a);
    };
    return bytes;
}
