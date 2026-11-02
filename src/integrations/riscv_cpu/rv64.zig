//! Concrete CPU proof lifecycle for the separately admitted bounded RV64 AIR.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const B = @import("stwo_cpu_backend").CpuBackend;
const P = rv.protocol;
const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const Statement = rv.statement.Statement;
pub const Metadata = rv.statement.Metadata;
pub const Proof = P.Proof;
pub const Bundle = struct {
    metadata: Metadata,
    proof: Proof,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        self.metadata.deinit(a);
        self.proof.deinit(a);
        self.* = undefined;
    }
};

pub fn prove(a: std.mem.Allocator, public: Statement) !Bundle {
    return provePreparedOwned(a, public, try rv.witness.Witness.build(a, public));
}

/// Consumes the untrusted witness on every path. Execution/capture constructs
/// hints once; projection releases the wide row storage before proving.
pub fn provePreparedOwned(a: std.mem.Allocator, public: Statement, witness_value: rv.witness.Witness) !Bundle {
    var witness = witness_value;
    defer witness.deinit();
    var trace = try rv.trace.Trace.init(a, public, witness.metadata, witness.rows);
    defer trace.deinit();
    witness.allocator.free(witness.rows);
    witness.rows = &.{};
    return proveTrace(a, public, witness.metadata, &trace);
}

/// Prepared rows are untrusted. Their constraints and state closure are proved;
/// acceptance is not a comparison with the execution engine.
pub fn provePrepared(a: std.mem.Allocator, public: Statement, witness: *const rv.witness.Witness) !Bundle {
    var trace = try rv.trace.Trace.init(a, public, witness.metadata, witness.rows);
    defer trace.deinit();
    return proveTrace(a, public, witness.metadata, &trace);
}

fn proveTrace(a: std.mem.Allocator, public: Statement, metadata: Metadata, trace: *rv.trace.Trace) !Bundle {
    var channel = P.Channel{};
    try P.mix(&channel, public, metadata, trace.log_size);
    var scheme = try Scheme.init(a, P.config());
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    const fixed = try trace.columns(a, 0);
    defer a.free(fixed);
    const main = try trace.columns(a, 1);
    defer a.free(main);
    try scheme.commit(a, fixed, &channel);
    try scheme.commit(a, main, &channel);
    const challenges = rv.relations.Challenges.draw(&channel);
    const target = try rv.relations.expected(public, metadata, challenges);
    _ = try trace.generateInteraction(challenges);
    const interaction = try trace.columns(a, 2);
    defer a.free(interaction);
    try scheme.commit(a, interaction, &channel);
    var component = try rv.component.Component.init(trace.log_size, trace.projection, challenges, target);
    // PCS owns its prepared columns; release the source buffers before proving.
    trace.releaseColumns();
    const components = [_]engine.air.component_prover.ComponentProver{component.asProverComponent()};
    // The core consumes scheme on both success and error.
    owns_scheme = false;
    var proof = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, &components, &channel, scheme);
    errdefer proof.deinit(a);
    const path = try a.dupe(u64, metadata.path);
    errdefer a.free(path);
    const clocks = try a.dupe(u16, metadata.memory_clocks);
    return .{ .metadata = .{ .path = path, .register_clocks = metadata.register_clocks, .memory_clocks = clocks }, .proof = proof };
}

/// Caller-owned immutable preprocessing, independently derived from the public
/// program and execution schedule. No producer key/root is accepted. Registers,
/// RAM values/rights and final access clocks remain per-request transcript data.
pub const PreparedSetup = struct {
    allocator: std.mem.Allocator,
    program: []u32,
    program_addresses: []u64,
    path: []u64,
    program_base: u64,
    final_pc: u64,
    log_size: u32,
    projection: rv.projection.Projection,
    root: [32]u8,

    pub fn init(a: std.mem.Allocator, public: Statement, metadata: Metadata) !PreparedSetup {
        var trusted = try rv.trace.Trace.init(a, public, metadata, null);
        defer trusted.deinit();
        var fixed_scheme = try Scheme.init(a, P.config());
        defer fixed_scheme.deinit(a);
        const fixed = try trusted.columns(a, 0);
        defer a.free(fixed);
        var channel = P.Channel{};
        try fixed_scheme.commit(a, fixed, &channel);
        var roots = try fixed_scheme.roots(a);
        defer roots.deinit(a);
        const program = try a.dupe(u32, public.program);
        errdefer a.free(program);
        const addresses = try a.dupe(u64, public.program_addresses);
        errdefer a.free(addresses);
        const path = try a.dupe(u64, metadata.path);
        return .{ .allocator = a, .program = program, .program_addresses = addresses, .path = path, .program_base = public.program_base, .final_pc = public.final_pc, .log_size = trusted.log_size, .projection = trusted.projection, .root = roots.items[0] };
    }
    pub fn deinit(self: *PreparedSetup) void {
        self.allocator.free(self.program);
        self.allocator.free(self.program_addresses);
        self.allocator.free(self.path);
        self.* = undefined;
    }
    fn validateProofShape(self: *const PreparedSetup, proof: *const Proof) !void {
        const pcs = &proof.commitment_scheme_proof;
        if (pcs.commitments.items.len != 4 or pcs.sampled_values.items.len != 4 or
            pcs.queried_values.items.len != 4 or pcs.decommitments.items.len != 4) return error.InvalidRv64ProofShape;
        const composition_columns = core.verifier_types.compositionColumnCount(rv.layout.EXPANSION, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidRv64ProofShape;
        const counts = [4]usize{ self.projection.fixed_count, self.projection.main_count, rv.layout.INTERACTION, composition_columns };
        for (counts, 0..) |count, tree| {
            if (pcs.sampled_values.items[tree].len != count or pcs.queried_values.items[tree].len != count) return error.InvalidRv64ProofShape;
            for (pcs.sampled_values.items[tree], 0..) |column, c| {
                const expected: usize = if (tree == 2 and c >= 32) 2 else 1;
                if (column.len != expected) return error.InvalidRv64ProofShape;
            }
            for (pcs.queried_values.items[tree]) |column| {
                if (column.len == 0 or column.len > P.config().fri_config.n_queries) return error.InvalidRv64ProofShape;
            }
        }
    }
    /// Always consumes proof, including a mismatched request. The caller supplies
    /// the expected statement independently on every verification.
    pub fn verifyOwned(self: *const PreparedSetup, a: std.mem.Allocator, public: Statement, metadata: Metadata, proof_value: Proof) !void {
        var proof = proof_value;
        var owns_proof = true;
        defer if (owns_proof) proof.deinit(a);
        try metadata.validate(public);
        if (public.program_base != self.program_base or public.final_pc != self.final_pc or
            !std.mem.eql(u32, public.program, self.program) or !std.mem.eql(u64, public.program_addresses, self.program_addresses) or !std.mem.eql(u64, metadata.path, self.path)) return error.Rv64SetupIdentityMismatch;
        if (!std.meta.eql(proof.commitment_scheme_proof.config, P.config())) return error.InvalidRv64ProofConfig;
        try self.validateProofShape(&proof);
        const commitments = proof.commitment_scheme_proof.commitments.items;
        if (!std.mem.eql(u8, &self.root, &commitments[0])) return error.UntrustedRv64Preprocessing;
        var channel = P.Channel{};
        try P.mix(&channel, public, metadata, self.log_size);
        var verifier = try Verifier.init(a, P.config());
        defer verifier.deinit(a);
        const fixed_logs = try filledLogs(a, self.projection.fixed_count, self.log_size);
        defer a.free(fixed_logs);
        const main_logs = try filledLogs(a, self.projection.main_count, self.log_size);
        defer a.free(main_logs);
        const interaction_logs = try filledLogs(a, rv.layout.INTERACTION, self.log_size);
        defer a.free(interaction_logs);
        try verifier.commit(a, commitments[0], fixed_logs, &channel);
        try verifier.commit(a, commitments[1], main_logs, &channel);
        const challenges = rv.relations.Challenges.draw(&channel);
        const target = try rv.relations.expected(public, metadata, challenges);
        try verifier.commit(a, commitments[2], interaction_logs, &channel);
        var component = try rv.component.Component.init(self.log_size, self.projection, challenges, target);
        const components = [_]core.air.components.Component{component.asVerifierComponent()};
        owns_proof = false;
        try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &components, &channel, &verifier, proof);
    }
};

/// Convenience path. Repeated verifications should retain PreparedSetup instead.
/// Always consumes proof, including setup derivation failures.
pub fn verifyOwned(a: std.mem.Allocator, public: Statement, metadata: Metadata, proof: Proof) !void {
    var setup = PreparedSetup.init(a, public, metadata) catch |err| {
        var owned = proof;
        owned.deinit(a);
        return err;
    };
    defer setup.deinit();
    try setup.verifyOwned(a, public, metadata, proof);
}

fn filledLogs(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
    const result = try a.alloc(u32, count);
    @memset(result, log);
    return result;
}
