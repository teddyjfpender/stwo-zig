//! Bounded RISC circuit-proof fold. Both children are actually verified by the
//! existing eleven-AIR circuit STARK verifier, under independently derived
//! RISC entries. Cairo registry hashes confer no authority here.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const Registry = @import("registry_v1.zig");
const Authority = @import("authority_v1.zig");
const Typed = @import("fold_statement_v1.zig");
const Conversion = @import("../verifier_proof.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
const OriginalAdmission = @import("../riscv_originals_v1/admission.zig");
const OriginalJoin = @import("../riscv_originals_v1/window_join.zig");
const OriginalRegistry = @import("../riscv_originals_v1/window_registry.zig");
const b = circuit.builder;
const Q = core.fields.qm31.QM31;
const Proof = circuit.stark_verifier.proof;
pub const production_active = false;
pub const qualification_status = "source only: bounded depth-two circuit fold not compiled or qualified";
pub const Metadata = union(enum) {
    leaf: Upper.Tree,
    /// Indirection is required for a finite Zig type. Exactly two ordered
    /// children; a depth/visit budget rejects cycles before rendering begins.
    pair: *const [2]Metadata,
    /// Actual original metadata only: no NativeParent root/proof/key exists.
    originals: OriginalAdmission.Metadata,
};
pub const Descriptor = struct {
    certificate: Typed.Certificate,
    registry_id: [32]u8,
    config: core.pcs.config_v2.PcsConfigV2,
    layout: circuit.common.preprocessed.ColumnLayout,
    preprocessed_root: [32]u8,
    circuit_hash: [32]u8,
    output_digest: [32]u8,
    fn child(v: Descriptor) Typed.Child {
        return .{ .role = v.certificate.role(), .registry_id = v.registry_id, .preprocessed_root = v.preprocessed_root, .circuit_hash = v.circuit_hash, .output_digest = v.output_digest };
    }
};
pub const Owned = struct {
    entry: Registry.Entry,
    descriptor: Descriptor,
    pub fn deinit(v: *Owned) void {
        v.entry.deinit();
        v.* = undefined;
    }
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    certificate: Typed.Certificate,
    pub fn deinit(v: *Artifact) void {
        v.allocator.free(v.bytes);
        v.* = undefined;
    }
};
pub fn validateMetadata(metadata: Metadata) !void {
    var visits: usize = 4095;
    try requireBounds(metadata, 0, &visits);
}

/// No child proof/key/receipt is an input. Every expected entry is rebuilt
/// from bounded RISC metadata and canonical circuit-AIR authorities.
pub fn derive(a: std.mem.Allocator, metadata: Metadata, backend: *const Registry.BackendAuthority, options: Registry.Options) anyerror!Owned {
    try validateMetadata(metadata);
    return deriveAt(a, metadata, backend, options);
}
fn deriveAt(a: std.mem.Allocator, metadata: Metadata, backend: *const Registry.BackendAuthority, options: Registry.Options) anyerror!Owned {
    switch (metadata) {
        .leaf => |source| {
            var authority = try Authority.Owned.derive(a, source);
            defer authority.deinit();
            const entry = try Registry.Entry.derive(a, &authority, options);
            const certificate = Typed.Certificate{ .window = authority.statement };
            return .{ .entry = entry, .descriptor = describe(&entry, certificate) };
        },
        .originals => |source| {
            var authority = try OriginalJoin.Authority.derive(a, source);
            defer authority.deinit();
            const entry = try OriginalRegistry.deriveEntry(a, &authority, options);
            const certificate = Typed.Certificate{ .originals = authority.statement };
            return .{ .entry = entry, .descriptor = describe(&entry, certificate) };
        },
        .pair => |children| {
            const descriptors = try deriveChildren(a, children, backend, options);
            const certificate = try parentCertificate(descriptors);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var ctx = try b.Context(b.NoValue).init(a, 8);
            defer ctx.deinit();
            var placeholders: [2]Proof.Proof(b.NoValue) = undefined;
            for (&placeholders, descriptors) |*placeholder, child| {
                var config = try circuit.statements.circuit_statement.circuitVerifierProofConfig(arena.allocator(), &child.layout, child.config);
                defer config.deinit(arena.allocator());
                placeholder.* = try Proof.emptyProof(arena.allocator(), config);
            }
            try build(b.NoValue, &ctx, descriptors, certificate, &placeholders, backend);
            const entry = try Registry.Entry.deriveFromTopology(a, &ctx, try certificate.digest(a), try certificate.digest(a), options);
            return .{ .entry = entry, .descriptor = describe(&entry, certificate) };
        },
    }
}
fn deriveChildren(a: std.mem.Allocator, children: *const [2]Metadata, backend: *const Registry.BackendAuthority, options: Registry.Options) ![2]Descriptor {
    var descriptors: [2]Descriptor = undefined;
    for (&descriptors, children.*) |*destination, child| {
        var owned = try deriveAt(a, child, backend, options);
        // Keep only structural layout/config and typed statement. No child
        // preprocessed polynomial/tree or parent proof remains in the descriptor.
        destination.* = owned.descriptor;
        owned.deinit();
    }
    return descriptors;
}
fn describe(entry: *const Registry.Entry, certificate: Typed.Certificate) Descriptor {
    var h = core.proof_suites.Blake3.Channel{};
    h.mixU32s(&.{ 0x52384352, 1, certificate.role() });
    h.mixRoot(entry.authority_id);
    h.mixRoot(entry.preprocessed_root);
    h.mixRoot(entry.circuit_hash);
    h.mixRoot(entry.output_digest);
    entry.config.fri_config.mixInto(&h);
    h.mixU32s(&.{ entry.config.trace_lifting_log_size, entry.config.preprocessed_lifting_log_size });
    return .{ .certificate = certificate, .registry_id = h.digestBytes(), .config = entry.config, .layout = entry.preprocessed.layout(), .preprocessed_root = entry.preprocessed_root, .circuit_hash = entry.circuit_hash, .output_digest = entry.output_digest };
}
fn parentCertificate(children: [2]Descriptor) !Typed.Certificate {
    for (children) |child| {
        if (!std.meta.eql(child.config.fri_config, @as(Registry.Options, .{}).fri)) return error.UnsupportedRiscFoldSecurity;
    }
    const depth = try std.math.add(u32, @max(children[0].certificate.depth(), children[1].certificate.depth()), 1);
    const leaves = try std.math.add(u32, children[0].certificate.leaves(), children[1].certificate.leaves());
    const statement = Typed.Statement{ .span = try Typed.Span.merge(children[0].certificate.span(), children[1].certificate.span()), .children = .{ children[0].child(), children[1].child() }, .depth = depth, .leaves = leaves };
    try statement.validate();
    return .{ .fold = statement };
}

/// The same builder is used in independent NoValue key derivation and proving.
/// Child output digests are computed from the typed words used for adjacency,
/// then handed directly to the complete circuit STARK verifier.
pub fn build(comptime V: type, ctx: *b.Context(V), children: [2]Descriptor, parent: Typed.Certificate, proofs: *const [2]Proof.Proof(V), backend: *const Registry.BackendAuthority) !void {
    if (parent != .fold) return error.InvalidRiscFoldParentRole;
    const expected = try parentCertificate(children);
    if (!std.meta.eql(parent, expected)) return error.UntrustedRiscFoldCoverage;
    const parent_view = try parent.allocate(V, ctx);
    var views: [2]Typed.View = undefined;
    for (&views, children, proofs.*, 0..) |*view, child, input, index| {
        view.* = try child.certificate.allocate(V, ctx);
        const digest = try view.digest(V, ctx);
        const first = 116 + 33 * index;
        try ctx.eq(parent_view.words[first].get(), view.words[2].get());
        for (digest, parent_view.words[first + 25 ..][0..8]) |actual, declared| try ctx.eq(actual.get(), declared.get());
        // The authenticated parent descriptor words are the actual root wires
        // consumed by the child verifier, not an unrelated host hash equality.
        const root = b.blake.HashValue(b.Var){ .words = parent_view.words[first + 9 ..][0..8].* };
        const output = b.blake.HashValue(b.Var){ .words = digest };
        const config = circuit.statements.circuit_statement.CircuitConfig{ .config = child.config, .preprocessed_column_log_sizes = child.layout };
        const statement = try circuit.statements.circuit_statement.CircuitStatement(V).init(ctx, &backend.table, &config, root, output);
        for (statement.circuit_hash.words, parent_view.words[first + 17 ..][0..8]) |actual, declared| try ctx.eq(actual.get(), declared.get());
        var proof_config = try circuit.statements.circuit_statement.circuitVerifierProofConfig(ctx.scratch(), &child.layout, child.config);
        defer proof_config.deinit(ctx.scratch());
        const proof_vars = try Proof.guess(V, ctx, &input);
        try circuit.stark_verifier.verify.verify(V, ctx, &proof_vars, proof_config, &statement, circuit.stark_verifier.verify.NoStages{});
    }
    try Typed.constrainMerge(V, ctx, views[0], views[1], parent_view);
    // Leaf counts/depth are statement operands of folded children. Native
    // wrapper leaves have the structural constants depth=0, leaves=1.
    var counts: [2]b.Var = undefined;
    var depths: [2]b.Var = undefined;
    for (&counts, &depths, views, children) |*count, *depth, view, child| {
        count.* = if (child.certificate == .fold) try wordScalar(V, ctx, view.words[183]) else ctx.one();
        depth.* = if (child.certificate == .fold) try wordScalar(V, ctx, view.words[182]) else ctx.zero();
    }
    try ctx.eq(try wordScalar(V, ctx, parent_view.words[183]), try ctx.add(counts[0], counts[1]));
    const bigger: usize = if (children[0].certificate.depth() >= children[1].certificate.depth()) 0 else 1;
    try ctx.eq(try wordScalar(V, ctx, parent_view.words[182]), try ctx.add(depths[bigger], ctx.one()));
    const digest = try parent_view.digest(V, ctx);
    var outputs: [8]b.Var = undefined;
    for (&outputs, digest) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
}

/// Exactly two raw child CIRCUIT proofs. No native proof re-execution or
/// successful host receipt replaces either in-circuit child verifier.
pub fn produce(a: std.mem.Allocator, metadata: Metadata, proofs: [2][]const u8, backend: *const Registry.BackendAuthority, options: Registry.Options) !Artifact {
    const pair = switch (metadata) {
        .pair => |children| children,
        .leaf, .originals => return error.InvalidRiscFoldFanIn,
    };
    var visits: usize = 4095;
    try requireBounds(metadata, 0, &visits);
    const result = block: {
        const children = try deriveChildren(a, pair, backend, options);
        const certificate = try parentCertificate(children);
        var key = try derive(a, metadata, backend, options);
        defer key.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var inputs: [2]Proof.Proof(Q) = undefined;
        for (&inputs, proofs, children) |*input, bytes, child| {
            const config = try Conversion.proofConfig(child.layout.entries.len, child.config);
            if (bytes.len == 0 or bytes.len > 128 << 20 or bytes.len != config.serializedLen()) return error.NonCanonicalRiscCircuitChildProof;
            var decoded = try wire.circuit_serialize.deserializeProof(a, bytes, config);
            defer decoded.deinit();
            if (decoded.consumed != bytes.len) return error.NonCanonicalRiscCircuitChildProof;
            input.* = try Conversion.circuitVerifierValues(arena.allocator(), &decoded.proof, config);
        }
        var ctx = try b.Context(Q).init(a, 8);
        var owns_ctx = true;
        defer if (owns_ctx) ctx.deinit();
        try build(Q, &ctx, children, certificate, &inputs, backend);
        try Registry.finalizeStrict(Q, &ctx);
        try circuit.common.finalize.padToTargets(Q, &ctx, key.entry.target);
        owns_ctx = false;
        const bytes = try Registry.proveFinalized(a, &ctx, &key.entry, backend, options);
        break :block Artifact{ .allocator = a, .bytes = bytes, .certificate = certificate };
    };
    errdefer a.free(result.bytes);
    // Producer keys, child decoded material and value context have gone away.
    try verifyBytes(a, metadata, result.bytes, backend, options);
    return result;
}
pub fn verifyBytes(a: std.mem.Allocator, metadata: Metadata, bytes: []const u8, backend: *const Registry.BackendAuthority, options: Registry.Options) !void {
    if (bytes.len == 0 or bytes.len > 128 << 20) return error.RiscCircuitProofResourceLimit;
    var expected = try derive(a, metadata, backend, options);
    defer expected.deinit();
    try Registry.verifyWithEntry(a, &expected.entry, bytes, backend);
}
pub fn verifyFull(a: std.mem.Allocator, metadata: Metadata, bytes: []const u8, boundary: *const Full.Owned, backend: *const Registry.BackendAuthority, options: Registry.Options) !void {
    if (bytes.len == 0 or bytes.len > 128 << 20) return error.RiscCircuitProofResourceLimit;
    var visits: usize = 4095;
    try requireBounds(metadata, 0, &visits);
    try requireSelections(metadata, boundary);
    var expected = try derive(a, metadata, backend, options);
    defer expected.deinit();
    const s = expected.descriptor.certificate.span();
    if (!std.meta.eql(boundary.config, @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config())) return error.UnsupportedRiscFoldSecurity;
    const cpu = boundary.initial_policy.cpu;
    var initial: [33]u32 = undefined;
    initial[0] = cpu.pc;
    @memcpy(initial[1..], &cpu.regs);
    if (s.first_cycle != 1 or s.cycles != boundary.terminal_policy.policy.final_cycle or !std.meta.eql(s.elf_sha256, boundary.elf_sha256) or !std.meta.eql(s.incoming_snapshot_id, boundary.initial_policy.snapshot_id) or !std.meta.eql(s.initial_cpu, initial) or s.initial_policy_id == null or s.terminal_policy_id == null or !std.meta.eql(s.initial_policy_id.?, boundary.initial_policy.policy_id) or !std.meta.eql(s.terminal_policy_id.?, boundary.terminal_policy.policy_id)) return error.UntrustedRiscCircuitFullBoundary;
    try Registry.verifyWithEntry(a, &expected.entry, bytes, backend);
}

/// An odd frontier element is carried unchanged: no padding, invented sibling,
/// new key or receipt. Borrowed metadata/proof lifetimes stay with the caller.
pub const Pending = struct { metadata: Metadata, bytes: []const u8 };
pub fn oddCarry(frontier: []const Pending) !?Pending {
    if (frontier.len == 0 or frontier.len > 2048) return error.InvalidRiscFoldFrontier;
    return if (frontier.len % 2 == 1) frontier[frontier.len - 1] else null;
}
fn requireBounds(metadata: Metadata, depth: usize, visits: *usize) anyerror!void {
    if (depth > 16 or visits.* == 0) return error.RiscCircuitFoldResourceLimit;
    visits.* -= 1;
    switch (metadata) {
        .leaf => |source| try requireSourceBounds(source, 0, visits),
        .originals => {}, // Original admission is finite/nonrecursive and bounded independently.
        .pair => |children| for (children.*) |child| try requireBounds(child, depth + 1, visits),
    }
}
fn requireSourceBounds(source: Upper.Tree, depth: usize, visits: *usize) anyerror!void {
    if (depth > 16 or visits.* == 0) return error.RiscCircuitFoldResourceLimit;
    visits.* -= 1;
    switch (source) {
        .leaf, .mixed_leaf => {},
        .branch => |branch| {
            if (branch.children.len < 2 or branch.children.len > 4) return error.InvalidB8WindowFanIn;
            for (branch.children) |child| try requireSourceBounds(child, depth + 1, visits);
        },
    }
}
fn requireSelections(metadata: Metadata, boundary: *const Full.Owned) anyerror!void {
    switch (metadata) {
        .leaf => |source| try requireSourceSelections(source, boundary),
        .originals => |source| switch (source) {
            inline else => |leaf| if (!std.meta.eql(try boundary.windowOptions(leaf.external.trusted.window.skip_cycles, leaf.external.trusted.window.cycles), leaf.external.boundary)) return error.UntrustedRiscCircuitFullBoundary,
        },
        .pair => |children| for (children.*) |child| try requireSelections(child, boundary),
    }
}
fn requireSourceSelections(source: Upper.Tree, boundary: *const Full.Owned) anyerror!void {
    switch (source) {
        inline .leaf, .mixed_leaf => |leaf| if (!std.meta.eql(try boundary.windowOptions(leaf.external.trusted.window.skip_cycles, leaf.external.trusted.window.cycles), leaf.external.boundary)) return error.UntrustedRiscCircuitFullBoundary,
        .branch => |branch| for (branch.children) |child| try requireSourceSelections(child, boundary),
    }
}
fn wordScalar(comptime V: type, ctx: *b.Context(V), word: Typed.W) !b.Var {
    const limbs = b.simd.Simd.fromPacked(&.{word.get()}, 2);
    const high = try b.simd.unpackIdx(V, ctx, limbs, 1);
    try ctx.eq(high, ctx.zero());
    return b.simd.unpackIdx(V, ctx, limbs, 0);
}
