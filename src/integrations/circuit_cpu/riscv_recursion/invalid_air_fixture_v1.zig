//! Qualification-only: a genuine PCS proof with an invalid typed AIR trace.
//! Correct canonical fixed tree, exact prefix, all physical claims and their
//! public-supply closure, correct FS/PoW/q70/FRI. No native AIR verdict is used.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const b = @import("stwo_circuit_frontend").builder;
const Authority = @import("authority_v1.zig");
const Material = @import("proof_material_v1.zig");
const Leaf = @import("leaf_wrap_v1.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Parent = @import("../../../frontends/riscv/recursion/blake3_execution_parent_proof.zig");
const Universal = @import("../../../frontends/riscv/recursion/air/universal_challenges.zig");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Scheme = Engine.pcs.CommitmentSchemeProver(Cpu, suite.Hasher, suite.MerkleChannel);
pub const production_active = false;

pub fn qualify(a: std.mem.Allocator, metadata: Upper.Tree) !void {
    var seed = try Authority.Owned.deriveRetainingFixedForQualification(a, metadata);
    defer seed.deinit();
    var scheme = try Scheme.init(a, seed.geometry.config);
    var scheme_owned = true;
    defer if (scheme_owned) scheme.deinit(a);
    // Keep polynomial storage bounded; this does not change any commitment.
    scheme.setCompactPolynomialStorage(20);
    const fixed = if (seed.fixed_for_qualification) |*value| value else return error.MissingQualificationFixedTree;
    if (!std.meta.eql(fixed.tree.root(), seed.profile.fixed_root)) return error.UntrustedQualificationFixedTree;
    var discarded = suite.Channel{};
    try fixed.tree.share(a);
    var lease = fixed.tree;
    var lease_transferred = false;
    defer if (!lease_transferred) lease.deinit(a);
    try scheme.appendCommittedTree(a, lease, &discarded);
    lease_transferred = true;
    // All MAIN columns are the constant polynomial 2. No AIR writer is called.
    try commitConstants(a, &scheme, seed.geometry.trees[1], 2, &discarded);
    var first_roots = try scheme.roots(a);
    defer first_roots.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), first_roots.items.len);
    const request = withMainRoot(metadata, first_roots.items[1]);
    var admitted = try Authority.Owned.derive(a, request);
    defer admitted.deinit();
    try std.testing.expectEqualDeep(seed.profile.fixed_root, admitted.profile.fixed_root);
    // Actual MAIN is nominated before the independent receiving key/prefix is
    // rebuilt. No post-prefix root mutation or stale producer key is involved.
    var transcript = suite.Channel{};
    try admitted.profile.admission.mix(&transcript);
    transcript.mixRoot(first_roots.items[0]);
    transcript.mixRoot(first_roots.items[1]);
    const draws = try transcript.drawSecureFelts(a, Universal.DRAW_COUNT);
    defer a.free(draws);
    const relations = Universal.UniversalRelations.fromDraws(draws);
    const supply = try publicSupply(&admitted, relations);
    var claims: Parent.artifact.Claims = @splat(Q.zero());
    claims[0] = supply.neg();
    try admitted.profile.admission.validateClaimsForRelations(claims, relations);
    try admitted.profile.admission.mixClaims(&transcript, &claims);
    // Interaction columns are constant 3; quotient columns are constant zero.
    try commitConstants(a, &scheme, admitted.geometry.trees[2], 3, &transcript);
    _ = transcript.drawSecureFelt(); // composition alpha, before quotient root.
    try commitConstants(a, &scheme, admitted.geometry.trees[3], 0, &transcript);
    const point = core.circle.secureFieldPointFromRandomSeed(transcript.drawSecureFelt());
    const points = try Material.samplePoints(a, admitted.geometry, point);
    // PCS prover computes honest sampled evaluations, DEEP, PoW26, openings,
    // and FRI from the committed polynomials. It never evaluates typed AIR.
    scheme_owned = false; // proveValues consumes scheme and sample points.
    var pcs = try scheme.proveValues(a, points, &transcript);
    defer pcs.deinit(a);
    const borrowed = Parent.artifact.Owned{ .allocator = a, .proof = .{ .commitment_scheme_proof = pcs.proof }, .key_id = admitted.profile.admission.expected_id, .claims = claims };
    // borrowed aliases pcs.proof and must NOT be separately deinitialized.
    const bytes = try Parent.codec.encode(a, &borrowed, &admitted.profile.admission);
    defer a.free(bytes);
    // Positive PCS-only control from freshly decoded bytes. This is the same
    // expansion path used by the deployed wrapper; no AIR pre-verification.
    var material = try Material.Owned.fromBytes(a, bytes, &admitted);
    defer material.deinit();
    try admitted.profile.admission.validateClaimsForRelations(material.claims, relations);
    // Diagnose the exact two canonical graph outputs: AIR/OODS must be false,
    // while the independent public-supply/physical-claim closure stays true.
    try requireAirInvalidSupplyValid(a, &admitted, &material, draws);
    // Crucially this is the REAL complete leaf builder, with its actual emitted
    // constraints enforced eagerly. No PCS-only mode or stubbed AIR is exposed.
    var ctx = try b.Context(Q).init(a, Leaf.OUTPUTS);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = true;
    try std.testing.expectError(error.RiscCircuitTypedCompositionRejected, Leaf.build(Q, &ctx, &admitted, &material));
    std.debug.print("RISC_CIRCUIT_AIR_INVALID_CONTROL q70=70 pow=26 valid_pcs=true correct_fixed=true correct_prefix=true claims=25 public_supply_closed=true typed_air_oods_nonzero=true actual_leaf_rejected=true\n", .{});
}

fn publicSupply(authority: *const Authority.Owned, relations: Universal.UniversalRelations) !Q {
    const relation = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (authority.profile.admission.source.terms) |term| {
        const tuple = [_]M{ M.fromCanonical(term.circuit), M.fromCanonical(term.wire) } ++ term.coordinates;
        const value = Q.fromBase(M.fromCanonical(term.uses)).mul(try (try relation.combineBase(&tuple)).inv());
        sum = if (term.negative) sum.sub(value) else sum.add(value);
    }
    return sum;
}
fn commitConstants(a: std.mem.Allocator, scheme: *Scheme, tree: @import("stwo_circuit_frontend").builder.blake3_pcs_reuse_v1.Tree, value: u32, transcript: *suite.Channel) !void {
    const columns = try a.alloc(Engine.pcs.ColumnEvaluation, tree.columns.len);
    defer a.free(columns);
    var initialized: usize = 0;
    defer for (columns[0..initialized]) |column| a.free(column.values);
    for (columns, tree.columns) |*column, geometry| {
        const values = try a.alloc(M, @as(usize, 1) << @intCast(geometry.log_size));
        @memset(values, M.fromCanonical(value));
        column.* = .{ .log_size = geometry.log_size, .values = values };
        initialized += 1;
    }
    // This API borrows source values and copies polynomial/commitment storage.
    try scheme.commit(a, columns, transcript);
}
fn withMainRoot(tree: Upper.Tree, root: [32]u8) Upper.Tree {
    var out = tree;
    switch (out) {
        .leaf => |*leaf| leaf.input.main_root = root,
        .mixed_leaf => |*leaf| leaf.main_root = root,
        .branch => |*branch| branch.main_root = root,
    }
    return out;
}
fn requireAirInvalidSupplyValid(a: std.mem.Allocator, authority: *const Authority.Owned, material: *const Material.Owned, draws: []const Q) !void {
    const graph = &authority.composition.circuit;
    try std.testing.expectEqual(@as(usize, 2), graph.outputs.len);
    const inputs = try a.alloc(Q, authority.composition.sources.len);
    defer a.free(inputs);
    for (inputs, authority.composition.sources) |*value, source| value.* = switch (source) {
        .sample => |i| material.material.sampled_values[i],
        .claim => |i| material.claims[i],
        .challenge => |i| draws[i],
        .composition => material.material.composition_randomness,
        .oods => material.material.oods_seed,
        .packed_public_input => |i| Q.fromBase(authority.profile.admission.source.terms[i / 4].coordinates[i % 4]),
        .public_input => return error.UnsupportedQualificationLegacySpan,
    };
    const values = try a.alloc(Q, graph.nodes.len);
    defer a.free(values);
    // evaluateInto fills every node before checking its zero anchors. Thus the
    // failure is expected, while both completed residual values stay inspectable.
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.evaluateInto(inputs, values));
    try std.testing.expect(!values[graph.outputs[0]].isZero());
    try std.testing.expect(values[graph.outputs[1]].isZero());
}
