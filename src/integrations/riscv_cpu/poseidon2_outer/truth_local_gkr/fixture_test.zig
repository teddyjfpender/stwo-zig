//! Actual source proof gate for the opt-in width replacement. No production
//! manifest/CLI chooses this route until the recursive/catalog joins qualify.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const W = @import("../pure_p2_worker_protocol.zig").W;
const Profile = @import("../op_profile.zig").Profile;
const Source = @import("../../word16_global_execution/services/roster.zig").TruthSource;
const Fixtures = @import("../../word16_global_execution/services/gkr_local/truth_test.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/truth_frame.zig");
const Meta = @import("../../word16_global_execution/services/gkr_local/truth_metadata.zig");
const GM = @import("../../word16_global_execution/services/gkr_local/truth_global_metadata.zig");
const GW = @import("../../word16_global_execution/services/gkr_local/truth_global_witness.zig");
const N = @import("native.zig");
const Shapes = @import("authority.zig");
const C = @import("component.zig");
const O = core.fields.om31.OM31;
fn check(source: *Source) !void {
    const owner = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 8 << 30);
    defer owner.destroy();
    const a = owner.allocator();
    const frames = try Frame.forSource(source);
    var shapes: [3]Shapes.Shape = undefined;
    for (frames, &shapes) |frame, *shape| shape.* = .{ .original = .{ .kind = frame.role, .log_size = frame.row_log, .keccak_policy = frame.keccak_policy, .byte_policy = frame.byte_policy } };
    try Shapes.validate(shapes);
    var fixed_list: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
    defer fixed_list.deinit(a);
    for (shapes, 0..) |shape, index| {
        const values: []const core.fields.m31.M31 = switch (source.*) {
            .keccak => |v| if (index == 0) v.permutation.fixed else if (index == 1) v.chi.fixed else v.xor5.fixed,
            .secp => |v| if (index == 0) v.batch.product.fixed else if (index == 1) v.batch.linear.fixed else v.bytes.fixed,
            else => unreachable,
        };
        const rows = try shape.instance().rows();
        for (0..shape.widths()[0]) |column| try fixed_list.append(a, .{ .log_size = shape.original.log_size, .values = values[column * rows ..][0..rows] });
    }
    const fixed = try fixed_list.toOwnedSlice(a);
    defer a.free(fixed);
    const main = try source.columns(a, 1);
    defer a.free(main);
    const profile = Profile.op_target_b4_q72_p0_fold4_v1;
    var channel = W.Channel.init();
    profile.config().mixInto(&channel);
    channel.mixU32s(&N.DOMAIN);
    var scheme = try W.Prover.init(a, profile.config());
    var scheme_owned = true;
    defer if (scheme_owned) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    try scheme.commitBorrowedStreaming(a, fixed, 64, &channel);
    try scheme.commitBorrowedStreaming(a, main, 64, &channel);
    const scope = N.Scope{ .statement = @import("../pure_p2_native.zig").hashBytes("truth-local-gkr-fixture")[0..32].*, .fixed = scheme.trees.items[0].root(), .main = scheme.trees.items[1].root(), .manifest = @import("../pure_p2_native.zig").hashWords(&.{42}), .ordinal = 0 };
    const metadata = try Meta.Provider.initClassic(source, frames);
    var child = try N.proveUnbound(a, scope, shapes, metadata);
    defer child.deinit(a);
    const child_bytes = try N.encode(a, shapes, &child.result.proof);
    defer a.free(child_bytes);
    var decoded_child = try N.decode(a, shapes, child_bytes);
    defer decoded_child.deinit();
    var pending = try N.verifyPending(a, scope, shapes, &decoded_child.proof, child.digest);
    defer pending.deinit(a);
    var binding = try @import("witness.zig").Witness.init(a, shapes, &pending.challenges, metadata, &pending.artifact, pending.eta);
    defer binding.deinit();
    const shared = try @import("../pure_p2_manifest.zig").drawShared(scope.manifest);
    var global_metadata = try GM.Provider.init(a, source, 8 << 20);
    defer global_metadata.deinit();
    const challenges = GW.Challenges{ .io = shared.kio, .wire = shared.wire };
    var globals: [2]GW.Witness = undefined;
    var global_count: usize = 0;
    defer for (globals[0..global_count]) |*w| w.deinit();
    globals[0] = try GW.generate(a, &global_metadata, frames[0].role, &challenges, 64 << 20);
    global_count = 1;
    if (source.* == .secp) {
        globals[1] = try GW.generate(a, &global_metadata, frames[1].role, &challenges, 64 << 20);
        global_count = 2;
    }
    var data: [3]C.Data = undefined;
    var count: usize = 0;
    defer for (data[0..count]) |*d| d.deinit();
    var components: [3]C.Component = undefined;
    var offsets: [3]usize = .{ 0, 0, 0 };
    var inter: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
    defer inter.deinit(a);
    for (shapes, 0..) |shape, index| {
        data[index] = try C.Data.init(a, shape, pending.terminal(), index);
        count += 1;
        const calls: u32 = if (index < global_count) if (source.* == .keccak) source.keccak.permutation.calls else source.secp.batch.product.calls else 0;
        const first: u32 = if (index < global_count) if (source.* == .keccak) source.keccak.permutation.first_call_id else source.secp.batch.product.first_id else 1;
        components[index] = .{ .original = .{ .kind = shape.original.kind, .log_size = shape.original.log_size, .calls = calls, .first_id = first, .program = if (source.* == .secp) source.secp.batch.product.program else null, .keccak_policy = shape.original.keccak_policy, .byte_policy = shape.original.byte_policy, .local = pending.challenges, .shared = shared, .claim = O.zero(), .global_claim = if (index < global_count) globals[index].claims[0] else O.zero(), .split = if (source.* == .keccak) 2 else 1 }, .data = &data[index], .offsets = offsets };
        try components[index].validate();
        const rows = try frames[index].rows();
        for (0..16) |column| try inter.append(a, .{ .log_size = frames[index].row_log, .values = binding.columns[index][column * rows ..][0..rows] });
        if (index < global_count) for (0..globals[index].width()) |column| try inter.append(a, .{ .log_size = frames[index].row_log, .values = globals[index].data[column * rows ..][0..rows] });
        for (components[index].widths(), 0..) |width, tree| offsets[tree] += width;
    }
    channel.mixRoot(scope.manifest);
    channel.mixRoot(child.digest);
    const claims = [_]O{ globals[0].claims[0], if (global_count == 2) globals[1].claims[0] else O.zero() };
    channel.mixFelts(&claims);
    try scheme.commitBorrowedStreaming(a, inter.items, 64, &channel);
    const handles = [_]engine.air.component_prover.ForField(O).ComponentProver{ components[0].asProverComponent(), components[1].asProverComponent(), components[2].asProverComponent() };
    scheme_owned = false;
    var proof = try W.Prover.prove(a, &handles, &channel, scheme, .{});
    defer proof.deinit(a);
    const encoded = try W.Wire.encodeProofBytesBinary(a, proof.proof);
    defer a.free(encoded);
    var decoded = try W.Wire.decodeProofBytesBinary(a, encoded);
    defer decoded.deinit(a);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, profile.config());
    defer receiver.deinit(a);
    var verifier_channel = W.Channel.init();
    profile.config().mixInto(&verifier_channel);
    verifier_channel.mixU32s(&N.DOMAIN);
    const roots = decoded.commitment_scheme_proof.commitments.items;
    for ([_][]const engine.pcs.ColumnEvaluation{ fixed, main }, 0..) |columns, tree| {
        const logs = try a.alloc(u32, columns.len);
        defer a.free(logs);
        for (columns, logs) |column, *log| log.* = column.log_size;
        try receiver.commit(a, roots[tree], logs, &verifier_channel);
    }
    verifier_channel.mixRoot(scope.manifest);
    verifier_channel.mixRoot(child.digest);
    verifier_channel.mixFelts(&claims);
    const logs = try a.alloc(u32, inter.items.len);
    defer a.free(logs);
    for (inter.items, logs) |column, *log| log.* = column.log_size;
    try receiver.commit(a, roots[2], logs, &verifier_channel);
    const verifiers = [_]core.air.components.ForField(O).Component{ components[0].asVerifierComponent(), components[1].asVerifierComponent(), components[2].asVerifierComponent() };
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &verifiers, &verifier_channel, &receiver, &decoded, &capture);
    defer capture.deinit(a);
    std.debug.print("OP_TRUTH_LOCAL_GKR_NATIVE kind={s} native_bytes={d} columns={any} samples={d}\n", .{ @tagName(source.*), encoded.len, (try Shapes.cost(shapes)).new_widths, (try Shapes.cost(shapes)).new_samples });
}
test "OP truth local GKR physical original Keccak and secp source AIRs freshly verify" {
    var keccak = try Fixtures.keccakSource();
    defer keccak.deinit();
    try check(&keccak);
    var secp = try Fixtures.secpSource(.canonical_inputs);
    defer secp.deinit();
    try check(&secp);
}
