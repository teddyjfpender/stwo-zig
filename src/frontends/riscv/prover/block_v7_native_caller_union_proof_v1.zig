//! Experimental finite nine-tree native/access + active-caller original STARK.
//! Returns OPEN source exports only after original verification. No recursive
//! receipt or complete block admission is implied. Existing routes unchanged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Native = @import("block_v7_native_proof_v1.zig");
const NS = @import("block_v7_native_source_v1.zig");
const NC = @import("block_v7_native_components_v1.zig");
const Caller = @import("block_v7_caller_active_proof_v1.zig");
const CS = @import("block_v7_caller_active_source_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const NF = @import("block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const CF = @import("block_v5_caller_fused_proof_v1.zig");
const Layout = @import("block_v7_caller_active_layout_v1.zig").Layout;
const Schedule = @import("block_v7_caller_active_schedule_v1.zig");
const Assembly = @import("block_v7_caller_active_assembly_v1.zig").Assembly;
const CC = @import("block_v6_caller_joint_components_v1.zig");
const Union = @import("block_v7_native_caller_union_components_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
pub const TAG: u32 = 0x42375543; // B7UC, never an existing source proof.
pub const VERSION: u32 = 1;
pub const Proof = struct {
    stark: S.Proof,
    native: []NF.Claim,
    access: []Memory.Claim,
    arithmetic: P.ExtensionClaim,
    relations: CF.ClaimFrames,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.native);
        a.free(self.access);
        self.relations.deinit(a);
        self.* = undefined;
    }
};
pub const Open = struct { native: NS.Exports, caller: CS.Exports };
pub fn require(a: std.mem.Allocator, np: NS.Pin, cp: CS.Pin, epoch: E.Epoch, entries: []const E.Entry) !void {
    const ne = try np.entry(a);
    try epoch.requireEntry(entries, ne);
    _ = try cp.require(a, epoch, entries);
    if (ne.root_count != 3 or np.expected_events == 0 or np.shape.n_components == 0 or cp.execution_index != np.index or !std.meta.eql(cp.frame, np.frame) or cp.total_steps != np.frame.cycle_count or P.externalCount(cp.statement) != np.template.external_retirements or !std.meta.eql(np.template.config, epoch.config)) return error.InvalidNativeCallerUnionScope;
}
pub fn fixed(a: std.mem.Allocator, np: NS.Pin, cp: CS.Pin) ![]Column {
    var columns: std.ArrayList(Column) = .empty;
    try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(a, np.shape, np.template.external_retirements, &columns);
    const all = try P.preprocessed(a, cp.statement);
    const selected = try (try Layout.derive(cp.statement, cp.total_steps)).columns(a, 0, all);
    try columns.appendSlice(a, selected);
    return columns.toOwnedSlice(a);
}
fn prefix(a: std.mem.Allocator, np: NS.Pin, cp: CS.Pin, epoch: E.Epoch, root: [32]u8, nc: *const NC.Owner, schedule: *const @import("block_v5_caller_fused_schedule_v1.zig").Schedule, claims: []const NF.Claim, access: []const Memory.Claim, arithmetic: *const P.ExtensionClaim, relations: *const CF.ClaimFrames) !S.Channel {
    var ch = S.Channel{};
    ch.mixU32s(&.{ TAG, VERSION, 8, 9 });
    epoch.config.mixInto(&ch);
    ch.mixRoot(epoch.digest);
    ch.mixRoot(root);
    ch.mixU32s(&.{ 0, 1, 2, 5, 0, 3, 4, 6, 7 });
    // Geometry is independently reconstructed; every original physical sum
    // remains absorbed before any interaction commitment, in exact order.
    try Native.recordAfterChallenges(&ch, np, try np.entry(a), nc.layout.slots, nc.slots, claims, access);
    try CS.recordAfterChallenges(&ch, cp, try cp.entry(a), schedule, arithmetic, relations);
    return ch;
}
pub fn callerOwner(comptime proving: bool, a: std.mem.Allocator, cp: CS.Pin, drawn: *const CS.Drawn, arithmetic: *const P.ExtensionClaim, relations: *const CF.ClaimFrames, schedule: *const @import("block_v5_caller_fused_schedule_v1.zig").Schedule) !*CC.Owner(proving) {
    const ao = try Assembly(if (proving) .prover else .verifier).init(a, cp.statement, cp.total_steps, &drawn.relations, arithmetic);
    // Schedule helpers allocate through their stored allocator. Redirect only
    // this local descriptor's allocation policy to the proof-lifetime arena;
    // the source schedule's admitted geometry and ownership stay unchanged.
    var local_schedule = schedule.*;
    local_schedule.a = a;
    const il = try local_schedule.interactionLogs();
    const wl = try local_schedule.witnessLogs();
    const al = try (try Layout.derive(cp.statement, cp.total_steps)).columnLogs(a, 2);
    const fo = try a.create(CF.Components);
    fo.* = try CF.Components.init(a, schedule, relations, &drawn.relations, &drawn.epoch.bytes, &drawn.epoch.word, il, wl, 1);
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    const handles = if (proving) blk: {
        const out = try a.alloc(H, fo.memory.len + fo.program.len + fo.tables.len);
        var i: usize = 0;
        inline for (.{ fo.memory, fo.program, fo.tables }) |partition| for (partition) |*c| {
            out[i] = c.asProverComponent();
            i += 1;
        };
        break :blk out;
    } else try fo.verifier();
    return CC.Owner(proving).create(a, ao.active(), handles, .{ schedule.fixed, schedule.main, wl, al, il }, fo.memory.len);
}
pub const NativeInteraction = struct { claims: []NF.Claim, access: []Memory.Claim, columns: []Column };
pub fn nativeInteraction(a: std.mem.Allocator, first: *Native.For(Cpu).First, owner: *@import("blake3_execution_trace.zig").Owner, inputs: []const Memory.Input, pin: NS.Pin, drawn: *const E.Drawn) !NativeInteraction {
    return nativeInteractionWithScratch(a, a, first, owner, inputs, pin, drawn);
}
pub fn nativeInteractionWithScratch(a: std.mem.Allocator, scratch: std.mem.Allocator, first: *Native.For(Cpu).First, owner: *@import("blake3_execution_trace.zig").Owner, inputs: []const Memory.Input, pin: NS.Pin, drawn: *const E.Drawn) !NativeInteraction {
    const layout = try pin.layout(a);
    const slots = try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, pin.shape, pin.frame, 1);
    if (!std.meta.eql(owner.statement, pin.shape.*) or owner.external_retirements != pin.template.external_retirements or !owner.native_only_v5 or owner.failed or !owner.tables_ready or owner.interaction_ready or !first.owns_scheme or !std.meta.eql(first.scheme.config, pin.template.config) or inputs.len != slots.len or first.snapshots.len != slots.len) return error.InvalidUnionNativePhase;
    const claims = try a.alloc(NF.Claim, layout.slots.len);
    const access = try a.alloc(Memory.Claim, slots.len);
    var columns: std.ArrayList(Column) = .empty;
    for (layout.slots, claims) |slot, *claim| {
        const generated = try NF.generateProjection(a, owner.main.items, slot, &drawn.word.universal_prefix);
        claim.* = .{ .sum = generated.sum, .row_count = slot.n_rows };
        for (generated.columns) |values| try columns.append(a, .{ .log_size = slot.log_size, .values = values });
    }
    for (inputs, slots, first.snapshots, access) |input, slot, snapshot, *claim| {
        if (!std.meta.eql(input.descriptor, slot) or input.trace.register_custody_mode != 1) return error.InvalidUnionNativeInputs;
        try columns.ensureUnusedCapacity(a, @import("block_v7_native_access_interaction_v1.zig").COLUMN_COUNT);
        const generated = try @import("block_v7_native_access_interaction_v1.zig").generateWithScratch(a, scratch, input.trace, &drawn.word, snapshot);
        claim.* = .{ .transition_sum = generated.transition_sum, .universal_sum = generated.universal_sum, .range_claims = generated.range_claims, .active_count = generated.active_count };
        // Transfer every owned column once; no full-domain row arrays or copy.
        for (generated.columns) |values| columns.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
    }
    const Frame = @import("block_v5_native_frame_v1.zig");
    if (Frame.required(pin.shape)) {
        if (claims.len != 0 or access.len != 0 or columns.items.len != 0) return error.InvalidV7ExternalNativeEnvelope;
        try columns.appendSlice(a, try Frame.interactionColumns(a));
    }
    return .{ .claims = claims, .access = access, .columns = try columns.toOwnedSlice(a) };
}
fn appendPrivate(a: std.mem.Allocator, scheme: *Scheme, source: *Scheme, roots: []const [32]u8, ch: *S.Channel) !void {
    if (source.trees.items.len != 3 or roots.len != 3) return error.InvalidUnionFirstTrees;
    for (source.trees.items, roots) |tree, root| if (!std.meta.eql(tree.root(), root)) return error.UntrustedUnionPrivateRoot;
    for (source.trees.items[1..]) |*tree| {
        try tree.share(a);
        var retained = tree.retainShared();
        scheme.appendCommittedTree(a, retained, ch) catch |err| {
            retained.deinit(a);
            return err;
        };
    }
}
pub fn prove(a: std.mem.Allocator, first: *Native.For(Cpu).First, owner: *@import("blake3_execution_trace.zig").Owner, inputs: []const Memory.Input, np: NS.Pin, caller: *Caller.ForBackend(Cpu).Stage, cp: CS.Pin, epoch: E.Epoch, entries: []const E.Entry, pool: *engine.work_pool.WorkPool) !Proof {
    try require(a, np, cp, epoch, entries);
    if (!caller.first.owns_scheme or !std.meta.eql(try caller.pin(cp.execution_index, cp.execution_identity).entry(a), try cp.entry(a))) return error.InvalidUnionCallerPhase;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const drawn = try epoch.draw(temp);
    const cd = try CS.draw(temp, epoch, try cp.entry(temp));
    const ni = try nativeInteractionWithScratch(temp, a, first, owner, inputs, np, &drawn);
    const arithmetic = try @import("block_v7_caller_active_columns_v1.zig").interactions(temp, caller.witness, &cd.relations, pool);
    const fused = try @import("block_v6_caller_joint_interaction_v1.zig").generate(temp, &caller.columns, &caller.schedule, caller.inputs, caller.first.snapshots, &cd.relations, &drawn.word);
    const nc = try NC.Owner.init(temp, np, ni.claims, ni.access, &drawn);
    var nb = try nc.proving();
    defer nb.deinit(temp);
    const cc = try callerOwner(true, temp, cp, &cd, &arithmetic.claim, &fused.claims, &caller.schedule);
    var combined = try Union.Owner(true).init(temp, nb.handles, cc.asProverComponent(), nc.fixed.len, caller.schedule.fixed.len);
    defer combined.deinit(temp);
    var scheme = try Scheme.init(a, epoch.config);
    var owned = true;
    defer if (owned) scheme.deinit(a);
    var ignored = S.Channel{};
    try scheme.commitBorrowedStreaming(a, try fixed(temp, np, cp), 8, &ignored);
    try appendPrivate(a, &scheme, &first.scheme, &(np.roots ++ .{np.access_root}), &ignored);
    try appendPrivate(a, &scheme, &caller.first.scheme, &(cp.roots ++ .{cp.access_root}), &ignored);
    var ch = try prefix(temp, np, cp, epoch, scheme.trees.items[0].root(), &nc, &caller.schedule, ni.claims, ni.access, &arithmetic.claim, &fused.claims);
    try scheme.commitBorrowedStreaming(a, ni.columns, 8, &ch);
    try scheme.commitBorrowedStreaming(a, try caller.layout.columns(temp, 2, arithmetic.columns), 8, &ch);
    try scheme.commitBorrowedStreaming(a, fused.columns, 8, &ch);
    const claims = try a.dupe(NF.Claim, ni.claims);
    errdefer a.free(claims);
    const access = try a.dupe(Memory.Claim, ni.access);
    errdefer a.free(access);
    var relations = try CF.ClaimFrames.clone(a, &fused.claims);
    errdefer relations.deinit(a);
    owned = false;
    const stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, combined.handles, &ch, scheme);
    return .{ .stark = stark, .native = claims, .access = access, .arithmetic = arithmetic.claim, .relations = relations };
}
pub fn verify(a: std.mem.Allocator, proof: *const Proof, np: NS.Pin, cp: CS.Pin, epoch: E.Epoch, entries: []const E.Entry) !Open {
    try require(a, np, cp, epoch, entries);
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (roots.len != 9 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, epoch.config) or !std.meta.eql(roots[1..3].*, .{ np.roots[1], np.access_root }) or !std.meta.eql(roots[3..5].*, .{ cp.roots[1], cp.access_root })) return error.UntrustedUnionPrivateRoot;
    try @import("block_v5_native_execution_proof_v3.zig").ForBackend(Cpu).verifyFixed(a, np.shape, np.template, epoch.config);
    try Caller.ForBackend(Cpu).requireFixedRoot(a, cp);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var fs = try Scheme.init(a, epoch.config);
    defer fs.deinit(a);
    var ignored = S.Channel{};
    try fs.commitBorrowedStreaming(a, try fixed(temp, np, cp), 8, &ignored);
    if (!std.meta.eql(fs.trees.items[0].root(), roots[0])) return error.UntrustedUnionFixedRoot;
    const drawn = try epoch.draw(temp);
    const cd = try CS.draw(temp, epoch, try cp.entry(temp));
    const nc = try NC.Owner.init(temp, np, proof.native, proof.access, &drawn);
    var nb = try nc.verifying();
    defer nb.deinit(temp);
    const schedule = try Schedule.derive(temp, cp.statement, cp.total_steps, cp.frame);
    var ch = try prefix(temp, np, cp, epoch, roots[0], &nc, &schedule, proof.native, proof.access, &proof.arithmetic, &proof.relations);
    const cc = try callerOwner(false, temp, cp, &cd, &proof.arithmetic, &proof.relations, &schedule);
    var combined = try Union.Owner(false).init(temp, nb.handles, cc.asVerifierComponent(), nc.fixed.len, schedule.fixed.len);
    defer combined.deinit(temp);
    // Fixed columns may be independently committed but unused by equations.
    // Preserve the full admitted physical inventory, as both original verifiers
    // do, rather than asking core to infer it from selected fixed openings.
    const fixed_logs = try std.mem.concat(temp, u32, &.{ nc.fixed, schedule.fixed });
    const logs = [8][]const u32{ fixed_logs, nc.main, nc.witness, cc.logs.items[1], cc.logs.items[2], nc.interactions, cc.logs.items[3], cc.logs.items[4] };
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, epoch.config);
    defer verifier.deinit(a);
    for (0..5) |i| try verifier.commit(a, roots[i], logs[i], &ignored);
    for (5..8) |i| try verifier.commit(a, roots[i], logs[i], &ch);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, combined.handles, &ch, &verifier, &proof.stark, &capture);
    defer capture.deinit(a);
    const result = Open{ .native = try NS.exportsFromClaims(temp, np, proof.native, proof.access, &drawn), .caller = try CS.exports(&schedule, &proof.arithmetic, &proof.relations) };
    if (!result.caller.internal_residual.isZero()) return error.UnclosedV7CallerInternalRelations;
    return result;
}
