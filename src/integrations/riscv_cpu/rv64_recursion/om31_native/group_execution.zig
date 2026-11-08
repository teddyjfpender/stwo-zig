//! One bounded outer proof of the entire native roster, with no intermediate
//! leaf STARKs or fold. This is a separate transport and admission route. It
//! requires the native bundle and an independently derived, statement-specific
//! authority; it is not a portable constant-key or anchored OP receiver.
const std = @import("std");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const FixedSet = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Group = @import("native_group.zig");
const Root = @import("services_root.zig");
const Outer = @import("outer_wrap.zig");
const Wire = @import("stwo_circuit_cpu_integration").om31.wire;
const Publication = @import("publication.zig");
pub const Report = struct {
    schema: []const u8 = "rv64-native-group-root/v1",
    accepted: bool = true,
    arithmetic: []const u8,
    native_members: usize,
    pre_padding_variables: u32,
    pre_padding_qm31_rows: usize,
    pre_padding_blake_rows: usize,
    padding_targets: @import("stwo_circuit_frontend").common.finalize.ComponentSizes,
    outer_proofs: usize = 1,
    fold_proofs: usize = 0,
    restored: bool,
    trace_only: bool,
    manifest: [32]u8,
    root_digest: [32]u8,
    root_authority: [32]u8,
    root_proof_bytes: usize,
    graph_ns: u64,
    preprocess_ns: u64,
    prove_ns: u64,
    verify_ns: u64,
    total_ns: u64,
    portable_root_key_admission: bool = false,
};
/// Existing-only reception never falls back to proving and never writes. The
/// caller pins the native/outer profiles, code, input, expected endpoint and
/// resource policy exactly as for the tree receiver.
pub fn run(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const Coordinator.Bundle, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, dir: std.fs.Dir, existing_only: bool) !Report {
    var timer = try std.time.Timer.start();
    const n = try std.math.add(usize, setups.len, truths.len);
    if (n == 0 or n > Group.MAX_MEMBERS or bundle.cpus.len != setups.len or bundle.truths.len != truths.len) return error.NativeGroupCompleteRoster;
    if (Outer.hybridProfileActive()) try Outer.requireHybridProofBudget(1);
    // Preflight before constructing even a trace-only authority. A receiver
    // with a missing physical root cannot accidentally become a producer.
    const encoded = if (existing_only) try dir.readFileAlloc(a, "root.proof", Wire.MAX_BYTES) else null;
    defer if (encoded) |bytes| a.free(bytes);
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, bundle.requests, expected, config, fixed);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    var members: [Group.MAX_MEMBERS]Group.Member = undefined;
    for (setups, 0..) |setup, i| members[i] = .{ .cpu = .{ .setup = setup, .request = bundle.requests[i], .expected = inventory.workers[i], .first = inventory.first_ids[i], .manifest = &manifest, .index = i, .stage = &stages.stages[i], .config = config, .encoded = &bundle.cpus[i], .fixed = if (fixed) |set| set.at(i) else null } };
    for (truths, 0..) |truth, i| {
        const ordinal = setups.len + i;
        members[ordinal] = .{ .truth = .{ .truth = truth, .expected = inventory.workers[ordinal], .manifest = &manifest, .config = config, .encoded = &bundle.truths[i], .fixed = if (fixed) |set| set.at(ordinal) else null } };
    }
    // first=0,total=n,count=n are receiver-derived, never producer declarations.
    const reduced = try Group.reducedFromEnv();
    const build = if (reduced) &Group.buildReduced else &Group.build;
    var graph = try build(a, members[0..n], .{ .first = 0, .total = @intCast(n) }, existing_only);
    defer graph.deinit();
    if (existing_only and (!graph.ctx.trace_only or graph.ctx.value_table.items.len != 0 or graph.ctx.value_table.capacity != 0)) return error.NativeGroupReceiverAssignment;
    var cpus: [Group.MAX_MEMBERS]Root.CpuFrame = undefined;
    var truth_words: [Group.MAX_MEMBERS][]const u32 = undefined;
    for (setups, 0..) |_, i| {
        const local = manifest.entries[i].local orelse return error.WideCpuLocalRequired;
        cpus[i] = .{ .words = graph.frames[i].words, .physical_claims = bundle.cpus[i].claims, .terminal_marginals = local.artifact.claims_to_verify_by_instance };
    }
    for (truths, 0..) |_, i| truth_words[i] = graph.frames[setups.len + i].words;
    const frames = Root.Frames{ .cpus = cpus[0..setups.len], .truths = truth_words[0..truths.len] };
    const metadata = try Root.checkPrepared(a, setups, truths, bundle.requests, &inventory, stages.stages, frames, .{}, 1);
    if (!std.mem.eql(u8, &metadata.manifest.digest, &manifest.digest)) return error.NativeGroupManifest;
    const graph_ns = timer.read();
    const variables = graph.ctx.circuit.n_vars;
    const qm31_rows = graph.ctx.circuit.nQm31OpsRows();
    const blake_rows = graph.ctx.circuit.blake_g_gate.items.len;
    const padding_targets = try Outer.paddingTargets(graph.ctx);
    var proof = try Outer.wrapGraphOrLoad(a, graph.ctx, graph.digest, encoded);
    defer proof.deinit();
    if (proof.restored != existing_only) return error.NativeGroupReceiverProving;
    // Reclose the authenticated metadata before publication. There is no
    // prefix acceptance: every native worker appears exactly once in this root.
    _ = try Root.checkPrepared(a, setups, truths, bundle.requests, &inventory, stages.stages, frames, .{}, 1);
    const bytes = try proof.serialize(a);
    defer a.free(bytes);
    if (existing_only) try Publication.requireBytes(dir, "root.proof", bytes) else try Publication.write(dir, "root.proof", bytes);
    return .{ .schema = if (reduced) "rv64-native-group-root/v2" else "rv64-native-group-root/v1", .arithmetic = if (reduced) "structural-v1" else "legacy", .native_members = n, .pre_padding_variables = variables, .pre_padding_qm31_rows = qm31_rows, .pre_padding_blake_rows = blake_rows, .padding_targets = padding_targets, .restored = proof.restored, .trace_only = existing_only, .manifest = metadata.manifest.digest, .root_digest = graph.digest, .root_authority = proof.effectiveIdentity(), .root_proof_bytes = bytes.len, .graph_ns = graph_ns, .preprocess_ns = proof.timings.preprocess_ns, .prove_ns = proof.timings.prove_ns, .verify_ns = proof.timings.verify_ns, .total_ns = timer.read() };
}
