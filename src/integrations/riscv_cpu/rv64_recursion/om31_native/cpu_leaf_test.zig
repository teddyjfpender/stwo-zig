//! Real service CPU shard, independently verified native transcript, SAME GKR
//! child + original MAIN/binding/global AIRs + full PCS/FRI in one graph.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("mod.zig");
const C = V.common;
const Leaf = @import("cpu_leaf.zig");
const Capture = @import("cpu_capture.zig");
const Public = @import("frame.zig");
const Fixture = @import("../../word16_global_execution/services/gkr_local/coordinator_fixture.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const F = @import("../../word16_global_execution/services/fixture.zig");
const a = std.testing.allocator;
const Mutation = enum { none, endpoint, physical_high_coordinate, ram_claim, scope_main };
fn qualify(case: *const Fixture.Case, comptime mutation: Mutation) !bool {
    const config = try Fixture.config();
    const pointers = case.keys.pointers();
    const truths = case.keys.truths();
    var inventory = try Execution.Inventory.init(a, &pointers, &truths, case.bundle.requests, F.expectedFor(case.keys.cpus[0].materials.program.identity), config);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, case.bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    var capture = try Capture.verify(a, case.keys.cpus[0], case.bundle.requests[0], inventory.workers[0], inventory.first_ids[0], &manifest, 0, config, &case.bundle.cpus[0], null);
    defer capture.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const geometry = try Capture.geometry(arena.allocator(), case.keys.cpus[0], config);
    var source = try V.proof.fromNative(arena.allocator(), &capture.proof, &capture.capture, &geometry);
    if (mutation == .physical_high_coordinate) {
        const samples = @constCast(source.sampled_values[1][0]);
        var delta = [_]core.fields.m31.M31{core.fields.m31.M31.zero()} ** 8;
        delta[7] = core.fields.m31.M31.one();
        samples[0] = samples[0].add(C.O.fromM31Array(delta));
    }
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    const proof = try V.proof.guess(&ctx, &source, &geometry);
    var frame = Public.Frame.init(&ctx);
    var request = case.bundle.requests[0];
    if (mutation == .endpoint) request.base.cpu.final_pc += 4;
    var claims = try arena.allocator().dupe(C.O, case.bundle.cpus[0].claims);
    if (mutation == .ram_claim) claims[0] = claims[0].add(C.O.one());
    if (mutation == .scope_main) {
        // A new MAIN root changes both the child and physical transcript.
        const root = proof.commitments[1].words[0];
        ctx.value_table.items[root.get().idx] = ctx.get(root.get()).add(C.Q.one());
    }
    var statement = try Leaf.Statement.init(&frame, case.keys.cpus[0], request, inventory.first_ids[0], inventory.workers[0], manifest.digest, claims, &proof, stages.stages[0].local.?.proof, config, null);
    defer statement.deinit(&ctx);
    const verified = try V.verify(&ctx, &geometry, &proof, &statement);
    if (mutation == .none) {
        try std.testing.expectEqual(capture.channel.digestBytes(), verified.channel.raw.inner.debugDigest(&ctx));
        try std.testing.expect(verified.composition_randomness.value().eql(capture.capture.composition_randomness));
    }
    if (mutation == .none) {
        const expected_words = try Leaf.expectedWords(arena.allocator(), case.keys.cpus[0], request, inventory.first_ids[0], inventory.workers[0], manifest.digest, stages.stages[0].main, manifest.entries[0].local.?.digest, case.bundle.cpus[0].claims);
        try std.testing.expectEqual(expected_words.len, frame.free_words.items.len);
        for (expected_words, frame.free_words.items) |expected_word, actual| try std.testing.expectEqual(expected_word, @import("stwo_circuit_frontend").builder.ivalue.unpackU32(C.Q, ctx.get(actual.get())));
    }
    _ = try frame.finish();
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    if (mutation == .none) std.debug.print("CPU_OM31_LEAF vars={} frame_words={} gates={any}\n", .{ ctx.circuit.n_vars, frame.free_words.items.len, ctx.gate_counts });
    return ctx.isCircuitValid();
}
test "CPU complete OM31 service leaf authenticates GKR terminal binding original AIR and native PCS" {
    var fixture = try Fixture.Case.init(a);
    defer fixture.deinit();
    _ = try fixture.verify(a);
    try std.testing.expect(try qualify(&fixture, .none));
}
test "CPU complete OM31 service leaf rejects public endpoint and physical high-coordinate mutation" {
    var fixture = try Fixture.Case.init(a);
    defer fixture.deinit();
    inline for (.{ Mutation.endpoint, Mutation.physical_high_coordinate, Mutation.ram_claim, Mutation.scope_main }) |mutation| {
        const valid = qualify(&fixture, mutation) catch |err| switch (err) {
            error.EqFailedOnEval => false,
            else => return err,
        };
        try std.testing.expect(!valid);
    }
}
