//! Rung R5: finalization and padding (design §8.2) against the oracle's
//! `finalize` checkpoint (`vectors/circuit/r5/finalize.json`).
//!
//! For every `prover_test.rs` circuit (`testing/contexts.zig`), in value mode
//! and in topology mode, the gate summary after each sub-stage must equal
//! the oracle's:
//!
//! 1. `built`;
//! 2. `finalize_constants` alone, on a fresh build;
//! 3. `finalized` (`finalize(false)`: constants, then guesses);
//! 4. `padded_<kind>`: `pad_to_targets` raising one component at a time to
//!    its padded size, in the order eq, qm31_ops, triple_xor, m31_to_u32,
//!    blake_g_gate, which must also equal one `pad_context`;
//! 5. `zk_blinded` (the privacy amount, the fixture seed in value mode and
//!    the zero seed in topology mode, as upstream), then `zk_blinded_padded`.
//!
//! From `finalized` on, the raw component sizes must match, and in value
//! mode the value table digest must match and the circuit must be satisfied.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const fixture = @import("../../testing/fixture_json.zig");
const circuit_summary = @import("../../testing/circuit_summary.zig");
const contexts = @import("../../testing/contexts.zig");

const QM31 = core.fields.qm31.QM31;
const builder = circuit.builder;
const finalize = circuit.common.finalize;
const ComponentSizes = finalize.ComponentSizes;
const Value = std.json.Value;

const fixture_path = "vectors/circuit/r5/finalize.json";

const Blinding = struct { amount: usize, seed: [32]u8 };

test "R5: finalization, per-kind padding and ZK blinding match the oracle" {
    const gpa = std.testing.allocator;
    var document = try fixture.load(gpa, fixture_path, 1 << 20);
    defer document.deinit();
    const body = try fixture.checkpointBody(document.root(), "r5", "finalize");
    const blinding: Blinding = .{
        .amount = try fixture.unsigned(usize, try fixture.field(body, "zk_blinding_amount")),
        .seed = try fixture.digest(try fixture.field(body, "zk_blinding_seed")),
    };

    const records = try fixture.array(try fixture.field(body, "contexts"));
    try std.testing.expectEqual(contexts.TestContext.all.len, records.len);
    for (contexts.TestContext.all, records) |which, record| {
        try std.testing.expectEqualStrings(@tagName(which), try fixture.string(try fixture.field(record, "name")));
        try std.testing.expectEqual(which.nReserved(), try fixture.unsigned(usize, try fixture.field(record, "n_reserved")));
        const stages = try fixture.array(try fixture.field(record, "stages"));
        try checkStages(QM31, which, stages, blinding);
        try checkStages(builder.NoValue, which, stages, .{ .amount = blinding.amount, .seed = @splat(0) });

        var topology = try contexts.build(builder.NoValue, gpa, which);
        defer topology.deinit();
        try topology.finalize(false);
        try expectSizes(try fixture.field(record, "padded_sizes"), finalize.computePaddedSizes(.fromBuilder(&topology.circuit)));
    }
}

/// Walks the oracle's stage list for one circuit in one value mode.
fn checkStages(comptime V: type, which: contexts.TestContext, stages: []const Value, blinding: Blinding) !void {
    const gpa = std.testing.allocator;
    var at: usize = 0;

    {
        var ctx = try contexts.build(V, gpa, which);
        defer ctx.deinit();
        try expectStage(V, stages[at], "built", &ctx, false);
        at += 1;
    }
    {
        var ctx = try contexts.build(V, gpa, which);
        defer ctx.deinit();
        try builder.finalize_constants.finalizeConstants(V, &ctx);
        try expectStage(V, stages[at], "finalize_constants", &ctx, false);
        at += 1;
    }
    {
        var ctx = try contexts.build(V, gpa, which);
        defer ctx.deinit();
        try ctx.finalize(false);
        try expectStage(V, stages[at], "finalized", &ctx, true);
        at += 1;
    }
    {
        var ctx = try contexts.build(V, gpa, which);
        defer ctx.deinit();
        try ctx.finalize(false);
        const targets = finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
        var current = finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
        inline for (finalize.PAD_ORDER) |kind| {
            @field(current, @tagName(kind)) = @field(targets, @tagName(kind));
            try finalize.padToTargets(V, &ctx, current);
            try expectStage(V, stages[at], "padded_" ++ @tagName(kind), &ctx, true);
            at += 1;
        }

        var once = try contexts.build(V, gpa, which);
        defer once.deinit();
        try once.finalize(false);
        try finalize.padContext(V, &once);
        try std.testing.expectEqual(circuit_summary.gateSummary(&ctx.circuit), circuit_summary.gateSummary(&once.circuit));
    }
    {
        var ctx = try contexts.build(V, gpa, which);
        defer ctx.deinit();
        try ctx.finalize(false);
        try circuit.common.zk_blinding.addZkBlinding(V, &ctx, blinding.seed, blinding.amount);
        try expectStage(V, stages[at], "zk_blinded", &ctx, true);
        at += 1;
        try finalize.padContext(V, &ctx);
        try expectStage(V, stages[at], "zk_blinded_padded", &ctx, true);
        at += 1;
    }
    try std.testing.expectEqual(stages.len, at);
}

fn expectStage(comptime V: type, stage: Value, name: []const u8, ctx: *const builder.Context(V), finalized: bool) !void {
    try std.testing.expectEqualStrings(name, try fixture.string(try fixture.field(stage, "stage")));
    try circuit_summary.expectGateSummary(try fixture.field(stage, "circuit"), circuit_summary.gateSummary(&ctx.circuit));
    const raw_sizes = try fixture.optionalField(stage, "raw_sizes");
    const values_sha256 = try fixture.optionalField(stage, "values_sha256");
    if (!finalized) {
        try std.testing.expect(raw_sizes == null and values_sha256 == null);
        return;
    }
    try expectSizes(raw_sizes orelse return error.FixtureShape, finalize.rawComponentSizes(.fromBuilder(&ctx.circuit)));
    if (V == QM31) {
        try std.testing.expectEqual(try fixture.digest(values_sha256 orelse return error.FixtureShape), circuit_summary.valuesSha256(ctx.values()));
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

fn expectSizes(expected: Value, actual: ComponentSizes) !void {
    inline for (std.meta.fields(ComponentSizes)) |field| {
        try std.testing.expectEqual(try fixture.unsigned(usize, try fixture.field(expected, field.name)), @field(actual, field.name));
    }
}
