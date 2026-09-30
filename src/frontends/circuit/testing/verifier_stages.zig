//! The R4 rung's multiverifier (design §8.2) and its stage-by-stage
//! comparison with the oracle's `verifier-stages` checkpoint
//! (`vectors/circuit/r4/verifier_stages.json`).
//!
//! The circuit is the one `test_verify_cairo_proof_and_multiverifier_proof`
//! of `crates/circuit_multiverifier/src/verify_test.rs` builds
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): a multiverifier over two
//! proofs at the privacy configuration of `test_utils.rs`, padded to its
//! `TARGET_PADDING_SIZES`. Gates are only appended, so the summary after
//! each stage is that of a prefix of the final gate lists; topology mode
//! (empty proofs) and value mode (the committed proofs) must give the same
//! summaries.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const fixture = @import("fixture_json.zig");
const circuit_summary = @import("circuit_summary.zig");

const builder = circuit.builder;
const multiverifier = circuit.statements.multiverifier;
const finalize = circuit.common.finalize;
const preprocessed = circuit.common.preprocessed;
const Stage = circuit.stark_verifier.verify.Stage;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const Value = std.json.Value;

pub const fixture_path = "vectors/circuit/r4/verifier_stages.json";
pub const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

/// `TARGET_PADDING_SIZES` of `circuit_multiverifier/src/test_utils.rs`.
pub const privacy_target_sizes: finalize.ComponentSizes = .{
    .eq = 1 << 17,
    .qm31_ops = 1 << 21,
    .m31_to_u32 = 1 << 18,
    .triple_xor = 1 << 17,
    .blake_g_gate = 1 << 20,
};

/// `PRIVACY_CAIRO_VERIFIER_TRACE_LOG_SIZE` and `LOG_BLOWUP_FACTOR` of
/// `test_utils.rs`.
pub const privacy_trace_log_size: u32 = 21;
pub const privacy_log_blowup_factor: u32 = 3;

/// `get_pcs_config(21, 3)` of `cairo_verifier/src/privacy.rs`: 27 PoW bits
/// and 23 queries at blowup 3.
pub fn privacyPcsConfig() !PcsConfigV2 {
    const fri = try FriConfigV2.init(27, 0, privacy_log_blowup_factor, 23, 4);
    return PcsConfigV2.fromFriAndTraceSize(fri, privacy_trace_log_size);
}

/// The multiverifier's `SharedConfig` at the privacy configuration.
pub fn privacySharedConfig(allocator: std.mem.Allocator) !multiverifier.SharedConfig {
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(privacy_target_sizes);
    return multiverifier.sharedConfig(allocator, layout, try privacyPcsConfig());
}

/// Compares the circuit after every stage with the checkpoint's list.
pub const StageRecorder = struct {
    summarizer: circuit_summary.Summarizer = .init(),
    expected: []const Value,
    at: usize = 0,

    pub fn mark(self: *StageRecorder, circuit_state: *const builder.Circuit, stage: Stage) !void {
        var buffer: [128]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        if (stage.child) |child| try writer.print("input_{d}.", .{child});
        if (stage.in_verify) try writer.writeAll("verify.");
        try writer.writeAll(stage.name);
        if (self.at >= self.expected.len) return error.UnexpectedStage;
        const record = self.expected[self.at];
        errdefer std.debug.print("R4 stage {d} ({s}) differs from the oracle\n", .{ self.at, writer.buffered() });
        try std.testing.expectEqualStrings(try fixture.string(try fixture.field(record, "stage")), writer.buffered());
        try circuit_summary.expectGateSummary(try fixture.field(record, "circuit"), self.summarizer.mark(circuit_state));
        self.at += 1;
    }
};

/// Builds the multiverifier over `inputs`, pads it to the privacy target
/// and checks every stage against `body.stages`. Returns the padded context.
pub fn buildAndCompare(
    comptime V: type,
    gpa: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    inputs: []const multiverifier.MultiverifierInput(V),
    shared: *const multiverifier.SharedConfig,
    body: Value,
) !builder.Context(V) {
    var recorder: StageRecorder = .{ .expected = try fixture.array(try fixture.field(body, "stages")) };
    var ctx = try multiverifier.buildMultiverifierCircuit(V, gpa, table, inputs, shared, &recorder);
    errdefer ctx.deinit();
    try finalize.padToTargets(V, &ctx, privacy_target_sizes);
    try recorder.mark(&ctx.circuit, .{ .name = "pad_to_targets" });
    try std.testing.expectEqual(recorder.expected.len, recorder.at);
    return ctx;
}

/// Reads eight `u32` words.
pub fn words8(value: Value) ![8]u32 {
    const items = try fixture.array(value);
    if (items.len != 8) return error.FixtureShape;
    var out: [8]u32 = undefined;
    for (&out, items) |*word, item| word.* = try fixture.unsigned(u32, item);
    return out;
}
