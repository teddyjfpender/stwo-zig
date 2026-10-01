//! Adapter from the verified, fully resident circuit prover to the shared
//! leaf/fold recursion driver. All STARK proving is done by resident_prover;
//! the host only verifies the published proof and prepares child wire values.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const air_aot = @import("air_aot.zig");
const resident = @import("resident_prover.zig");
const verifier = @import("resident_verifier.zig");

const QM31 = core.fields.qm31.QM31;
const Source = cpu.recursion.proof_source;
const N = circuit.common.component_list.N_COMPONENTS;

pub const Context = struct {
    catalog: *const air_aot.Catalog,

    pub fn source(self: *Context) Source.Source {
        return .{ .context = self, .prove = prove };
    }
};

fn prove(erased: *anyopaque, allocator: std.mem.Allocator, input: Source.Input) !Source.Produced {
    const context: *Context = @ptrCast(@alignCast(erased));
    var timer = try std.time.Timer.start();
    const layout = input.preprocessed.layout();
    const log_sizes = try circuit.common.component_list.circuitComponentLogSizes(&layout);
    var bound_air = try cpu.air.bind(allocator, input.air, log_sizes, &layout);
    defer bound_air.deinit();
    const resident_input = resident.Input{
        .values = input.values,
        .preprocessed = input.preprocessed,
        .air = &bound_air,
        .catalog = context.catalog,
        .config = input.config,
        .profile = switch (input.profile) {
            .internal => .internal,
            .root => .root,
        },
    };
    var result = try resident.prove(allocator, resident_input);
    defer result.deinit();
    const resident_ns = timer.lap();
    if (!result.verdict.isResident() or
        result.verdict.counters.cpu_fallback_attempts != 0)
        return error.NonresidentCircuitProof;
    var verified = try verifier.verify(allocator, resident_input, &result);
    defer verified.deinit();
    const verify_ns = timer.lap();

    const stark = &result.stark.commitment_scheme_proof;
    const pp_root = stark.commitments.items[0];
    const circuit_hash = try circuit.common.circuit_hash.hostCircuitHash(
        log_sizes,
        input.config.fri_config.log_blowup_factor,
        pp_root,
    );
    const output_start = circuit.witness.trace.U_VAR_IDX + 1;
    if (output_start + input.preprocessed.n_outputs > input.values.len or input.preprocessed.n_outputs != 8)
        return error.InvalidCircuitResidentOutput;
    const outputs = input.values[output_start..][0..8];
    var digest: [8]u32 = undefined;
    for (&digest, outputs) |*word, value| {
        const limbs = circuit.builder.ivalue.limbs(value);
        if (limbs[2] != 0 or limbs[3] != 0 or limbs[0] > 0xffff or limbs[1] > 0xffff)
            return error.InvalidCircuitResidentOutput;
        word.* = limbs[0] | (limbs[1] << 16);
    }
    const claim_words = result.terminal_proof.decoded.words[result.terminal_proof.decoded.layout.interaction_claim.start..result.terminal_proof.decoded.layout.interaction_claim.end];
    if (claim_words.len != N * 4) return error.InvalidCircuitResidentClaim;
    var claims: [N]QM31 = undefined;
    for (&claims, 0..) |*out, index| {
        const words = claim_words[index * 4 ..][0..4];
        out.* = QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
    }
    const nonce = result.terminal_proof.decoded.interactionNonce();
    const root_words = core.vcs.blake2_hash.digestToU32s(pp_root);
    const hash_words = core.vcs.blake2_hash.digestToU32s(circuit_hash);
    const produced: Source.Produced = switch (input.profile) {
        .internal => blk: {
            const internal = try cpu.verifier_proof.fromVerifiedCapture(
                allocator,
                &result.stark,
                &verified.capture,
                try cpu.verifier_proof.proofConfig(input.preprocessed.columns.len, input.config),
                &claims,
                nonce,
                0,
            );
            break :blk .{
                .arena = internal.arena,
                .proof = .{ .internal = internal.proof },
                .preprocessed_root = root_words,
                .circuit_hash = hash_words,
                .output_digest = digest,
            };
        },
        .root => blk: {
            const root = try cpu.cairo_verifier_proof.fromVerifiedStark(
                allocator,
                &result.stark,
                log_sizes,
                outputs,
                &claims,
                nonce,
                0,
                input.config.fri_config,
            );
            break :blk .{
                .arena = root.arena,
                .proof = .{ .root = root.proof },
                .preprocessed_root = root_words,
                .circuit_hash = hash_words,
                .output_digest = digest,
            };
        },
    };
    std.debug.print("circuit-cuda circuit-proof profile={s} resident_ns={} verify_ns={} convert_ns={} arena_bytes={} peak_device_bytes={} terminal_bytes={}\n", .{
        @tagName(input.profile),                 resident_ns,                             verify_ns, timer.lap(), result.planned_arena_bytes,
        result.verdict.counters.peak_live_bytes, result.verdict.counters.d2h_proof_bytes,
    });
    return produced;
}

test "resident recursion source typechecks both wire profiles" {
    const entry: *const fn (*anyopaque, std.mem.Allocator, Source.Input) anyerror!Source.Produced = &prove;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
