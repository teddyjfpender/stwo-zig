//! Full official Cairo proof construction through the CPU/SIMD backend.

const std = @import("std");
const stwo = @import("stwo");

const cairo = stwo.frontends.cairo;
const cairo_cpu = stwo.integrations.cairo_cpu;

test "official Cairo all-opcodes canonical-small CPU proof completes" {
    const allocator = std.testing.allocator;
    const input_path = "vectors/cairo/official/all_opcodes.prover_input.json";

    var input = try cairo.adapter.official_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var programs = try cairo.witness.bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer programs.deinit();
    var topology = try cairo.witness.feed_topology.readOfficial(
        allocator,
        "vectors/cairo/official/witness_feed_topology_v1.json",
    );
    defer topology.deinit();
    var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    var relations = try cairo.witness.relation_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();
    var air_templates = try cairo.air.template_library.Library.readFile(
        allocator,
        "vectors/cairo/official/air_template_library_v1.json",
    );
    defer air_templates.deinit();

    var result = cairo_cpu.prover.transaction.proveFixture(
        allocator,
        .{
            .input = &input,
            .programs = &programs,
            .topology = topology,
            .fixed = &fixed,
            .relations = &relations,
            .air_templates = &air_templates,
        },
        .canonical_small,
    ) catch |err| {
        std.debug.print("Cairo CPU proof failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer result.deinit();

    try std.testing.expectEqual(
        @as(usize, 4),
        result.proof.proof.commitment_scheme_proof.commitments.items.len,
    );
    try std.testing.expectEqual(@as(usize, 46), result.claimed_sums.len);
    try std.testing.expect(
        result.preprocessed_variant == .canonical_small,
    );
    try emitProofIfRequested(&input, &result);

    result.interaction_pow ^= 1;
    try std.testing.expectError(
        error.ProofOfWork,
        cairo_cpu.prover.transaction.verifyAndConsume(
            &input,
            &result,
        ),
    );
    result.interaction_pow ^= 1;
    try std.testing.expect(result.proof_owned);

    result.claimed_sums[0] = result.claimed_sums[0].add(
        stwo.core.fields.qm31.QM31.one(),
    );
    try std.testing.expectError(
        error.InvalidGlobalLookupSum,
        cairo_cpu.prover.transaction.verifyAndConsume(
            &input,
            &result,
        ),
    );
    result.claimed_sums[0] = result.claimed_sums[0].sub(
        stwo.core.fields.qm31.QM31.one(),
    );
    try std.testing.expect(result.proof_owned);

    try cairo_cpu.prover.transaction.verifyAndConsume(&input, &result);
    try std.testing.expect(!result.proof_owned);
}

fn emitProofIfRequested(
    input: *const cairo.adapter.ProverInput,
    result: *const cairo_cpu.prover.transaction.Result,
) !void {
    const output_path = std.process.getEnvVarOwned(
        std.testing.allocator,
        "STWO_CAIRO_PROOF_OUTPUT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer std.testing.allocator.free(output_path);
    if (!std.fs.path.isAbsolute(output_path)) return error.OutputPathNotAbsolute;

    const file = try std.fs.createFileAbsolute(output_path, .{ .truncate = true });
    defer file.close();
    var buffer: [64 * 1024]u8 = undefined;
    var file_writer = file.writer(&buffer);
    try std.json.Stringify.value(
        cairo.proof.json.Document(
            @TypeOf(result.proof.proof),
        ){
            .input = input,
            .composition = &result.composition,
            .claimed_sums = result.claimed_sums,
            .interaction_pow = result.interaction_pow,
            .channel_salt = 0,
            .preprocessed_variant = result.preprocessed_variant,
            .stark_proof = &result.proof.proof,
        },
        .{},
        &file_writer.interface,
    );
    try file_writer.interface.writeByte('\n');
    try file_writer.interface.flush();
    try file.sync();
}
