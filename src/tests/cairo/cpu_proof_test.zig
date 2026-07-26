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
    var composition = try cairo.witness.composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/official/all_opcodes.air_programs_v1.bin",
    );
    defer composition.deinit();

    var expected = try cairo.conformance.receipt.readFile(
        allocator,
        "vectors/cairo/official/all_opcodes.base_trace_checkpoint.json",
        .{
            .input_sha256 = try inputDigest(allocator, input_path),
            .authority = .{
                .stwo_cairo_revision = cairo.claim_registry.source_revision.stwo_cairo,
                .stwo_revision = cairo.claim_registry.source_revision.stwo,
            },
        },
    );
    defer expected.deinit();

    var result = cairo_cpu.prover.transaction.proveFixture(
        allocator,
        .{
            .input = &input,
            .programs = &programs,
            .topology = topology,
            .fixed = &fixed,
            .relations = &relations,
            .expected_base = expected.components,
            .composition = &composition,
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
}

fn inputDigest(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![32]u8 {
    const encoded = try std.fs.cwd().readFileAlloc(
        allocator,
        path,
        2 * 1024 * 1024,
    );
    defer allocator.free(encoded);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    return digest;
}
