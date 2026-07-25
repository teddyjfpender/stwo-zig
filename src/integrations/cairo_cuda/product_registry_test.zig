const std = @import("std");
const product_aot = @import("../../backends/cuda/aot/product_registry.zig");
const witness_bundle = @import("../../frontends/cairo/witness/bundle.zig");

test "product registry admits all exact canonical recorded witnesses" {
    var witnesses = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    var registry = try product_aot.Registry.initProduct(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expectEqual(@as(usize, 33), witnesses.entries.len);
    for (witnesses.entries) |witness| {
        const resolved = registry.resolveRecordedWitness(.{
            .label = witness.label,
            .semantic_hash = witness.semantic_hash,
            .program_identity = witness.program.semanticIdentity(),
        }) orelse return error.MissingCanonicalWitness;
        const expected: product_aot.ModuleGlobals =
            if (witness.program.deductionRequirements().pedersen_table)
                .pedersen_w18_columns_rows_v1
            else
                .none;
        try std.testing.expectEqual(expected, resolved.module_globals);
    }

    const admitted = witnesses.find("add_ap_opcode") orelse
        return error.MissingCanonicalWitness;
    const resolved = registry.resolveRecordedWitness(.{
        .label = admitted.label,
        .semantic_hash = admitted.semantic_hash,
        .program_identity = admitted.program.semanticIdentity(),
    }) orelse return error.MissingCanonicalWitness;
    try std.testing.expectEqual(
        @as(u64, 0x735903777afd70d2),
        resolved.cache_key,
    );
    try std.testing.expectEqualStrings(
        "stwo_jit_witness_d94540f2fd219001",
        resolved.kernel_name,
    );
}
