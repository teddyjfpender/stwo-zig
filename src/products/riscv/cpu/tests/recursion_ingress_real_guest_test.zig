//! Fast production-shaped regression for recursive public-statement ingress.
//!
//! This deliberately stops before native STARK proving.  It keeps the exact
//! ELF runner and verifier-facing `PublicData` derivation used by the full leaf
//! test, while making rows 12--17 semantic iteration cheap and deterministic.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const committed = @import("committed_forgery_harness.zig");

const recursion = frontend.recursion;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const BODY = [_]u32{
    0x0010_0313, // ADDI x6, x0, 1
    0x0023_0393, // ADDI x7, x6, 2
    0x0073_0433, // ADD  x8, x6, x7
};

test "recursive public ingress accepts production-derived self-loop guest" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 8,
        .completion = .self_loop,
    });
    defer guest.deinit();

    const input_capacity = std.math.cast(
        u32,
        guest.public.data.io_entries.input_words.len,
    ) orelse return error.InvalidIngressShape;
    const output_capacity = std.math.cast(
        u32,
        guest.public.data.io_entries.output_words.len,
    ) orelse return error.InvalidIngressShape;
    const shape = try recursion.vm_public_claim.Shape.init(
        input_capacity,
        output_capacity,
    );
    if (std.process.hasEnvVarConstant("STWO_RECURSION_PUBLIC_SEMANTIC_DIAGNOSTIC")) {
        std.debug.print(
            "  ingress shape input={d} output={d} clock={d} input_len={d} " ++
                "output_len={d} output_len_addr={x} output_data_addr={x}\n",
            .{
                shape.max_input_words,
                shape.max_output_words,
                guest.public.data.clock,
                guest.public.data.io_entries.input_len,
                guest.public.data.io_entries.output_len,
                guest.public.data.io_entries.output_len_addr,
                guest.public.data.io_entries.output_data_addr,
            },
        );
        for (guest.public.data.reg_last_clock, 0..) |clock, index|
            std.debug.print("  register_last_clock[{d}]={d}\n", .{ index, clock });
        for (guest.public.data.io_entries.output_words, 0..) |word, index|
            std.debug.print(
                "  output[{d}] addr={x} value={x} clock={d}\n",
                .{ index, word.addr, word.value, word.clock },
            );
    }
    var leaf_preprocessing = try recursion.segment_leaf_authority.Preprocessing.init(
        allocator,
        shape,
    );
    defer leaf_preprocessing.deinit();
    var leaf = try recursion.segment_leaf_authority.Prepared.init(
        allocator,
        &leaf_preprocessing,
        &guest.public.data,
    );
    defer leaf.deinit();

    var plans = try recursion.segment_profile.initPlans(
        allocator,
        shape.max_input_words,
        shape.max_output_words,
    );
    defer plans.recursion.deinit();
    defer plans.vm.deinit();
    var source = try recursion.segment_public_outer_source.Source.init(
        allocator,
        &plans.vm,
        &plans.recursion,
        &leaf_preprocessing,
        frontend.air.transcript.claims.COMPONENT_COUNT,
    );
    defer source.deinit();
    const relations = frontend.air.relation_challenges.Relations.dummy();
    var sums = [_]QM31{QM31.zero()} ** frontend.air.transcript.claims.COMPONENT_COUNT;
    sums[0] = try recursion.vm_public_semantics_circuit.expectedClaimedSum(
        &guest.public.data,
        &relations,
    );
    var prepared = try recursion.segment_public_outer_source.Prepared.init(
        allocator,
        &source,
        &leaf_preprocessing,
        &leaf,
        &guest.public.data,
        &relations,
        &sums,
    );
    defer prepared.deinit();
    try prepared.validateAgainst(
        &source,
        &leaf_preprocessing,
        &leaf,
        &guest.public.data,
    );
}
