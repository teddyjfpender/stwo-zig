//! Rung R8 (design §8.2, milestone M8): the Zig leaf lane reproduces
//! upstream `leaf-prover`'s output byte for byte.
//!
//! `leaf-prover --program use_all_opcodes_and_builtins_compiled.json
//! --circuit_registry_json circuit_registry_canonical_small.json` at
//! https://github.com/starkware-libs/proving 5a7c5ede4299c91a61df19a07cba4f7502c14230
//! writes `crates/leaf_prover/tests/data/expected_output.json`, which its
//! `cli_test.rs` pins and which is committed here as
//! `vectors/circuit/official/leaf_prover/expected_output.json`. The Zig lane
//! starts from the same execution, adapted by the upstream adapter
//! (`vectors/circuit/r10/use_all_opcodes_and_builtins.prover_input.json`,
//! `stwo-circuit-oracle adapt-program`), proves it as a canonical_small leaf
//! Cairo proof (trace log size 20), wraps it and must write the same file:
//! circuit proof bytes, circuit preprocessed root and circuit hash.
//!
//! Labelled large: a 2^23-row circuit proof.

const std = @import("std");
const app = @import("app");

const expected_path = "vectors/circuit/official/leaf_prover/expected_output.json";

test "R8: leaf-wrap of use_all_opcodes_and_builtins equals leaf-prover's expected_output.json" {
    const allocator = std.testing.allocator;
    var timings = app.Timings{};
    var leaf = try app.leafWrap(allocator, .{
        .registry_path = "vectors/circuit/official/registries/leaf_prover_canonical_small.json",
        .program_path = "vectors/circuit/official/programs/use_all_opcodes_and_builtins_compiled.json",
        .prover_input_path = "vectors/circuit/r10/use_all_opcodes_and_builtins.prover_input.json",
        .options = .{ .compact_polynomial_min_log = 18 },
    }, &timings);
    defer leaf.deinit();
    std.debug.print("R8: cairo prove {d} ms, wrap {d} ms\n", .{ timings.cairo_prove_ns / std.time.ns_per_ms, timings.wrap_ns / std.time.ns_per_ms });

    var written = std.Io.Writer.Allocating.init(allocator);
    defer written.deinit();
    try leaf.writeJson(&written.writer);
    const expected = try std.fs.cwd().readFileAlloc(allocator, expected_path, 16 << 20);
    defer allocator.free(expected);
    if (!std.mem.eql(u8, expected, written.written())) {
        std.debug.print("R8: {d} bytes, expected {d}\n", .{ written.written().len, expected.len });
        return error.LeafOutputDiffers;
    }
}
