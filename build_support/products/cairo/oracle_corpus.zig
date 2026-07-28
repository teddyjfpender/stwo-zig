//! One authoritative release corpus shared by Cairo CPU and Metal gates.

pub const DirectCase = struct {
    name: []const u8,
    input: []const u8,
    params: []const u8,
    proof: []const u8,
    report: []const u8,
    verdict: []const u8,
};

pub const ProgramCase = struct {
    name: []const u8,
    program: []const u8,
    program_type: []const u8 = "json",
    arguments: ?[]const u8 = null,
    proof_format: []const u8 = "json",
};

pub const direct_cases = [_]DirectCase{
    .{
        .name = "all-opcodes",
        .input = "vectors/cairo/official/all_opcodes.prover_input.json",
        .params = "vectors/cairo/official/all_opcodes.params.json",
        .proof = "all-opcodes-proof.json",
        .report = "all-opcodes-report.json",
        .verdict = "all-opcodes-rust-verdict.json",
    },
    .{
        .name = "all-builtins",
        .input = "vectors/cairo/official/all_builtins.prover_input.json",
        .params = "vectors/cairo/official/all_builtins.params.json",
        .proof = "all-builtins-proof.json",
        .report = "all-builtins-report.json",
        .verdict = "all-builtins-rust-verdict.json",
    },
};

pub const program_cases = [_]ProgramCase{
    .{
        .name = "all-opcodes",
        .program = "vectors/cairo/programs/all_opcodes.compiled.json",
        .proof_format = "binary",
    },
    .{
        .name = "bitwise",
        .program = "vectors/cairo/programs/test_prove_verify_bitwise_builtin/compiled.json",
    },
    .{
        .name = "range-check-96",
        .program = "vectors/cairo/programs/test_prove_verify_range_check_bits_96_builtin/compiled.json",
    },
    .{
        .name = "range-check-128",
        .program = "vectors/cairo/programs/test_prove_verify_range_check_bits_128_builtin/compiled.json",
    },
    .{
        .name = "poseidon",
        .program = "vectors/cairo/programs/test_prove_verify_poseidon_builtin/compiled.json",
    },
    .{
        .name = "ret",
        .program = "vectors/cairo/programs/test_prove_verify_ret_opcode/compiled.json",
    },
    .{
        .name = "pedersen",
        .program = "vectors/cairo/programs/test_prove_verify_pedersen_builtin/compiled.json",
    },
    .{
        .name = "executable-add-one",
        .program = "vectors/cairo/programs/executable/add_one.executable.json",
        .program_type = "executable",
        .arguments = "vectors/cairo/programs/executable/add_one.arguments.json",
    },
};

test "release corpus spans direct, transport, legacy, and executable paths" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 2), direct_cases.len);
    try std.testing.expectEqual(@as(usize, 8), program_cases.len);
    try std.testing.expectEqualStrings(
        "executable",
        program_cases[program_cases.len - 1].program_type,
    );
}
