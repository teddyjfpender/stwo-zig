//! Canonical typed domain interfaces; test hooks are explicitly unstable.

pub const benchmarks = struct {
    pub const auipc_witness = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_auipc_witness_test.zig").benchmarkLegacyThroughput;
    };
    pub const base_alu_imm_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_base_alu_imm_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const base_alu_reg_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_base_alu_reg_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const branch_eq_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_branch_eq_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const branch_lt_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_branch_lt_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const div_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_div_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const fence_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_fence_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const jal_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_jal_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const jal_witness = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_jal_witness_test.zig").benchmarkLegacyThroughput;
    };
    pub const jalr_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_jalr_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const jalr_witness = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_jalr_witness_test.zig").benchmarkLegacyThroughput;
    };
    pub const load_store_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_load_store_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const lt_imm_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_lt_imm_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const lt_reg_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_lt_reg_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const lui_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_lui_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const lui_witness = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_lui_witness_test.zig").benchmarkLegacyThroughput;
    };
    pub const mul_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_mul_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const mul_witness = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_mul_witness_test.zig").benchmarkLegacyThroughput;
    };
    pub const mulh_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_mulh_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const shifts_imm_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_shifts_imm_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const shifts_reg_evaluator = struct {
        pub const benchmarkLegacyThroughput = @import("cases/air/lang/tests/typed_shifts_reg_authority_test.zig").benchmarkLegacyThroughput;
    };
    pub const split_main_trace = struct {
        pub const benchmarkLegacyThroughput = @import("cases/prover/guest_precompile/tests/split_main_trace_test.zig").benchmarkLegacyThroughput;
    };
};
pub const regressions = struct {
    pub const keccak_tuples = struct {
        pub const run = @import("cases/air/guest_precompile/tests/keccakf_lookup_tuple_test.zig").run;
    };
    pub const segment_wire = struct {
        pub const expectNativeView = @import("cases/recursion/tests/segment_statement_transcript_layout_test.zig").expectNativeView;
    };
};
pub const testing = struct {
    pub const inventory_source = @embedFile("tests/root.zig");
};

test {
    _ = @import("tests/root.zig");
}
