test {
    _ = @import("stwo_riscv_rv64").modules.tests_boundary_capture_test;
    _ = @import("stwo_riscv_frontend").modules.rv64_tests_ethereum_services_test;
    _ = @import("stwo_riscv_rv64").modules.tests_compact_tape_test;
    _ = @import("stwo_riscv_rv64").modules.tests_tape_wire_test;
    _ = @import("stwo_riscv_rv64").modules.tests_frequent_operations_test;
    _ = @import("stwo_riscv_rv64").modules.tests_access_census_test;
    _ = @import("stwo_riscv_rv64").modules.tests_execution_test;
    _ = @import("stwo_riscv_rv64").modules.tests_foundations_test;
    _ = @import("stwo_riscv_frontend").modules.rv64_tests_ethereum_contract_test;
    _ = @import("stwo_riscv_rv64").modules.tests_service_session_test;
    _ = @import("stwo_riscv_rv64").modules.tests_fast_execution_test;
    _ = @import("stwo_riscv_rv64").modules.ram_word_set;
    _ = @import("stwo_riscv_rv64").modules.tests_zbb_binary_test;
    _ = @import("stwo_riscv_rv64").modules.isa_audit;
}
