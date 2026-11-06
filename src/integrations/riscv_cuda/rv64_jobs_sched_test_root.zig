//! M8 scheduler + request tests: a separate binary because they need
//! ready_dag.zig as a standalone module, which must not coexist with
//! stwo_riscv_cpu_integration (that module owns the same file) in one binary.
test {
    _ = @import("rv64/jobs/scheduler_test.zig");
    _ = @import("rv64/jobs/request_test.zig");
}
