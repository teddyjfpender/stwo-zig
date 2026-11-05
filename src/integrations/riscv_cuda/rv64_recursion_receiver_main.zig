//! Independent receiver entry: the native authority loader with no GPU factory.
//! No CUDA module is imported or initialized by this executable.
//! M5 rootverify: `derive-vk-tables` and root-only `verify-root-candidate`
//! dispatch first; every other mode is the unchanged legacy receiver.
pub fn main() !void {
    const cpu = @import("stwo_riscv_cpu_integration");
    {
        const std = @import("std");
        const args = try std.process.argsAlloc(std.heap.page_allocator);
        defer std.process.argsFree(std.heap.page_allocator, args);
        if (cpu.rv64_root_verify_main.wants(args)) return cpu.rv64_root_verify_main.main();
    }
    return cpu.rv64_ethereum_gkr_main.mainWithRecursion();
}
