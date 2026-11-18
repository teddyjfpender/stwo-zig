//! OP Stack product line: Kona/Mantle RV64 guests proven by the shared RV64
//! block pipeline. The product owns the guest ABI, the 43-byte statement and
//! the pipeline hooks; it imports no other product.
const std = @import("std");

pub const cpu = @import("opstack_cpu_component");
pub const frontend = @import("opstack_frontend_component");
pub const hooks = @import("rv64_pipeline_hooks");
pub const statement = frontend.statement;

test "api signature: OP Stack product exposes its four owning domains" {
    try std.testing.expect(@hasDecl(cpu, "Pipeline"));
    try std.testing.expect(@hasDecl(frontend, "guest_abi"));
    try std.testing.expect(@hasDecl(hooks, "admitsProfile"));
    try std.testing.expectEqual(@as(usize, 43), statement.OUTPUT_BYTES);
}

test "api invariant: the pipeline instance is bound to the OP hooks" {
    try std.testing.expect(cpu.Pipeline.Hooks == hooks);
    try std.testing.expectEqualStrings("opstack", cpu.Pipeline.label);
    try std.testing.expect(cpu.Pipeline.request.Config != void);
}

test {
    _ = @import("tests/guest_abi_test.zig");
    _ = @import("tests/statement_test.zig");
    _ = @import("tests/hooks_contract_test.zig");
    _ = @import("cpu/cli.zig");
}
