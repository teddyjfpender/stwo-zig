//! Consumer-owned laws selected for the stwo_metal_backend boundary.
const builtin = @import("builtin");
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");
const core = @import("stwo_core");
const consumer = @import("stwo_metal_backend");

test "cdc: stwo_metal_backend line geometry rejects invalid storage" {
    // The native FRI capability requires a linked Objective-C runtime.
    if (comptime builtin.os.tag == .macos) comptime provider.assertBackend(consumer.MetalCommitBackend);
    try laws.line(provider, core);
}
