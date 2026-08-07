test {
    _ = @import("runner/access_witness.zig");
    _ = @import("runner/cpu.zig");
    _ = @import("runner/decode.zig");
    _ = @import("runner/elf_admission.zig");
    _ = @import("runner/elf_loader.zig");
    _ = @import("runner/execute.zig");
    _ = @import("runner/guest_precompile/call_buffer.zig");
    _ = @import("runner/guest_precompile/mod.zig");
    _ = @import("runner/guest_precompile/poseidon2_v1.zig");
    _ = @import("runner/guest_precompile/runner_test.zig");
    _ = @import("runner/host_integration_test.zig");
    _ = @import("runner/memory.zig");
    _ = @import("runner/memory_state.zig");
    _ = @import("runner/mod.zig");
    _ = @import("runner/sail_oracle.zig");
    _ = @import("runner/state_chain.zig");
    _ = @import("runner/trace.zig");
    _ = @import("runner/trace_dump.zig");
    _ = @import("runner/witness/load_store.zig");
    _ = @import("runner/witness/m_extension.zig");
    _ = @import("runner/witness/shift.zig");
}
