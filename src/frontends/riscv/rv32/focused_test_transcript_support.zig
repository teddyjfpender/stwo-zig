//! Explicit original transcript support cases at their canonical owner.
test {
    _ = @import("air/component.zig");
    _ = @import("air/component_order.zig");
    _ = @import("air/constraint_program.zig");
    _ = @import("air/extract/runtime_program.zig");
    _ = @import("air/lookups/opcode_entries.zig");
    _ = @import("air/program/commitment.zig");
    _ = @import("air/program/decode.zig");
    _ = @import("air/program/interaction.zig");
    _ = @import("air/program/opcode.zig");
    _ = @import("air/program/table.zig");
    _ = @import("air/public_data.zig");
    _ = @import("air/semantic_eval.zig");
    _ = @import("air/trace_columns.zig");
    _ = @import("air/trace_columns/m_extension.zig");
    _ = @import("air/transcript/claims.zig");
    _ = @import("air/x0_local_custody.zig");
    _ = @import("air/x0_native_envelope.zig");
    _ = @import("infra_trace.zig");
    _ = @import("recursion/segment_statement_identity_preimage.zig");
    _ = @import("runner/guest_precompile/poseidon2.zig");
}
