//! Cairo-to-generic-proof-program integration.
//!
//! No CUDA runtime is exposed yet. The only emitter is explicitly limited to
//! proof-derived development semantics.

pub const identity = @import("identity.zig");
pub const base_writer_plan = @import("base_writer_plan.zig");
pub const casm_input = @import("casm_input.zig");
pub const lowering_map = @import("lowering_map.zig");
pub const native_ec = @import("native_ec.zig");
pub const program = @import("program.zig");
pub const relation_adapter = @import("relation_adapter.zig");
pub const recorded_witness = @import("recorded_witness.zig");
pub const recorded_witness_oracle = @import("recorded_witness_oracle.zig");
pub const request_compiler = @import("request_compiler.zig");
pub const diagnostic_sn2 = @import("diagnostic_sn2.zig");
pub const eval_codegen = @import("eval_codegen.zig");
pub const eval_aot = @import("eval_aot.zig");
pub const eval_product_registry = @import("eval_product_registry.zig");
pub const eval_simd_oracle = @import("eval_simd_oracle.zig");
pub const eval_parity_fixture = @import("eval_parity_fixture.zig");
pub const relation_sn2_parity_fixture = @import(
    "relation_sn2_parity_fixture.zig",
);
pub const executor = @import("executor/mod.zig");

test "api signature: Cairo CUDA keeps its emitter explicitly development-only" {
    comptime {
        if (program.production_ready) {
            @compileError("development Cairo emitter cannot claim production readiness");
        }
        switch (@typeInfo(@TypeOf(program.emitDevelopmentOnly))) {
            .@"fn" => {},
            else => @compileError("emitDevelopmentOnly must remain a function"),
        }
    }
}

test {
    _ = @import("casm_input_test.zig");
    _ = base_writer_plan;
    _ = @import("witness_edge_test.zig");
    _ = @import("witness_multi_edge_test.zig");
    _ = lowering_map;
    _ = native_ec;
    _ = @import("program_test.zig");
    _ = @import("product_registry_test.zig");
    _ = @import("recorded_witness_fixture_test.zig");
    _ = @import("relation_adapter_test.zig");
    _ = @import("relation_adapter_layout_test.zig");
    _ = recorded_witness;
    _ = @import("request_compiler.zig");
    _ = diagnostic_sn2;
    _ = eval_codegen;
    _ = eval_product_registry;
    _ = @import("eval_aot_test.zig");
    _ = @import("eval_parity_fixture_test.zig");
    _ = @import("relation_sn2_parity_fixture_test.zig");
    _ = executor;
    @import("std").testing.refAllDeclsRecursive(@This());
}
