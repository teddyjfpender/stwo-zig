//! Opt-in, instance-admitted RISC circuit recursion. Default routes unchanged.
//! Import this src-root module to share circuit/RISC types without reaching
//! outside either existing frontend module's package root.
pub const authority = @import("integrations/circuit_cpu/riscv_recursion/authority_v1.zig");
pub const proof_material = @import("integrations/circuit_cpu/riscv_recursion/proof_material_v1.zig");
pub const leaf_wrap = @import("integrations/circuit_cpu/riscv_recursion/leaf_wrap_v1.zig");
pub const registry = @import("integrations/circuit_cpu/riscv_recursion/registry_v1.zig");
pub const fold = @import("integrations/circuit_cpu/riscv_recursion/circuit_fold_v1.zig");
pub const fold_statement = @import("integrations/circuit_cpu/riscv_recursion/fold_statement_v1.zig");
pub const fold_wire = @import("integrations/circuit_cpu/riscv_recursion/fold_wire_v1.zig");
pub const statement = @import("stwo_circuit_frontend").statements.riscv_native_parent_v1;
pub const production_active = false;
