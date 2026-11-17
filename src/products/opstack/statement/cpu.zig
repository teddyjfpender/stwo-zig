//! OP Stack CPU component: this product's instance of the neutral RV64 block
//! pipeline, bound to the OP hooks module.
pub const Pipeline = @import("stwo_riscv_rv64_pipeline").Pipeline(@import("rv64_pipeline_hooks"));
