//! Legacy bytecode analysis and jump table.

mod analysis;
mod jump_map;
#[cfg(all(feature = "stwo-jumpdest-service", any(target_arch = "riscv64", test)))]
mod jumpdest_service;

pub(crate) use analysis::analyze_legacy;
pub use jump_map::JumpTable;
