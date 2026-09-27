//! Explicit genuine capacity roster/receiver policy with shared assembly.
const Impl = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(true);
pub const Assembly = Impl.Assembly;
pub const assemble = Impl.assemble;
