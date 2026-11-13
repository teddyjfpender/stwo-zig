//! Product composition facade; native declarations retain their canonical owners.
const native = @import("stwo_riscv_frontend").host;
pub const BlockInput = native.BlockInput;
pub const HintOracle = native.HintOracle;
pub const HostInterface = native.HostInterface;
pub const HostRuntime = native.HostRuntime;
pub const MemoryWrite = native.MemoryWrite;
pub const SyscallNr = native.SyscallNr;
pub const SyscallResult = native.SyscallResult;
pub const block_input = native.block_input;
pub const hint_oracle = native.hint_oracle;
pub const proveEthereumBlockWithEngine = prove_block.proveEthereumBlockWithEngine;
pub const prove_block = @import("prove_block.zig");
pub const runtime = native.runtime;
