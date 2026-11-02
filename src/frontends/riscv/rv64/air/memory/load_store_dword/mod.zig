//! LS-D64: a second, narrower LS component that consumes only naturally
//! aligned 8-byte LD/SD accesses (83% of evmone v3 accesses). It feeds the
//! same RAM14 relation and the same CPU OWNER19, U16 and U8 relations as the
//! LS32 component (load_store_v2); the CPU, ROM and OWNER tuple are unchanged
//! and the prover chooses which component consumes each OWNER tuple.
//! Every row is an affine projection onto the audited V1 logical row with
//! flags in {LD, SD} and offset 0; the V1 local equations and closed-RAM
//! transition run unchanged. Soundness: design/riscv-proving-stack/
//! rv64-ls-dword-fast-row.md and rv64-ls-joint-write-induction.md section 12.
pub const types = @import("types.zig");
pub const layout = @import("layout.zig");
pub const equations = @import("equations.zig");
pub const source = @import("source.zig");
pub const component = @import("component.zig");
pub const encoding = @import("encoding.zig");
