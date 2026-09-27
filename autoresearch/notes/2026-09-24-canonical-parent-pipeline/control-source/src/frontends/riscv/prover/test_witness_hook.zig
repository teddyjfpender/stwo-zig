//! Stable witness-mutation facade.

const core = @import("test_witness_hook_core.zig");

pub const Target = core.Target;
pub const Cell = core.Cell;
pub const ColumnValue = core.ColumnValue;
pub const RowOverride = core.RowOverride;
pub const Mutation = core.Mutation;
pub const Error = core.Error;
pub const applyPreprocessed = core.applyPreprocessed;
pub const applyMain = core.applyMain;
pub const applyInteraction = core.applyInteraction;
pub const isInteraction = core.isInteraction;
pub const applyOpcodeWitness = core.applyOpcodeWitness;
pub const applyLegacyOpcodeAuthority = core.applyLegacyOpcodeAuthority;
pub const applyLegacyLuiAuthority = core.applyLegacyLuiAuthority;

test {
    _ = @import("test_witness_hook_test.zig");
}
