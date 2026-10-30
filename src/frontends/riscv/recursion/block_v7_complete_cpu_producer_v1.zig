//! Bounded CPU execution originals -> one complete mixed root candidate.
//! The receiver independently selects policy/key and authenticates the output;
//! this producer returns no verification receipt. All original proof owners
//! remain borrowed only for this call. Returned metadata/proof are detached.
pub const For = @import("block_v7_complete_cpu_family_v1.zig").For;
const Default = For(false);
pub const Options = Default.Options;
pub const Stats = Default.Stats;
pub const Output = Default.Output;
pub const produce = Default.produce;
