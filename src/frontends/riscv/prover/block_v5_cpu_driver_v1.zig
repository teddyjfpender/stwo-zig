//! Explicit default NativeV3 CPU orchestration. Fresh all-family detached Complete verification remains mandatory.
const Common = @import("block_v5_cpu_driver_common_v1.zig");
pub const ForCapacity = Common.ForCapacity;
const Impl = ForCapacity(false);
pub const Options = Impl.Options;
pub const Result = Impl.Result;
pub const run = Impl.run;
pub const nativeMetadata = Impl.nativeMetadata;
pub const externalRetirements = Impl.externalRetirements;
