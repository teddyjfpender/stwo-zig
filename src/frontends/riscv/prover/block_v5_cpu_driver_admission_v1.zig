//! Shared bounded two-pass planning with explicit typed native authority.
const Common = @import("block_v5_cpu_driver_admission_common_v1.zig");
pub const ForCapacity = Common.ForCapacity;
const Impl = ForCapacity(false);
pub const Digest = Common.Digest;
pub const Fetch = Common.Fetch;
pub const Demand = Common.Demand;
pub const Limits = Impl.Limits;
pub const InputPolicy = Impl.InputPolicy;
pub const GlobalPlans = Impl.GlobalPlans;
pub const Record = Impl.Record;
pub const Bound = Impl.Bound;
pub const Planning = Impl.Planning;
pub const nativeMetadata = Impl.nativeMetadata;
pub const externalRetirements = Impl.externalRetirements;
pub const validatePhysical = Impl.validatePhysical;
