//! Explicit B5CT leaf specialization of the bounded incremental OpenV2 stage.
//! Only the typed leaf verifier/supply changes; no old receipt is reinterpreted.
const Common = @import("block_v5_open_forest_stage_v1.zig");
const Impl = @import("block_v5_open_forest_stage_impl_v1.zig").ForLeafAdapter(@import("../recursion/block_v5_capacity_exact_leaf_adapter_v1.zig"));
pub const VERSION = Common.VERSION;
pub const LeafFile = Impl.LeafFile;
pub const ParentPin = Common.ParentPin;
pub const OuterPin = Common.OuterPin;
pub const Options = Common.Options;
pub const Stage = Common.Stage;
pub const Stream = Impl.Stream;
pub const prove = Impl.prove;
pub const leafPath = Common.leafPath;
pub const parentPath = Common.parentPath;
pub const OUTER_FILE = Common.OUTER_FILE;
pub const openPinned = Common.openPinned;
pub const writeProof = Common.writeProof;
