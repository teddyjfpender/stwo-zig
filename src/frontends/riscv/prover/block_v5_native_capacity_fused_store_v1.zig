//! Distinct typed capacity artifact authority over the shared durable store.
//! Codec, fresh verifier, filenames and protocol errors remain family-specific.
const Impl = @import("block_v5_capacity_artifact_store_common_v1.zig").ForFamily(true);
pub const Policy = Impl.Policy;
pub const FilePin = Impl.FilePin;
pub const Limits = Impl.Limits;
pub const Sink = Impl.Sink;
pub const Loader = Impl.Loader;
pub const Store = Impl.Store;
pub const fileName = Impl.fileName;
pub const OwnedPins = Impl.OwnedPins;
pub const writePins = Impl.writePins;
pub const readPins = Impl.readPins;
