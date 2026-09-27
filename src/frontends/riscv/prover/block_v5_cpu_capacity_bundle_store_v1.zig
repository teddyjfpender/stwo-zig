//! Explicit typed capacity complete-bundle transport.
const Impl = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
pub const Family = Impl.Family;
pub const ProofFor = Impl.ProofFor;
pub const Geometry = Impl.Geometry;
pub const Limits = Impl.Limits;
pub const FilePin = Impl.FilePin;
pub const Policy = Impl.Policy;
pub const Store = Impl.Store;
pub const ProofReader = Impl.ProofReader;
pub const fileName = Impl.fileName;
pub const readPinned = Impl.readPinned;
pub const hash = Impl.hash;
pub const OwnedFiles = Impl.OwnedFiles;
pub const writePins = Impl.writePins;
pub const readPins = Impl.readPins;
pub const MANIFEST = Impl.MANIFEST;
pub const MANIFEST_MAGIC = Impl.MANIFEST_MAGIC;
