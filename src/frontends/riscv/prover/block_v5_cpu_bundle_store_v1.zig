//! Durable bounded all-family transport. Independent policies choose codecs;
//! file manifests contain only hashes/lengths, never accepted proof receipts.
//! Default loaders use Store's allocator. withProofAllocator supplies fresh
//! receiver proof ownership separately. Writers use the producer allocator.
pub const ForCapacity = @import("block_v5_cpu_bundle_store_impl_v1.zig").ForCapacity;
const Default = ForCapacity(false);
pub const Family = Default.Family;
pub const ProofFor = Default.ProofFor;
pub const Geometry = Default.Geometry;
pub const Limits = Default.Limits;
pub const FilePin = Default.FilePin;
pub const Policy = Default.Policy;
pub const Store = Default.Store;
pub const ProofReader = Default.ProofReader;
pub const fileName = Default.fileName;
pub const readPinned = Default.readPinned;
pub const hash = Default.hash;
pub const OwnedFiles = Default.OwnedFiles;
pub const writePins = Default.writePins;
pub const readPins = Default.readPins;
pub const MANIFEST = Default.MANIFEST;
pub const MANIFEST_MAGIC = Default.MANIFEST_MAGIC;
