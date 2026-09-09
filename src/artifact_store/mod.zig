//! Host-neutral persistent typed artifact substrate.

pub const encoding = @import("encoding.zig");
pub const types = @import("types.zig");
pub const manifest = @import("manifest.zig");
pub const wire = @import("wire.zig");
pub const store = @import("store.zig");

pub const Digest = encoding.Digest;
pub const ArtifactKindV1 = types.ArtifactKindV1;
pub const StageKindV1 = types.StageKindV1;
pub const InputRoleV1 = types.InputRoleV1;
pub const BlobRefV1 = types.BlobRefV1;
pub const InputRefV1 = types.InputRefV1;
pub const SemanticKeyFieldsV1 = types.SemanticKeyFieldsV1;
pub const SemanticKeyV1 = types.SemanticKeyV1;
pub const ExecutionKeyFieldsV1 = types.ExecutionKeyFieldsV1;
pub const ExecutionKeyV1 = types.ExecutionKeyV1;
pub const StagePhaseV1 = manifest.StagePhaseV1;
pub const StageStatusV1 = manifest.StageStatusV1;
pub const ValidationReceiptRefV1 = manifest.ValidationReceiptRefV1;
pub const ProfileReceiptRefV1 = manifest.ProfileReceiptRefV1;
pub const StageManifestFieldsV1 = manifest.StageManifestFieldsV1;
pub const StageManifestV1 = manifest.StageManifestV1;
pub const OwnedSemanticKeyV1 = wire.OwnedSemanticKeyV1;
pub const OwnedStageManifestV1 = wire.OwnedStageManifestV1;
pub const decodeSemanticKeyAlloc = wire.decodeSemanticKeyAlloc;
pub const decodeExecutionKey = wire.decodeExecutionKey;
pub const decodeStageManifestAlloc = wire.decodeStageManifestAlloc;
pub const FileIdentity = store.FileIdentity;
pub const Measurement = store.Measurement;
pub const CopyMethod = store.CopyMethod;
pub const IngestPolicy = store.IngestPolicy;
pub const ObjectRef = store.ObjectRef;
pub const Snapshot = store.Snapshot;
pub const OwnedBlobV1 = store.OwnedBlobV1;
pub const Store = store.Store;
pub const measureFile = store.measureFile;
pub const digestBytes = store.digestBytes;

test {
    _ = @import("types_test.zig");
    _ = @import("store_test.zig");
}
