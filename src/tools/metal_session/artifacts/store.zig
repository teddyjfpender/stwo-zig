//! Metal-session compatibility adapter over the host-neutral artifact store.

const shared = @import("stwo_artifact_store");

pub const CopyMethod = shared.CopyMethod;
pub const IngestPolicy = shared.IngestPolicy;
pub const ObjectRef = shared.ObjectRef;
pub const Snapshot = shared.Snapshot;
pub const Store = shared.Store;

test "Metal artifact store retains the exclusive init and snapshot API" {
    comptime {
        const init_new = @typeInfo(@TypeOf(Store.initNew)).@"fn";
        if (init_new.params.len != 3) @compileError("Store.initNew API drifted");
        const ingest = @typeInfo(@TypeOf(Store.ingestPath)).@"fn";
        if (ingest.params.len != 2) @compileError("Store.ingestPath API drifted");
        const resolve = @typeInfo(@TypeOf(Store.resolveRef)).@"fn";
        if (resolve.params.len != 2) @compileError("Store.resolveRef API drifted");
    }
}
