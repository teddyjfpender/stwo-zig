//! Stable API facade for exact opcode-source ingestion.

const core = @import("source_ingest_core.zig");

pub const Digest = core.Digest;
pub const Error = core.Error;
pub const Shard = core.Shard;
pub const FamilySource = core.FamilySource;
pub const Result = core.Result;
pub const GeneratedCounters = core.GeneratedCounters;
pub const UnrepresentableRequest = core.UnrepresentableRequest;
pub const Options = core.Options;
pub const ingest = core.ingest;
pub const ingestGenerated = core.ingestGenerated;
pub const ingestGeneratedCounters = core.ingestGeneratedCounters;
pub const digestShard = core.digestShard;
pub const registerGeneratedCommittedRow = core.registerGeneratedCommittedRow;

test {
    _ = @import("source_ingest_test.zig");
}
