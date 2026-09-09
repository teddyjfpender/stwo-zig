//! Named current Ethereum conformance fixture for the count-generic importer.
//!
//! This module is test/profile metadata only. It is deliberately not imported
//! by the campaign importer command or Stage101 worker, and it cannot wrap an
//! import operation. Production algorithms accept the authenticated protocol-
//! bounded count carried by STWCIR04/STWCIT04 and the sealed manifests.

const publication = @import("ethereum_incremental_capture_publication_v4.zig");

pub const CURRENT_CONFORMANCE_SEGMENT_COUNT: u32 =
    publication.CANONICAL_SEGMENT_COUNT;

pub const Error = error{
    IncrementalEthereumCampaignConformanceFixtureMismatchV4,
};

pub fn requireCurrentConformanceFixture(segment_count: u32) Error!void {
    if (segment_count != CURRENT_CONFORMANCE_SEGMENT_COUNT)
        return error.IncrementalEthereumCampaignConformanceFixtureMismatchV4;
}

comptime {
    if (CURRENT_CONFORMANCE_SEGMENT_COUNT !=
        publication.CANONICAL_SEGMENT_COUNT)
    {
        @compileError("current Ethereum conformance fixture count drifted");
    }
}
