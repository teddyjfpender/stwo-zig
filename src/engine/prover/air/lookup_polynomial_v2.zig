//! Compatibility source path bound by the historical P-003 matrix.
//! Remove only with its owner-reviewed source-binding refresh.
const canonical = @import("lookup_polynomial.zig");

pub const MAX_MAIN_COLUMNS = canonical.MAX_MAIN_COLUMNS;
pub const MAX_PROGRAM_NODES = canonical.MAX_PROGRAM_NODES;
pub const MAX_LOOKUP_ENTRIES = canonical.MAX_LOOKUP_ENTRIES;
pub const MAX_LOOKUP_BATCHES = canonical.MAX_LOOKUP_BATCHES;
pub const EVALUATE_ROW_ALLOCATION_COUNT = canonical.EVALUATE_ROW_ALLOCATION_COUNT;
pub const PreparedEvaluator = canonical.PreparedEvaluator;
pub const PreparedCapability = canonical.PreparedCapability;
pub const evaluatorScratchBytes = canonical.evaluatorScratchBytes;
pub const capabilityResidentBytes = canonical.capabilityResidentBytes;
