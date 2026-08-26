//! Concrete typed-component bridge for resumed-segment V2 public rows 12--17.
//!
//! The source owns authenticated bridge words and exact relation events. This
//! module only projects those rows into the six typed AIRs, validates the
//! compiler-authored direct/event programs, and writes the three commitment
//! trees. All hot operations use a caller-retained workspace. Tree 2 is first
//! generated into a complete private slab and is committed only after all six
//! bulk inversions and claims succeed.
const shard_0 = @import("segment_public_outer_components_v2_contract.zig");
const shard_1 = @import("segment_public_outer_components_v2_validate_events_for.zig");
const shard_2 = @import("segment_public_outer_components_v2_workspace.zig");
const shard_3 = @import("segment_public_outer_components_v2_fill_interaction_into.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const HOT_HEAP_ALLOCATIONS = shard_0.HOT_HEAP_ALLOCATIONS;
pub const TREE_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.TREE_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const Error = shard_0.Error;
pub const Claims = shard_0.Claims;
pub const DomainAudits = shard_0.DomainAudits;
pub const Components = shard_0.Components;
pub const Parameters = shard_0.Parameters;
pub const Source = shard_0.Source;
/// Reusable single-worker cache. `init` owns every allocation; `prepare` and
/// all tree/claim writers are allocation free.
pub const Workspace = shard_2.Workspace;
/// Writes Tree 0 after complete source/cache/manifest/alias admission.
pub const fillPreprocessedInto = shard_3.fillPreprocessedInto;
/// Writes Tree 1 from the same sealed logical rows.
pub const fillMainInto = shard_3.fillMainInto;
/// Generates every Tree-2 column into retained private staging. No committed
/// cell changes until all six framework generators return successfully.
pub const fillInteractionInto = shard_3.fillInteractionInto;
/// Cold diagnostic decomposition of the exact rows used for Tree 2. Rows
/// 12--17 intentionally own no row-35 range contribution.
pub const auditInteractionDomains = shard_3.auditInteractionDomains;
