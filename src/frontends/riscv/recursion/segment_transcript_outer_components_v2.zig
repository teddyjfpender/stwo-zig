//! Proof-component bridge for resumed-segment V2 transcript rows 0--9.
//!
//! The frozen V2 source owns native Program/Execution/Evidence custody and
//! publishes exact typed rows, relation events, and Poseidon2 provider calls.
//! This module does not reinterpret that schedule. It converts one successful
//! source publication into the existing ten universal typed AIR programs,
//! seals a worker-local prepared cache, and writes the three committed trees
//! in protocol order.
//!
//! Tree 0 and Tree 1 are independent allocation-free writes. Tree 2 retains
//! one inversion workspace per component and a complete rows-0--9 staging
//! slab: every relation evaluation and denominator inversion succeeds before
//! the first committed interaction cell changes. Provider calls are copied
//! only into their authenticated half-open range in the one shared row-34
//! stream; this bridge never instantiates a second Poseidon2 component.
//!
//! V2 changes row 5's authenticated preprocessing source, including dynamic
//! statement geometry (`source_kind = 13`), but not its polynomial equations
//! or universal relation ABI. Keeping the existing typed AIR identity is what
//! preserves universal roster indices 0--35 and their manifest geometry.
const shard_0 = @import("segment_transcript_outer_components_v2_contract.zig");
const shard_1 = @import("segment_transcript_outer_components_v2_source.zig");
const shard_2 = @import("segment_transcript_outer_components_v2_workspace.zig");
const shard_3 = @import("segment_transcript_outer_components_v2_fill_interaction_into.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const HOT_HEAP_ALLOCATIONS = shard_0.HOT_HEAP_ALLOCATIONS;
pub const TREE_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.TREE_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const SHARED_PROVIDER_COMPONENT_COUNT = shard_0.SHARED_PROVIDER_COMPONENT_COUNT;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const Error = shard_0.Error;
pub const NativeInputs = shard_0.NativeInputs;
pub const Claims = shard_0.Claims;
pub const Components = shard_0.Components;
pub const Parameters = shard_0.Parameters;
pub const Source = shard_1.Source;
/// One reusable worker cache. All allocations occur in `init`; preparation,
/// tree publication, claim generation, and provider publication allocate
/// nothing. A cache is intentionally single-worker and non-reentrant.
pub const Workspace = shard_2.Workspace;
/// Writes Tree 0 for universal rows 0--9 from the sealed V2 cache. All shape,
/// authority, alias, and cache-integrity checks precede the first store.
pub const fillPreprocessedInto = shard_3.fillPreprocessedInto;
/// Writes Tree 1 for universal rows 0--9 from the same sealed logical rows.
pub const fillMainInto = shard_3.fillMainInto;
/// Generates all ten framework LogUp traces into retained private staging,
/// then commits Tree 2 only after every denominator, claim, and prefix check
/// succeeds. A failing later row can never expose an earlier partial trace.
pub const fillInteractionInto = shard_3.fillInteractionInto;
/// Publishes only this transcript source's authenticated half-open interval in
/// the one caller-owned row-34 ProviderCall stream. No provider component or
/// second permutation trace is created here.
pub const writeProviderCallsInto = shard_3.writeProviderCallsInto;
