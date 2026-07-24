//! Compatibility aliases for shared Native CUDA resident data-plane views.

const shared = @import("../../common/resident_views.zig");

pub const max_fri_layers = shared.max_fri_layers;
pub const max_trace_trees = shared.max_trace_trees;
pub const TraceTree = shared.TraceTree;
pub const TraceTrees = shared.TraceTrees;
pub const Trace = shared.Trace;
pub const Transcript = shared.Transcript;
pub const Constraint = shared.Constraint;
pub const Oods = shared.Oods;
pub const Quotient = shared.Quotient;
pub const FriLayer = shared.FriLayer;
pub const Fri = shared.Fri;
pub const Pow = shared.Pow;
pub const Counts = shared.Counts;
pub const Decommit = shared.Decommit;
pub const Proof = shared.Proof;
pub const Views = shared.Views;
