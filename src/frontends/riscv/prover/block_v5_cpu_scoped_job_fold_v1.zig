//! One actual bounded typed fold implementation. Complete remains the original
//! API/default; requester geometry, context and filenames are distinct.
const Impl = @import("block_v5_cpu_scoped_job_fold_impl_v1.zig");
pub const Recipe = Impl.Recipe;
pub const Pin = Impl.Pin;
pub const Limits = Impl.Limits;
pub const Sink = Impl.Sink;
pub const Result = Impl.Result;
pub const Action = Impl.Action;
pub const path = Impl.path;
pub const ForBackend = Impl.ForBackend;
pub const ForRecipe = Impl.ForRecipe;
pub const slotValue = Impl.slotValue;
