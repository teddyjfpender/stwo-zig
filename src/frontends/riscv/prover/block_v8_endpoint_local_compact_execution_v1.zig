//! Experimental compact global-memory variant of the continuous local producer.
const Mode = @import("block_v8_endpoint_local_execution_mode_v1.zig").For(true);
pub const production_active = Mode.production_active;
pub const Request = Mode.Request;
pub const Options = Mode.Options;
pub const Stats = Mode.Stats;
pub const Result = Mode.Result;
pub const FileProvider = Mode.FileProvider;
pub const run = Mode.run;
