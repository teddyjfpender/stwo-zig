//! Prover measurement primitives shared by product and benchmark frontends.

pub const process_usage = @import("process_usage.zig");
pub const resource_report = @import("resource_report.zig");

test {
    _ = process_usage;
    _ = resource_report;
}
