//! Native CUDA wide-Fibonacci proof integration.

pub const driver = @import("driver.zig");
pub const layout = @import("layout.zig");
pub const protocol = @import("protocol.zig");
pub const request = @import("request.zig");

test {
    _ = driver;
    _ = layout;
    _ = protocol;
    _ = request;
}
