//! Optional reuse of immutable, protocol-owned prepared columns.
//! The frontend owns admission, source identity, integrity and storage. Exact
//! work requests bypass this seam and execute their actual transforms.
const M31 = @import("stwo_core").fields.m31.M31;

pub const Request = struct {
    base_log_size: u32,
    extended_log_size: u32,
    column_count: usize,
};

pub const Source = struct {
    ctx: *anyopaque,
    /// Identify sources before in-place interpolation may overwrite them.
    identify: *const fn (*anyopaque, Request, []const []const M31) ?[32]u8,
    /// Must authenticate before modifying either destination family. A miss
    /// leaves the original sources intact so the normal transform can run.
    load: *const fn (*anyopaque, [32]u8, Request, []const []M31, []const []M31) bool,
    store: *const fn (*anyopaque, [32]u8, Request, []const []M31, []const []M31) void,
};

threadlocal var source: ?Source = null;
pub fn arm(value: Source) void {
    source = value;
}
pub fn disarm() void {
    source = null;
}
pub fn armed() ?Source {
    return source;
}
