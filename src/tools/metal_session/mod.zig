//! Persistent Metal-session protocol and content-addressed artifact services.

pub const artifact_manifest = @import("artifacts/manifest.zig");
pub const artifact_store = @import("artifacts/store.zig");
pub const artifact_views = @import("artifacts/views.zig");
pub const protocol = @import("protocol.zig");

test "api signature: Metal session parser returns an owned parsed request" {
    comptime {
        const parse = @typeInfo(@TypeOf(protocol.parseRequest)).@"fn";
        if (parse.params.len != 4) @compileError("parseRequest parameter count drifted");
        const result = @typeInfo(parse.return_type.?);
        if (result != .error_union or result.error_union.payload != protocol.ParsedRequest) {
            @compileError("parseRequest must return !ParsedRequest");
        }
    }
}
