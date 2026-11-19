//! Persistent Metal-session protocol and content-addressed artifact services.

pub const artifact_manifest = @import("artifact_io/manifest.zig");
pub const artifact_store = @import("artifact_io/store.zig");
pub const artifact_views = @import("artifact_io/views.zig");
pub const persistent_artifacts = @import("stwo_artifact_store");
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
