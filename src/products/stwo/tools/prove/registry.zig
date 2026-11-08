//! Compiled AIR registry and deferred adapter status.

const capabilities = @import("aggregate_capabilities");
const native = @import("native_cpu_capabilities");
const riscv = @import("riscv_cpu_capabilities");

/// The single typed admission switch for the Sail-profile RISC-V CPU adapter.
/// It changes with the artifact release status after every gate passes.
pub const RISCV_ADAPTER_RELEASE_GATED = riscv.adapter_release_gated;

pub fn requireRiscVAdmission(experimental: bool) !void {
    return riscv.requireAdmission(experimental);
}

pub fn write(writer: anytype) !void {
    try writer.writeAll("{\"schema_version\":1,\"backend_availability\":{\"cpu\":true,\"metal-hybrid\":");
    try writer.writeAll(if (capabilities.metal_enabled) "true" else "false");
    try writer.print("}},\"product_matrix\":{{\"native_cpu\":{{\"product_id\":\"{s}\",\"state\":\"{s}\"}},\"native_metal\":{{\"product_id\":\"{s}\",\"state\":\"{s}\",\"selected\":{s}}}}},\"applications\":[", .{
        capabilities.native_cpu_product,
        capabilities.native_cpu_state,
        capabilities.native_metal_product,
        capabilities.native_metal_state,
        if (capabilities.metal_enabled) "true" else "false",
    });
    if (!capabilities.native_cpu_enabled) @compileError("aggregate requires released Native CPU product");
    inline for (native.applications, 0..) |air, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"air\":\"{s}\",\"status\":\"release_gated\",\"backends\":[\"cpu\"", .{air});
        if (capabilities.metal_enabled) try writer.writeAll(",\"metal-hybrid\"");
        try writer.writeAll("]}");
    }
    if (RISCV_ADAPTER_RELEASE_GATED) try writer.print(
        \\,{{"adapter":"{s}","air":"{s}","status":"release_gated","isa":"{s}","backends":["{s}"]}}
    , .{ riscv.adapter, riscv.air, riscv.isa, riscv.backend });
    try writer.writeAll(
        \\],"deferred_adapters":[
    );
    if (!RISCV_ADAPTER_RELEASE_GATED) try writer.print(
        \\  {{"adapter":"{s}","status":"not_release_gated","isa":"{s}","backends":["{s}"],"reason":"{s}"}}
    , .{ riscv.adapter, riscv.isa, riscv.backend, riscv.deferred_reason });
    try writer.writeAll(
        \\]}
    );
}

test "registry is valid JSON and separates deferred adapters" {
    const std = @import("std");
    var storage: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&storage);
    try write(stream.writer());
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        stream.getWritten(),
        .{},
    );
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(
        @as(usize, 6) + @as(usize, @intFromBool(RISCV_ADAPTER_RELEASE_GATED)),
        root.get("applications").?.array.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1) - @as(usize, @intFromBool(RISCV_ADAPTER_RELEASE_GATED)),
        root.get("deferred_adapters").?.array.items.len,
    );
}

test "staged RISC-V admission is explicit and fail closed" {
    const std = @import("std");
    if (RISCV_ADAPTER_RELEASE_GATED) {
        try requireRiscVAdmission(false);
        try std.testing.expectError(error.ExperimentalFlagAfterPromotion, requireRiscVAdmission(true));
    } else {
        try requireRiscVAdmission(true);
        try std.testing.expectError(error.ExperimentalFlagRequired, requireRiscVAdmission(false));
    }
}
