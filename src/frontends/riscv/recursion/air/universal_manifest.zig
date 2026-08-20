//! Exact allocation-free manifest construction for the universal recursion AIR.
//!
//! Logical rows retain compiler-owned equation authority and shared primitive
//! rows retain native-provider authority. This module owns only their final
//! protocol order and column geometry. It deliberately performs no witness
//! allocation and contains no component equation.

const manifest_mod = @import("universal_adapter_manifest.zig");
const provider = @import("universal_shared_provider.zig");
const range_bridge = @import("range_check_8_8_bridge.zig");
const binding = @import("universal_relation_binding.zig");
const adapter = @import("universal_typed_component.zig");
const catalog = @import("universal_catalog.zig");
const roster = @import("universal_roster.zig");

pub const Error = manifest_mod.Error || error{
    IncompleteRoster,
    LogSizeMismatch,
};

/// Per-row trace sizes are verifier-owned statement data. Providers with fixed
/// geometry validate their supplied value rather than silently replacing it.
pub const LogSizes = [roster.COMPONENT_COUNT]u32;

pub fn build(log_sizes: LogSizes) Error!manifest_mod.Manifest {
    var builder = manifest_mod.Builder{};
    inline for (catalog.LOGICAL_ROWS) |entry|
        try appendTyped(&builder, entry.Air, entry.row, log_sizes);

    const poseidon_log = rowLogSize(log_sizes, .poseidon2);
    if (poseidon_log == 0 or
        poseidon_log >= provider.POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT)
    {
        return error.LogSizeMismatch;
    }
    _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(poseidon_log));
    if (rowLogSize(log_sizes, .range_check_8_8) != range_bridge.LOG_SIZE)
        return error.LogSizeMismatch;
    _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());

    const manifest = try builder.seal();
    if (manifest.roster_count != roster.COMPONENT_COUNT)
        return error.IncompleteRoster;
    return manifest;
}

fn appendTyped(
    builder: *manifest_mod.Builder,
    comptime Air: type,
    comptime row: roster.Component,
    log_sizes: LogSizes,
) Error!void {
    const Relation = binding.Binding(Air);
    const TypedAdapter = adapter.Component(Air, Relation);
    _ = try builder.append(TypedAdapter.manifestGeometry(
        row,
        rowLogSize(log_sizes, row),
    ));
}

fn rowLogSize(log_sizes: LogSizes, row: roster.Component) u32 {
    return log_sizes[@intFromEnum(row)];
}

comptime {
    if (@sizeOf(LogSizes) != roster.COMPONENT_COUNT * @sizeOf(u32))
        @compileError("universal log-size vector contains hidden state");
}
