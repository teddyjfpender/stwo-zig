//! Private authority-mint transaction for a validated V3 graph recording.

const std = @import("std");

pub fn mint(
    comptime CircuitAuthorityStorage: type,
    recording: anytype,
    identityFn: anytype,
) !CircuitAuthorityStorage {
    const graph = recording.graph();
    var result = CircuitAuthorityStorage{
        .configuration_identity = recording.configuration.identity,
        .graph_identity = graph.identity_digest,
        .binding_count = std.math.cast(
            u32,
            recording.bindings.len,
        ) orelse return error.CircuitAuthorityMismatch,
        .identity = undefined,
    };
    result.identity = identityFn(result);
    try result.validateAgainstValidatedConfiguration(
        recording.configuration,
        graph,
        recording.bindings,
    );
    return result;
}
