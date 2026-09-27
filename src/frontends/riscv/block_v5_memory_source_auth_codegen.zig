//! Retain genuine sealed admission/draw/build bodies. No source proof exists or
//! is invoked here, and no base/recursive proof/guest/device work is launched.
const std = @import("std");
const Protocol = @import("prover/block_v5_memory_source_auth_protocol_v1.zig");
const Circuit = @import("prover/block_v5_memory_source_circuit_v1.zig");
const Equations = @import("recursion/air/block_v5_memory_source_equations_v1.zig");
const Seal = @import("prover/block_v5_source_seal_v1.zig");
const Endpoint = @import("prover/block_v5_rw_endpoint_sources_v1.zig");
fn admit(pins: Endpoint.Pins, seal_pins: Seal.Pins, entries: []const Seal.Entry, sealed: Seal.Sealed, limits: Protocol.Limits) anyerror!Protocol.Admitted {
    return Protocol.admit(pins, seal_pins, entries, sealed, limits);
}
fn prepare(a: std.mem.Allocator, admitted: *const Protocol.Admitted, kind: Equations.Kind, witness: Equations.Witness, claims: Protocol.Sums, sealed: Seal.Sealed) anyerror!*Circuit.Prepared {
    return Circuit.prepare(a, admitted, kind, witness, claims, sealed);
}
test "source auth bodies: actual sealed admission and challenge circuit construction retained" {
    inline for (.{ &admit, &prepare, &Circuit.prepareClosureWithChallenges, &Circuit.Prepared.deinit }) |body| std.mem.doNotOptimizeAway(body);
}
