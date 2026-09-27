//! Fresh block-wide endpoint + sorted-memory + range/initial closure. Proof
//! bytes are loaded one instance at a time; caller receipts have no authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const seal = @import("block_v5_source_seal_v1.zig");
const base = @import("block_v5_memory_batch_receiver_v1.zig");
const sources = @import("block_v5_rw_endpoint_sources_v1.zig");
const proof_mod = @import("block_v5_rw_endpoint_proof_v1.zig");
const sorted = @import("block_memory_shared_instance_proof_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
pub const Loader = struct {
    memory: base.ProofLoader,
    context: *anyopaque,
    take_endpoint: *const fn (*anyopaque, u32) anyerror!proof_mod.Proof,
};
pub const Scoped = struct {
    sorted_initial_range_endpoints_verified: void = {},
    memory: base.ScopedMemory,
    final_rw_root: [32]u8,
    memory_endpoints: u64,
    input_endpoints: u64,
    rw_endpoints: u64,
};
pub fn verify(comptime Backend: type, a: std.mem.Allocator, pins: base.Pins, endpoint_pins: sources.Pins, public_input: []const u8, files: sources.Sources, loader: Loader, sealed: seal.Sealed) !Scoped {
    return verifyMode(Backend, false, a, pins, endpoint_pins, public_input, files, loader, sealed);
}
pub fn verifyCompact(comptime Backend: type, a: std.mem.Allocator, pins: base.Pins, endpoint_pins: sources.Pins, public_input: []const u8, files: sources.Sources, loader: Loader, sealed: seal.Sealed) !Scoped {
    return verifyMode(Backend, true, a, pins, endpoint_pins, public_input, files, loader, sealed);
}
fn verifyMode(comptime Backend: type, comptime compact: bool, a: std.mem.Allocator, pins: base.Pins, endpoint_pins: sources.Pins, public_input: []const u8, files: sources.Sources, loader: Loader, sealed: seal.Sealed) !Scoped {
    if (!std.meta.eql(pins.source, endpoint_pins.initial)) return error.UntrustedV5EndpointInitialSources;
    const public = try sources.check(a, endpoint_pins, public_input, files, pins.seal, pins.first_round, sealed);
    var state = State(Backend, compact){ .a = a, .pins = &pins, .sealed = sealed, .loader = loader };
    const verify_memory = if (compact) base.verifyCompact else base.verify;
    const memory = try verify_memory(Backend, a, pins, public_input, files.initial, .{ .context = &state, .take_memory = State(Backend, compact).takeMemory, .take_table = State(Backend, compact).takeTable }, sealed);
    if (state.count != public.count or !state.sum.eql(public.sum)) return error.UnclosedV5RwEndpointRelation;
    return .{ .memory = memory, .final_rw_root = public.final_root, .memory_endpoints = public.count, .input_endpoints = public.input_endpoints, .rw_endpoints = public.rw_endpoints };
}
fn State(comptime Backend: type, comptime compact: bool) type {
    return struct {
        a: std.mem.Allocator,
        pins: *const base.Pins,
        sealed: seal.Sealed,
        loader: Loader,
        sum: Q = Q.zero(),
        count: u64 = 0,
        next: u32 = 0,
        fn takeMemory(context: *anyopaque, index: u32) anyerror!sorted.Proof {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (index != self.next or index >= self.pins.claims.len) return error.InvalidV5EndpointInstanceOrder;
            const received = try self.loader.take_endpoint(self.loader.context, index);
            const claim = try (if (compact) proof_mod.ForCompactBackend(Backend) else proof_mod.ForBackend(Backend)).verifyOpenOwned(self.a, received, self.pins.claims[index], self.sealed, self.pins.seal, self.pins.first_round, index, self.pins.memory_roots[index]);
            self.sum = self.sum.add(claim.sum);
            self.count = try std.math.add(u64, self.count, claim.count);
            self.next += 1;
            // Fresh sorted verification follows immediately in base.verify;
            // failure cannot issue Scoped authority even if sidecar passed.
            return self.loader.memory.take_memory(self.loader.memory.context, index);
        }
        fn takeTable(context: *anyopaque, index: u32) anyerror!table.Proof {
            const self: *@This() = @ptrCast(@alignCast(context));
            return self.loader.memory.take_table(self.loader.memory.context, index);
        }
    };
}
