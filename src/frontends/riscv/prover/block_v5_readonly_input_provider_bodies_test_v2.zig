//! Retains genuine producer/fresh receiver kernels; test invokes none of them.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Source = @import("block_v5_native_readonly_source_proof_v2.zig");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Original = @import("block_v5_readonly_input_proof_v1.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Range = @import("block_v5_range16_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Api = Provider.ForBackend(Cpu);
const Native = Source.ForBackend(Cpu);
pub export fn readonly_global_provider_actual_pair(a: *const std.mem.Allocator, proof: *const Provider.Proof, range_proof: *const Range.Proof, pin: *const Provider.Pin, ordinals: [*]const u32, n: usize, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, entry_count: usize, out: *Provider.OpenSource) callconv(.c) bool {
    out.* = Api.verifyPairOwned(a.*, proof.*, range_proof.*, pin.*, ordinals[0..n], authority, sealed.*, pins.*, entries[0..entry_count], .{}) catch return false;
    return true;
}
pub export fn readonly_global_provider_actual_prove(a: *const std.mem.Allocator, columns: *const Table.Columns, pin: *const Provider.Pin, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, entry_count: usize, out: *Provider.Proof) callconv(.c) bool {
    var first = Api.commit(a.*, columns, pin.*) catch return false;
    defer first.deinit(a.*);
    out.* = Api.prove(a.*, &first, columns, pin.*, authority, sealed.*, pins.*, entries[0..entry_count]) catch return false;
    return true;
}
pub export fn readonly_global_native_actual_capture(a: *const std.mem.Allocator, proof: *const Source.Proof, pin: *const Source.Pin, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, entry_count: usize, out: *Native.Captured) callconv(.c) bool {
    out.* = Native.verifyCaptureBorrowed(a.*, proof, pin.*, authority, sealed.*, pins.*, entries[0..entry_count]) catch return false;
    return true;
}
pub export fn readonly_global_native_actual_prove(a: *const std.mem.Allocator, trace: *const Original.Trace, pin: *const Source.Pin, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, entry_count: usize, out: *Source.Proof) callconv(.c) bool {
    var first = Native.commit(a.*, trace, pin.*) catch return false;
    defer first.deinit(a.*);
    out.* = Native.prove(a.*, &first, trace, pin.*, authority, sealed.*, pins.*, entries[0..entry_count]) catch return false;
    return true;
}
pub export fn readonly_global_native_actual_replay(a: *const std.mem.Allocator, pin: *const Source.Pin, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, entry_count: usize, events: [*]const @import("../air/block/memory_transition.zig").Transition, event_count: usize, out: *Source.Trace) callconv(.c) bool {
    out.* = Source.Trace.init(a.*, pin.*, authority, sealed.*, pins.*, entries[0..entry_count], events[0..event_count]) catch return false;
    return true;
}
test "readonly global provider: actual native provider range capture and fresh bodies retained" {
    try std.testing.expect(@intFromPtr(&readonly_global_provider_actual_pair) != 0);
    try std.testing.expect(@intFromPtr(&readonly_global_provider_actual_prove) != 0);
    try std.testing.expect(@intFromPtr(&readonly_global_native_actual_capture) != 0);
    try std.testing.expect(@intFromPtr(&readonly_global_native_actual_prove) != 0);
    try std.testing.expect(@intFromPtr(&readonly_global_native_actual_replay) != 0);
}
