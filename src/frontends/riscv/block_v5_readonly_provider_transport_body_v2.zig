//! Retained actual production bodies ONLY. Never invoke these exports in tests.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Artifact = @import("prover/block_v5_readonly_provider_artifact_v2.zig");
const Files = @import("prover/block_v5_readonly_provider_files_v2.zig");
const Provider = @import("prover/block_v5_readonly_input_provider_proof_v2.zig");
const Table = @import("prover/block_v5_readonly_input_provider_v2.zig");
const Range = @import("prover/block_v5_range16_proof_v1.zig");
const RangeTable = @import("prover/block_v5_range16_v1.zig");
const Roster = @import("prover/block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("prover/block_v5_source_seal_v1.zig");
const Original = Provider.ForBackend(Cpu);
pub export fn stwo_readonly_provider_transport_publish_pair(a: *const std.mem.Allocator, dir: *const std.fs.Dir, expected: *const Files.Expected, authority: *const Roster.Authority, sealed: *const Seal.Sealed, provider: *Provider.Proof, range: *Range.Proof, ordinals: [*]const u32, count: usize, limits: *const Files.Limits, outcome: *Files.Publication) void {
    outcome.* = Files.publishPair(a.*, dir.*, expected.*, authority, sealed.*, provider, range, ordinals[0..count], limits.*);
}
pub export fn stwo_readonly_provider_transport_load(a: *const std.mem.Allocator, dir: *const std.fs.Dir, expected: *const Files.Expected, authority: *const Roster.Authority, sealed: *const Seal.Sealed, files: *const Files.FileSet, limits: *const Files.Limits, result: *Files.Loaded) void {
    result.* = Files.load(a.*, dir.*, expected.*, authority, sealed.*, files.*, limits.*) catch return;
}
pub export fn stwo_readonly_provider_transport_verify_pair(received: *Files.Loaded, pins: *const Seal.Pins, entries: [*]const Seal.Entry, count: usize, limits: *const Table.Limits) void {
    _ = received.verifyPair(Cpu, pins.*, entries[0..count], limits.*) catch return;
}
pub export fn stwo_readonly_provider_transport_decode(a: *const std.mem.Allocator, bytes: [*]const u8, count: usize, expected: *const Artifact.Expected, limits: *const Artifact.Limits) void {
    var received = Artifact.decode(a.*, bytes[0..count], expected.*, limits.*) catch return;
    received.deinit(a.*);
    var range = Artifact.decodeRange(a.*, bytes[0..count], expected.*, limits.*) catch return;
    range.deinit(a.*);
}
pub export fn stwo_readonly_provider_transport_producer(a: *const std.mem.Allocator, first: *Original.First, columns: *const Table.Columns, expected: *const Artifact.Expected, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, count: usize) void {
    var proof = Original.prove(a.*, first, columns, expected.provider, authority, sealed.*, pins.*, entries[0..count]) catch return;
    proof.deinit(a.*);
}
pub export fn stwo_readonly_provider_transport_range_producer(a: *const std.mem.Allocator, first: *Range.ForAdmission(Cpu).FirstRound, counter: *const RangeTable.Counter, expected: *const Artifact.Expected, authority: *const Roster.Authority, sealed: *const Seal.Sealed, pins: *const Seal.Pins, entries: [*]const Seal.Entry, count: usize) void {
    var proof = Range.ForAdmission(Cpu).proveWithAdmission(a.*, first, counter, expected.range.shard, expected.range.plan_digest, sealed.*, pins.*, entries[0..count], Provider.RangeAdmission{ .authority = authority, .pin = expected.range }) catch return;
    proof.deinit(a.*);
}
pub export fn stwo_readonly_provider_transport_cleanup(outcome: *Files.Publication) void {
    outcome.deinit() catch return; // on error, custody remains in outcome
}
pub fn retain() void {}
