//! Typed ROM, lookup, RAM and range first-round checkpoint adapters.
//! Each adapter derives geometry and identity from its independently admitted
//! protocol inputs. Loaded PCS is never proof verification authority.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Store = @import("block_v6_cpu_scheme_store_v1.zig");
const Rom = @import("block_v5_program_table_proof_v1.zig");
const RomPlan = @import("block_v5_program_table_v1.zig").Plan;
const Lookup = @import("block_v5_native_lookup_proof_v1.zig");
const Assembly = @import("block_v5_native_lookup_assembly_v1.zig");
const Counters = @import("../air/lookups/tables/counter.zig").Set;
const Ram = @import("block_v5_ram_lanes_proof_v1.zig");
const RamSpec = @import("block_v5_ram_lanes_component_v1.zig").Spec;
const Range = @import("block_v5_range16_v1.zig");
const RangeProof = @import("block_v5_range16_proof_v1.zig");
const Hash = [32]u8;
pub const Limits = Store.Limits;
pub const Pin = Store.Pin;
pub fn writeProgram(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, plan: RomPlan, first: *const Rom.ForBackend(Cpu).FirstRound, limits: Limits) !Pin {
    const digest = try plan.digest();
    if (!first.owns_scheme or !std.meta.eql(first.plan_digest, digest)) return error.InvalidProviderCheckpointScope;
    const fixed = [_]u32{plan.log_size} ** Rom.Air.PREPROCESSED_COLUMN_COUNT;
    return Store.write(a, dir, name, .{ .identity = digest, .config = first.scheme.config, .roots = &first.roots, .logs = &.{ &fixed, &.{} } }, &first.scheme, limits);
}
pub fn loadProgram(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, plan: RomPlan, roots: [2]Hash, config: core.pcs.PcsConfig, pin: Pin, limits: Limits) !Rom.ForBackend(Cpu).FirstRound {
    const digest = try plan.digest();
    const fixed = [_]u32{plan.log_size} ** Rom.Air.PREPROCESSED_COLUMN_COUNT;
    const scheme = try Store.load(a, dir, name, .{ .identity = digest, .config = config, .roots = &roots, .logs = &.{ &fixed, &.{} } }, pin, limits);
    return .{ .scheme = scheme, .roots = roots, .plan_digest = digest };
}
fn lookupIdentity(plan: Lookup.Plan, counters: *const Counters) !Hash {
    try Lookup.validateSourceCounters(counters, plan);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x4236504c, 1 });
    channel.mixRoot(try plan.identity());
    for (Lookup.snapshots(counters)) |snapshot| channel.mixRoot(snapshot);
    return channel.digestBytes();
}
pub fn writeRam(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, first: *const Ram.ForBackend(Cpu).FirstRound, limits: Limits) !Pin {
    const pin = first.pin;
    if (!first.pcs_first.owns_scheme or !std.meta.eql(first.pcs_first.roots, pin.roots) or !std.meta.eql(first.pcs_first.scheme.config, pin.config)) return error.InvalidProviderCheckpointScope;
    const fixed = [_]u32{pin.claim.row_log} ** RamSpec.FIXED_COUNT;
    const main = [_]u32{pin.claim.row_log} ** RamSpec.MAIN_COUNT;
    return Store.write(a, dir, name, .{ .identity = try pin.identity(), .config = pin.config, .roots = &pin.roots, .logs = &.{ &fixed, &main }, .retain_coefficients = first.pcs_first.scheme.trees.items[0].coefficients != null }, &first.pcs_first.scheme, limits);
}
pub fn loadRam(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, expected: Ram.Pin, pin: Pin, limits: Limits) !Ram.ForBackend(Cpu).FirstRound {
    const fixed = [_]u32{expected.claim.row_log} ** RamSpec.FIXED_COUNT;
    const main = [_]u32{expected.claim.row_log} ** RamSpec.MAIN_COUNT;
    var scheme = try Store.load(a, dir, name, .{ .identity = try expected.identity(), .config = expected.config, .roots = &expected.roots, .logs = &.{ &fixed, &main }, .retain_coefficients = pin.coefficient_bytes != 0 }, pin, limits);
    // The existing warm API admits a retaining proof owner. Original trees
    // remain materialized; subsequent interaction/composition work may retain
    // coefficients without rebuilding these first-round commitments.
    scheme.setCoefficientRetentionPolicy(.always);
    return .{ .pcs_first = .{ .scheme = scheme, .roots = expected.roots }, .pin = expected };
}
fn rangeIdentity(shard: Range.Shard, plan_digest: Hash, counter: *const Range.Counter) !Hash {
    if (shard.instance_count == 0 or shard.request_count > Range.MAX_REQUESTS or counter.total != shard.request_count or counter.values.len != Range.TABLE_SIZE) return error.InvalidProviderCheckpointScope;
    _ = try std.math.add(u32, shard.first_instance, shard.instance_count);
    var total: u64 = 0;
    for (counter.values) |value| total = try std.math.add(u64, total, value);
    if (total != counter.total) return error.InvalidProviderCheckpointScope;
    var channel = RangeProof.firstChannel(shard, plan_digest);
    channel.mixRoot(counter.digest());
    return channel.digestBytes();
}
pub fn writeRange(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, shard: Range.Shard, plan_digest: Hash, counter: *const Range.Counter, first: *const RangeProof.ForBackend(Cpu).FirstRound, limits: Limits) !Pin {
    if (!first.pcs_first.owns_scheme or !std.meta.eql(first.counter_digest, counter.digest())) return error.InvalidProviderCheckpointScope;
    const logs = [_]u32{Range.TABLE_LOG};
    return Store.write(a, dir, name, .{ .identity = try rangeIdentity(shard, plan_digest, counter), .config = first.pcs_first.scheme.config, .roots = &first.pcs_first.roots, .logs = &.{ &logs, &logs }, .retain_coefficients = first.pcs_first.scheme.trees.items[0].coefficients != null }, &first.pcs_first.scheme, limits);
}
pub fn loadRange(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, shard: Range.Shard, plan_digest: Hash, counter: *const Range.Counter, roots: [2]Hash, config: core.pcs.PcsConfig, pin: Pin, limits: Limits) !RangeProof.ForBackend(Cpu).FirstRound {
    const logs = [_]u32{Range.TABLE_LOG};
    var scheme = try Store.load(a, dir, name, .{ .identity = try rangeIdentity(shard, plan_digest, counter), .config = config, .roots = &roots, .logs = &.{ &logs, &logs }, .retain_coefficients = pin.coefficient_bytes != 0 }, pin, limits);
    scheme.setCoefficientRetentionPolicy(.always);
    return .{ .pcs_first = .{ .scheme = scheme, .roots = roots }, .counter_digest = counter.digest() };
}

fn lookupFixedIdentity() Hash {
    var hash: Hash = undefined;
    std.crypto.hash.Blake3.hash("stwo-zig/block-v6/lookup-fixed-checkpoint/v1\x00", &hash, .{});
    return hash;
}
pub fn writeLookupFixed(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, basis: *const Lookup.ForBackend(Cpu).FixedBasis, limits: Limits) !Pin {
    const fixed = try Assembly.logs(a, .fixed);
    defer a.free(fixed);
    return Store.write(a, dir, name, .{ .identity = lookupFixedIdentity(), .config = basis.scheme.config, .roots = &.{basis.root}, .logs = &.{fixed} }, &basis.scheme, limits);
}
pub fn loadLookupFixed(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, root: Hash, config: core.pcs.PcsConfig, pin: Pin, limits: Limits) !Lookup.ForBackend(Cpu).FixedBasis {
    const fixed = try Assembly.logs(a, .fixed);
    defer a.free(fixed);
    return .{ .root = root, .scheme = try Store.load(a, dir, name, .{ .identity = lookupFixedIdentity(), .config = config, .roots = &.{root}, .logs = &.{fixed} }, pin, limits) };
}
fn lookupMainIdentity(plan: Lookup.Plan, counters: *const Counters, fixed_root: Hash) !Hash {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixRoot(try lookupIdentity(plan, counters));
    channel.mixRoot(fixed_root);
    return channel.digestBytes();
}
pub fn writeLookupMain(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, plan: Lookup.Plan, counters: *const Counters, first: *const Lookup.ForBackend(Cpu).FirstRound, limits: Limits) !Pin {
    if (!first.owns_scheme or first.scheme.trees.items.len != 2 or !std.meta.eql(first.plan_id, try plan.identity()) or !std.meta.eql(first.counter_snapshots, Lookup.snapshots(counters))) return error.InvalidProviderCheckpointScope;
    const main = try Assembly.logs(a, .main);
    defer a.free(main);
    // Borrow-only serialization view. Never deinit this shallow descriptor;
    // first retains every allocation and the write operation cannot consume it.
    var view = first.scheme;
    view.trees.items = first.scheme.trees.items[1..2];
    view.trees.capacity = 1;
    return Store.write(a, dir, name, .{ .identity = try lookupMainIdentity(plan, counters, first.roots[0]), .config = first.scheme.config, .roots = first.roots[1..2], .logs = &.{main} }, &view, limits);
}
pub fn loadLookupMain(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, plan: Lookup.Plan, counters: *const Counters, roots: [2]Hash, basis: *Lookup.ForBackend(Cpu).FixedBasis, pin: Pin, limits: Limits) !Lookup.ForBackend(Cpu).FirstRound {
    if (!std.meta.eql(roots[0], basis.root)) return error.InvalidProviderCheckpointScope;
    const main = try Assembly.logs(a, .main);
    defer a.free(main);
    var loaded = try Store.load(a, dir, name, .{ .identity = try lookupMainIdentity(plan, counters, roots[0]), .config = basis.scheme.config, .roots = roots[1..2], .logs = &.{main} }, pin, limits);
    defer loaded.deinit(a);
    var channel = core.proof_suites.Blake3.Channel{};
    var scheme = try @import("block_v5_shared_first_round_v1.zig").copyFixed(Cpu, a, &basis.scheme, &channel);
    errdefer scheme.deinit(a);
    try scheme.appendCommittedTree(a, loaded.trees.items[0], &channel);
    loaded.trees.items.len = 0; // transferred only after append succeeds
    return .{ .scheme = scheme, .roots = roots, .plan_id = try plan.identity(), .counter_snapshots = Lookup.snapshots(counters) };
}
