//! Actual standalone PAGE-backed complete CPU receiver. Independent original
//! Metadata and PAGE policy pins precede proposal decoding. Native/caller/ROM/
//! lookup and recursive forest close in the same original global fresh loop.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Detached = @import("block_v5_cpu_detached_receive_v1.zig").ForCapacity(true);
const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(true);
const Policy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Durable = @import("block_v5_memory_source_page_durable_loader_v1.zig");
const Join = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
pub const Pins = struct { original: Detached.Pins, pages: Policy.Pin };
pub const Limits = struct { original: Detached.Limits, pages: Durable.Limits, join: Join.Limits = .{}, max_heap_bytes: usize = 40 << 30 };
pub fn verify(a: std.mem.Allocator, dir: std.fs.Dir, public_input: []const u8, pins: Pins, limits: Limits) !Global.VerifiedGlobals {
    if (limits.max_heap_bytes == 0 or !std.meta.eql(limits.original.store, limits.pages.store) or !std.meta.eql(limits.join.pages, limits.pages.policy.pages)) return error.InvalidDetachedSourcePageLimits;
    try limits.original.metadata.validate();
    try limits.original.store.validate();
    try limits.pages.policy.validate();
    const budget = try Budget.createRetainingParent(a, limits.max_heap_bytes);
    defer budget.destroy();
    const bounded = budget.allocator();
    const metadata = try Metadata.read(bounded, dir, pins.original.receiver_policy_sha256, pins.original.identity, limits.original.metadata);
    defer metadata.deinit();
    const globals = metadata.globals();
    const loader = try Durable.Loader.init(bounded, dir, pins.pages, globals, pins.original.bundle_manifest_sha256, limits.pages);
    defer loader.deinit();
    const owner = try loader.createJoin(bounded, globals, limits.join);
    defer owner.deinit();
    var proofs = loader.withProofAllocator(bounded);
    var complete = try Global.ForBackend(Cpu).verifyCompleteDetachedWithSourcePages(bounded, globals, .{
        .public_input = public_input,
        // Compile-time PAGE selection never opens/reads these legacy host
        // source files; authentic source authority comes from original PAGE
        // proofs and the fresh sorted lane/range join inside this exact call.
        .endpoint_sources = undefined,
        .memory = proofs.packedMemoryLoader(),
        .execution_memory = proofs.executionMemoryLoader(),
        .tables = proofs.tableLoader(),
        .programs = proofs.programLoader(),
    }, .{ .owner = owner, .loader = loader.pageLoader() }, metadata.recursion(), .{
        .dir = dir,
        .manifest_sha256 = pins.original.forest_manifest_sha256,
        .limits = limits.original.forest,
    });
    defer complete.deinit();
    try loader.requireConsumed();
    return complete.globals;
}
