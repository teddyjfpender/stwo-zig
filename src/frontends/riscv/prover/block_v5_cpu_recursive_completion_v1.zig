//! One selected CPU completion pipeline over genuine original durable files.
//! The final root compresses requester and independent PAGE/RAM roots; this
//! coordinator does not confer CompleteBlock authority or reusable setup.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Requester = @import("block_v5_cpu_requester_job_v1.zig");
const Page = @import("block_v5_cpu_owned_memory_source_page_forest_v1.zig");
const Memory = @import("block_v5_cpu_owned_ram_range_forest_v1.zig");
const Final = @import("block_v5_cpu_final_job_v1.zig");
const Bundle = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(true);
const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
const Native = @import("block_v5_capacity_open_forest_stage_v1.zig");
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
const PagePolicy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Windows = @import("block_v5_register_windows_v1.zig");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Rollback = @import("block_v5_cpu_recursive_completion_rollback_v1.zig");
pub const Options = struct {
    max_owned_bytes: usize = 32 << 30,
    requester: Requester.Limits = .{},
    page: @import("block_v5_memory_source_page_forest_policy_owner_v1.zig").Limits = .{},
    memory: @import("block_v5_ram_range_forest_policy_owner_v1.zig").Limits = .{},
    final: Final.Limits = .{},
    pub fn validate(self: Options) !void {
        if (self.max_owned_bytes == 0) return error.CpuRecursiveCompletionResourceLimit;
        try self.requester.validate();
        try self.page.validate();
        try self.memory.validate();
        try self.final.validate();
        // Borrowed authenticated memory setup is reused by the join and FINAL22.
        // Reject incompatible geometry before collecting or proving any family.
        if (self.page.transcript_capacity != self.memory.transcript_capacity or
            self.memory.transcript_capacity != self.final.transcript_capacity) return error.UntrustedCpuRecursiveCompletionGeometry;
    }
    /// Original lane limits are reconstructed from collection policy, before
    /// guest/witness/proof work. Default phase policies need not match a caller's
    /// independently selected larger row log or provider census limits.
    pub fn requireOriginalMemory(self: Options, lanes: @import("block_v5_ram_lanes_stage_v1.zig").Limits) !void {
        if (!std.meta.eql(self.memory.catalogue.ram.proof, lanes.proof) or !std.meta.eql(self.memory.plan.lane, lanes.plan)) return error.UntrustedCpuRecursiveCompletionMemory;
    }
    pub fn withOriginalMemory(self: Options, lanes: @import("block_v5_ram_lanes_stage_v1.zig").Limits) Options {
        var result = self;
        result.memory.catalogue.ram.proof = lanes.proof;
        result.memory.plan.lane = lanes.plan;
        return result;
    }
    pub fn requireDependencies(self: Options, families: bool, pages: bool, old_scoped: bool) !void {
        try self.validate();
        if (!families) return error.RecursiveCompletionRequiresRecursiveFamilies;
        if (!pages) return error.RecursiveCompletionRequiresSourcePages;
        if (old_scoped) return error.ConflictingCpuRecursiveCompletion;
    }
};
pub const Selection = struct {
    assembly: *const Assembly.Assembly,
    publication: *Publication.Session,
    natives: []const Native.LeafFile,
    independently_expected_page: PagePolicy.Pin,
    original_policies: []const Bundle.Policy,
    original_files: []const Bundle.FilePin,
    original_limits: Bundle.Limits,
    windows: Windows.Plan,
    profile: Profile,
    /// Accounting only. Validate aggregate report arithmetic while this
    /// completion still owns its failure rollback, before returning success.
    prior_totals: ProofTotals = .{},
};
pub const ProofTotals = struct {
    bytes: u64 = 0,
    files: usize = 0,
    pub fn add(self: ProofTotals, other: ProofTotals) !ProofTotals {
        return .{ .bytes = try std.math.add(u64, self.bytes, other.bytes), .files = try std.math.add(usize, self.files, other.files) };
    }
};
pub const Report = struct {
    requester_parents: usize,
    page_leaves: usize,
    page_parents: usize,
    memory_leaves: usize,
    memory_parents: usize,
    final_roots: usize = 2,
    proof_files: usize,
    proof_bytes: u64,
    combined_totals: ProofTotals,
    final_manifest: @import("block_v5_cpu_final_job_manifest_v1.zig").FilePin,
    /// Each stage includes expected setup, actual proving, file staging and
    /// fresh verification. These are deliberately not isolated STARK timers.
    stage_ns: struct { requester: u64, page: u64, memory: u64, final: u64 },
    peak_owned_bytes: usize,
    pub const complete_block_authority = false;
    pub const reusable_setup = false;
};
const Counter = struct {
    next: u32 = 0,
    fn put(raw: *anyopaque, index: u32, pin: Fold.Pin, spec: *const @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig").NodeSpec) !void {
        const self: *Counter = @ptrCast(@alignCast(raw));
        if (index != self.next or pin.byte_len == 0 or !std.meta.eql(try spec.key.identity(), spec.expected_id)) return error.InvalidCpuRequesterPublicationOrder;
        self.next = try std.math.add(u32, self.next, 1);
    }
};
pub fn publish(backing: std.mem.Allocator, dir: std.fs.Dir, selection: Selection, options: Options) !Report {
    try options.validate();
    try selection.windows.validate();
    if (selection.profile != selection.publication.profile) return error.UntrustedCpuRecursiveCompletionSecurity;
    const lane = switch (selection.assembly.global_pins.memory.memory) {
        .lanes => |pins| pins,
        .word => return error.CpuRecursiveCompletionRequiresLaneMemory,
    };
    if (!std.meta.eql(selection.profile.config(), lane.seal.config) or
        !std.meta.eql(options.memory.catalogue.ram.proof, lane.limits.proof) or
        !std.meta.eql(options.memory.plan.lane, lane.limits.plan)) return error.UntrustedCpuRecursiveCompletionMemory;
    const budget = try Budget.createRetainingParent(backing, options.max_owned_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var timer = try std.time.Timer.start();
    var counter = Counter{};
    var published = Rollback.Inventory{};
    errdefer {
        published.requester_nodes = counter.next;
        published.rollback(dir);
    }
    const requester = try Requester.ForBackend(Cpu).build(a, dir, selection.assembly, selection.publication, selection.natives, selection.profile, options.requester, .{ .publish = .{ .context = &counter, .put_open = Counter.put } });
    defer requester.deinit();
    const requester_pins = try requester.pins();
    if (counter.next != requester_pins.len) return error.IncompleteCpuRequesterPublication;
    const requester_ns = timer.lap();
    var page = try Page.publish(a, dir, .{ .independently_expected = selection.independently_expected_page, .globals = selection.assembly.global_pins, .profile = selection.profile, .limits = options.page });
    var owns_page = true;
    defer if (owns_page) page.deinit();
    const page_leaves = page.owner.leaf_files.len;
    const page_parents = page.owner.node_files.len;
    published.page_leaves = page_leaves;
    published.page_nodes = page_parents;
    var proof_bytes: u64 = 0;
    for (requester_pins) |pin| proof_bytes = try std.math.add(u64, proof_bytes, pin.byte_len);
    for (page.owner.leaf_files) |pin| proof_bytes = try std.math.add(u64, proof_bytes, pin.byte_len);
    for (page.owner.node_files) |pin| proof_bytes = try std.math.add(u64, proof_bytes, pin.byte_len);
    const page_ns = timer.lap();
    var originals = try Bundle.Store.initReader(a, dir, selection.original_policies, selection.original_files, selection.profile.config(), selection.original_limits);
    defer originals.deinit();
    var memory = try Memory.publish(a, dir, .{ .page = &page, .originals = &originals, .memory = lane, .sealed = selection.assembly.sealed, .profile = selection.profile, .limits = options.memory });
    owns_page = false; // Existing typed builder transfers PAGE only on success.
    var owns_memory = true;
    defer if (owns_memory) memory.deinit();
    const memory_leaves = memory.owner.ram.len + memory.owner.range.len;
    const memory_parents = memory.owner.specs.len;
    published.memory_ram = memory.owner.ram.len;
    published.memory_range = memory.owner.range.len;
    published.memory_nodes = memory_parents;
    published.memory_join = true;
    published.memory_manifest = true;
    // Includes the one independent PAGE+RAM memory-root join.
    for (memory.owner.records) |record| proof_bytes = try std.math.add(u64, proof_bytes, record.file.byte_len);
    const memory_ns = timer.lap();
    var final = try Final.publish(a, dir, .{ .requester = .{ .source = try requester.source(), .after_preparation = .{ .context = requester, .call = Requester.Owner.releaseRootCaptureCallback } }, .memory = &memory, .windows = selection.windows, .profile = selection.profile, .limits = options.final });
    owns_memory = false; // FINAL success alone transfers the memory owner.
    defer final.deinit();
    published.public_root = true;
    published.final_root = true;
    published.final_manifest = true;
    for (final.owner.proposal.records) |record| proof_bytes = try std.math.add(u64, proof_bytes, record.file.byte_len);
    var proof_files = try std.math.add(usize, requester_pins.len, page_leaves);
    proof_files = try std.math.add(usize, proof_files, page_parents);
    proof_files = try std.math.add(usize, proof_files, memory_leaves);
    proof_files = try std.math.add(usize, proof_files, memory_parents);
    proof_files = try std.math.add(usize, proof_files, 3); // memory join + PUBLIC21 + FINAL22
    const combined_totals = try selection.prior_totals.add(.{ .bytes = proof_bytes, .files = proof_files });
    return .{ .requester_parents = requester_pins.len, .page_leaves = page_leaves, .page_parents = page_parents, .memory_leaves = memory_leaves, .memory_parents = memory_parents, .proof_files = proof_files, .proof_bytes = proof_bytes, .combined_totals = combined_totals, .final_manifest = final.owner.manifest_pin.?, .stage_ns = .{ .requester = requester_ns, .page = page_ns, .memory = memory_ns, .final = timer.lap() }, .peak_owned_bytes = budget.snapshot().peak_live_bytes };
}
