//! Requester-only durable fold with its genuine fresh root retained for the
//! original PUBLIC21 verifier rows. This does not close source or memory buses.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(true);
const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
const NativeForest = @import("block_v5_capacity_open_forest_stage_v1.zig");
const Sources = @import("block_v5_cpu_scoped_job_sources_v1.zig");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Scoped = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Summary = @import("../recursion/block_v5_requester_summary_source_v1.zig");
const Fresh = @import("../recursion/block_v5_heterogeneous_scoped_receiver_v1.zig").Fresh;
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;

pub const Action = Fold.Action;
pub const Limits = struct {
    max_owned_bytes: usize = 8 << 30,
    sources: Sources.Limits = .{},
    fold: Fold.Limits = .{},
    pub fn validate(self: Limits) !void {
        try self.fold.validate();
        if (self.max_owned_bytes == 0 or self.sources.max_owned_bytes == 0 or
            self.sources.max_proof_bytes == 0 or self.sources.max_source_cells == 0)
            return error.CpuRequesterJobResourceLimit;
    }
};

/// Stable addresses are required by Summary.Source. Publication, Assembly,
/// native admissions and their caller catalogue remain externally owned and
/// immutable until this owner (and every Scoped.Owner borrow) is released.
/// The retained parent budget controls all nested metadata, rows and proofs.
pub const Owner = struct {
    budget: *Budget,
    sources: ?*Sources.Owner = null,
    folded: ?Fold.Result = null,
    summary: ?Summary.Source = null,
    pub const complete_block_authority = false;

    pub fn allocator(self: *const Owner) std.mem.Allocator {
        return self.budget.allocator();
    }
    pub fn scoped(self: *const Owner) !*const Scoped.Owner {
        return (self.folded orelse return error.CpuRequesterJobLifetime).owner;
    }
    pub fn source(self: *const Owner) !*const Summary.Source {
        return if (self.summary) |*value| value else error.CpuRequesterRootCaptureReleased;
    }
    pub fn rootFresh(self: *const Owner) !*const Fresh {
        const folded = if (self.folded) |*value| value else return error.CpuRequesterJobLifetime;
        return folded.rootFresh();
    }
    pub fn pins(self: *const Owner) ![]const Fold.Pin {
        return (self.folded orelse return error.CpuRequesterJobLifetime).files;
    }
    /// Only after every requester-root verifier row has been materialized.
    /// No previously borrowed Source/Fresh pointer may be used afterward.
    /// Independently borrowed Scoped.Owner receiver policy remains alive.
    pub fn releaseRootCapture(self: *Owner) void {
        if (self.summary) |*value| value.deinit();
        self.summary = null;
        if (self.folded) |*value| value.releaseRootCapture();
    }
    /// Exact typed lifecycle callback for FINAL job's after_preparation seam.
    /// It returns no key, claim, acceptance flag or verifier authority.
    pub fn releaseRootCaptureCallback(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.releaseRootCapture();
    }
    fn releaseOwners(self: *Owner) void {
        self.releaseRootCapture();
        if (self.folded) |*value| value.deinit();
        self.folded = null;
        if (self.sources) |value| value.deinit();
        self.sources = null;
    }
    pub fn deinit(self: *Owner) void {
        self.releaseOwners();
        const budget = self.budget;
        budget.allocator().destroy(self);
        budget.destroy();
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Reconstruction derives every parent key from actual fresh children
        /// and original rows. Action pins select bounded transport only.
        pub fn build(backing: std.mem.Allocator, dir: std.fs.Dir, assembly: *const Assembly.Assembly, publication: *Publication.Session, natives: []const NativeForest.LeafFile, profile: Profile, limits: Limits, action: Action) !*Owner {
            try limits.validate();
            if (profile != publication.profile) return error.UntrustedCpuRequesterJobSecurity;
            const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            const self = try a.create(Owner);
            errdefer a.destroy(self);
            self.* = .{ .budget = budget };
            errdefer self.releaseOwners();
            self.sources = try Sources.create(a, assembly, publication, natives, limits.sources);
            self.folded = try Fold.ForRecipe(.requesters).ForBackend(Backend).run(a, dir, self.sources.?, profile, limits.fold, action);
            const folded = if (self.folded) |*value| value else unreachable;
            if (folded.owner.scoped.recipe != .requesters or folded.owner.cohorts.recipe != .requesters)
                return error.NotRequesterSummaryRoot;
            self.summary = try Summary.Source.init(folded.owner, try folded.rootFresh());
            try self.summary.?.validate();
            return self;
        }
    };
}
