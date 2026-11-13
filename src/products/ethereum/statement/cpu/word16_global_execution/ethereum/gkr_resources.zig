//! Explicit operational admissions, receiver-selected profiles and setup policy.
const std = @import("std");
const core = @import("stwo_core");
const CaptureOptions = @import("capture_options.zig").Options;
const Worker = @import("stwo_riscv_cpu_integration").rv64_gkr_worker_protocol;
const Schedule = @import("stwo_riscv_cpu_integration").rv64_execution.services.schedule;
const ReceiverBudget = @import("receiver_budget.zig");
const FixedSet = @import("stwo_riscv_cpu_integration").rv64_gkr_fixed_authority_set.Set;
const Candidate = @import("stwo_riscv_cpu_integration").rv64_om31_security_candidate;
const SetupCache = @import("setup_cache.zig");

pub const SETUP_CACHE_ENV = "STWO_ZIG_RV64_SETUP_CACHE";
/// A/B switch for the identity-only CPU source (default on).
pub const IDENTITY_ONLY_ENV = "STWO_ZIG_RV64_SETUP_IDENTITY_ONLY_CPU";
pub fn requireIndependentReceiverSetup(persisted_selected: bool) !void {
    if (persisted_selected) return error.PersistedSetupCacheForbiddenForReceiver;
}
/// M4 resident: the session's SetupCache components are resident and frozen for
/// the session's life, so their fixed-authority bindings are validated once per
/// service and reused (pointer provenance, as for the key-owner catalogue). A
/// failure (for example the fixed cache's byte budget) clears the catalogue and
/// retries once from scratch: the result is the same pure function either way.
pub fn residentSetupFixedSet(a: std.mem.Allocator, owner: anytype, keys: anytype, pcs: anytype, catalogue: *@import("stwo_riscv_cpu_integration").rv64_gkr_fixed_authority_set.ValidatedCatalogue) !FixedSet {
    return FixedSet.initWithValidatedCatalogue(a, owner, keys.cpus, keys.truths, pcs, catalogue) catch {
        catalogue.clear();
        return FixedSet.initWithValidatedCatalogue(a, owner, keys.cpus, keys.truths, pcs, catalogue);
    };
}

pub fn setupCacheOptions(a: std.mem.Allocator, mode: SetupCache.Mode, fixed_setup_bytes: usize) !struct { options: SetupCache.Options, owned: ?[]u8 } {
    const dir = std.process.getEnvVarOwned(a, SETUP_CACHE_ENV) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    errdefer if (dir) |d| a.free(d);
    const identity_only = blk: {
        const v = std.process.getEnvVarOwned(a, IDENTITY_ONLY_ENV) catch break :blk true;
        defer a.free(v);
        break :blk !std.mem.eql(u8, v, "0");
    };
    const threads = blk: {
        const v = std.process.getEnvVarOwned(a, "STWO_ZIG_RV64_SETUP_BUILD_THREADS") catch break :blk @as(usize, 8);
        defer a.free(v);
        break :blk std.fmt.parseUnsigned(usize, v, 10) catch return error.InvalidSetupBuildThreads;
    };
    const directory: ?[]const u8 = if (dir) |d| (if (d.len == 0) null else d) else null;
    return .{ .options = .{ .mode = mode, .directory = directory, .fixed_setup_bytes = fixed_setup_bytes, .identity_only_cpu = identity_only, .max_build_threads = threads }, .owned = dir };
}

pub const CANDIDATE_PROFILE = "experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering";
pub const CONJECTURED_PROFILE = "experimental-om31-local-gkr-conjectured128-b2-q108-p20-fold4-engineering";
/// Report label of a receiver-selected candidate profile (historical label for proven).
pub fn candidateLabel(profile: Candidate.Profile) []const u8 {
    return switch (profile) {
        .proven_beta2_q256_p0_fold4 => CANDIDATE_PROFILE,
        .conjectured128_b2_q108_p20_fold4 => CONJECTURED_PROFILE,
        .d2_native_b4_q54_p20_fold4 => "experimental-om31-local-gkr-d2-b4-q54-p20-fold4-engineering",
    };
}
/// The receiver's/producer's OWN policy: `--security-profile NAME` before the
/// mode, candidate modes only; default Candidate.DEFAULT_PROFILE. Proof bytes
/// and bundle metadata never select it.
pub const ProfileSelection = struct { profile: Candidate.Profile, explicit: bool, args: []const [:0]u8 };
pub fn selectProfile(all: []const [:0]u8) !ProfileSelection {
    if (all.len >= 3 and std.mem.eql(u8, all[1], "--security-profile"))
        return .{ .profile = try Candidate.Profile.parse(all[2]), .explicit = true, .args = all[2..] };
    return .{ .profile = Candidate.DEFAULT_PROFILE, .explicit = false, .args = all };
}
pub const PROFILE = "experimental-om31-local-gkr-q70-p26-fold4";
/// Operational admission only. These limits never enter statement authority.
/// The coordinator's accounting is not a complete bound on process RSS.
pub const Resources = struct {
    gkr_bytes: usize,
    global_bytes: usize,
    retained_frontend_bytes: usize,
    disk_bytes: usize,
    /// Explicit operational choice: small inventories may retain MAIN in RAM.
    park_main: bool = true,
    /// Operational cache only; never changes live proof ownership or protocol.
    recycler_cache_bytes: usize = ReceiverBudget.RECYCLER_CACHE_BYTES,
    /// Producer geometry experiment. The default preserves the admitted roster.
    keccak_max_log: u32 = 18,
    one_truth_per_family: bool = false,
    coalesce_truth_families: bool = false,
    checkpoint_above_gkr_bytes: usize = 0,
    defer_local_binding: bool = false,
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    pub fn validate(self: Resources) !void {
        if (self.gkr_bytes == 0 or self.global_bytes == 0 or self.retained_frontend_bytes == 0 or (self.park_main and self.disk_bytes == 0) or self.schedule.memory_cap_bytes == 0) return error.MissingWideResourceAdmission;
        try self.capture_options.validate();
        try self.schedule.validate();
        if (self.recycler_cache_bytes > ReceiverBudget.RECYCLER_CACHE_BYTES) return error.UnsupportedRecyclerCacheLimit;
        if (self.keccak_max_log < 16 or self.keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
        try Schedule.validateOrder(self.stage2_order, self.stage2_order.len);
    }
    pub fn jsonStringify(self: Resources, writer: anytype) !void {
        try writer.beginObject();
        inline for (.{ "gkr_bytes", "global_bytes", "retained_frontend_bytes", "disk_bytes", "park_main", "schedule" }) |name| {
            try writer.objectField(name);
            try writer.write(@field(self, name));
        }
        // Preserve historical default report schema; only explicit opt-in emits order.
        if (self.stage2_order.len != 0) {
            try writer.objectField("stage2_order");
            try writer.write(self.stage2_order);
        }
        if (!self.capture_options.isDefault()) {
            try writer.objectField("capture_options");
            try writer.write(self.capture_options);
        }
        if (self.recycler_cache_bytes != ReceiverBudget.RECYCLER_CACHE_BYTES) {
            try writer.objectField("recycler_cache_bytes");
            try writer.write(self.recycler_cache_bytes);
        }
        if (self.coalesce_truth_families) {
            try writer.objectField("coalesce_truth_families");
            try writer.write(true);
        }
        if (self.one_truth_per_family) {
            try writer.objectField("one_truth_per_family");
            try writer.write(true);
        }
        if (self.keccak_max_log != 18) {
            try writer.objectField("keccak_max_log");
            try writer.write(self.keccak_max_log);
        }
        if (self.checkpoint_above_gkr_bytes != 0) {
            try writer.objectField("checkpoint_above_gkr_bytes");
            try writer.write(self.checkpoint_above_gkr_bytes);
        }
        if (self.defer_local_binding) {
            try writer.objectField("defer_local_binding");
            try writer.write(true);
        }
        try writer.endObject();
    }
};
/// Separate operational schema keeps historical control resource/report bytes
/// unchanged. No field in either schema selects a security construction.
pub const CandidateResources = struct {
    /// Geometry-only producer option. Every emitted policy/shape remains bound
    /// by the existing statement and independently rebuilt by the receiver.
    keccak_uniform_throughput: bool = false,
    gkr_bytes: usize,
    global_bytes: usize,
    retained_frontend_bytes: usize,
    disk_bytes: usize,
    fixed_setup_bytes: usize,
    park_main: bool = true,
    recycler_cache_bytes: usize = ReceiverBudget.RECYCLER_CACHE_BYTES,
    /// Producer geometry experiment. The default preserves the admitted roster.
    keccak_max_log: u32 = 18,
    one_truth_per_family: bool = false,
    coalesce_truth_families: bool = false,
    checkpoint_above_gkr_bytes: usize = 0,
    defer_local_binding: bool = false,
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    pub fn operational(self: CandidateResources) Resources {
        return .{ .gkr_bytes = self.gkr_bytes, .global_bytes = self.global_bytes, .retained_frontend_bytes = self.retained_frontend_bytes, .disk_bytes = self.disk_bytes, .park_main = self.park_main, .recycler_cache_bytes = self.recycler_cache_bytes, .keccak_max_log = self.keccak_max_log, .one_truth_per_family = self.one_truth_per_family, .coalesce_truth_families = self.coalesce_truth_families, .checkpoint_above_gkr_bytes = self.checkpoint_above_gkr_bytes, .defer_local_binding = self.defer_local_binding, .capture_options = self.capture_options, .stage2_order = self.stage2_order, .schedule = self.schedule };
    }
    pub fn validate(self: CandidateResources) !void {
        if (self.fixed_setup_bytes == 0) return error.MissingCandidateFixedSetupAdmission;
        try self.operational().validate();
    }
};
pub fn config() !Worker.PcsConfig {
    var value = Worker.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.ForField(Worker.O).FriConfig.init(0, 1, 70) };
    value.fri_config.fold_step = 4;
    return value;
}

pub fn residentWorkerLimit(park_main: bool, count: usize, keccak_max_log: u32) !usize {
    if (park_main) return error.ResidentPipelineCannotParkMain;
    if (keccak_max_log < 16 or keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    if (count == 0 or count > Candidate.MAX_PROOFS or count > @import("stwo_riscv_cpu_integration").rv64_gkr_manifest.MAX_WORKERS) return error.BoundedWideCoordinatorLimit;
    return count;
}

pub fn producerWorkerLimit(park_main: bool, count: usize, keccak_max_log: u32) !usize {
    if (keccak_max_log < 16 or keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    const cap: usize = if (park_main) @intCast(Candidate.MAX_PROOFS) else 8;
    if (count == 0 or count > cap or count > @import("stwo_riscv_cpu_integration").rv64_gkr_manifest.MAX_WORKERS) return error.BoundedWideCoordinatorLimit;
    return if (park_main) @max(@as(usize, 32), count) else 8;
}
