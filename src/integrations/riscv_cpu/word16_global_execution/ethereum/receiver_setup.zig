//! Fresh, process-owned receiver setup. Identity-only CPU source keys avoid a
//! historical Merkle commitment which the candidate statement never binds.
//! Candidate FIXED roots still derive from the independently loaded image and
//! source coefficients. No persisted setup is selected, loaded or saved here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Image = @import("../../word16_execution/expected_image.zig");
const Materials = @import("../../word16_execution/setup.zig");
const Keys = @import("keys.zig").Owner;
const W = @import("../services/wire.zig");
const Fixed = @import("../services/gkr_local/fixed_authority.zig");
const Authority = @import("../services/gkr_local/fixed_authority_set.zig");
const Set = Authority.Set;
const Cache = @import("setup_cache.zig");
const Request = @import("../../rv64_ethereum_request.zig");

pub const IDENTITY_ONLY_ENV = "STWO_ZIG_RV64_RECEIVER_IDENTITY_ONLY_CPU";
pub fn parseIdentityOnly(value: ?[]const u8) !bool {
    const text = value orelse return false;
    if (std.mem.eql(u8, text, "0")) return false;
    if (std.mem.eql(u8, text, "1")) return true;
    return error.InvalidReceiverSourceKeyPolicy;
}
pub fn identityOnly() !bool {
    return parseIdentityOnly(std.posix.getenv(IDENTITY_ONLY_ENV));
}

/// Verification-only process state. Nothing enters it from disk except the
/// authenticated request image; the proof bundle never supplies setup data.
pub const Session = struct {
    budget: *engine.host_budget_allocator.SharedHostBudget,
    cache: Cache.Cache,
    catalogue: Authority.ValidatedCatalogue,
    native: Materials.NativeCache.Cache,
    metadata: Materials.ProgramMetadata.Cache,
    images: Image.AuthorityCache,
    fixed_bytes: usize,

    pub fn init(a: std.mem.Allocator, bytes: usize, fixed_bytes: usize, config: core.pcs.PcsConfig) !Session {
        const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, bytes);
        errdefer budget.destroy();
        const bounded = budget.allocator();
        var cache = try newCache(bounded, config, fixed_bytes);
        errdefer cache.deinit();
        var native = try Materials.NativeCache.Cache.init(bounded, 256 << 20);
        errdefer native.deinit();
        const metadata = try Materials.ProgramMetadata.Cache.init(bounded, 64 << 20);
        return .{
            .budget = budget,
            .cache = cache,
            .catalogue = .{ .allocator = bounded },
            .native = native,
            .metadata = metadata,
            .images = Image.AuthorityCache.init(bounded),
            .fixed_bytes = fixed_bytes,
        };
    }

    pub fn caches(self: *Session) Materials.ImmutableCaches {
        return .{ .native = &self.native, .program = &self.metadata };
    }

    pub fn deinit(self: *Session) void {
        self.catalogue.deinit();
        self.cache.deinit();
        self.native.deinit();
        self.metadata.deinit();
        self.images.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};

fn newCache(a: std.mem.Allocator, config: core.pcs.PcsConfig, fixed_bytes: usize) !Cache.Cache {
    const workers = if (std.posix.getenv("STWO_ZIG_RV64_RECEIVER_SETUP_THREADS")) |value|
        std.fmt.parseUnsigned(usize, value, 10) catch return error.InvalidReceiverSetupThreads
    else
        1;
    if (workers == 0 or workers > 8) return error.InvalidReceiverSetupThreads;
    return Cache.Cache.init(a, .{ .log_blowup = config.fri_config.log_blowup_factor }, .{
        .mode = .verifier,
        .directory = null,
        .fixed_setup_bytes = fixed_bytes,
        .identity_only_cpu = true,
        .max_build_threads = workers,
    });
}

pub const Owner = struct {
    allocator: std.mem.Allocator,
    cache: ?Cache.Cache = null,
    legacy_fixed: ?Fixed.Fixed.Cache = null,
    session: ?*Session = null,
    keys: Keys,
    set: ?Set = null,
    keys_ns: u64 = 0,
    fixed_ns: u64 = 0,
    identity_only: bool,

    /// Heap owner keeps the cache address stable while keys/sets borrow it.
    pub fn create(a: std.mem.Allocator, budget: *engine.host_budget_allocator.SharedHostBudget, image: *const Image.Owner, request: Request.Config, cpus: []const W.CpuDeclaration, truths: []const W.TruthDeclaration, config: core.pcs.PcsConfig, caches: Materials.ImmutableCaches, candidate: bool, fixed_bytes: usize, identity_only: bool, session: ?*Session) !*Owner {
        if (identity_only and !candidate) return error.ReceiverSourceKeysRequireCandidate;
        if (session) |shared| if (!identity_only or shared.fixed_bytes != fixed_bytes or shared.cache.candidate.log_blowup != config.fri_config.log_blowup_factor)
            return error.ReceiverSessionSetupMismatch;
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .keys = undefined, .identity_only = identity_only, .session = session };
        var timer = try std.time.Timer.start();
        if (identity_only and session == null) self.cache = try newCache(a, config, fixed_bytes);
        errdefer if (self.cache) |*cache| cache.deinit();
        const shared_cache = if (session) |shared| &shared.cache else if (self.cache) |*cache| cache else null;
        self.keys = if (shared_cache) |cache| blk: {
            const workers = @min(cache.max_build_threads, cpus.len + truths.len);
            var stacks = try budget.reserveExternal((workers -| 1) * Cache.Cache.build_thread_stack_bytes);
            defer stacks.deinit();
            try cache.bindRequest(request);
            break :blk try Keys.initResident(cache.allocator, image, cpus, truths, true, Materials.Suite.experimentalFold4(), caches, cache);
        } else try Keys.initWithSuiteAndCaches(a, image, cpus, truths, true, Materials.Suite.experimentalFold4(), caches);
        errdefer self.keys.deinit();
        self.keys_ns = timer.lap();
        if (candidate and shared_cache == null) self.legacy_fixed = try Fixed.Fixed.Cache.init(a, fixed_bytes);
        errdefer if (self.legacy_fixed) |*cache| cache.deinit();
        if (self.fixedCache()) |cache| {
            self.set = if (session) |shared|
                try Set.initWithValidatedCatalogue(a, cache, self.keys.cpus, self.keys.truths, config, &shared.catalogue)
            else
                try Set.init(a, cache, self.keys.cpus, self.keys.truths, config);
        }
        self.fixed_ns = timer.read();
        return self;
    }
    pub fn fixedCache(self: *Owner) ?*Fixed.Fixed.Cache {
        if (self.session) |shared| return &shared.cache.fixed;
        if (self.cache) |*cache| return &cache.fixed;
        if (self.legacy_fixed) |*cache| return cache;
        return null;
    }
    pub fn fixedSet(self: *Owner) ?*Set {
        if (self.set) |*set| return set;
        return null;
    }
    pub fn destroy(self: *Owner) void {
        const a = self.allocator;
        if (self.set) |*set| set.deinit();
        self.keys.deinit();
        if (self.legacy_fixed) |*cache| cache.deinit();
        if (self.cache) |*cache| cache.deinit();
        a.destroy(self);
    }
};

test "fresh receiver source-key policy is explicit and rejects malformed values" {
    try std.testing.expect(!try parseIdentityOnly(null));
    try std.testing.expect(!try parseIdentityOnly("0"));
    try std.testing.expect(try parseIdentityOnly("1"));
    for ([_][]const u8{ "", "true", "2", " 1" }) |value|
        try std.testing.expectError(error.InvalidReceiverSourceKeyPolicy, parseIdentityOnly(value));
}
