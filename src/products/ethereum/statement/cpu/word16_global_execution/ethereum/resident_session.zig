//! Sequential resident requests retain only independently derived immutable setup.
//! Request images, statements, channels and witnesses never enter this cache.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Keys = @import("keys.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const W = @import("stwo_riscv_cpu_integration").rv64_execution.services.wire;
const Setup = @import("stwo_riscv_cpu_integration").rv64_execution.word16.setup;
const Fixed = @import("stwo_riscv_cpu_integration").rv64_gkr_fixed_authority.Fixed;
const FixedSet = @import("stwo_riscv_cpu_integration").rv64_gkr_fixed_authority_set;
const SetupCache = @import("setup_cache.zig");
pub const Session = struct {
    allocator: std.mem.Allocator,
    key_budget: *engine.host_budget_allocator.SharedHostBudget,
    keys: Keys.Owner,
    validated_fixed: FixedSet.ValidatedCatalogue,
    native: Setup.NativeCache.Cache,
    metadata: Setup.ProgramMetadata.Cache,
    fixed: ?Fixed.Cache = null,
    fixed_limit: usize = 0,
    namespace: ?[32]u8 = null,
    /// Session-lifetime candidate setup (resident + optionally persisted,
    /// #320). Created on the first request when STWO_ZIG_RV64_SETUP_CACHE is
    /// set; every later request in this process reuses it.
    setup: ?SetupCache.Cache = null,
    setup_fixed_bytes: usize = 0,
    /// M4 resident: fixed-authority validations of the SetupCache's resident,
    /// pointer-stable (frozen) components, reused by every later request of
    /// this service (same provenance rule as `validated_fixed`). Its leases live
    /// in `setup.fixed`, so it is torn down before `setup`.
    setup_validated: FixedSet.ValidatedCatalogue,
    /// M5 platform: receiver-derived ProgramAuthority, built once per guest.
    authorities: Image.AuthorityCache,
    active: bool = false,
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,
    pub fn init(a: std.mem.Allocator, key_bytes: usize) !Session {
        const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, key_bytes);
        errdefer budget.destroy();
        var native = try Setup.NativeCache.Cache.init(a, 256 << 20);
        errdefer native.deinit();
        return .{ .allocator = a, .key_budget = budget, .keys = emptyKeys(budget.allocator()), .validated_fixed = .{ .allocator = budget.allocator() }, .setup_validated = .{ .allocator = budget.allocator() }, .native = native, .metadata = try Setup.ProgramMetadata.Cache.init(a, 64 << 20), .authorities = Image.AuthorityCache.init(a) };
    }
    fn emptyKeys(a: std.mem.Allocator) Keys.Owner {
        return .{ .allocator = a, .cpus = &.{}, .truths = &.{} };
    }
    pub fn deinit(self: *Session) void {
        std.debug.assert(!self.active);
        self.validated_fixed.deinit();
        self.keys.deinit();
        if (self.fixed) |*cache| cache.deinit();
        self.setup_validated.deinit();
        if (self.setup) |*cache| cache.deinit();
        self.native.deinit();
        self.metadata.deinit();
        self.authorities.deinit();
        self.key_budget.destroy();
        self.* = undefined;
    }
    /// Write artifacts for components first built by earlier requests. The
    /// caller runs this between requests so disk writes stay off request wall.
    pub fn persistSetup(self: *Session) !void {
        if (self.active) return error.ResidentRequestAlreadyActive;
        if (self.setup) |*cache| try cache.persist();
    }
    pub fn setupStats(self: *const Session) ?SetupCache.Stats {
        return if (self.setup) |cache| cache.stats else null;
    }
    pub fn caches(self: *Session) Setup.ImmutableCaches {
        return .{ .native = &self.native, .program = &self.metadata };
    }
    pub fn fixedAuthority(self: *Session, bytes: usize) !*Fixed.Cache {
        if (bytes == 0) return error.MissingCandidateFixedSetupAdmission;
        if (self.fixed) |*cache| {
            if (self.fixed_limit != bytes) return error.ResidentFixedBudgetChanged;
            return cache;
        }
        self.fixed = try Fixed.Cache.init(self.allocator, bytes);
        self.fixed_limit = bytes;
        return &self.fixed.?;
    }
    pub fn acquireKeys(self: *Session, image: *const Image.Owner, program: [32]u8, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, suite: Setup.Suite) !Keys.Owner {
        if (!self.active) return error.ResidentRequestNotActive;
        // A program identity comes from this request's independently loaded image,
        // not producer declarations. Suite changes must never reuse prior keys.
        const encoded = try std.json.Stringify.valueAlloc(self.allocator, suite, .{});
        defer self.allocator.free(encoded);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/rv64/resident/immutable-host-authority/v1\x00");
        hash.update(&program);
        hash.update(encoded);
        const namespace = hash.finalResult();
        if (self.namespace == null or !std.mem.eql(u8, &self.namespace.?, &namespace)) {
            self.validated_fixed.clear();
            self.keys.deinit();
            self.keys = emptyKeys(self.key_budget.allocator());
            self.namespace = namespace;
        }
        const before = self.keyCount();
        const evictions_before = self.evictions;
        const out = Keys.Owner.initWithSharedCache(self.key_budget.allocator(), image, cpu, truth, suite, self.caches(), &self.keys) catch |err| blk: {
            if (err != error.OutOfMemory) return err;
            // No previous request holds an owner here. Reclaim cached classes
            // and retry once under the SAME byte cap; never fall back unbounded.
            self.validated_fixed.clear();
            self.keys.deinit();
            self.keys = emptyKeys(self.key_budget.allocator());
            self.evictions += 1;
            break :blk try Keys.Owner.initWithSharedCache(self.key_budget.allocator(), image, cpu, truth, suite, self.caches(), &self.keys);
        };
        if (self.keyCount() == before and self.evictions == evictions_before) self.hits += 1 else self.misses += 1;
        return out;
    }
    pub fn keyCount(self: *const Session) usize {
        return self.keys.cpu_owners.items.len + self.keys.keccak_owners.items.len + self.keys.secp_owners.items.len + self.keys.sha256_owners.items.len + self.keys.arith256_owners.items.len + self.keys.curve_owners.items.len + self.keys.secp_row_owners.items.len;
    }
};
