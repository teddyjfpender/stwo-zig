//! In-process, bounded cache of independently derived verifier roots/metadata.
//! Scope owners outlive this cache. No producer cache ID, fixed root, claims,
//! component instances or Fiat-Shamir state can populate an entry.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const K = @import("rv64_execution_verifier_key.zig");
const MAX_ENTRIES = 16;
pub const Limits = struct { entries: usize = 8, bytes: usize = 4 * 1024 * 1024 };
const Group = struct { present: bool, logs: [3]u32 };
/// Every variable fixed-column dependency; active counts/IDs/endpoints are
/// deliberately absent. Domain-only phase/tail schedules are keyed by log.
/// This format stays inside one executable/process, never imported from disk.
pub const Signature = struct {
    revision: u32 = 1,
    program_identity: [32]u8,
    policy_identity: [32]u8,
    config: @TypeOf(A.P.config()),
    profile: A.frontend.rv64.execution_profile.Profile,
    arithmetic: A.rv.arithmetic.division.policy.Policy,
    state: A.rv.state_policy.Policy,
    control: A.rv.control_policy.Policy,
    opcodes: [65]bool,
    cpu_log: u32,
    program_log: u32,
    and_table: bool,
    shift_table: bool,
    division: bool,
    division_log: u32,
    multiplication: bool,
    multiplication_log: u32,
    crypto: bool,
    keccak_log: u32,
    bridge_log: u32,
    secp: [2]Group,
    geometry: A.R.values.Geometry,
    ram: ?K.RamGeometry,
    pub fn derive(authority: *const A.Full.ProgramAuthority, policy: *const A.R.policy.Policy, public: A.Public) !Signature {
        // Admission precedes every lookup, not only misses. This includes the
        // merged characteristic bound and each service's fresh count/ID span.
        try A.Full.validateAuthorityProgram(authority, public.cpu.statement.program);
        try public.validateWithAdmittedOpcodes(policy, &authority.opcodes);
        if (public.cpu.execution_profile != authority.profile or public.cpu.control_policy != authority.control_policy or !std.mem.eql(bool, &public.cpu.statement.opcodes, &authority.opcodes)) return error.InvalidReceiverKeyAuthority;
        try K.validateProgram(&authority.program, authority, public.cpu.statement.program);
        var groups: [2]Group = undefined;
        for (public.cpu.secp.groups(), &groups) |source, *group| group.* = .{ .present = source.roster == .present, .logs = .{ source.geometry.product_log, source.geometry.linear_log, source.geometry.bridge_log } };
        const policy_log: u32 = @intCast(@max(4, std.math.log2_int_ceil(usize, @max(1, policy.grants.len))));
        return .{ .program_identity = authority.program.identity, .policy_identity = policy.identity, .config = A.P.config(), .profile = public.cpu.execution_profile, .arithmetic = public.cpu.arithmetic_policy, .state = public.cpu.state_policy, .control = public.cpu.control_policy, .opcodes = authority.opcodes, .cpu_log = public.cpu.statement.logSize(), .program_log = authority.program.log_size, .and_table = authority.and_table != null, .shift_table = authority.shift_table != null, .division = public.cpu.division_roster == .present, .division_log = public.cpu.division_log, .multiplication = public.cpu.arithmetic_policy == .division_multiplication_services_v3 and public.cpu.multiplication_roster == .present, .multiplication_log = public.cpu.multiplication_log, .crypto = public.cpu.roster == .paired, .keccak_log = public.cpu.keccak_log, .bridge_log = public.cpu.bridge_log, .secp = groups, .geometry = public.geometry, .ram = if (public.ram) |counts| K.RamGeometry.fromShapes(try counts.shapes(public.geometry), policy_log) else null };
    }
};
const Entry = struct { signature: Signature, key: *K.ReceiverKey, age: u64 };
pub const Stats = struct { hits: u64, misses: u64, entries: usize, retained_bytes: usize, peak_retained_bytes: usize, cold_setup_ns: u64 };
pub const Cache = struct {
    allocator: std.mem.Allocator,
    authority: *const A.Full.ProgramAuthority,
    policy: *const A.R.policy.Policy,
    limits: Limits,
    slots: [MAX_ENTRIES]?Entry = @splat(null),
    age: u64 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    cold_setup_ns: u64 = 0,
    retained_bytes: usize = @sizeOf(Cache),
    peak_retained_bytes: usize = @sizeOf(Cache),
    /// Single caller owner: lookup/verification is synchronous; no eviction can
    /// occur while components borrow a key's Plan. Entries are heap-stable.
    pub fn init(a: std.mem.Allocator, authority: *const A.Full.ProgramAuthority, policy: *const A.R.policy.Policy, limits: Limits) !Cache {
        if (limits.entries > MAX_ENTRIES or limits.bytes < @sizeOf(Cache)) return error.InvalidReceiverCacheLimits;
        try policy.validateImmutableExecution();
        return .{ .allocator = a, .authority = authority, .policy = policy, .limits = limits };
    }
    pub fn deinit(self: *Cache) void {
        for (&self.slots) |*slot| if (slot.*) |entry| {
            entry.key.deinit();
            self.allocator.destroy(entry.key);
            slot.* = null;
        };
        self.* = undefined;
    }
    pub fn stats(self: *const Cache) Stats {
        var count: usize = 0;
        for (self.slots) |slot| if (slot != null) {
            count += 1;
        };
        return .{ .hits = self.hits, .misses = self.misses, .entries = count, .retained_bytes = self.retained_bytes, .peak_retained_bytes = self.peak_retained_bytes, .cold_setup_ns = self.cold_setup_ns };
    }
    fn tick(self: *Cache) u64 {
        self.age +%= 1;
        if (self.age == 0) {
            for (&self.slots) |*slot| if (slot.*) |*entry| {
                entry.age = 0;
            };
            self.age = 1;
        }
        return self.age;
    }
    fn evict(self: *Cache, index: usize) void {
        const entry = self.slots[index].?;
        self.retained_bytes -= entry.key.metadataBytes();
        entry.key.deinit();
        self.allocator.destroy(entry.key);
        self.slots[index] = null;
    }
    fn oldest(self: *const Cache) usize {
        var found: ?usize = null;
        for (self.slots, 0..) |slot, i| if (slot) |entry| {
            if (found == null or entry.age < self.slots[found.?].?.age) found = i;
        };
        return found.?;
    }
    /// Proof is consumed even on admission failure, a miss, OOM, or rejection.
    pub fn verifyOwned(self: *Cache, public: A.Public, claims: A.Claims, proof_value: A.P.Proof) !void {
        var proof = proof_value;
        var owns_proof = true;
        defer if (owns_proof) proof.deinit(self.allocator);
        const signature = try Signature.derive(self.authority, self.policy, public);
        for (&self.slots) |*slot| if (slot.*) |*entry| {
            if (std.meta.eql(entry.signature, signature)) {
                self.hits += 1;
                entry.age = self.tick();
                owns_proof = false;
                return entry.key.verifyOwned(self.allocator, public, claims, proof);
            }
        };
        self.misses += 1;
        var setup_timer = try std.time.Timer.start();
        // Fixed material is derived from expected authority/policy, never from
        // a producer root. It exists only during the cold key construction.
        var prepared = try A.Prepared.initWithAuthority(self.allocator, public, self.policy, self.authority);
        var owns_prepared = true;
        defer if (owns_prepared) prepared.deinit();
        const key = try self.allocator.create(K.ReceiverKey);
        var owns_key = true;
        var initialized = false;
        defer if (owns_key) {
            if (initialized) key.deinit();
            self.allocator.destroy(key);
        };
        key.* = try K.ReceiverKey.fromPrepared(self.allocator, &prepared, public, self.authority);
        initialized = true;
        // This is a hard lifetime gate: the following proof verification has
        // no access to any per-geometry fixed matrix or Prepared Plan pointer.
        prepared.deinit();
        owns_prepared = false;
        self.cold_setup_ns += setup_timer.read();
        const bytes = key.metadataBytes();
        if (self.limits.entries == 0 or bytes > self.limits.bytes - @sizeOf(Cache)) {
            owns_proof = false;
            return key.verifyOwned(self.allocator, public, claims, proof);
        }
        while (self.stats().entries >= self.limits.entries or bytes > self.limits.bytes - self.retained_bytes) self.evict(self.oldest());
        var index: usize = 0;
        while (self.slots[index] != null) : (index += 1) {}
        self.slots[index] = .{ .signature = signature, .key = key, .age = self.tick() };
        self.retained_bytes += bytes;
        self.peak_retained_bytes = @max(self.peak_retained_bytes, self.retained_bytes);
        owns_key = false;
        owns_proof = false;
        return key.verifyOwned(self.allocator, public, claims, proof);
    }
};
