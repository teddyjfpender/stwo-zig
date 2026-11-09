//! Receiver-derived canonical fold topology. No proposed root VK or proof bytes
//! enter construction: only independently rebuilt ordered leaf source keys.
const std = @import("std");
const Fold = @import("fold.zig");
const Authority = @import("authority.zig").Key;
const Profile = @import("../op_profile.zig").Profile;
pub const Binding = struct { ordinal: u32, native_identity: [32]u8, kind: enum { cpu, catalog, miller } };
/// No raw-Authority constructor: each leaf key is derived by a concrete source
/// verifier builder, normalizing PCS geometry from its independently owned key.
pub const SourceLeaf = struct {
    authority: Authority,
    binding: Binding,
    pub fn deinit(self: *SourceLeaf) void {
        self.authority.deinit();
        self.* = undefined;
    }
    fn finish(a: std.mem.Allocator, profile: Profile, binding: Binding, produced: @import("../context.zig").Context) !SourceLeaf {
        var trace = produced;
        defer trace.deinit();
        var timer = try std.time.Timer.start();
        var authority = try Authority.init(a, &trace, profile);
        errdefer authority.deinit();
        const json = try std.json.Stringify.valueAlloc(a, .{ .kind = @tagName(binding.kind), .ordinal = binding.ordinal, .raw = try trace.rawCounts(), .legacy_component_cells = try trace.census(false), .native_mul_rows = authority.mul_rows, .logs = authority.base.logs, .immutable_setup_ns = timer.read(), .source_identity = std.fmt.bytesToHex(authority.base.identity, .lower) }, .{});
        defer a.free(json);
        std.debug.print("OP_P2_SOURCE_CLASS {s}\n", .{json});
        return .{ .authority = authority, .binding = binding };
    }
    pub fn initCpu(a: std.mem.Allocator, source: @import("../pure_p2_cpu_leaf_test.zig").ShapeView) !SourceLeaf {
        _ = source.op_span orelse return error.OpRootRequiresOpCpuSource;
        try source.key.requireForOp(source.setup, source.key.profile);
        if (source.expected.kind != .cpu or source.expected.profile != source.key.profile or !std.mem.eql(u8, &source.expected.fixed_identity, &source.key.identity)) return error.OpRootLeafSourceAuthority;
        if (source.values.cap_log != 0) return error.OpRootLeafCapVariant;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), source.setup, source.key.profile.config());
        var normalized = source;
        normalized.shape = &shape;
        var phases: @import("../pure_p2_cpu_leaf_test.zig").CompleteCounts = .{};
        var scope = @import("scope.zig").begin();
        defer scope.deinit();
        var trace = try normalized.build(a, true, &phases);
        const json = std.json.Stringify.valueAlloc(a, phases, .{}) catch |err| {
            trace.deinit();
            return err;
        };
        defer a.free(json);
        std.debug.print("OP_P2_SOURCE_CPU_PHASES ordinal={} {s}\n", .{ source.expected.ordinal, json });
        return finish(a, source.key.profile, .{ .ordinal = source.expected.ordinal, .native_identity = source.key.identity, .kind = .cpu }, trace);
    }
    pub fn initCatalog(a: std.mem.Allocator, source: @import("../pure_p2_truth_leaf_test.zig").View) !SourceLeaf {
        try source.key.require(source.truth);
        const expected = try source.key.expected(source.truth, source.expected.ordinal);
        if (source.expected.kind != expected.kind or !std.mem.eql(u8, &source.expected.statement, &expected.statement) or source.expected.profile != source.key.profile or !std.mem.eql(u8, &source.expected.fixed_identity, &source.key.identity)) return error.OpRootLeafSourceAuthority;
        if (source.values.cap_log != 0) return error.OpRootLeafCapVariant;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../pure_p2_truth_statement.zig").geometry(arena.allocator(), source.key, source.truth);
        var normalized = source;
        normalized.shape = &shape;
        var scope = @import("scope.zig").begin();
        defer scope.deinit();
        return finish(a, source.key.profile, .{ .ordinal = source.expected.ordinal, .native_identity = source.key.identity, .kind = .catalog }, try normalized.build(a, true));
    }
    pub fn initMiller(a: std.mem.Allocator, source: @import("../pure_p2_tower_leaf_test.zig").View) !SourceLeaf {
        try source.key.validateSpan(source.span);
        const expected = try source.key.expected(source.span, source.expected.ordinal);
        if (source.expected.kind != expected.kind or !std.mem.eql(u8, &source.expected.statement, &expected.statement) or source.expected.profile != source.key.profile or !std.mem.eql(u8, &source.expected.fixed_identity, &source.key.identity)) return error.OpRootLeafSourceAuthority;
        if (source.values.cap_log != 0) return error.OpRootLeafCapVariant;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../pure_p2_tower_statement.zig").geometry(arena.allocator(), source.key);
        var normalized = source;
        normalized.shape = &shape;
        var scope = @import("scope.zig").begin();
        defer scope.deinit();
        return finish(a, source.key.profile, .{ .ordinal = source.expected.ordinal, .native_identity = source.key.identity, .kind = .miller }, try normalized.build(a, true));
    }
};
pub const Topology = struct {
    allocator: std.mem.Allocator,
    execution: [32]u8,
    leaf_count: usize,
    leaf_fingerprint: [32]u8,
    leaf_bindings: []Binding,
    profile: Profile,
    owned: std.ArrayList(*Authority) = .empty,
    final: *const Authority,
    pub fn key(self: *const Topology) *const Authority {
        return self.final;
    }
    pub fn deinit(self: *Topology) void {
        for (self.owned.items) |authority| {
            authority.deinit();
            self.allocator.destroy(authority);
        }
        self.allocator.free(self.leaf_bindings);
        self.owned.deinit(self.allocator);
        self.* = undefined;
    }
    /// Leaves must be derived by trusted CPU/catalog/Miller source constructors;
    /// they are borrowed until this handle is destroyed (one-leaf case).
    pub fn init(a: std.mem.Allocator, profile: Profile, execution: [32]u8, sources: []const SourceLeaf) !Topology {
        if (sources.len == 0 or sources.len > 256) return error.InvalidOpRootTopologyCount;
        const bindings = try a.alloc(Binding, sources.len);
        var self = Topology{ .allocator = a, .execution = execution, .leaf_count = sources.len, .leaf_bindings = bindings, .leaf_fingerprint = undefined, .profile = profile, .final = &sources[0].authority };
        errdefer self.deinit();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("OP_SOURCE_FOLD_TOPOLOGY_R6_V1");
        hash.update(&profile.identity());
        var count: [8]u8 = undefined;
        std.mem.writeInt(u64, &count, @intCast(sources.len), .little);
        hash.update(&count);
        for (sources, bindings, 0..) |*source, *binding, i| {
            const leaf = &source.authority;
            if (source.binding.ordinal != i) return error.OpRootTopologyLeafOrder;
            binding.* = source.binding;
            if (leaf.base.n_outputs != 9 or leaf.base.profile != profile) return error.OpRootTopologyLeafAuthority;
            var ordinal: [4]u8 = undefined;
            std.mem.writeInt(u32, &ordinal, source.binding.ordinal, .little);
            hash.update(&ordinal);
            hash.update(&source.binding.native_identity);
            hash.update(&.{@intFromEnum(source.binding.kind)});
            hash.update(&leaf.base.identity);
            hash.update(&leaf.base.fixed_root);
        }
        hash.final(&self.leaf_fingerprint);
        const level = try a.alloc(*const Authority, sources.len);
        for (sources, level) |*source, *slot| slot.* = &source.authority;
        defer a.free(level);
        var n = level.len;
        while (n > 1) {
            var next: usize = 0;
            var i: usize = 0;
            while (i + 1 < n) : (i += 2) {
                const source = Fold.TraceSource{ .keys = .{ level[i], level[i + 1] } };
                var trace = try source.build(a);
                defer trace.deinit();
                const authority = try a.create(Authority);
                authority.* = Authority.init(a, &trace, profile) catch |err| {
                    a.destroy(authority);
                    return err;
                };
                self.owned.append(a, authority) catch |err| {
                    authority.deinit();
                    a.destroy(authority);
                    return err;
                };
                level[next] = authority;
                next += 1;
            }
            if (i < n) {
                level[next] = level[i];
                next += 1;
            }
            n = next;
        }
        self.final = level[0];
        return self;
    }
};
