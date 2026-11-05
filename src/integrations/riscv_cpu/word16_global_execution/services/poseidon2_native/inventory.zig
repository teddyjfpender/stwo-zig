//! Independent full public/source admission for the mixed P2 CPU fixture route.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("../protocol.zig");
const R = @import("../roster.zig");
const T = @import("../types.zig");
const M = @import("../gkr_local/manifest.zig");
const Frame = @import("../gkr_local/frame.zig");
const Protocol = @import("worker_protocol.zig");
const Key = @import("fixed_key.zig").Key;
pub const Inventory = struct {
    allocator: std.mem.Allocator,
    execution_identity: [32]u8,
    workers: []M.ExpectedWorker,
    instances: [][]Frame.Instance,
    first_ids: [][T.FAMILIES]u32,
    pub fn init(a: std.mem.Allocator, setups: []const *const R.CpuSetup, requests: []const P.Request, expected: P.Expected, keys: []const Key, profile: Protocol.Profile) !Inventory {
        if (setups.len == 0 or setups.len != requests.len or setups.len != keys.len or setups.len > 256) return error.PoseidonNativeInventory;
        _ = try P.admit(a, setups, &.{}, requests, expected);
        const Scope = @import("../gkr_local/service_scope.zig");
        for (setups, requests, keys) |setup, request, key| {
            try Scope.setup(setup);
            try Scope.request(request);
            try key.require(setup, profile);
        }
        const workers = try a.alloc(M.ExpectedWorker, setups.len);
        errdefer a.free(workers);
        const instances = try a.alloc([]Frame.Instance, setups.len);
        errdefer a.free(instances);
        var done: usize = 0;
        errdefer for (instances[0..done]) |instance| a.free(instance);
        const ids = try a.alloc([T.FAMILIES]u32, setups.len);
        errdefer a.free(ids);
        var next: [T.FAMILIES]u64 = @splat(1);
        for (setups, requests, keys, workers, instances, ids, 0..) |setup, request, *key, *worker, *instance, *first, i| {
            for (next, first) |id, *v| v.* = std.math.cast(u32, id) orelse return error.PoseidonNativeInventory;
            instance.* = try @import("../gkr_local/roster.zig").fromSetup(a, setup);
            done += 1;
            worker.* = .{ .kind = .cpu, .ordinal = @intCast(i), .statement = key.statement(setup, request, first.*), .fixed = key.scope(), .local_instances = instance.*, .mass = try @import("../gkr_local/cpu_worker.zig").cpuMass(request), .global_relations = .{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = @import("../gkr_local/cpu_worker.zig").wirePresent(setup.bridges) } };
            for (&next, request.calls) |*v, count| v.* = try std.math.add(u64, v.*, count);
        }
        try M.validateRoster(workers);
        // Source-derived signed/absolute characteristic and roster bounds.
        const Wire = @import("../wire.zig");
        const declarations = try a.alloc(Wire.CpuDeclaration, setups.len);
        defer a.free(declarations);
        for (setups, declarations) |setup, *d| d.* = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges };
        var bounds = try @import("../gkr_local/source_bounds.zig").derive(a, setups[0].materials.program.log_size, declarations, &.{}, requests);
        defer bounds.deinit();
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        h.update("rv64-p2v2/raw-manifest-execution/FIXTURE-v1\x00");
        h.update(&profile.identity());
        h.update(&@import("../gkr_local/execution.zig").executionIdentity(profile.config(), expected));
        for (keys) |key| {
            h.update(&key.identity);
            h.update(&key.root);
        }
        var execution_id: [32]u8 = undefined;
        h.final(&execution_id);
        return .{ .allocator = a, .execution_identity = execution_id, .workers = workers, .instances = instances, .first_ids = ids };
    }
    pub fn deinit(self: *Inventory) void {
        for (self.instances) |instances| self.allocator.free(instances);
        self.allocator.free(self.instances);
        self.allocator.free(self.workers);
        self.allocator.free(self.first_ids);
        self.* = undefined;
    }
};
