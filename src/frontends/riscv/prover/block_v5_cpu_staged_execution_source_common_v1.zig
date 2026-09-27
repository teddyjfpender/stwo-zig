//! Late-admitted execution from bounded stored cells, without guest replay.
//! One fresh recommit is moved into the producer and freed before its owner.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;

const Names = @import("block_v5_cpu_witness_staging_v1.zig");
const Store = @import("block_v5_witness_columns_store_v1.zig");

const Admission = @import("block_v5_native_public_admission_v1.zig");

const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
const Recipe = @import("block_v5_execution_recipe_v1.zig").Recipe;
pub fn ForCapacity(comptime capacity: bool) type {
    const Stage = if (capacity) @import("block_v5_capacity_native_columns_stage_v1.zig") else @import("block_v5_native_columns_stage_v1.zig");
    const Driver = @import("block_v5_cpu_driver_admission_v1.zig").ForCapacity(capacity);
    const Producer = @import("block_v5_block_producer_v1.zig").ForCapacity(capacity);
    const Native = if (capacity) @import("block_v5_native_capacity_proof_v1.zig") else @import("block_v5_native_execution_proof_v3.zig");
    const FixedCache = @import("block_v5_native_capacity_fixed_cache_v1.zig").ForBackend(Cpu);
    return struct {
        pub const Source = struct {
            a: std.mem.Allocator,
            dir: std.fs.Dir,
            records: []const Driver.Record,
            pins: []const Store.Pin,
            admissions: []const Admission.Admission,
            limits: Stage.Limits,
            recipe: Recipe,
            fixed_cache: if (capacity) ?FixedCache.Cache else void = if (capacity) null else {},
            /// Optional immutable reuse is separately bounded; a cache-sized miss is
            /// a cold commit, never an admission bypass or changed proof grammar.
            fixed_basis_limits: @import("block_v5_native_capacity_fixed_basis_v1.zig").Limits = .{},
            next: u32 = 0,
            outstanding: bool = false,

            pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, records: []const Driver.Record, pins: []const Store.Pin, admissions: []const Admission.Admission, limits: Stage.Limits) !Source {
                return initForRecipe(a, dir, records, pins, admissions, limits, @import("block_v5_execution_recipe_v1.zig").canonical);
            }
            pub fn initForRecipe(a: std.mem.Allocator, dir: std.fs.Dir, records: []const Driver.Record, pins: []const Store.Pin, admissions: []const Admission.Admission, limits: Stage.Limits, recipe: Recipe) !Source {
                try recipe.requireCompiled();
                if (records.len == 0 or records.len != pins.len or records.len != admissions.len or records.len > std.math.maxInt(u32))
                    return error.InvalidV5StagedExecutionRoster;
                for (records, admissions, 0..) |*record, admission, index| {
                    const metadata = Driver.nativeMetadata(&record.physical);
                    try Driver.validatePhysical(&record.physical);
                    try recipe.requireNative(&metadata.shape);
                    try recipe.requireMode(admission.context.register_custody_mode);
                    if (metadata.index != index or admission.context.execution_index != index)
                        return error.InvalidV5StagedExecutionRoster;
                    _ = try record.physical.bind(admission.context);
                }
                return .{ .a = a, .dir = dir, .records = records, .pins = pins, .admissions = admissions, .limits = limits, .recipe = recipe };
            }
            pub fn deinit(self: *Source) void {
                std.debug.assert(!self.outstanding);
                if (capacity) if (self.fixed_cache) |*cache| {
                    cache.deinit() catch @panic("Capacity staged source destroyed with a live fixed PCS lease");
                };
                self.* = undefined;
            }
            pub fn source(self: *Source) Producer.LightweightExecutionSource {
                return .{ .context = self, .load = load };
            }
            pub fn requireFinished(self: *const Source) !void {
                if (self.outstanding or self.next != self.records.len) return error.IncompleteV5StagedExecution;
            }
            fn load(raw: *anyopaque, index: u32) !Producer.LightweightReplay {
                const self: *Source = @ptrCast(@alignCast(raw));
                if (self.outstanding or index != self.next or index >= self.records.len) return error.InvalidV5StagedExecutionOrder;
                try self.recipe.requireCompiled();
                try self.recipe.requireNative(&Driver.nativeMetadata(&self.records[index].physical).shape);
                const lease = try self.a.create(Lease);
                errdefer self.a.destroy(lease);
                var buffer: [96]u8 = undefined;
                const name = try Names.nativeName(index, &buffer);
                const physical = &self.records[index].physical;
                var fixed: ?FixedCache.Lease = if (capacity) try self.chooseBasis(physical) else null;
                var transferred = false;
                defer if (capacity and !transferred) if (fixed) |*token| {
                    token.release() catch @panic("Failed staged load retained a fixed PCS lease");
                };
                const prepared = if (capacity and fixed != null)
                    try Stage.ForBackend(Cpu).loadWithBasis(self.a, self.dir, name, physical, self.pins[index], self.limits, profile, fixed.?.basis)
                else
                    try Stage.ForBackend(Cpu).load(self.a, self.dir, name, physical, self.pins[index], self.limits, profile);
                lease.* = .{ .source = self, .index = index, .prepared = prepared, .basis_lease = if (capacity) fixed else {} };
                transferred = true;
                self.outstanding = true;
                self.next += 1;
                return .{ .owner = lease.prepared.owner, .admission = self.admissions[index], .profile = profile, .native_limits = if (capacity) physical.limits.native else {}, .context = lease, .release = release };
            }
            /// Called by the producer's first-round preparation hook. Moving the
            /// scheme prevents a duplicate transform/commit of the loaded columns.
            pub fn takeFirstRound(replay: *const Producer.LightweightReplay, index: u32) !Native.ForBackend(Cpu).FirstRound {
                const lease: *Lease = @ptrCast(@alignCast(replay.context));
                if (!lease.source.outstanding or lease.index != index or lease.prepared.owner != replay.owner or
                    !std.meta.eql(replay.admission, lease.source.admissions[index])) return error.UntrustedV5StagedExecution;
                if (capacity and !std.meta.eql(replay.native_limits, lease.source.records[index].physical.limits.native)) return error.UntrustedV5StagedExecution;
                return lease.prepared.takeFirstRound(&lease.source.records[index].physical, replay.admission);
            }
            fn chooseBasis(self: *Source, physical: *const @import("block_v5_cpu_capacity_root_proposal_v1.zig").Proposal) !?FixedCache.Lease {
                if (!capacity) @compileError("Only capacity templates admit shared fixed basis");
                std.debug.assert(!self.outstanding);
                try physical.validate();
                const metadata = Driver.nativeMetadata(physical);
                if (self.fixed_cache == null) self.fixed_cache = try FixedCache.Cache.init(self.a, self.fixed_basis_limits);
                if (!std.meta.eql(self.fixed_cache.?.limits, self.fixed_basis_limits)) return error.ChangedV5StagedFixedBasisLimits;
                return self.fixed_cache.?.acquire(self.a, &metadata.shape, metadata.external_retirements, metadata.template.config, profile, .{ .template = metadata.template, .template_id = metadata.template_id });
            }
            const Lease = struct {
                source: *Source,
                index: u32,
                prepared: Stage.ForBackend(Cpu).Prepared,
                basis_lease: if (capacity) ?FixedCache.Lease else void,
            };
            fn release(raw: *anyopaque, replay: *Producer.LightweightReplay) void {
                const lease: *Lease = @ptrCast(@alignCast(raw));
                const self = lease.source;
                std.debug.assert(lease.prepared.owner == replay.owner);
                lease.prepared.deinit(self.a);
                // The producer releases its moved FirstRound before this replay.
                // A retained tree reference is an explicit lifecycle error.
                if (capacity) if (lease.basis_lease) |*token| {
                    token.release() catch @panic("Capacity staged replay released before fixed PCS cleanup");
                };
                self.outstanding = false;
                self.a.destroy(lease);
            }
        };
    };
}
