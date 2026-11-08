//! Enqueue-only local GKR (spec §3.5 item 1, "local GKR ... with the channel
//! kept; no host partiallyVerifyBatch; the GKR section goes into the slab").
//!
//! Same kernels, inputs and transcript as the legacy v1-flat numerical stage
//! (rv64/gkr_stage.zig Job.execute), read-only reuse of rv64/gkr.zig (the
//! traversal), rv64/gkr_sources.zig (projection plan) and rv64/gkr_result.zig
//! (readback framing). What changes:
//!
//!   * The child transcript lives on the device. It is derived exactly as
//!     gkr_local/child.zig `begin(scope, instances)`: the challenge-free host
//!     prefix (header, statement, FIXED root) is a staged 9-word checkpoint;
//!     the MAIN root is mixed straight from its device buffer (it is produced by
//!     the MAIN commit in the same job); the instance list is mixed from staged
//!     words. Relation draws, projection and the closure traversal follow on
//!     the exec stream. Nothing returns to the host before `finish`.
//!   * No leases, no joins, no readbacks. Status, the traversal header, the
//!     child channel snapshot, the MAIN root, the packed roots and every layer's
//!     records/masks are D2D-copied into slab fields; `finish` reads them from
//!     the worker's single pinned D2H.
//!
//! Rejection / retry policy (decided here, M8-INTERFACES.md native-producers):
//! the v1-flat local GKR has NO salt and NO retry. A nonzero device verdict
//! (pole, zero-weight 0/0 or nonzero rational root sum) is a terminal
//! `LocalGkrClosureRejected`, exactly like the legacy stage (gkr.zig
//! ClosureEnqueued.validate). `finish` verifies status, traversal header and the
//! device child transcript (replayed on the host from the slab's MAIN root);
//! any mismatch fails the job, and the request fails closed (the legacy path
//! fails the same way; no resubmission can change a deterministic transcript).
//! Salted attempts exist only in the native-GKR v2 route (native_gkr_stage.zig),
//! which this producer does not implement and refuses (v1 catalogue only).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const Runtime = @import("stwo_cuda_backend").runtime;
const api = @import("api.zig");
const DC = @import("channel.zig");
const Slab = @import("slab.zig");
const G = @import("../gkr.zig");
const R = @import("../resident.zig");
const A = @import("../abi.zig");
const N = @import("../runtime_api.zig");
const Results = @import("../gkr_result.zig");
const Sources = @import("../gkr_sources.zig");
const Source = @import("../projection_codegen.zig").Source;
const F = @import("../projection_fixture_support.zig");

const Child = CPU.rv64_gkr_child;
const D = CPU.rv64_device_pcs;
const O = core.fields.om31.OM31;
const HostChannel = core.channel.raw_mod_m31.Om31Channel;
pub const Request = Child.NumericalStage.Request;
pub const Instance = std.meta.Child(@FieldType(Request, "instances"));
pub const Scope = @FieldType(Request, "scope");
pub const Proof = engine.lookups.gkr_verifier.ForField(O).GkrBatchProof;
const Slice = Runtime.column.DeviceSlice(u32);

const Projection = extern struct {
    fixed: [*]const u32,
    main: [*]const u32,
    public_values: [*]const u32,
    offsets: [*]const u64,
    parameters: [*]const u32,
    n: [*]u32,
    d: [*]u32,
    status: [*]u32,
    log: u32,
    first: u32,
    rows: u32,
};
const Launch = *const fn (*anyopaque, *const Projection) callconv(.c) c_int;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const Gather = *const fn (*anyopaque, u32, [*]const u32, [*]u32, [*]const u32, u32, u32, [*]u32) callconv(.c) c_int;
const CopyD2d = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;

/// Legacy constants (gkr_stage.zig): relation reservoir 10 x 31 felts, the
/// traversal chain tag, and the projection metadata header.
const reservoir_felts = 310;
pub const traversal_chain: u64 = 0x47524b5300000000;
const relations = std.enums.values(Source.Fractions.Relation);

/// Base-image entry points (frozen image exports), loaded once per worker.
pub const Symbols = struct {
    n2b: N2b,
    gather: Gather,
    copy_d2d: CopyD2d,
    memset: Memset,
    launch: [F.count]Launch,
    numerical: N.Api,
    /// Numerical routes, mirrored from the legacy Backend.init environment
    /// rules (same defaults, same flags). Routes never change proof bytes.
    batched_oracles: bool,
    batched_trees: bool,
    batched_tail: bool,
    batched_fold_sum: bool,

    pub fn load(base: *std.DynLib) !Symbols {
        var out: Symbols = .{
            .n2b = try lookup(N2b, base, "stwo_ntt_n2b_columns_on"),
            .gather = try lookup(Gather, base, "stwo_rv64_parameter_gather_on"),
            .copy_d2d = try lookup(CopyD2d, base, "stwo_exec_context_memcpy_d2d_async"),
            .memset = try lookup(Memset, base, "stwo_exec_context_memset_async"),
            .launch = undefined,
            .numerical = try N.Api.load(base),
            .batched_oracles = false,
            .batched_trees = false,
            .batched_tail = false,
            .batched_fold_sum = false,
        };
        for (&out.launch, 0..) |*launch, i| {
            var name: [32]u8 = undefined;
            launch.* = try lookup(Launch, base, try std.fmt.bufPrintZ(&name, "launch_{}", .{i}));
        }
        const n = &out.numerical;
        const batch_available = n.stwo_rv64_batch_sum_on != null and n.stwo_rv64_batch_fold_on != null;
        const explicit_batch = std.posix.getenv("STWO_RV64_GKR_BATCH_ORACLES") != null;
        const explicit_serial = std.posix.getenv("STWO_RV64_GKR_SERIAL_ORACLES") != null;
        if (explicit_batch and explicit_serial) return error.ConflictingCudaGkrOracleModes;
        if (explicit_batch and !batch_available) return error.MissingCudaBatchedOracleSymbol;
        out.batched_oracles = batch_available and !explicit_serial;
        if (std.posix.getenv("STWO_RV64_GKR_BATCH_TREES")) |v| {
            if (!std.mem.eql(u8, v, "0")) {
                if (!std.mem.eql(u8, v, "1")) return error.InvalidCudaGkrTreeMode;
                if (n.stwo_rv64_batch_layer_on == null) return error.MissingCudaBatchedTreeSymbol;
                out.batched_trees = true;
            }
        }
        out.batched_tail = std.posix.getenv("STWO_RV64_GKR_BATCH_TAIL") != null;
        if (out.batched_tail and (!out.batched_oracles or n.stwo_rv64_batch_tail_on == null)) return error.MissingCudaBatchedTailSymbol;
        if (std.posix.getenv("STWO_RV64_GKR_BATCH_FOLD_SUM")) |v| {
            if (!std.mem.eql(u8, v, "0")) {
                if (!std.mem.eql(u8, v, "1")) return error.InvalidCudaBatchedFoldSumMode;
                if (!out.batched_oracles or n.stwo_rv64_batch_fold_sum_on == null) return error.MissingCudaBatchedFoldSumSymbol;
                if (out.batched_tail) return error.ConflictingCudaGkrFusions;
                out.batched_fold_sum = true;
            }
        }
        return out;
    }
};

fn lookup(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse {
        std.log.err("native GKR job: missing base-image symbol {s}", .{name});
        return error.MissingNativeGkrJobSymbol;
    };
}
fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

/// The device view `R.Commands` runs on: lane 0 of the worker's exec context;
/// every slice is a sub-range of a job arena/slab buffer, tagged with `token`.
pub const DeviceContext = struct {
    native: *anyopaque,
    pub const token: usize = 0x4d384a4f; // "M8JO"
    pub const Lane = struct { owner: usize, index: u32 };
    pub fn lane(self: *DeviceContext, index: u32) !Lane {
        if (index != 0) return error.InvalidLane;
        return .{ .owner = @intFromPtr(self.native), .index = 0 };
    }
    pub fn validateLane(self: *DeviceContext, value: Lane) !void {
        if (value.owner != @intFromPtr(self.native) or value.index != 0) return error.InvalidLane;
    }
    pub fn deviceSlicePointer(_: *DeviceContext, comptime T: type, value: Runtime.column.DeviceSlice(T), count: usize) ![*]T {
        if (value.owner != token or value.generation != 1 or value.address == 0 or value.address % @alignOf(T) != 0 or count == 0 or count > value.len) return error.InvalidDeviceAddress;
        return @ptrFromInt(value.address);
    }
    pub fn slice(b: api.DeviceBuffer) Slice {
        return .{ .address = @intFromPtr(b.ptr), .len = b.words, .owner = token, .generation = 1 };
    }
};

/// One input column at enqueue (original order: FIXED columns then MAIN).
pub const Input = struct { device: ?[*]const u32 = null, host: []const u32 = &.{} };

/// Host replay of child.zig `begin` split at the MAIN root: the prefix
/// checkpoint before it, then the MAIN root, then the instance list.
pub fn childPrefix(scope: Scope, instances: []const Instance) HostChannel {
    var ch = HostChannel.init();
    ch.mixU32s(&.{ if (v3Instances(instances)) @as(u32, 0x53474b33) else 0x53474b31, 8, scope.ordinal });
    for ([_][32]u8{ scope.statement, scope.fixed }) |bytes| ch.mixU32s(&rootWords(bytes));
    return ch;
}
/// The instance-list mixes of `begin` (after the MAIN root), as word spans.
pub const instance_mixes_per_instance = 4;
pub fn instanceWords(a: std.mem.Allocator, instances: []const Instance) ![]u32 {
    const out = try a.alloc(u32, 1 + 8 * instances.len);
    out[0] = @intCast(instances.len);
    for (instances, 0..) |instance, i| {
        const w = out[1 + 8 * i ..][0..8];
        w[0..2].* = originWords(instance.origin);
        w[2] = instance.row_log;
        w[3] = instance.terms;
        w[4] = @truncate(instance.fixed_offset);
        w[5] = @truncate(@as(u64, instance.fixed_offset) >> 32);
        w[6] = @truncate(instance.main_offset);
        w[7] = @truncate(@as(u64, instance.main_offset) >> 32);
    }
    return out;
}
/// Span (offset, words) of the k-th instance-list mix inside `instanceWords`.
fn instanceSpan(k: usize) [2]usize {
    if (k == 0) return .{ 0, 1 };
    const i = (k - 1) / instance_mixes_per_instance;
    const part = (k - 1) % instance_mixes_per_instance;
    return .{ 1 + 8 * i + 2 * part, 2 };
}
pub fn mixInstancesHost(ch: *HostChannel, words: []const u32) void {
    const mixes = 1 + instance_mixes_per_instance * ((words.len - 1) / 8);
    for (0..mixes) |k| {
        const s = instanceSpan(k);
        ch.mixU32s(words[s[0]..][0..s[1]]);
    }
}
fn rootWords(bytes: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}
// Restated from gkr_local/frame.zig (not exported by the CPU module).
pub fn originWords(origin: anytype) [2]u32 {
    return switch (origin) {
        .core => |v| .{ 0, @intFromEnum(v) },
        .bridge => |v| .{ 1, @intFromEnum(v) },
        .bulk => |v| .{ 2, @intFromEnum(v) },
        .dword => |v| .{ 3, v },
        .sponge => |v| .{ 4, @intFromEnum(v) },
    };
}
// Restated from gkr_local/frame.zig v3Instances.
pub fn v3Instances(instances: []const Instance) bool {
    for (instances) |instance| switch (instance.origin) {
        .bulk, .dword, .sponge => return true,
        .bridge => |family| if (@intFromEnum(family) >= CPU.rv64_services_types.V2_FAMILIES) return true,
        .core => {},
    };
    return false;
}
pub fn seedWords(ch: HostChannel) [9]u32 {
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, ch.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = ch.inner.n_draws;
    return seed;
}

/// Relation-draw transcript (gkr_stage.zig, = challenges.zig drawMode) on a
/// host channel: the finish-time replay of the device child channel.
pub fn drawRelationsHost(ch: *HostChannel, v3: bool) void {
    const count: usize = if (v3) relations.len else @intFromEnum(Source.Fractions.Relation.byte_pair);
    ch.mixU32s(&.{ if (v3) @as(u32, 0x4c474b33) else 0x4c474b31, 8, @intCast(count) });
    for (relations[0..count], 0..) |relation, i| {
        ch.mixU32s(&.{ @intCast(i), @intCast(relation.arity()) });
        const draws: usize = 1 + if (relation == .range8) @as(usize, 0) else relation.arity();
        for (0..draws) |_| _ = ch.drawSecureFelt();
    }
}

/// Slab fields of one local GKR section. `base` namespaces the field indices
/// so a larger job (NativeStage1) can host the section next to other fields.
pub const Fields = struct {
    base: u32,
    layers: u32,
    pub fn status(self: Fields) u32 {
        return self.base;
    }
    pub fn header(self: Fields) u32 {
        return self.base;
    }
    pub fn roots(self: Fields) u32 {
        return self.base + 1;
    }
    pub fn mainRoot(self: Fields) u32 {
        return self.base + 2;
    }
    pub fn records(self: Fields, depth: u32) u32 {
        return self.base + 3 + 2 * depth;
    }
    pub fn masks(self: Fields, depth: u32) u32 {
        return self.base + 4 + 2 * depth;
    }
};

/// Static per-segment plan: everything challenge-free, computed on the host
/// before stage (pre-stage) from the segment's roster and column geometry.
pub const Plan = struct {
    a: std.mem.Allocator,
    catalogue: *const Sources.Catalogue,
    source: Sources.Plan,
    variables: []u32,
    traversal: G.Plan,
    v3: bool,
    relation_count: u32,
    byte_cap: usize,
    fixed_count: usize,
    /// Constants mixed before the relation draws (gkr_stage.zig `metadata`).
    constants: [3 + 2 * relations.len]u32,
    prefix: [9]u32,
    prefix_channel: HostChannel,
    instances: []u32,
    /// Sorted (ingress) position -> original column index.
    order: []usize,
    /// Original column index -> log size.
    logs: []u32,
    instance_mixes: usize,
    /// Child channel ops after init (cursor at the snapshot) and its chain.
    child_steps: u32,
    /// Staged metadata layout (words): seed | constants | instances | per item {offsets, public}.
    staged_words: usize,
    item_offsets: []usize,
    twiddle_words: usize,
    host_column_words: usize,
    fields: Fields,

    /// `fixed` / `main`: the segment's committed coefficient column shapes in
    /// original order (FIXED tree, MAIN tree). A column with `.device` set is
    /// supplied as a device pointer at enqueue; with `.coefficients` it is a
    /// host column staged in phase 1.
    pub fn init(a: std.mem.Allocator, catalogue: *const Sources.Catalogue, scope: Scope, instances: []const Instance, native: *const @import("stwo_riscv_cpu_integration").rv64_services_roster.Sources, fixed: []const D.Column, main: []const D.Column, byte_cap: usize, base: u32) !Plan {
        if (instances.len == 0 or instances.len > G.max_instances) return error.InvalidGeometry;
        if (instances[0].origin != .core or instances[0].origin.core != .cpu) return error.InvalidGkrSourceColumn;
        const request = Request{ .scope = scope, .instances = instances, .challenges = undefined, .sources = &.{}, .native_source = native, .native_fixed_columns = fixed, .native_main_columns = main, .source_channel = undefined, .channel = undefined, .byte_cap = byte_cap };
        var source = try Sources.Plan.init(a, request, catalogue);
        errdefer source.deinit();
        const v3 = native.core.cpu.u8_pairs;
        if (source.items[0].terms != Source.Fractions.cpuTerms(v3)) return error.InvalidGkrSourceColumn;
        const variables = try a.alloc(u32, source.items.len);
        errdefer a.free(variables);
        for (source.items, variables) |item, *v| v.* = item.log + std.math.log2_int(u32, item.lanes);
        const traversal = try G.Plan.init(variables, byte_cap);
        const relation_count: u32 = if (v3) @intCast(relations.len) else @intFromEnum(Source.Fractions.Relation.byte_pair);
        var constants: [3 + 2 * relations.len]u32 = @splat(0);
        constants[0..3].* = .{ if (v3) 0x4c474b33 else 0x4c474b31, 8, relation_count };
        for (relations[0..relation_count], 0..) |relation, i| {
            constants[3 + 2 * i] = @intCast(i);
            constants[4 + 2 * i] = @intCast(relation.arity());
        }
        const words = try instanceWords(a, instances);
        errdefer a.free(words);
        const item_offsets = try a.alloc(usize, source.items.len);
        errdefer a.free(item_offsets);
        var staged: usize = 9 + constants.len + words.len;
        for (source.items, item_offsets) |item, *offset| {
            // u64 offsets: keep each item's block 8-byte aligned.
            staged = std.mem.alignForward(usize, staged, 2);
            offset.* = staged;
            staged += 2 * item.offsets.len + Source.Public.count;
        }
        const order = try a.alloc(usize, source.columns.len);
        errdefer a.free(order);
        const logs = try a.alloc(u32, source.columns.len);
        errdefer a.free(logs);
        for (fixed, 0..) |c, i| logs[i] = c.log_size;
        for (main, 0..) |c, i| logs[fixed.len + i] = c.log_size;
        {
            var cells: usize = 0;
            for (source.columns, order) |column, *original| {
                original.* = for (source.offsets, 0..) |offset, i| {
                    if (offset == cells and logs[i] == column.log_size) break i;
                } else return error.InvalidGkrSourceColumn;
                cells += @as(usize, 1) << @intCast(column.log_size);
            }
        }
        var host_words: usize = 0;
        for (source.columns) |column| if (column.device == null) {
            host_words += @as(usize, 1) << @intCast(column.log_size);
        };
        const mixes = 1 + instance_mixes_per_instance * instances.len;
        const prefix = childPrefix(scope, instances);
        return .{ .a = a, .catalogue = catalogue, .source = source, .variables = variables, .traversal = traversal, .v3 = v3, .relation_count = relation_count, .byte_cap = byte_cap, .fixed_count = fixed.len, .constants = constants, .prefix = seedWords(prefix), .prefix_channel = prefix, .instances = words, .order = order, .logs = logs, .instance_mixes = mixes, .child_steps = @intCast(1 + mixes + 1 + 2 * relation_count), .staged_words = staged, .item_offsets = item_offsets, .twiddle_words = @as(usize, 1) << @intCast(source.max_log - 1), .host_column_words = host_words, .fields = .{ .base = base, .layers = traversal.layers } };
    }
    pub fn deinit(self: *Plan) void {
        self.source.deinit();
        self.a.free(self.variables);
        self.a.free(self.instances);
        self.a.free(self.item_offsets);
        self.a.free(self.order);
        self.a.free(self.logs);
        self.* = undefined;
    }
    /// Slab fields of the section (add to the job's ProofLayout before enqueue).
    pub fn addFields(self: *const Plan, layout: *Slab.ProofLayout) !void {
        const f = self.fields;
        _ = try layout.add(.status, f.status(), 1);
        _ = try layout.add(.gkr_section, f.header(), 20);
        _ = try layout.add(.snapshot, f.base, DC.snapshot_words);
        _ = try layout.add(.gkr_section, f.roots(), 16 * self.source.items.len);
        _ = try layout.add(.gkr_section, f.mainRoot(), 8);
        for (0..self.traversal.layers) |depth| {
            const l = self.traversal.layer[depth];
            _ = try layout.add(.gkr_section, f.records(@intCast(depth)), l.records.words);
            _ = try layout.add(.gkr_section, f.masks(@intCast(depth)), l.masks.words);
        }
    }
    pub fn slabWords(self: *const Plan) usize {
        var words: usize = 1 + 20 + DC.snapshot_words + 16 * self.source.items.len + 8;
        for (self.traversal.layer[0..self.traversal.layers]) |l| words += l.records.words + l.masks.words;
        return words;
    }
    fn parameterWords(self: *const Plan, item: Sources.Item) usize {
        return self.catalogue.artifacts[item.kernel].source_slots.len * 8;
    }
    fn fractionWords(self: *const Plan) usize {
        var words: usize = 0;
        for (self.source.items) |item| words += 9 * @as(usize, item.facts);
        return words;
    }
    /// Static device peak of enqueue (arena words, 64-word granules included):
    /// child channel, reservoir, status, parameters, fractions, then the larger
    /// of {decoded values} and {traversal workspace} (values are freed LIFO
    /// before the workspace is allocated, as the legacy stage retires them).
    pub fn enqueueWords(self: *const Plan) usize {
        const g = @import("worker.zig").Arena.granule;
        var words: usize = std.mem.alignForward(usize, DC.state_words, g) + std.mem.alignForward(usize, reservoir_felts * 8, g) + g;
        for (self.source.items) |item| {
            words += std.mem.alignForward(usize, @max(1, self.parameterWords(item)), g);
            words += std.mem.alignForward(usize, item.facts, g) + std.mem.alignForward(usize, @as(usize, item.facts) * 8, g);
        }
        return words + @max(std.mem.alignForward(usize, self.source.cells, g), std.mem.alignForward(usize, self.traversal.total_words, g));
    }
    /// Phase-1 arena words (metadata + host columns not held in a persistent region).
    pub fn stagedWords(self: *const Plan, persistent_host: bool) usize {
        const g = @import("worker.zig").Arena.granule;
        return std.mem.alignForward(usize, self.staged_words, g) + if (persistent_host or self.host_column_words == 0) 0 else std.mem.alignForward(usize, self.host_column_words, g);
    }
    /// Pinned words phase 1 needs (staged metadata, plus host columns copied
    /// into pinned memory by Stager.upload when they are not persistent-warm).
    pub fn pinnedWords(self: *const Plan) usize {
        return self.staged_words + self.host_column_words + self.twiddle_words;
    }
};

/// One segment's local GKR inside a job: `stage`, then `enqueue`; after the
/// worker's wait, `Section.read` decodes and verifies the slab fields.
pub const Gkr = struct {
    a: std.mem.Allocator,
    plan: *const Plan,
    sym: *const Symbols,
    /// Key of a worker-persistent region for the host (FIXED) columns, e.g. the
    /// FIXED root. Null stages them per job.
    host_key: ?[32]u8 = null,
    // Host scratch owned for the job's lifetime (launch packets are read at launch).
    fractions: []R.Fraction,
    packets: []Projection,
    host_offsets: []usize,
    /// Input views built at enqueue from committed trees (enqueueCommitted).
    views: []Input,
    // Phase-1 outputs.
    staged: ?api.DeviceBuffer = null,
    host_columns: ?api.DeviceBuffer = null,
    twiddles: ?api.DeviceBuffer = null,
    // Phase-2 bookkeeping for finish (child transcript guard) and later
    // consumers on the same stream (binding reads the fractions and state).
    child_steps: u32 = 0,
    child_chain: u64 = 0,
    traversal: ?G.ClosureEnqueued = null,
    reservoir: ?api.DeviceBuffer = null,
    launches: u64 = 0,

    pub fn init(a: std.mem.Allocator, plan: *const Plan, sym: *const Symbols) !Gkr {
        const fractions = try a.alloc(R.Fraction, plan.source.items.len);
        errdefer a.free(fractions);
        const packets = try a.alloc(Projection, plan.source.items.len);
        errdefer a.free(packets);
        const host_offsets = try a.alloc(usize, plan.source.columns.len);
        errdefer a.free(host_offsets);
        const views = try a.alloc(Input, plan.source.columns.len);
        return .{ .a = a, .plan = plan, .sym = sym, .fractions = fractions, .packets = packets, .host_offsets = host_offsets, .views = views };
    }
    pub fn deinit(self: *Gkr) void {
        self.a.free(self.fractions);
        self.a.free(self.packets);
        self.a.free(self.host_offsets);
        self.a.free(self.views);
        self.* = undefined;
    }

    /// Phase 1 when every column is device-resident at enqueue (the segment's
    /// own FIXED/MAIN commitments in the same job): metadata and twiddles only.
    pub fn stageCommitted(self: *Gkr, s: *api.Stager) !void {
        for (self.views) |*v| v.* = .{ .device = @ptrFromInt(@alignOf(u32)) }; // placeholders: "device at enqueue"
        try self.stage(s, self.views);
    }
    /// Phase 2 fed by the job's committed FIXED and MAIN trees (original column
    /// order, coefficient views) and the device MAIN root they produced.
    pub fn enqueueCommitted(self: *Gkr, e: *api.Enqueue, fixed_plan: anytype, fixed: anytype, main_plan: anytype, main: anytype, main_root: api.DeviceBuffer) !void {
        const p = self.plan;
        if (fixed_plan.shapes.len != p.fixed_count or fixed_plan.shapes.len + main_plan.shapes.len != self.views.len) return error.NativeGkrInputCount;
        for (self.views, 0..) |*v, i| {
            const column = if (i < p.fixed_count) fixed.column(fixed_plan, i) else main.column(main_plan, i - p.fixed_count);
            if (column.words != @as(usize, 1) << @intCast(p.logs[i])) return error.InvalidGkrSourceColumn;
            v.* = .{ .device = column.ptr };
        }
        try self.enqueue(e, self.views, main_root);
    }

    /// Phase 1: metadata (prefix checkpoint, constants, instance words, per
    /// item offsets/public values), class twiddles (persistent, keyed by the
    /// largest log) and host columns (`inputs`, original order).
    pub fn stage(self: *Gkr, s: *api.Stager, inputs: []const Input) !void {
        const p = self.plan;
        if (inputs.len != p.logs.len) return error.NativeGkrInputCount;
        const meta = try s.pinned(p.staged_words);
        @memset(meta, 0);
        meta[0..9].* = p.prefix;
        @memcpy(meta[9..][0..p.constants.len], &p.constants);
        @memcpy(meta[9 + p.constants.len ..][0..p.instances.len], p.instances);
        for (p.source.items, p.item_offsets) |item, offset| {
            @memcpy(meta[offset..][0 .. 2 * item.offsets.len], @as([*]const u32, @ptrCast(item.offsets.ptr))[0 .. 2 * item.offsets.len]);
            @memcpy(meta[offset + 2 * item.offsets.len ..][0..Source.Public.count], &item.public);
        }
        const staged = try s.alloc(p.staged_words);
        try s.upload(staged, meta);
        self.staged = staged;
        // Twiddles: the legacy GKR cache's tower for the largest log (immutable setup).
        var key: [32]u8 = @splat(0);
        @memcpy(key[0..16], "rv64-m8-gkr-twid");
        key[16] = @intCast(p.source.max_log);
        const tw = try s.persistent(key, p.twiddle_words);
        if (tw.fresh) {
            var cache = @import("../gkr_twiddles.zig").Cache{ .allocator = self.a };
            defer cache.deinit();
            var borrow = try cache.acquire(p.source.max_log);
            defer borrow.deinit();
            if (borrow.values.len != p.twiddle_words) return error.InvalidGkrTwiddles;
            try s.upload(tw.buffer, @as([*]const u32, @ptrCast(borrow.values.ptr))[0..borrow.values.len]);
        }
        self.twiddles = tw.buffer;
        var words: usize = 0;
        for (inputs, p.logs, self.host_offsets) |input, log, *offset| {
            offset.* = words;
            if (input.device != null) continue;
            if (input.host.len != @as(usize, 1) << @intCast(log)) return error.InvalidGkrSourceColumn;
            words += input.host.len;
        }
        self.host_columns = null;
        if (words != 0) {
            var fresh = true;
            const region = if (self.host_key) |hk| blk: {
                const persistent = try s.persistent(hk, words);
                fresh = persistent.fresh;
                break :blk persistent.buffer;
            } else try s.alloc(words);
            if (fresh) for (inputs, self.host_offsets) |input, offset| if (input.device == null) try s.upload(try region.slice(offset, input.host.len), input.host);
            self.host_columns = region;
        }
    }

    /// Phase 2. `main_root`: the device MAIN root (8 words) the child transcript
    /// binds; `inputs`: device column pointers (host columns were staged).
    pub fn enqueue(self: *Gkr, e: *api.Enqueue, inputs: []const Input, main_root: api.DeviceBuffer) !void {
        const p = self.plan;
        const sym = self.sym;
        const staged = self.staged orelse return error.NativeGkrNotStaged;
        const tw = self.twiddles orelse return error.NativeGkrNotStaged;
        if (inputs.len != p.logs.len or main_root.words < 8) return error.NativeGkrInputCount;
        const layout = e.slab.layout orelse return error.ProofSlabHasNoLayout;
        const ctx = e.ctx();
        const stream = e.stream();
        const f = p.fields;
        // Child transcript: child.zig begin(scope, instances), then the relation draws.
        var child = DC.DeviceChannel.init(e.worker, e.channel.exec, ctx, stream, try e.alloc(DC.state_words), 0);
        try child.initFromCheckpoint(try staged.slice(0, 9));
        try child.mixRootFromTree(main_root);
        const instance_base = 9 + p.constants.len;
        for (0..p.instance_mixes) |k| {
            const span = instanceSpan(k);
            try child.mixWords(try staged.slice(instance_base + span[0], span[1]));
        }
        const reservoir = try e.alloc(reservoir_felts * 8);
        self.reservoir = reservoir;
        try check(sym.memset(ctx, reservoir.ptr, 0, reservoir.bytes()));
        const status = try e.alloc(1);
        try check(sym.memset(ctx, status.ptr, 0, 4));
        try child.mixWords(try staged.slice(9, 3));
        for (relations[0..p.relation_count], 0..) |relation, i| {
            try child.mixWords(try staged.slice(9 + 3 + 2 * i, 2));
            const draws: u32 = 1 + if (relation == .range8) @as(u32, 0) else @as(u32, @intCast(relation.arity()));
            try child.drawSecureFelts(draws, try reservoir.slice(i * 31 * 8, draws * 8));
        }
        try child.snapshot(e.slab, (try layout.get(.snapshot, f.base)).offset);
        self.child_steps = child.step;
        self.child_chain = child.expectedChain(child.step);
        try check(sym.copy_d2d(ctx, (try e.slab.field(.gkr_section, f.mainRoot())).ptr, main_root.ptr, 32));
        // Parameters and fraction planes first, decoded values last, so the
        // values are freed LIFO ahead of the traversal workspace (the legacy
        // stage retires them at the same point).
        const params = try self.a.alloc(api.DeviceBuffer, p.source.items.len);
        defer self.a.free(params);
        for (p.source.items, self.fractions, params) |item, *fraction, *parameters| {
            parameters.* = try e.alloc(@max(1, p.parameterWords(item)));
            const numerator = try e.alloc(item.facts);
            const denominator = try e.alloc(@as(usize, item.facts) * 8);
            fraction.* = .{ .n = .{ .data = DeviceContext.slice(numerator), .stride = item.facts, .coordinates = 1 }, .d = .{ .data = DeviceContext.slice(denominator), .stride = item.facts, .coordinates = 8 }, .count = item.facts };
        }
        const values = try e.alloc(p.source.cells);
        // Ingress in sorted order (Sources.Plan offsets), device or staged host.
        var cells: usize = 0;
        for (p.source.columns, p.order) |column, original| {
            const count = @as(usize, 1) << @intCast(column.log_size);
            const from: [*]const u32 = if (inputs[original].device) |d| d else (self.host_columns orelse return error.NativeGkrNotStaged).ptr + self.host_offsets[original];
            try check(sym.copy_d2d(ctx, values.ptr + cells, from, count * 4));
            cells += count;
        }
        var launches: u32 = 0;
        for (p.source.groups) |group| {
            const count = @as(u32, 1) << @intCast(group.log - 1);
            try check(sym.n2b(values.ptr + group.offset, @as(usize, 1) << @intCast(group.log), group.log, group.count, tw.ptr + (p.twiddle_words - count), count, count, stream, &launches));
        }
        for (p.source.items, self.packets, self.fractions, params, p.item_offsets) |item, *packet, fraction, parameters, offset| {
            const artifact = &p.catalogue.artifacts[item.kernel];
            const meta = staged.ptr + offset;
            packet.* = .{ .fixed = values.ptr, .main = values.ptr, .public_values = meta + 2 * item.offsets.len, .offsets = @ptrCast(@alignCast(meta)), .parameters = parameters.ptr, .n = @ptrFromInt(fraction.n.data.address), .d = @ptrFromInt(fraction.d.data.address), .status = status.ptr, .log = item.log, .first = 0, .rows = @as(u32, 1) << @intCast(item.log) };
            try check(sym.gather(ctx, 0, reservoir.ptr, parameters.ptr, artifact.source_slots.ptr, @intCast(artifact.source_slots.len), p.relation_count, status.ptr));
            try check(sym.launch[item.kernel](stream, packet));
        }
        e.free(values);
        const workspace = try e.alloc(p.traversal.total_words);
        var device = DeviceContext{ .native = ctx };
        var commands = R.Commands(DeviceContext, N.Api){ .context = &device, .api = &sym.numerical, .lane_index = 0 };
        commands.batched_oracles = sym.batched_oracles;
        commands.batched_trees = sym.batched_trees;
        commands.batched_tail = sym.batched_tail;
        commands.batched_fold_sum = sym.batched_fold_sum;
        const traversal = try G.enqueueWithClosure(&commands, self.fractions, DeviceContext.slice(.{ .ptr = child.state, .words = 9 }), DeviceContext.slice(workspace), p.byte_cap, traversal_chain, DeviceContext.slice(status));
        self.traversal = traversal;
        self.launches = commands.launches + launches + 2 * p.source.items.len;
        // The section into the slab (the legacy compact readback, minus the host).
        const t = traversal.traversal;
        try check(sym.copy_d2d(ctx, (try e.slab.field(.status, f.status())).ptr, status.ptr, 4));
        try check(sym.copy_d2d(ctx, (try e.slab.field(.gkr_section, f.header())).ptr, @ptrFromInt(t.state.address), 20 * 4));
        try check(sym.copy_d2d(ctx, (try e.slab.field(.gkr_section, f.roots())).ptr, @ptrFromInt(t.roots.address), t.roots.len * 4));
        for (t.proof[0..t.layers], 0..) |layer, depth| {
            const records = try e.slab.field(.gkr_section, f.records(@intCast(depth)));
            const masks = try e.slab.field(.gkr_section, f.masks(@intCast(depth)));
            if (records.words != layer.records.len or masks.words != layer.masks.len) return error.NativeGkrSlabGeometry;
            if (records.words != 0) try check(sym.copy_d2d(ctx, records.ptr, @ptrFromInt(layer.records.address), records.words * 4));
            try check(sym.copy_d2d(ctx, masks.ptr, @ptrFromInt(layer.masks.address), masks.words * 4));
        }
    }
};

/// The decoded, verified local GKR section (host memory, outlives the slab view).
pub const Section = struct {
    a: std.mem.Allocator,
    status: u32,
    header: [20]u32,
    snapshot: DC.Snapshot,
    main_root: [8]u32,
    roots: []u32,
    layers: []Results.Layer,

    /// Copy the section out of the pinned view and verify it (finish-time):
    /// verdict, traversal header and the device child transcript replayed on
    /// the host from the slab's MAIN root. See the retry policy at the top.
    pub fn read(a: std.mem.Allocator, gkr: *const Gkr, view: api.SlabView) !Section {
        const p = gkr.plan;
        const f = p.fields;
        const status = (try Slab.read(view, .status, f.status()))[0];
        var header: [20]u32 = undefined;
        @memcpy(&header, try Slab.read(view, .gkr_section, f.header()));
        const snapshot = DC.Snapshot.fromWords(try Slab.read(view, .snapshot, f.base));
        var main_root: [8]u32 = undefined;
        @memcpy(&main_root, try Slab.read(view, .gkr_section, f.mainRoot()));
        const roots = try a.dupe(u32, try Slab.read(view, .gkr_section, f.roots()));
        // Until `out` owns them, partial copies are released here (exactly once).
        var owned = false;
        errdefer if (!owned) a.free(roots);
        const layers = try a.alloc(Results.Layer, p.traversal.layers);
        var made: usize = 0;
        errdefer if (!owned) {
            for (layers[0..made]) |l| {
                a.free(l.records);
                a.free(l.masks);
            }
            a.free(layers);
        };
        for (layers, 0..) |*layer, depth| {
            const records = try a.dupe(u32, try Slab.read(view, .gkr_section, f.records(@intCast(depth))));
            const masks = a.dupe(u32, try Slab.read(view, .gkr_section, f.masks(@intCast(depth)))) catch |err| {
                a.free(records);
                return err;
            };
            layer.* = .{ .records = records, .masks = masks };
            made += 1;
        }
        var out = Section{ .a = a, .status = status, .header = header, .snapshot = snapshot, .main_root = main_root, .roots = roots, .layers = layers };
        owned = true;
        errdefer out.deinit();
        try out.verify(gkr);
        return out;
    }
    pub fn verify(self: *const Section, gkr: *const Gkr) !void {
        const p = gkr.plan;
        const traversal = gkr.traversal orelse return error.NativeGkrNotEnqueued;
        try traversal.validate(@bitCast(self.header), self.status);
        // Device child transcript: guard words, then digest/draws vs host replay.
        const s = self.snapshot;
        if (s.status != 0 or s.reserved != 0 or s.cursor != gkr.child_steps or s.chain != gkr.child_chain or s.padding[0] != 0 or s.padding[1] != 0) return error.InvalidDeviceTranscript;
        const expected = expectedChild(p, self.main_root);
        if (!std.mem.eql(u32, &s.digest, expected[0..8]) or s.draws != expected[8]) return error.InvalidDeviceTranscript;
    }
    /// The unchanged native GKR proof (legacy gkr_result.zig framing).
    pub fn proof(self: *const Section, a: std.mem.Allocator, plan: *const Plan) !Proof {
        return Results.assemble(a, .{ .variables = plan.variables, .roots = self.roots, .layers = self.layers });
    }
    pub fn deinit(self: *Section) void {
        for (self.layers) |l| {
            self.a.free(l.records);
            self.a.free(l.masks);
        }
        self.a.free(self.layers);
        self.a.free(self.roots);
        self.* = undefined;
    }
};

/// Host replay of the child transcript up to the snapshot (digest[8], draws).
pub fn expectedChild(p: *const Plan, main_root: [8]u32) [9]u32 {
    var ch = p.prefix_channel;
    ch.mixU32s(&main_root);
    mixInstancesHost(&ch, p.instances);
    drawRelationsHost(&ch, p.v3);
    return seedWords(ch);
}

/// A standalone local-GKR job (used by the real-block parity harness and as a
/// scheduler node when a segment's GKR is split from its MAIN commit). The MAIN
/// root is either a device buffer known at enqueue or 8 host words staged here.
pub const GkrJob = struct {
    gkr: Gkr,
    inputs: []const Input,
    main_root_host: ?[8]u32 = null,
    main_root_device: ?api.DeviceBuffer = null,
    layout: Slab.ProofLayout = .{},
    staged_root: ?api.DeviceBuffer = null,
    section: ?Section = null,
    failure: ?anyerror = null,

    pub fn init(a: std.mem.Allocator, plan: *const Plan, sym: *const Symbols, inputs: []const Input) !GkrJob {
        var out = GkrJob{ .gkr = try Gkr.init(a, plan, sym), .inputs = inputs };
        errdefer out.gkr.deinit();
        try plan.addFields(&out.layout);
        return out;
    }
    pub fn deinit(self: *GkrJob) void {
        if (self.section) |*s| s.deinit();
        self.gkr.deinit();
        self.* = undefined;
    }
    pub fn classKey(self: *GkrJob) [32]u8 {
        return classKeyOf(self.gkr.plan);
    }
    pub fn footprint(self: *GkrJob) api.Footprint {
        const p = self.gkr.plan;
        const staged = p.stagedWords(self.gkr.host_key != null) + 64;
        return .{ .device_words = staged + p.enqueueWords(), .staged_words = staged, .slab_words = self.layout.words, .pinned_words = p.pinnedWords() + 8 };
    }
    pub fn stage(self: *GkrJob, s: *api.Stager) !void {
        try self.gkr.stage(s, self.inputs);
        if (self.main_root_host) |root| {
            const b = try s.alloc(8);
            try s.upload(b, &root);
            self.staged_root = b;
        }
    }
    pub fn enqueue(self: *GkrJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const root = self.main_root_device orelse self.staged_root orelse return error.NativeGkrMainRootMissing;
        try self.gkr.enqueue(e, self.inputs, root);
    }
    pub fn finish(self: *GkrJob, view: api.SlabView) !void {
        self.section = Section.read(self.gkr.a, &self.gkr, view) catch |err| {
            self.failure = err;
            return err;
        };
    }
    pub fn abort(_: *GkrJob) void {}
};

/// Class key: the segment's static GKR geometry (kernels, logs, facts, cells).
pub fn classKeyOf(p: *const Plan) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-native-gkr-v1");
    h.update(std.mem.sliceAsBytes(p.variables));
    h.update(std.mem.sliceAsBytes(p.logs));
    for (p.source.items) |item| h.update(std.mem.asBytes(&[_]u32{ item.kernel, item.log, item.facts, item.lanes }));
    return h.finalResult();
}

test "child transcript split at the MAIN root replays child.zig begin exactly" {
    const a = std.testing.allocator;
    const instances = [_]Instance{
        .{ .origin = .{ .core = .cpu }, .row_log = 20, .terms = 14, .fixed_offset = 3, .main_offset = 0 },
        .{ .origin = .{ .bridge = @enumFromInt(0) }, .row_log = 12, .terms = 5, .fixed_offset = (1 << 33) + 7, .main_offset = 400 },
    };
    const scope = Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 5 };
    var split = childPrefix(scope, &instances);
    split.mixU32s(&rootWords(scope.main));
    const words = try instanceWords(a, &instances);
    defer a.free(words);
    mixInstancesHost(&split, words);
    const reference = Child.begin(scope, &instances);
    try std.testing.expectEqualSlices(u8, &reference.inner.digest, &split.inner.digest);
    try std.testing.expectEqual(reference.inner.n_draws, split.inner.n_draws);
}

test "v3 header tag follows frame.zig (bulk/dword/sponge or a post-v2 bridge)" {
    const v2 = [_]Instance{.{ .origin = .{ .core = .cpu }, .row_log = 20, .terms = 14, .fixed_offset = 0, .main_offset = 0 }};
    const v3 = [_]Instance{ v2[0], .{ .origin = .{ .dword = 0 }, .row_log = 10, .terms = 4, .fixed_offset = 0, .main_offset = 0 } };
    for ([_][]const Instance{ &v2, &v3 }) |set| {
        const scope = Scope{ .statement = @splat(9), .fixed = @splat(8), .main = @splat(7), .ordinal = 1 };
        var split = childPrefix(scope, set);
        split.mixU32s(&rootWords(scope.main));
        const words = try instanceWords(std.testing.allocator, set);
        defer std.testing.allocator.free(words);
        mixInstancesHost(&split, words);
        try std.testing.expectEqualSlices(u8, &Child.begin(scope, set).inner.digest, &split.inner.digest);
    }
}

test "instance mixes cover the instance list in begin order" {
    try std.testing.expectEqual([2]usize{ 0, 1 }, instanceSpan(0));
    try std.testing.expectEqual([2]usize{ 1, 2 }, instanceSpan(1));
    try std.testing.expectEqual([2]usize{ 7, 2 }, instanceSpan(4));
    try std.testing.expectEqual([2]usize{ 9, 2 }, instanceSpan(5));
}

test "slab fields of a section are namespaced by base and sized by the traversal plan" {
    const fields = Fields{ .base = 100, .layers = 3 };
    try std.testing.expectEqual(@as(u32, 100), fields.header());
    try std.testing.expectEqual(@as(u32, 101), fields.roots());
    try std.testing.expectEqual(@as(u32, 103), fields.records(0));
    try std.testing.expectEqual(@as(u32, 108), fields.masks(2));
}

test "local GKR job path is fully analyzed (stage, enqueue, finish, job adapter)" {
    _ = &Symbols.load;
    _ = &Plan.init;
    _ = &Plan.deinit;
    _ = &Plan.addFields;
    _ = &Gkr.stage;
    _ = &Gkr.enqueue;
    _ = &Section.read;
    _ = &Section.proof;
    _ = &GkrJob.init;
    _ = &GkrJob.deinit;
    _ = &api.Job.from(GkrJob, undefined).vtable;
}
