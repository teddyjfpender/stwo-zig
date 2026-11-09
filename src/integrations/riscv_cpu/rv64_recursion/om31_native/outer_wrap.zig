//! Actual native-OM31 circuit proving, independent fresh reception and bounded
//! serialization. This owns immutable topology and proof material together.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31.prove;
const Wire = @import("stwo_circuit_cpu_integration").om31.wire;
pub const Device = @import("stwo_circuit_cpu_integration").om31.device_prove;
const C = @import("common.zig");
const PP = circuit.common.preprocessed.PreprocessedCircuit;
const Finalize = circuit.common.finalize;
const CachePack = @import("stwo_circuit_cpu_integration").om31.cache_pack;
const CacheUnpack = @import("stwo_circuit_cpu_integration").om31.cache_unpack;
const HybridKey = @import("../../outer_gkr/hybrid_receiver.zig").Key;
const HybridSection = @import("../../outer_gkr/section.zig").Section;
const HybridDevice = @import("../../outer_gkr/hybrid_device.zig");
const HybridCpu = @import("../../outer_gkr/hybrid_cpu.zig");
const HybridWire = @import("../../outer_gkr/hybrid_wire.zig");
pub const HybridPayload = struct {
    key: *HybridKey,
    section: HybridSection,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.section.deinit(a);
        self.key.deinit();
        a.destroy(self.key);
        self.* = undefined;
    }
};
pub fn hybridProfileActive() bool {
    if (comptime @hasDecl(@import("stwo_circuit_cpu_integration").om31.protocol.Profile, "hybrid")) return @import("stwo_circuit_cpu_integration").om31.protocol.active().hybrid();
    return false;
}
pub fn requireHybridProofBudget(total_nodes: usize) !void {
    if (total_nodes == 0 or total_nodes > 256) return error.OuterGkrProofBudget;
}
/// Outer shape versions (canon-vk M5; binding note §1 `S_out`). The shape is
/// a function of the outer profile: the M5 canonical profiles
/// (`Profile.canonical()`) use `uniform_v1`, every other profile `exact`.
/// `STWO_RV64_OUTER_SHAPE` may only restate that (or force `uniform-v1` on a
/// non-canonical profile for diagnostics); `exact` under a canonical profile
/// is refused.
/// - `exact`: every gate component is padded to the next power of
///   two of its own row count, as in M4 (bytes unchanged).
/// - `uniform_v1`: every recursion node (leaf and fold) is padded to the one
///   shape `S_OUT_V1`. A fold's topology is a function of its children's
///   shapes (fold v2 `classKey`), so with one shape a fold circuit depends
///   only on its arity: one fold VK per arity, derivable without any block.
///   A node whose exact shape exceeds `S_OUT_V1` fails closed
///   (`ComponentExceedsTarget`). Padding only appends the builder's own
///   padding gates; the padded sizes enter the preprocessed circuit, hence
///   the FIXED root and authority identity, so producer and receiver must
///   select the same shape (a mismatch is an authority mismatch).
/// - `set_v2` (diagnostic, non-canonical profiles only; binding note §1
///   fallback generalised): every node is padded to the FIRST shape of
///   `SHAPE_SET_V2` that dominates its exact shape. A fold's topology is a
///   function of its children's shapes, so the binary fold classes are the
///   ordered pairs over 3 shapes (<= 9; 4-ary <= 81): still a constant set per
///   build. [D] tax +2.1% cells vs +18.7% for uniform-v1 on both dev blocks.
pub const Shape = enum {
    exact,
    uniform_v1,
    set_v2,
    pub fn parse(text: []const u8) !Shape {
        if (std.mem.eql(u8, text, "exact")) return .exact;
        if (std.mem.eql(u8, text, "uniform-v1")) return .uniform_v1;
        if (std.mem.eql(u8, text, "set-v2")) return .set_v2;
        return error.UnknownOm31OuterShape;
    }
};
const LogShape = struct { eq: u32, qm31_ops: u32, triple_xor: u32, m31_to_u32: u32, blake_g_gate: u32 };
/// Fixed order (ascending estimated cells): small leaf, fold, big leaf = S_OUT_V1.
/// From the RECURSION_NODE_SHAPE census of both dev blocks (54 nodes).
pub const SHAPE_SET_V2 = [_]LogShape{
    .{ .eq = 18, .qm31_ops = 23, .triple_xor = 19, .m31_to_u32 = 20, .blake_g_gate = 22 },
    .{ .eq = 15, .qm31_ops = 22, .triple_xor = 19, .m31_to_u32 = 20, .blake_g_gate = 23 },
    .{ .eq = 18, .qm31_ops = 23, .triple_xor = 20, .m31_to_u32 = 21, .blake_g_gate = 23 },
};
pub const SHAPE_ENV = "STWO_RV64_OUTER_SHAPE";
/// Elementwise maximum of the 33 node shapes of 24628607 (diet census
/// `24628607-cell-census-q108.json`, leaf-dominated): log2 rows of eq,
/// qm31_ops, triple_xor, m31_to_u32, blake_g_gate. [D] tax +19.5% cells.
pub const S_OUT_V1 = struct { eq: u32 = 18, qm31_ops: u32 = 23, triple_xor: u32 = 20, m31_to_u32: u32 = 21, blake_g_gate: u32 = 23 }{};
var shape_selected = std.atomic.Value(u8).init(0xff);
/// Process-wide; resolved once from `STWO_RV64_OUTER_SHAPE` (default exact).
/// Unknown or unreadable values fail closed.
pub fn shape() Shape {
    const current = shape_selected.load(.acquire);
    if (current != 0xff) return @enumFromInt(current);
    // Entry points call checkShapeEnv first (clean exit); this is the backstop.
    const resolved = checkShapeEnv() catch @panic("invalid STWO_RV64_OUTER_SHAPE for the outer profile");
    _ = shape_selected.cmpxchgStrong(0xff, @intFromEnum(resolved), .acq_rel, .acquire);
    return @enumFromInt(shape_selected.load(.acquire));
}
/// Fallible resolution of the outer shape from the profile and the env.
pub fn checkShapeEnv() !Shape {
    const canonical = @import("stwo_circuit_cpu_integration").om31.protocol.active().canonical();
    var buffer: [32]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const requested: ?Shape = if (std.process.getEnvVarOwned(fba.allocator(), SHAPE_ENV)) |text|
        try Shape.parse(text)
    else |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return error.UnreadableOm31OuterShape,
    };
    if (canonical) {
        if (requested != null and requested.? != .uniform_v1) return error.CanonicalOuterProfileRequiresUniformShape;
        return .uniform_v1;
    }
    return requested orelse .exact;
}
/// The padding targets of one finalized recursion graph under `shape()`.
pub fn paddingTargets(ctx: *const C.Context) !Finalize.ComponentSizes {
    const exact = Finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
    return switch (shape()) {
        .exact => exact,
        // padToTargets refuses a component above its target.
        .uniform_v1 => Finalize.ComponentSizes.fromLogSizes(S_OUT_V1),
        .set_v2 => for (SHAPE_SET_V2) |candidate| {
            const target = Finalize.ComponentSizes.fromLogSizes(candidate);
            if (exact.eq <= target.eq and exact.qm31_ops <= target.qm31_ops and exact.triple_xor <= target.triple_xor and exact.m31_to_u32 <= target.m31_to_u32 and exact.blake_g_gate <= target.blake_g_gate) break target;
        } else error.OuterShapeSetExceeded,
    };
}
/// Log-only census line: raw and padded component rows of one node.
pub fn reportShape(label: []const u8, id: usize, raw: Finalize.ComponentSizes, ctx: *const C.Context) void {
    const padded = Finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
    std.debug.print("RECURSION_NODE_SHAPE node={d} kind={s} shape={s} raw=[{d},{d},{d},{d},{d}] padded=[{d},{d},{d},{d},{d}]\n", .{ id, label, @tagName(shape()), raw.eq, raw.qm31_ops, raw.triple_xor, raw.m31_to_u32, raw.blake_g_gate, padded.eq, padded.qm31_ops, padded.triple_xor, padded.m31_to_u32, padded.blake_g_gate });
}
pub const Timings = struct {
    preprocess_ns: u64,
    prove_ns: u64,
    verify_ns: u64,
    restore_ns: u64 = 0,
    // Host-only setup attribution; never enters a proof or authority identity.
    finalize_ns: u64 = 0,
    preprocessed_columns_ns: u64 = 0,
    authority_ns: u64 = 0,
};
pub const Wrapped = struct {
    allocator: std.mem.Allocator,
    pp: *PP,
    authority: *Outer.Authority,
    produced: Outer.Produced,
    capture: Outer.Capture,
    digest: [32]u8,
    timings: Timings,
    hybrid: ?HybridPayload = null,
    restored: bool = false,
    /// PP/Authority owned by a class cache (fold v2); never freed here.
    borrowed: bool = false,
    /// PP only is owned by the producer PPCache (fold v2); authority is owned.
    borrowed_pp: bool = false,
    pub fn deinit(self: *Wrapped) void {
        self.capture.deinit(self.allocator);
        if (self.hybrid) |*extra| extra.deinit(self.allocator);
        self.produced.deinit();
        if (self.borrowed) {
            self.* = undefined;
            return;
        }
        self.authority.deinit();
        self.allocator.destroy(self.authority);
        if (!self.borrowed_pp) {
            self.pp.deinit(self.allocator);
            self.allocator.destroy(self.pp);
        }
        self.* = undefined;
    }
    pub fn serialize(self: *const Wrapped, a: std.mem.Allocator) ![]u8 {
        if (self.hybrid) |*extra| return HybridWire.encode(a, extra.key, self.produced.outputs, self.produced.claims, &extra.section, &self.produced.proof.proof);
        return Wire.encode(a, self.authority.identity, self.produced.outputs, self.produced.claims, &self.produced.proof.proof);
    }
    pub fn effectiveIdentity(self: *const Wrapped) [32]u8 {
        return if (self.hybrid) |extra| extra.key.identity else self.authority.identity;
    }
    pub fn verifyFresh(self: *const Wrapped, a: std.mem.Allocator) !Outer.Capture {
        if (self.hybrid) |*extra| {
            if (extra.key.source != self.authority) return error.InvalidHybridChildAuthority;
            return extra.key.verify(a, self.produced.outputs, self.produced.claims, &extra.section, &self.produced.proof.proof);
        }
        return Outer.verify(a, self.authority, self.produced.outputs, self.produced.claims, &self.produced.proof.proof);
    }
    pub fn asChild(self: *const Wrapped) @import("../om31_outer.zig").Child {
        return .{ .authority = self.authority, .produced = &self.produced, .capture = &self.capture, .hybrid = if (self.hybrid) |*extra| .{ .key = extra.key, .section = &extra.section } else null };
    }
    /// Call after fresh verification and durable serialization. A parent needs
    /// the child's original verifier metadata and proof, not its wide proving
    /// setup. Repeated calls are harmless; proving again is explicitly refused.
    pub fn retireProverData(self: *Wrapped) usize {
        if (self.authority.retired) return 0;
        self.authority.retireProverData();
        // A class-cached PP is shared by later folds of its class.
        if (self.borrowed_pp or self.borrowed) return 0;
        var bytes: usize = 0;
        for (&self.pp.columns) |*column| {
            bytes += column.values.len * @sizeOf(@import("stwo_core").fields.m31.M31);
            self.allocator.free(column.values);
            column.values = &.{};
        }
        return bytes;
    }
};
/// Producer-only, in-process fold v2 PP cache: a fold's preprocessed circuit is
/// a function of its geometry class (om31_outer.classKey), so later folds of a
/// class reuse the immutable PP instead of rebuilding columns. Proof-neutral:
/// the device precommit of an equal PP yields an equal FIXED root, and the
/// receiver independently rebuilds every authority. =check rebuilds and
/// compares column bytes; =0 disables. Not used by receivers.
pub const PPCache = struct {
    pub const Mode = enum { off, on, check };
    const gpa = std.heap.smp_allocator;
    const PackedPP = struct {
        meta: PP,
        columns: [@import("stwo_circuit_frontend").common.preprocessed.N_PREPROCESSED_COLUMNS]CachePack.Packed,
        fn destroy(self: *PackedPP) void {
            for (&self.columns) |*column| column.deinit(gpa);
            gpa.destroy(self);
        }
        fn unpack(self: *const PackedPP, a: std.mem.Allocator) !*PP {
            const pp = try a.create(PP);
            errdefer a.destroy(pp);
            pp.* = self.meta;
            var done: usize = 0;
            errdefer for (pp.columns[0..done]) |column| a.free(column.values);
            for (&pp.columns, self.columns) |*column, encoded| {
                column.values = try a.alloc(@import("stwo_core").fields.m31.M31, encoded.words);
                done += 1;
                try CacheUnpack.unpack(encoded, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values)));
            }
            return pp;
        }
    };
    const Entry = struct { key: [32]u8, pp: ?*PP = null, encoded: ?*PackedPP = null, bytes: usize };
    pub const Lease = struct {
        pp: *PP,
        borrowed: bool,
        fn deinit(self: Lease, a: std.mem.Allocator) void {
            if (!self.borrowed) {
                self.pp.deinit(a);
                a.destroy(self.pp);
            }
        }
    };
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayListUnmanaged(Entry) = .empty;
    var held_bytes: usize = 0;
    pub fn mode() Mode {
        const value = std.posix.getenv("STWO_RV64_OUTER_PP_CLASS_CACHE") orelse return .on;
        if (std.mem.eql(u8, value, "0")) return .off;
        if (std.mem.eql(u8, value, "check")) return .check;
        return .on;
    }
    fn limit() usize {
        const value = std.posix.getenv("STWO_RV64_OUTER_PP_CLASS_CACHE_BYTES") orelse return 6 << 30;
        return std.fmt.parseUnsigned(usize, value, 10) catch 6 << 30;
    }
    fn find(key: [32]u8) ?*PP {
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |e| if (std.mem.eql(u8, &e.key, &key)) return e.pp;
        return null;
    }
    fn contains(key: [32]u8) bool {
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |e| if (std.mem.eql(u8, &e.key, &key)) return true;
        return false;
    }
    fn acquire(a: std.mem.Allocator, key: [32]u8) !?Lease {
        mutex.lock();
        const hit: ?Entry = for (entries.items) |e| {
            if (std.mem.eql(u8, &e.key, &key)) break e;
        } else null;
        mutex.unlock();
        const e = hit orelse return null;
        if (e.pp) |pp| return .{ .pp = pp, .borrowed = true };
        var timer = try std.time.Timer.start();
        const pp = try e.encoded.?.unpack(a);
        std.debug.print("GPU_OUTER_PP_PACK unpack class={x} logical_bytes={} physical_bytes={} ns={}\n", .{ key[0..8], bytesOf(pp), e.bytes, timer.read() });
        return .{ .pp = pp, .borrowed = false };
    }
    fn bytesOf(pp: *const PP) usize {
        var bytes: usize = 0;
        for (pp.columns) |column| bytes += column.values.len * @sizeOf(@import("stwo_core").fields.m31.M31);
        return bytes;
    }
    fn equal(left: *const PP, right: *const PP) bool {
        if (left.n_outputs != right.n_outputs or left.first_permutation_row != right.first_permutation_row) return false;
        for (left.columns, right.columns) |l, r| if (!std.mem.eql(u8, l.id, r.id) or !std.mem.eql(u8, std.mem.sliceAsBytes(l.values), std.mem.sliceAsBytes(r.values))) return false;
        return true;
    }
    /// Clones `pp` into cache-owned memory (first fold of a class only).
    fn adopt(key: [32]u8, pp: *const PP) void {
        adoptImpl(key, pp) catch |err| std.debug.print("GPU_OUTER_PP_CLASS adopt_error={s}\n", .{@errorName(err)});
    }
    fn adoptImpl(key: [32]u8, pp: *const PP) !void {
        if (CachePack.compressClass(Device.class_is_leaf)) return adoptPacked(key, pp);
        const bytes = bytesOf(pp);
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |e| if (std.mem.eql(u8, &e.key, &key)) return;
        if (held_bytes + bytes > limit()) return;
        const copy = try gpa.create(PP);
        errdefer gpa.destroy(copy);
        copy.* = pp.*;
        var done: usize = 0;
        errdefer for (copy.columns[0..done]) |column| gpa.free(column.values);
        for (&copy.columns, pp.columns) |*out, column| {
            out.values = try gpa.dupe(@import("stwo_core").fields.m31.M31, column.values);
            done += 1;
        }
        try entries.append(gpa, .{ .key = key, .pp = copy, .bytes = bytes });
        held_bytes += bytes;
    }
    fn adoptPacked(key: [32]u8, pp: *const PP) !void {
        mutex.lock();
        const exists = for (entries.items) |e| {
            if (std.mem.eql(u8, &e.key, &key)) break true;
        } else false;
        mutex.unlock();
        if (exists) return;
        var timer = try std.time.Timer.start();
        const copy = try gpa.create(PackedPP);
        errdefer gpa.destroy(copy);
        copy.meta = pp.*;
        var done: usize = 0;
        errdefer for (copy.columns[0..done]) |*column| column.deinit(gpa);
        var bytes: usize = @sizeOf(PackedPP);
        for (&copy.columns, pp.columns) |*out, column| {
            out.* = try CachePack.pack(gpa, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values)), 1);
            done += 1;
            bytes += out.heldBytes();
        }
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |e| if (std.mem.eql(u8, &e.key, &key)) {
            copy.destroy();
            return;
        };
        if (held_bytes + bytes > limit()) {
            copy.destroy();
            std.debug.print("GPU_OUTER_PP_PACK refused=cap class={x} physical_bytes={} held_bytes={}\n", .{ key[0..8], bytes, held_bytes });
            return;
        }
        try entries.append(gpa, .{ .key = key, .encoded = copy, .bytes = bytes });
        held_bytes += bytes;
        std.debug.print("GPU_OUTER_PP_PACK adopt class={x} logical_bytes={} physical_bytes={} held_bytes={} classes={} ns={}\n", .{ key[0..8], bytesOf(pp), bytes, held_bytes, entries.items.len, timer.read() });
    }
};
/// Context must already be finalized by its concrete statement authority. Padding follows its exact graph counts; no external registry or legacy
/// profile is accepted here.
pub fn wrapGraph(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8) !Wrapped {
    return wrapGraphOrLoad(a, ctx, digest, null);
}
/// Restore only after independently rebuilding this graph's PP and Authority.
/// Encoded authority is never admitted; decode and fresh verification bind the
/// bytes to the receiver-derived topology and expected public digest.
pub fn wrapGraphOrLoad(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, encoded: ?[]const u8) !Wrapped {
    return wrapGraphOrLoadWithFactory(a, ctx, digest, encoded, 0, null);
}
/// Explicit device selection is terminal on refusal; cached bytes still use
/// independent native reception and never invoke a proving backend.
pub fn wrapGraphOrLoadWithFactory(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, encoded: ?[]const u8, ordinal: u32, factory: ?Device.Factory) !Wrapped {
    return wrapGraphInternal(a, ctx, digest, encoded, ordinal, factory, false);
}

/// The caller owns a disposable CPU graph. Keep its assignments for witness
/// generation but retire the gate arrays once preprocessed columns own the
/// topology. The context remains valid for deinit on both success and error.
pub fn wrapDisposableCpuGraph(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, ordinal: u32) !Wrapped {
    return wrapDisposableCpuGraphOrLoad(a, ctx, digest, null, ordinal);
}
/// Disposable CPU graph, including independently verified restore. Assignment
/// consumption and topology retirement never apply to device factories.
pub fn wrapDisposableCpuGraphOrLoad(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, encoded: ?[]const u8, ordinal: u32) !Wrapped {
    return wrapGraphInternal(a, ctx, digest, encoded, ordinal, null, true);
}
fn retireTopology(ctx: *C.Context, retire: bool) void {
    if (retire and !@import("topology_fingerprint.zig").enabled()) {
        ctx.circuit.deinit(ctx.gpa);
        ctx.circuit = .{};
        _ = ctx.scratch_arena.reset(.free_all);
    }
}

fn wrapGraphInternal(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, encoded: ?[]const u8, ordinal: u32, factory: ?Device.Factory, retire_topology: bool) !Wrapped {
    defer if (retire_topology) ctx.value_table.clearAndFree(ctx.gpa);
    if (hybridProfileActive()) return wrapHybridGraphOrLoad(a, ctx, digest, encoded, ordinal, factory, retire_topology);
    if (ctx.circuit.output.items.len != 9) return error.CurrentOm31OutputCount;
    if (ctx.trace_only and encoded == null and (factory == null or factory.?.prepare_from_circuit == null)) return error.TraceOnlySourceRequired;
    if (!ctx.trace_only and !try ctx.isCircuitValid()) return error.CurrentOm31LeafRejects;
    var timer = try std.time.Timer.start();
    try circuit.common.finalize.padToTargets(C.Q, ctx, try paddingTargets(ctx));
    const finalize_ns = timer.read();
    // Fold v2 producer only: class-keyed immutable PP reuse (device precommit).
    const class: ?[32]u8 = if (ctx.trace_only and encoded == null and factory != null and factory.?.precommit_fixed != null) Device.class_hint else null;
    const pp_mode = PPCache.mode();
    const cached_pp: ?*PP = if (class != null and pp_mode == .on) PPCache.find(class.?) else null;
    const pp: *PP = if (cached_pp) |shared| shared else blk: {
        const owned = try a.create(PP);
        errdefer a.destroy(owned);
        owned.* = try PP.fromBuilderCircuit(a, &ctx.circuit);
        break :blk owned;
    };
    errdefer if (cached_pp == null) {
        pp.deinit(a);
        a.destroy(pp);
    };
    if (class) |key| if (pp_mode == .check) if (PPCache.find(key)) |shared| {
        if (!PPCache.equal(shared, pp)) return error.PPClassMismatch;
        std.debug.print("GPU_OUTER_PP_CLASS check_ok class={x}\n", .{key[0..8]});
    };
    if (cached_pp != null) std.debug.print("GPU_OUTER_PP_CLASS hit=true class={x}\n", .{class.?[0..8]});
    retireTopology(ctx, retire_topology);
    const columns_end_ns = timer.read();
    const authority = try a.create(Outer.Authority);
    errdefer a.destroy(authority);
    // Cached reception always rebuilds the CPU fixed authority. Only new
    // explicitly selected device proofs may use trusted device precommit.
    var precommitted: ?Device.PrecommittedFixed = if (ctx.trace_only and encoded == null and factory != null and factory.?.precommit_fixed != null)
        try factory.?.precommit_fixed.?(factory.?.context, a, pp, ordinal)
    else
        null;
    defer if (precommitted) |fixed| fixed.release(fixed.context);
    authority.* = if (precommitted) |fixed| try Outer.Authority.initForDeviceProver(a, pp, fixed.tree.root) else try Outer.Authority.init(a, pp);
    errdefer authority.deinit();
    const preprocess_ns = timer.lap();
    const columns_ns = columns_end_ns - finalize_ns;
    const authority_ns = preprocess_ns - columns_end_ns;
    if (factory != null) std.log.info("CUDA_OUTER_PREPROCESS ordinal={d} finalize_ns={d} columns_ns={d} authority_ns={d} total_ns={d} fixed_setup_backend={s}", .{ ordinal, finalize_ns, columns_ns, authority_ns, preprocess_ns, if (precommitted != null) @as([]const u8, "device_candidate") else "cpu" });
    if (@import("topology_fingerprint.zig").enabled()) {
        var label: [48]u8 = undefined;
        @import("topology_fingerprint.zig").report(ctx, try std.fmt.bufPrint(&label, "node-{d:0>4}", .{ordinal}), "padded");
        std.debug.print("TOPOLOGY_AUTHORITY node={d} identity={x} fixed_root={x} vars={d} row_logs={any}\n", .{ ordinal, authority.identity, authority.fixedRoot(), ctx.circuit.n_vars, authority.logs.toArray() });
    }
    if (factory != null) std.log.info("CUDA_OUTER_AUTHORITY ordinal={d} vars={d} row_logs={any}", .{ ordinal, ctx.circuit.n_vars, authority.logs.toArray() });
    var produced = if (encoded) |bytes| blk: {
        var decoded = try Wire.decode(a, authority.identity, 8, bytes);
        errdefer decoded.deinit();
        // The prover-only auxiliary caches are not part of the native proof.
        // Restored proofs need no such caches; all containers are owned-safe
        // empty values so Produced.deinit remains the single cleanup path.
        break :blk Outer.Produced{ .allocator = a, .outputs = decoded.outputs, .claims = decoded.claims, .proof = .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = .{ .items = &.{} }, .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } } };
    } else if (factory) |gpu| blk: {
        if (!ctx.trace_only) break :blk try Device.prove(a, authority, ctx.values(), ordinal, gpu);
        var expected: [8]C.Q = undefined;
        for (&expected, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
        if (precommitted) |*fixed| break :blk try Device.proveFromPrecommittedCircuit(a, authority, ctx, &expected, ordinal, fixed);
        break :blk try Device.proveFromCircuit(a, authority, ctx, &expected, ordinal, gpu);
    } else if (retire_topology) try Outer.proveDisposableContext(a, authority, ctx) else try Outer.prove(a, authority, ctx.values());
    errdefer produced.deinit();
    const source_ns = timer.lap();
    try requireDigest(produced.outputs, digest);
    var capture = try Outer.verify(a, authority, produced.outputs, produced.claims, &produced.proof.proof);
    errdefer capture.deinit(a);
    // Adopt only after a complete, freshly verified proof under this PP.
    if (class) |key| if (cached_pp == null and pp_mode != .off) PPCache.adopt(key, pp);
    return .{ .allocator = a, .pp = pp, .authority = authority, .produced = produced, .capture = capture, .digest = digest, .restored = encoded != null, .borrowed_pp = cached_pp != null, .timings = .{ .preprocess_ns = preprocess_ns, .finalize_ns = finalize_ns, .preprocessed_columns_ns = columns_ns, .authority_ns = authority_ns, .prove_ns = if (encoded != null) 0 else source_ns, .verify_ns = timer.lap(), .restore_ns = if (encoded != null) source_ns else 0 } };
}
/// Receiver-only fold v2 path: restore and freshly verify `encoded` under a
/// class authority the receiver itself built (from an honest trace-only graph
/// of the same geometry class). No producer byte selects the authority; the
/// digest check binds the guessed child identity/FIXED root words.
pub fn restoreWithAuthority(a: std.mem.Allocator, pp: *PP, authority: *Outer.Authority, digest: [32]u8, encoded: []const u8) !Wrapped {
    if (hybridProfileActive()) {
        const expected = digestOutputs(digest);
        return restoreForOutputs(a, pp, authority, &expected, digest, encoded, true);
    }
    var timer = try std.time.Timer.start();
    // Ownership moves from `decoded` to `produced`; exactly one errdefer may
    // be live (a function-scope `decoded` errdefer double-freed on rejection).
    var produced = blk: {
        const decoded = try Wire.decode(a, authority.identity, 8, encoded);
        break :blk Outer.Produced{ .allocator = a, .outputs = decoded.outputs, .claims = decoded.claims, .proof = .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = .{ .items = &.{} }, .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } } };
    };
    errdefer produced.deinit();
    const restore_ns = timer.lap();
    try requireDigest(produced.outputs, digest);
    var capture = try Outer.verify(a, authority, produced.outputs, produced.claims, &produced.proof.proof);
    errdefer capture.deinit(a);
    return .{ .allocator = a, .pp = pp, .authority = authority, .produced = produced, .capture = capture, .digest = digest, .restored = true, .borrowed = true, .timings = .{ .preprocess_ns = 0, .prove_ns = 0, .restore_ns = restore_ns, .verify_ns = timer.lap() } };
}
/// Fresh receiver path with source-pinned public output count and an explicit
/// proof family. No byte in the envelope selects its authority or family.
pub fn restoreForOutputs(a: std.mem.Allocator, pp: *PP, authority: *Outer.Authority, expected: []const C.Q, digest: [32]u8, encoded: []const u8, hybrid: bool) !Wrapped {
    if (expected.len != pp.n_outputs or authority.pp != pp) return error.CurrentOm31OutputCount;
    var timer = try std.time.Timer.start();
    var payload: ?HybridPayload = null;
    errdefer if (payload) |*extra| extra.deinit(a);
    const decoded = if (hybrid) blk: {
        const key = try a.create(HybridKey);
        errdefer a.destroy(key);
        key.* = try HybridKey.init(a, authority, 256);
        errdefer key.deinit();
        const result = try HybridWire.decode(a, key, encoded);
        payload = .{ .key = key, .section = result.section };
        break :blk result.base;
    } else try Wire.decode(a, authority.identity, expected.len, encoded);
    var produced = Outer.Produced{ .allocator = a, .outputs = decoded.outputs, .claims = decoded.claims, .proof = .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = .{ .items = &.{} }, .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } } };
    errdefer produced.deinit();
    const restore_ns = timer.lap();
    try requireOutputs(produced.outputs, expected);
    var capture = if (payload) |*extra| try extra.key.verify(a, produced.outputs, produced.claims, &extra.section, &produced.proof.proof) else try Outer.verify(a, authority, produced.outputs, produced.claims, &produced.proof.proof);
    errdefer capture.deinit(a);
    return .{ .allocator = a, .pp = pp, .authority = authority, .produced = produced, .capture = capture, .hybrid = payload, .digest = digest, .restored = true, .borrowed = true, .timings = .{ .preprocess_ns = 0, .prove_ns = 0, .restore_ns = restore_ns, .verify_ns = timer.lap() } };
}
// ---------------------------------------------------------------------------
// Staged form of wrapGraphOrLoadWithFactory for NEW trace-only device proofs.
// The three stages execute exactly the same operations in exactly the same
// order on the same graph as the monolithic function; only the thread that
// runs each stage changes. Host prep is device-free and may run on any thread
// ahead of device admission. Proof bytes are therefore unchanged.
// ---------------------------------------------------------------------------

/// Device-free host stage output: padded graph (mutated in place), owned
/// preprocessed columns, the root-independent device authority and an
/// optional factory-owned assignment plan.
pub const HostPrep = struct {
    pp: ?*PP,
    /// `pp` is owned by the producer PPCache (one per fold class); never freed here.
    pp_borrowed: bool = false,
    authority: ?Outer.Authority.DevicePrepared = null,
    host: ?Device.HostPrepared = null,
    finalize_ns: u64 = 0,
    columns_ns: u64 = 0,
    authority_ns: u64 = 0,
    host_plan_ns: u64 = 0,
    pub fn deinit(self: *HostPrep, a: std.mem.Allocator) void {
        if (self.host) |h| h.destroy(h.context);
        self.host = null;
        if (self.authority) |*authority| authority.deinit();
        self.authority = null;
        if (self.pp) |pp| if (!self.pp_borrowed) {
            pp.deinit(a);
            a.destroy(pp);
        };
        self.pp = null;
    }
};
/// PP columns (+ root-independent device authority). Reads the padded graph
/// only; runs concurrently with the assignment plan, which also only reads it.
const ColumnsJob = struct {
    a: std.mem.Allocator,
    ctx: *const C.Context,
    pool: ?*@import("stwo_prover_engine").work_pool.WorkPool,
    device_authority: bool,
    /// Fold class (fold v2 classKey) when this node may share the class PP.
    class: ?[32]u8 = null,
    pp: ?*PP = null,
    pp_borrowed: bool = false,
    authority: ?Outer.Authority.DevicePrepared = null,
    columns_ns: u64 = 0,
    authority_ns: u64 = 0,
    failure: ?anyerror = null,
    fn run(self: *ColumnsJob) void {
        const Pools = @import("stwo_prover_engine").work_pool;
        var binding: ?Pools.ScopedPoolBinding = if (self.pool) |pool| (Pools.ScopedPoolBinding.initIfNeeded(pool) catch null) else null;
        defer if (binding) |*b| b.deinit();
        self.runImpl() catch |err| {
            self.failure = err;
        };
    }
    fn runImpl(self: *ColumnsJob) !void {
        var timer = try std.time.Timer.start();
        const mode = PPCache.mode();
        const shared: ?PPCache.Lease = if (self.class) |key| (if (mode == .on) try PPCache.acquire(self.a, key) else null) else null;
        const pp = if (shared) |hit| hit.pp else blk: {
            const owned = try self.a.create(PP);
            errdefer self.a.destroy(owned);
            owned.* = try PP.fromBuilderCircuit(self.a, &self.ctx.circuit);
            break :blk owned;
        };
        self.pp = pp;
        self.pp_borrowed = if (shared) |hit| hit.borrowed else false;
        if (self.class) |key| if (mode == .check) if (try PPCache.acquire(self.a, key)) |cached| {
            defer cached.deinit(self.a);
            if (!PPCache.equal(cached.pp, pp)) return error.PPClassMismatch;
            std.debug.print("GPU_OUTER_PP_CLASS pipelined check_ok class={x}\n", .{key[0..8]});
        };
        self.columns_ns = timer.lap();
        if (self.device_authority) self.authority = try Outer.Authority.prepareForDeviceProver(self.a, pp);
        self.authority_ns = timer.read();
    }
};
/// Stage 1 (any thread, no device): pad to the exact original targets, then
/// build PP columns (+ device authority prep) and the factory's assignment plan
/// from the padded graph, concurrently. Both are pure functions of the graph.
pub fn prepareHost(a: std.mem.Allocator, ctx: *C.Context, factory: Device.Factory) !HostPrep {
    return prepareHostForOutputs(a, ctx, factory, 8);
}
pub fn prepareHostForOutputs(a: std.mem.Allocator, ctx: *C.Context, factory: Device.Factory, n_outputs: usize) !HostPrep {
    if (n_outputs > Wire.MAX_OUTPUTS or ctx.circuit.output.items.len != n_outputs + 1) return error.CurrentOm31OutputCount;
    if (!ctx.trace_only or factory.prepare_from_circuit == null) return error.TraceOnlySourceRequired;
    var timer = try std.time.Timer.start();
    try circuit.common.finalize.padToTargets(C.Q, ctx, try paddingTargets(ctx));
    var result = HostPrep{ .pp = null, .finalize_ns = timer.lap() };
    errdefer result.deinit(a);
    // Fold v2 classes only (class_hint is threadlocal: read it on this thread).
    const class: ?[32]u8 = if (factory.precommit_fixed != null) Device.class_hint else null;
    var columns = ColumnsJob{ .a = a, .ctx = ctx, .pool = @import("stwo_prover_engine").work_pool.currentScopedPool(), .device_authority = factory.precommit_fixed != null, .class = class };
    const side = std.Thread.spawn(.{ .stack_size = 8 << 20 }, ColumnsJob.run, .{&columns}) catch null;
    if (side == null) columns.run();
    const plan: ?(anyerror!Device.HostPrepared) = if (factory.prepare_host) |prepare| prepare(factory.context, a, ctx) else null;
    result.host_plan_ns = timer.read();
    if (side) |thread| thread.join();
    result.pp = columns.pp;
    result.pp_borrowed = columns.pp_borrowed;
    result.authority = columns.authority;
    result.columns_ns = columns.columns_ns;
    // ColumnsJob laps after building columns: authority_ns is already the
    // authority-only duration. Subtracting columns_ns again underflows on
    // cold classes and corrupts the host-preparation attribution.
    result.authority_ns = columns.authority_ns;
    if (plan) |value| {
        result.host = value catch |err| return err;
    }
    if (columns.failure) |err| return err;
    // First fold of a class: the cache clones the PP (bounded by its byte cap).
    if (class) |key| if (!result.pp_borrowed and PPCache.mode() != .off) PPCache.adopt(key, result.pp.?);
    if (result.pp_borrowed) std.debug.print("GPU_OUTER_PP_CLASS pipelined hit=true class={x}\n", .{class.?[0..8]});
    return result;
}
/// M6 hint-tape (HT1) minimal hook: host prep of a fold whose class PP and
/// class plan are both cached, from the seed tape on `Device.seed_tape` and a
/// flags-only stub graph (no padding, no PP build, no graph walk). Returns null
/// (caller builds the ordinary graph) on any cache miss; proof-neutral.
/// Cheap pre-check before recording a tape: the class PP is cached (PP and
/// plan templates are adopted together by the first fold of a class).
pub fn tapeReady(factory: Device.Factory, class: [32]u8) bool {
    if (factory.precommit_fixed == null or factory.prepare_host == null or PPCache.mode() != .on) return false;
    const ready = factory.tape_ready orelse return false;
    return PPCache.contains(class) and ready(factory.context, class);
}
pub fn prepareHostTape(a: std.mem.Allocator, ctx: *C.Context, factory: Device.Factory, class: [32]u8) !?HostPrep {
    if (factory.precommit_fixed == null or PPCache.mode() != .on) return null;
    const prepare = factory.prepare_host orelse return null;
    if (Device.seed_tape == null or Device.class_hint == null) return error.MissingSeedTape;
    const cached = (try PPCache.acquire(a, class)) orelse return null;
    const pp = cached.pp;
    var timer = try std.time.Timer.start();
    var result = HostPrep{ .pp = pp, .pp_borrowed = cached.borrowed };
    errdefer result.deinit(a);
    result.authority = try Outer.Authority.prepareForDeviceProver(a, pp);
    result.authority_ns = timer.lap();
    result.host = prepare(factory.context, a, ctx) catch |err| switch (err) {
        error.SeedTapeClassMiss => {
            result.deinit(a);
            return null;
        },
        else => return err,
    };
    result.host_plan_ns = timer.read();
    return result;
}
/// Device stage output: proof material before the independent native verify.
pub const Proved = struct {
    pp: *PP,
    pp_borrowed: bool = false,
    authority: *Outer.Authority,
    produced: Outer.Produced,
    timings: Timings,
    hybrid: ?HybridPayload = null,
    pub fn deinit(self: *Proved, a: std.mem.Allocator) void {
        if (self.hybrid) |*extra| extra.deinit(a);
        self.produced.deinit();
        self.authority.deinit();
        a.destroy(self.authority);
        if (!self.pp_borrowed) {
            self.pp.deinit(a);
            a.destroy(self.pp);
        }
        self.* = undefined;
    }
};
/// Stage 2 (the device lane): FIXED precommit, authority, staged assignment
/// handoff and device proof. Consumes `prep` (PP and staged plan) on every path.
pub fn proveDevice(a: std.mem.Allocator, ctx: *C.Context, prep: *HostPrep, digest: [32]u8, ordinal: u32, factory: Device.Factory) !Proved {
    if (hybridProfileActive()) {
        const expected = digestOutputs(digest);
        return proveDeviceForOutputs(a, ctx, prep, &expected, ordinal, factory, true);
    }
    const pp = prep.pp orelse return error.MissingHostPrep;
    const pp_borrowed = prep.pp_borrowed;
    prep.pp = null;
    prep.pp_borrowed = false;
    errdefer if (!pp_borrowed) {
        pp.deinit(a);
        a.destroy(pp);
    };
    if (prep.host) |host| {
        prep.host = null;
        const stage = factory.stage_host orelse {
            host.destroy(host.context);
            return error.HostPrepStagingUnsupported;
        };
        // stage_host takes ownership on every path (destroys it on refusal).
        try stage(factory.context, host);
    }
    // A staged plan not consumed by the device source (early failure) is
    // discarded; a consumed plan has already moved into source custody.
    defer if (factory.unstage_host) |unstage| unstage(factory.context);
    var timer = try std.time.Timer.start();
    const authority = try a.create(Outer.Authority);
    errdefer a.destroy(authority);
    var precommitted: ?Device.PrecommittedFixed = if (factory.precommit_fixed) |precommit| try precommit(factory.context, a, pp, ordinal) else null;
    defer if (precommitted) |fixed| fixed.release(fixed.context);
    authority.* = if (precommitted) |fixed| blk: {
        if (prep.authority) |*prepared| break :blk try prepared.finish(pp, fixed.tree.root);
        break :blk try Outer.Authority.initForDeviceProver(a, pp, fixed.tree.root);
    } else try Outer.Authority.init(a, pp);
    errdefer authority.deinit();
    const authority_ns = timer.lap();
    std.log.info("CUDA_OUTER_PREPROCESS ordinal={d} finalize_ns={d} columns_ns={d} authority_ns={d} host_authority_ns={d} total_ns={d} fixed_setup_backend={s}", .{ ordinal, prep.finalize_ns, prep.columns_ns, authority_ns, prep.authority_ns, prep.finalize_ns + prep.columns_ns + authority_ns, if (precommitted != null) @as([]const u8, "device_candidate") else "cpu" });
    std.log.info("CUDA_OUTER_AUTHORITY ordinal={d} vars={d} row_logs={any}", .{ ordinal, ctx.circuit.n_vars, authority.logs.toArray() });
    var expected: [8]C.Q = undefined;
    for (&expected, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
    const produced = if (precommitted) |*fixed| try Device.proveFromPrecommittedCircuit(a, authority, ctx, &expected, ordinal, fixed) else try Device.proveFromCircuit(a, authority, ctx, &expected, ordinal, factory);
    return .{ .pp = pp, .pp_borrowed = pp_borrowed, .authority = authority, .produced = produced, .timings = .{ .preprocess_ns = prep.finalize_ns + prep.columns_ns + authority_ns, .finalize_ns = prep.finalize_ns, .preprocessed_columns_ns = prep.columns_ns, .authority_ns = authority_ns, .prove_ns = timer.read(), .verify_ns = 0 } };
}
/// Stage 3 (any thread, no device): canonical digest check and the same fresh
/// independent native verification/capture the monolithic path performs.
pub fn finishProved(a: std.mem.Allocator, proved: *Proved, digest: [32]u8) !Wrapped {
    if (proved.hybrid != null) {
        var expected: [8]C.Q = undefined;
        for (&expected, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
        return finishProvedForOutputs(a, proved, &expected, digest);
    }
    var timer = try std.time.Timer.start();
    try requireDigest(proved.produced.outputs, digest);
    var capture = try Outer.verify(a, proved.authority, proved.produced.outputs, proved.produced.claims, &proved.produced.proof.proof);
    errdefer capture.deinit(a);
    var timings = proved.timings;
    timings.verify_ns = timer.read();
    const result = Wrapped{ .allocator = a, .pp = proved.pp, .authority = proved.authority, .produced = proved.produced, .capture = capture, .digest = digest, .restored = false, .borrowed_pp = proved.pp_borrowed, .timings = timings };
    proved.* = undefined;
    return result;
}
/// New typed-output path. Public output length is fixed by the independently
/// built PP and every expected coordinate is compared before publication.
pub fn requireOutputs(outputs: []const C.Q, expected: []const C.Q) !void {
    if (outputs.len != expected.len) return error.CurrentOm31OutputCount;
    const modulus = @import("stwo_core").fields.m31.Modulus;
    for (outputs, expected) |value, want| {
        for (value.toM31Array(), want.toM31Array()) |actual, authorized| {
            if (actual.v >= modulus or authorized.v >= modulus) return error.NoncanonicalOm31CircuitOutput;
            if (actual.v != authorized.v) return error.CurrentOm31OutputMismatch;
        }
    }
}
pub fn finishProvedForOutputs(a: std.mem.Allocator, proved: *Proved, expected: []const C.Q, digest: [32]u8) !Wrapped {
    var timer = try std.time.Timer.start();
    if (expected.len != proved.authority.pp.n_outputs) return error.CurrentOm31OutputCount;
    try requireOutputs(proved.produced.outputs, expected);
    var capture = if (proved.hybrid) |*extra| blk: {
        if (extra.key.source != proved.authority) return error.InvalidHybridChildAuthority;
        break :blk try extra.key.verify(a, proved.produced.outputs, proved.produced.claims, &extra.section, &proved.produced.proof.proof);
    } else try Outer.verify(a, proved.authority, proved.produced.outputs, proved.produced.claims, &proved.produced.proof.proof);
    errdefer capture.deinit(a);
    var timings = proved.timings;
    timings.verify_ns = timer.read();
    const result = Wrapped{ .allocator = a, .pp = proved.pp, .authority = proved.authority, .produced = proved.produced, .capture = capture, .digest = digest, .restored = false, .borrowed_pp = proved.pp_borrowed, .timings = timings, .hybrid = proved.hybrid };
    proved.* = undefined;
    return result;
}
/// Explicit classic/hybrid dispatch for typed application outputs. This
/// consumes HostPrep on every path, just like the original digest-only API.
pub fn proveDeviceForOutputs(a: std.mem.Allocator, ctx: *C.Context, prep: *HostPrep, expected: []const C.Q, ordinal: u32, factory: Device.Factory, hybrid: bool) !Proved {
    const pp = prep.pp orelse return error.MissingHostPrep;
    const pp_borrowed = prep.pp_borrowed;
    prep.pp = null;
    prep.pp_borrowed = false;
    errdefer if (!pp_borrowed) {
        pp.deinit(a);
        a.destroy(pp);
    };
    if (expected.len != pp.n_outputs) return error.CurrentOm31OutputCount;
    if (prep.host) |host| {
        prep.host = null;
        const stage = factory.stage_host orelse {
            host.destroy(host.context);
            return error.HostPrepStagingUnsupported;
        };
        try stage(factory.context, host);
    }
    defer if (factory.unstage_host) |unstage| unstage(factory.context);
    var timer = try std.time.Timer.start();
    const authority = try a.create(Outer.Authority);
    errdefer a.destroy(authority);
    var precommitted: ?Device.PrecommittedFixed = if (factory.precommit_fixed) |precommit| try precommit(factory.context, a, pp, ordinal) else null;
    defer if (precommitted) |fixed| fixed.release(fixed.context);
    authority.* = if (precommitted) |fixed| blk: {
        if (prep.authority) |*prepared| break :blk try prepared.finish(pp, fixed.tree.root);
        break :blk try Outer.Authority.initForDeviceProver(a, pp, fixed.tree.root);
    } else try Outer.Authority.init(a, pp);
    errdefer authority.deinit();
    const authority_ns = timer.lap();
    var payload: ?HybridPayload = null;
    errdefer if (payload) |*extra| extra.deinit(a);
    const produced = if (hybrid) blk: {
        const key = try a.create(HybridKey);
        errdefer a.destroy(key);
        // The profile's request-level limit includes every leaf/fold/wrapper.
        key.* = try HybridKey.init(a, authority, 256);
        errdefer key.deinit();
        const result = try HybridDevice.proveFromCircuit(a, key, ctx, expected, ordinal, factory, if (precommitted) |*fixed| fixed else null);
        payload = .{ .key = key, .section = result.section };
        break :blk result.base;
    } else if (precommitted) |*fixed| try Device.proveFromPrecommittedCircuit(a, authority, ctx, expected, ordinal, fixed) else try Device.proveFromCircuit(a, authority, ctx, expected, ordinal, factory);
    return .{ .pp = pp, .pp_borrowed = pp_borrowed, .authority = authority, .produced = produced, .hybrid = payload, .timings = .{ .preprocess_ns = prep.finalize_ns + prep.columns_ns + authority_ns, .finalize_ns = prep.finalize_ns, .preprocessed_columns_ns = prep.columns_ns, .authority_ns = authority_ns, .prove_ns = timer.read(), .verify_ns = 0 } };
}
fn digestOutputs(digest: [32]u8) [8]C.Q {
    var expected: [8]C.Q = undefined;
    for (&expected, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
    return expected;
}
fn wrapHybridGraphOrLoad(a: std.mem.Allocator, ctx: *C.Context, digest: [32]u8, encoded: ?[]const u8, ordinal: u32, factory: ?Device.Factory, retire_topology: bool) !Wrapped {
    if (ctx.circuit.output.items.len != 9 or (factory != null and !ctx.trace_only)) return error.TraceOnlySourceRequired;
    const expected = digestOutputs(digest);
    if (encoded) |bytes| {
        try Finalize.padToTargets(C.Q, ctx, try paddingTargets(ctx));
        const pp = try a.create(PP);
        errdefer a.destroy(pp);
        pp.* = try PP.fromBuilderCircuit(a, &ctx.circuit);
        errdefer pp.deinit(a);
        retireTopology(ctx, retire_topology);
        const authority = try a.create(Outer.Authority);
        errdefer a.destroy(authority);
        authority.* = try Outer.Authority.init(a, pp);
        errdefer authority.deinit();
        var result = try restoreForOutputs(a, pp, authority, &expected, digest, bytes, true);
        result.borrowed = false;
        return result;
    }
    if (factory == null) {
        if (ctx.trace_only) return error.HybridCpuRequiresAssignment;
        var produced = proveHybridCpu(a, ctx, &expected, retire_topology) catch |err| {
            if (!@import("builtin").is_test) std.log.err("CPU_HYBRID_NODE_FAILED ordinal={} error={s}", .{ ordinal, @errorName(err) });
            return err;
        };
        var owns = true;
        defer if (owns) produced.deinit(a);
        const result = finishProvedForOutputs(a, &produced, &expected, digest) catch |err| {
            if (!@import("builtin").is_test) std.log.err("CPU_HYBRID_FINISH_FAILED ordinal={} error={s}", .{ ordinal, @errorName(err) });
            return err;
        };
        owns = false;
        return result;
    }
    const gpu = factory.?;
    _ = try HybridDevice.extension(gpu);
    var prep = try prepareHost(a, ctx, gpu);
    defer prep.deinit(a);
    var produced = try proveDeviceForOutputs(a, ctx, &prep, &expected, ordinal, gpu, true);
    var owns = true;
    defer if (owns) produced.deinit(a);
    const result = try finishProvedForOutputs(a, &produced, &expected, digest);
    owns = false;
    return result;
}
fn proveHybridCpu(a: std.mem.Allocator, ctx: *C.Context, expected: []const C.Q, retire_topology: bool) !Proved {
    var timer = try std.time.Timer.start();
    try Finalize.padToTargets(C.Q, ctx, try paddingTargets(ctx));
    const pp = try a.create(PP);
    errdefer a.destroy(pp);
    pp.* = try PP.fromBuilderCircuit(a, &ctx.circuit);
    errdefer pp.deinit(a);
    retireTopology(ctx, retire_topology);
    const authority = try a.create(Outer.Authority);
    errdefer a.destroy(authority);
    authority.* = try Outer.Authority.init(a, pp);
    errdefer authority.deinit();
    const key = try a.create(HybridKey);
    errdefer a.destroy(key);
    key.* = try HybridKey.init(a, authority, 256);
    errdefer key.deinit();
    const preprocess_ns = timer.lap();
    const produced = if (retire_topology) try HybridCpu.proveDisposableContext(a, key, ctx, expected) else try HybridCpu.prove(a, key, ctx.values(), expected);
    return .{ .pp = pp, .authority = authority, .produced = produced.base, .hybrid = .{ .key = key, .section = produced.section }, .timings = .{ .preprocess_ns = preprocess_ns, .prove_ns = timer.read(), .verify_ns = 0 } };
}
/// Output values must be canonical encoded raw-u32 words, not arbitrary QM31s
/// that happen to reduce to the same field value.
pub fn requireDigest(outputs: []const C.Q, expected: [32]u8) !void {
    if (outputs.len != 8) return error.CurrentOm31OutputCount;
    for (outputs, 0..) |value, i| {
        const coordinates = value.toM31Array();
        if (coordinates[0].v > 65535 or coordinates[1].v > 65535 or coordinates[2].v != 0 or coordinates[3].v != 0) return error.NoncanonicalCurrentOm31Output;
        const word = coordinates[0].v | (coordinates[1].v << 16);
        if (word != std.mem.readInt(u32, expected[4 * i ..][0..4], .little)) return error.CurrentOm31OutputDigest;
    }
}
