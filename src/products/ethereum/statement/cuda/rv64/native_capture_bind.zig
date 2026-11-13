//! Compact ingress binding for the GPU-native service. Setups, boundary RAM
//! and sponge offsets are installed per block. Every witness program is
//! serialized from the live capture's native segment and ledger shard.
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const CPU = @import("stwo_riscv_cpu_integration");
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const ND = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device;
const NCB = @import("jobs/native_class_build.zig");
const S1 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage1;
const Seed = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_stage1;
const NG = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_gkr;
const PC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pack_capture;
const P = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pack;
const Sources = @import("stwo_riscv_cuda_integration").rv64.execution.source.gkr_sources;
const Collector = CPU.rv64_services_collector;
const Replay = CPU.rv64_replay_capture;
const Execution = CPU.rv64_gkr_execution;
const Coordinator = CPU.rv64_gkr_coordinator;
const Owner = ProductCPU.rv64_ethereum_capture.Owner;
const Native = std.meta.Child(@FieldType(PC.Stage.Request, "native"));
const heads = .{ "events", "keccak", "secp", "sha256", "arith256_mod", "curves", "bulk", "sponge" };
pub const chunk_words = 1 << 20;

pub const Binding = struct {
    a: std.mem.Allocator,
    builder: *NCB.Builder,
    registry: *S1.Registry,
    roms: P.Roms,
    warm: std.AutoHashMapUnmanaged(u64, *const Owner) = .empty,

    pub fn init(a: std.mem.Allocator, builder: *NCB.Builder, registry: *S1.Registry) Binding {
        builder.retain_inventories = true;
        return .{ .a = a, .builder = builder, .registry = registry, .roms = P.Roms.init(a) };
    }
    pub fn deinit(self: *Binding) void {
        self.warm.deinit(self.a);
        self.roms.deinit();
    }
    pub fn shapeHooks(self: *Binding) ND.ShapeHooks {
        return .{ .ctx = self, .shape = shape, .class_of = classOf };
    }
    pub fn captureHooks(self: *Binding) ND.CaptureHooks {
        return .{ .ctx = self, .pack = pack, .captured = captured };
    }
    fn of(raw: *anyopaque) *Binding {
        return @ptrCast(@alignCast(raw));
    }
    fn classOf(raw: *anyopaque, block: ?u64, segment: u32, rows: u64) anyerror!G.ClassKey {
        return of(raw).builder.classOf(block, segment, rows);
    }
    const Counter = struct {
        words: []u32,
        fn buffer(raw: *anyopaque) anyerror![]u32 {
            const c: *@This() = @ptrCast(@alignCast(raw));
            return c.words;
        }
        fn emit(_: *anyopaque, _: usize, _: u32, _: bool) anyerror!void {}
        fn writer(c: *@This()) G.ChunkWriter {
            return .{ .ctx = c, .buffer = buffer, .emit = emit };
        }
    };
    fn shape(raw: *anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
        const self = of(raw);
        const rows = try self.builder.shape(a, wb);
        errdefer a.free(rows);
        const owner: *const Owner = @ptrCast(@alignCast(wb.capture.owner));
        const inv = self.builder.inventories.get(wb.block) orelse return error.GpuNativeInventoryMissing;
        var counter = Counter{ .words = try self.a.alloc(u32, chunk_words) };
        defer self.a.free(counter.words);
        for (rows, 0..) |r, i| {
            const native = owner.native.items[i];
            const seal = try Replay.sealCaptured(native);
            var overlay = try Replay.Capture.borrowSealed(self.a, native, seal);
            defer overlay.deinit();
            overlay.value.cpu.?.log_size = inv.setup(i).materials.geometry.cpu_log;
            overlay.value.jalr.?.log_size = inv.setup(i).materials.geometry.jalr_log;
            const req = PC.Stage.Request{ .setup = inv.setup(i), .request = inv.requests[i], .native = &overlay.value, .advice = &owner.advice, .ordinal = i, .first_ids = inv.first_ids[i], .scope = .{ .statement = @splat(0), .fixed = inv.binding(i).root(), .main = @splat(0), .ordinal = @intCast(i) }, .pcs_config = inv.config };
            const stats = try PC.pack(self.a, req, &self.roms, counter.writer(), r);
            const key = try self.builder.classOf(wb.block, @intCast(i), r);
            const spec = self.registry.specs.getPtr(key) orelse return error.GpuNativeClassNotWarmed;
            spec.compact_words = @max(spec.compact_words, stats.arena_words);
            spec.capture_words = @max(spec.capture_words, @as(u64, stats.chunks) * chunk_words);
            const rom_key = PC.romKey(&inv.setup(i).materials.program);
            spec.compact_rom = .{ .key = rom_key, .words = self.roms.get(rom_key) orelse return error.GnPackRomNotHeld };
            std.debug.print("GPU_M8_GN_PACK install block={d} segment={d} chunks={d} arena_words={d}\n", .{ wb.block, i, stats.chunks, stats.arena_words });
        }
        try self.warm.put(self.a, wb.block, owner);
        self.registry.roms = &self.roms;
        return rows;
    }

    fn pack(raw: *anyopaque, ctx: *const G.RequestContext, cs: G.CapturedSegment, writer: G.ChunkWriter) anyerror!u64 {
        const self = of(raw);
        const warm = self.warm.get(ctx.block) orelse return error.GpuNativeBlockNotWarmed;
        const inv = self.builder.inventories.get(ctx.block) orelse return error.GpuNativeInventoryMissing;
        const i: usize = cs.segment;
        if (i >= inv.count() or i >= ctx.native_classes.len) return error.GpuNativeSegmentOutOfRange;
        const native: *const Native = @ptrCast(@alignCast(cs.native));
        const shard: *const Collector.Shard = @ptrCast(@alignCast(cs.shard orelse return error.GpuNativeCaptureEventsMissing));
        const seal = native.cpu.?.capture_seal orelse return error.UnsealedEarlySegmentCapture;
        var overlay = try Replay.Capture.borrowSealed(self.a, native, seal);
        defer overlay.deinit();
        const setup = inv.setup(i);
        overlay.value.cpu.?.log_size = setup.materials.geometry.cpu_log;
        overlay.value.jalr.?.log_size = setup.materials.geometry.jalr_log;
        // Private head arrays: neither a second in-flight request nor the
        // install inventory can observe this segment's replacement shard.
        var arena = std.heap.ArenaAllocator.init(self.a);
        defer arena.deinit();
        const a = arena.allocator();
        const view = Collector.OneShardView.init(shard.*);
        var advice = warm.advice;
        inline for (heads) |name| {
            const T = @typeInfo(@FieldType(Collector.Advice, name)).pointer.child;
            @field(advice, name) = try a.dupe(T, @field(warm.advice, name));
            @field(advice, name)[i] = @field(view, name)[0];
        }
        const natives = try a.dupe(*Native, warm.native.items);
        natives[i] = &overlay.value;
        var request = try Coordinator.requestView(natives, &advice, i);
        try Coordinator.routeDword(&request, setup.bridges, shard.events);
        request.sponge.first_id = inv.requests[i].sponge.first_id;
        const expected = try Execution.localCpuExpected(a, setup, request, @intCast(i), inv.first_ids[i], inv.config, inv.binding(i));
        const installed = try Execution.localCpuExpected(a, setup, inv.requests[i], @intCast(i), inv.first_ids[i], inv.config, inv.binding(i));
        // This block's cached public planes are valid only for the admitted
        // segment statement from install. Witness bytes still come from the
        // current capture; a changed public statement fails before Stage1.
        try Execution.requireSameCpuExpected(expected, installed);
        const scope = NG.Scope{ .statement = expected.statement, .fixed = expected.fixed, .main = @splat(0), .ordinal = @intCast(i) };
        const cl = self.builder.class(ctx.native_classes[i]) orelse return error.GpuNativeClassNotWarmed;
        var source = NCB.stubSource(setup, request);
        const publics = try a.alloc(S1.PublicWords, cl.instances.len);
        for (publics, cl.instances) |*out, instance| out.* = try Sources.publicWords(&source, instance.origin);
        try self.registry.setRequest(ctx.generation, @intCast(i), cl.key, .{ .statement = expected.statement, .seed = Seed.seedOf(inv.binding(i).begin(inv.config, expected)), .prefix = NG.seedWords(NG.childPrefix(scope, cl.instances)), .publics = publics });
        const stats = try PC.pack(self.a, .{ .setup = setup, .request = request, .native = &overlay.value, .advice = &advice, .ordinal = i, .first_ids = inv.first_ids[i], .scope = .{ .statement = scope.statement, .fixed = scope.fixed, .main = scope.main, .ordinal = scope.ordinal }, .pcs_config = inv.config }, &self.roms, writer, cl.rows);
        return stats.rows;
    }
    fn sameCells(x: anytype, y: @TypeOf(x)) bool {
        if (x.len != y.len) return false;
        for (x, y) |left, right| if (!std.meta.eql(left, right)) return false;
        return true;
    }
    fn captured(raw: *anyopaque, ctx: *const G.RequestContext, ce: G.CaptureEnd) anyerror!void {
        const self = of(raw);
        const warm = self.warm.get(ctx.block) orelse return error.GpuNativeBlockNotWarmed;
        const current: *const Owner = @ptrCast(@alignCast(ce.owner));
        // Initial/terminal RAM and the block's total Keccak offset were
        // borrowed from warm setup while capture streamed. Validate them
        // before the capture-end gate can release the seal/publication.
        if (ce.segments != warm.native.items.len or current.total_steps != warm.total_steps or current.final_pc != warm.final_pc or !std.meta.eql(current.final_registers, warm.final_registers) or !sameCells(current.advice.initial, warm.advice.initial) or !sameCells(current.advice.terminal, warm.advice.terminal)) return error.GpuNativeCaptureInventoryMismatch;
        if (current.advice.keccak.len != warm.advice.keccak.len) return error.GpuNativeCaptureInventoryMismatch;
        for (current.advice.keccak, warm.advice.keccak) |x, y| if (x.len != y.len) return error.GpuNativeCaptureInventoryMismatch;
    }
};
