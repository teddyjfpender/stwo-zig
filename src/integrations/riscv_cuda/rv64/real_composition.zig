//! Hybrid, per-proof invocation of the actual joined CUDA kernels. CPU owns
//! trace construction and final bucket lifting; coefficients enter the GPU once
//! per role. This is explicitly not a fully resident execution controller.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const integration = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = @import("joined_codegen.zig");
const C = @import("composition_codegen.zig");
const Oracle = @import("joined_fixture_support.zig");
const P = G.Parameters;
const O = C.O;
const M = core.fields.m31.M31;
const Items = integration.rv64_gkr_cpu_components;
const Native = engine.air.component_prover.ForField(O);
const Acc = engine.air.accumulation.ForField(O).DomainEvaluationAccumulator;
const Column = engine.secure_column.SecureColumnByCoordsFor(O);
const IO = @import("fixture_io.zig");
fn literal(x: u32) O {
    return O.fromBase(M.fromCanonical(x));
}
fn word(out: []O, value: u64) void {
    for (out[0..4], 0..) |*v, i| v.* = literal(@as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
}
fn metadata(comptime T: type, c: *const T, d: G.Source.Descriptor) [P.count]O {
    var out: [P.count]O = @splat(O.zero());
    if (comptime @hasField(T, "data")) {
        const data = &c.data;
        for (std.enums.values(G.Source.Fractions.Relation)) |relation| {
            const r = @intFromEnum(relation);
            const slot = P.local + r * P.local_stride;
            out[slot] = data.challenges.offsets[r];
            for (0..relation.arity()) |i| out[slot + 1 + i] = data.challenges.coefficients[r][i];
        }
        @memcpy(out[P.weights..][0..data.lane_count], data.lane_weights[0..data.lane_count]);
        out[P.eta] = data.eta;
        out[P.target] = data.target_per_row;
        out[P.eq0] = data.point.eq0;
        out[P.eq1] = data.point.eq1;
    }
    if (comptime @hasField(T, "epoch")) out[P.epoch] = literal(c.epoch);
    if (comptime @hasField(T, "main")) switch (c.main.public) {
        .cpu, .cpu_compact => |v| {
            out[P.cpu_steps] = literal(v.steps);
            out[P.epoch] = literal(v.epoch);
            for (0..4) |i| {
                out[P.initial_pc + i] = literal(v.initial_pc[i]);
                out[P.final_pc + i] = literal(v.final_pc[i]);
            }
        },
        .ls => |v| out[P.rows] = literal(v.count),
        .mul => |v| out[P.rows] = literal(v.count),
        .div => |v| out[P.rows] = literal(v.count),
        else => {},
    };
    if (comptime @hasField(T, "rows")) out[P.rows] = literal(c.rows);
    if (comptime @hasField(T, "count")) out[P.rows] = literal(c.count);
    out[P.nonempty] = literal(@intFromBool(!out[P.rows].isZero()));
    if (comptime @hasField(T, "span")) {
        out[P.calls] = literal(c.span.calls);
        out[P.first_id] = literal(c.span.first_id);
        out[P.calls_nonempty] = literal(@intFromBool(c.span.calls != 0));
    }
    if (comptime @hasField(T, "first_id")) out[P.source_public + G.Source.Public.sponge_first_id] = literal(c.first_id);
    if (comptime @hasField(T, "boundary")) if (c.boundary) |boundary| {
        for (boundary.value.initial_registers, 0..) |value, i| word(out[P.source_public + G.Source.Public.initial_registers + 4 * i ..], value);
        for (boundary.value.final_registers, 0..) |value, i| word(out[P.source_public + G.Source.Public.final_registers + 4 * i ..], value);
        for (boundary.value.register_clocks, 0..) |value, i| out[P.source_public + G.Source.Public.register_clocks + i] = literal(value);
    };
    var shared: ?G.Authority.Manifest.Shared = null;
    var claims: G.Authority.Global.ClaimsFor(O) = .{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() };
    if (comptime @hasField(T, "shared")) shared = c.shared;
    if (comptime @hasField(T, "claims")) claims = c.claims;
    if (comptime @hasField(T, "claim")) claims.ram = c.claim;
    if (comptime @hasField(T, "global")) if (c.global) |global| {
        shared = global.shared;
        claims = global.claims;
    };
    if (shared) |s| inline for (.{ "ram", "kio", "wire" }) |name| {
        const slot = @field(P, name);
        const challenge = @field(s, name);
        out[slot] = challenge.offset;
        @memcpy(out[slot + 1 ..][0..challenge.coefficients.len], &challenge.coefficients);
    };
    out[P.claims] = claims.ram;
    out[P.claims + 1] = claims.kio;
    out[P.claims + 2] = claims.wire;
    _ = d;
    return out;
}
fn descriptor(comptime T: type, c: *const T) G.Source.Descriptor {
    if (comptime @hasField(T, "data")) {
        var result = G.Source.Descriptor{ .origin = c.data.instance.origin };
        if (comptime @hasField(@TypeOf(c.data), "cpu_u8_pairs")) {
            if (result.origin == .core and (result.origin.core == .cpu or result.origin.core == .and_table)) result.cpu_u8_pairs = c.data.cpu_u8_pairs;
        }
        if (comptime @hasField(@TypeOf(c.data), "cpu_compact_decode")) {
            if (result.origin == .core and result.origin.core == .cpu) result.cpu_compact_decode = c.data.cpu_compact_decode;
        }
        return result;
    }
    return .{ .origin = c.origin };
}
fn caseId(d: G.Source.Descriptor) !u32 {
    for (Oracle.descriptors(), 0..) |candidate, i| if (std.meta.eql(d, candidate)) return @intCast(i);
    std.debug.print("UNSUPPORTED_REAL_COMPOSITION origin={any} cpu_u8_pairs={} cpu_compact_decode={}\n", .{ d.origin, d.cpu_u8_pairs, d.cpu_compact_decode });
    return error.UnsupportedRealCompositionDescriptor;
}
pub const Context = struct {
    helper: []const u8,
    directory: []const u8,
    mutex: std.Thread.Mutex = .{},
    serial: u64 = 0,
    keep_jobs: bool = false,
    pub fn stage(self: *Context) integration.rv64_gkr_cpu_worker.CompositionStage {
        return .{ .context = self, .evaluate = evaluate };
    }
    fn evaluate(raw: *anyopaque, a: std.mem.Allocator, items: []const Items.Item, alpha: O, log: u32, total: usize, opaque_trace: *const anyopaque, opaque_output: *anyopaque) anyerror!bool {
        const self: *Context = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        const trace: *const Native.Trace = @ptrCast(@alignCast(opaque_trace));
        try std.fs.cwd().makePath(self.directory);
        const input_path = try std.fmt.allocPrint(a, "{s}/composition-{}.in", .{ self.directory, self.serial });
        defer a.free(input_path);
        const output_path = try std.fmt.allocPrint(a, "{s}/composition-{}.out", .{ self.directory, self.serial });
        defer a.free(output_path);
        self.serial += 1;
        defer if (!self.keep_jobs) std.fs.cwd().deleteFile(input_path) catch {};
        defer if (!self.keep_jobs) std.fs.cwd().deleteFile(output_path) catch {};
        var acc = try Acc.init(a, alpha, log, total);
        defer acc.deinit();
        var gpu_count: u32 = 0;
        for (items) |*item| switch (item.*) {
            inline else => |*c| {
                _ = try caseId(descriptor(@TypeOf(c.*), c));
                gpu_count += 1;
            },
        };
        var file = try std.fs.cwd().createFile(input_path, .{});
        defer file.close();
        var buffer: [65536]u8 = undefined;
        var writer = file.writer(&buffer);
        const w = &writer.interface;
        try IO.words(w, &.{ 0x52565243, 1, gpu_count, 1 });
        const Destination = struct { log: u32, column: *Column };
        var destinations: std.ArrayList(Destination) = .empty;
        defer destinations.deinit(a);
        const cpu_count: usize = 0;
        for (items) |*item| switch (item.*) {
            inline else => |*c| {
                const T = @TypeOf(c.*);
                const d = descriptor(T, c);
                const id = try caseId(d);
                const role_log = G.Authority.RoleGeometry.logSize(c);
                const eval_log = c.maxConstraintLogDegreeBound();
                if (eval_log != role_log + 1) return error.UnsupportedRealCompositionDomain;
                var artifact = try G.record(a, d);
                defer artifact.deinit();
                if (artifact.program.roots.len != c.nConstraints()) return error.RealCompositionConstraintCountMismatch;
                const params = metadata(T, c, d);
                for (artifact.program.parameters, artifact.parameter_slots) |*value, slot| value.* = params[slot];
                const shape = c.mainShape();
                const width = G.Authority.RoleGeometry.interWidth(c);
                const aux_count: usize = if (G.Authority.hasLocal(d)) 10 else 0;
                var aux: [10]engine.poly.circle.CircleCoefficients = undefined;
                var aux_owned: usize = 0;
                defer for (aux[0..aux_owned]) |*p| p.deinit(a);
                if (comptime @hasField(T, "data")) {
                    aux = try G.Authority.PublicAux.init(a, &c.data.point, role_log, null);
                    aux_owned = 10;
                }
                const widths = [3]usize{ shape.fixed, shape.main, width + aux_count };
                const offsets = c.columnOffsets();
                var source: std.ArrayList(Native.Poly) = .empty;
                defer source.deinit(a);
                try source.appendSlice(a, trace.polys.items[0][offsets[0]..][0..shape.fixed]);
                try source.appendSlice(a, trace.polys.items[1][offsets[1]..][0..shape.main]);
                try source.appendSlice(a, trace.polys.items[2][c.inter_offset..][0..width]);
                if (aux_owned != 0) {
                    // Native public_aux stores carry[8], first, second. The
                    // joined IR's explicit mask namespace is first, second,
                    // carry[8]; preserve that semantic permutation at ingress.
                    for ([_]usize{ 8, 9, 0, 1, 2, 3, 4, 5, 6, 7 }) |index|
                        try source.append(a, .{ .log_size = role_log, .values = &.{}, .coefficients = aux[index] });
                }
                var coefficient_words: usize = 0;
                for (source.items) |p| {
                    const coefficients = p.coefficients orelse return error.MissingRealCompositionCoefficients;
                    if (coefficients.logSize() > eval_log) return error.RealCompositionSourceDegreeMismatch;
                    coefficient_words = try std.math.add(usize, coefficient_words, coefficients.coefficients().len);
                }
                const bucket = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = artifact.program.roots.len }});
                defer a.free(bucket);
                try destinations.append(a, .{ .log = eval_log, .column = bucket[0].col });
                const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
                var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &tw);
                try IO.words(w, &.{ id, role_log, eval_log, @intCast(widths[0]), @intCast(widths[1]), @intCast(widths[2]), @intCast(artifact.program.inputs.len), @intCast(artifact.program.parameters.len), @intCast(artifact.program.roots.len), @intCast(coefficient_words), @intCast(tw.twiddles.len), 0 });
                const rows = @as(u64, 1) << @intCast(eval_log);
                for (artifact.program.inputs) |mask| {
                    const off = @as(u64, mask.column) * rows;
                    try IO.words(w, &.{ @truncate(off), @truncate(off >> 32) });
                }
                var source_offset: u64 = 0;
                for (source.items) |p| {
                    const coeff = p.coefficients.?;
                    try IO.words(w, &.{ coeff.logSize(), @truncate(source_offset), @truncate(source_offset >> 32) });
                    source_offset += coeff.coefficients().len;
                }
                for (source.items) |p| try w.writeAll(std.mem.sliceAsBytes(p.coefficients.?.coefficients()));
                try w.writeAll(std.mem.sliceAsBytes(tw.twiddles));
                try IO.felts(w, artifact.program.parameters);
                try IO.felts(w, bucket[0].random_coeff_powers);
                const denoms = try A.geometry.denominatorInverses(a, role_log, eval_log);
                defer a.free(denoms);
                try w.writeAll(std.mem.sliceAsBytes(denoms));
            },
        };
        try w.flush();
        const child = try std.process.Child.run(.{ .allocator = a, .argv = &.{ self.helper, input_path, output_path }, .max_output_bytes = 1 << 20 });
        defer a.free(child.stdout);
        defer a.free(child.stderr);
        switch (child.term) {
            .Exited => |code| if (code != 0) {
                std.debug.print("GPU composition helper failed: {s}\n", .{child.stderr});
                return error.RealGpuCompositionFailed;
            },
            else => return error.RealGpuCompositionFailed,
        }
        var output = try std.fs.cwd().openFile(output_path, .{});
        defer output.close();
        var read_buffer: [65536]u8 = undefined;
        var reader = output.reader(&read_buffer);
        const r = &reader.interface;
        for (destinations.items) |destination| for (destination.column.columns) |column| {
            const values = try a.alloc(M, column.len);
            defer a.free(values);
            try r.readSliceAll(std.mem.sliceAsBytes(values));
            for (column, values) |*v, x| {
                if (x.v >= core.fields.m31.Modulus) return error.NoncanonicalRealCompositionReadback;
                v.* = v.add(x);
            }
        };
        var expected_bytes: u64 = 0;
        for (destinations.items) |destination| expected_bytes += 32 * (@as(u64, 1) << @intCast(destination.log));
        if ((try output.stat()).size != expected_bytes) return error.TrailingRealCompositionReadback;
        const result: *Column = @ptrCast(@alignCast(opaque_output));
        result.* = try acc.finalize();
        std.debug.print("REAL_GPU_COMPOSITION gpu_roles={} cpu_roles={} {s}", .{ gpu_count, cpu_count, child.stdout });
        return true;
    }
};

test "real hybrid composition exposes an OM31 frontend stage" {
    var context = Context{ .helper = "unused", .directory = "unused" };
    const selected = context.stage();
    try std.testing.expect(@intFromPtr(selected.context) == @intFromPtr(&context));
}
test "real component descriptors normalize layout flags outside CPU and AND" {
    for (std.enums.values(G.Source.RoleId)) |role| {
        if (role == .initial or role == .terminal) {
            _ = try caseId(.{ .origin = .{ .core = role } });
            continue;
        }
        var item: Items.Item = .{ .arithmetic = undefined };
        item.arithmetic.data.instance.origin = .{ .core = role };
        item.arithmetic.data.cpu_u8_pairs = true;
        item.arithmetic.data.cpu_compact_decode = true;
        const d = descriptor(@TypeOf(item.arithmetic), &item.arithmetic);
        _ = try caseId(d);
    }
}
