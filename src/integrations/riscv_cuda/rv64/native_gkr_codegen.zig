//! Native-GKR-only raw CPU fraction and reduced interaction AIR lowering.
//! Equations come from cpu_component, Source.emit and global query authority;
//! this module supplies symbolic public slots and retains real numerator poles.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const CPU = @import("stwo_riscv_cpu_integration");
pub const Native = CPU.rv64_native_gkr_cpu;
pub const Authority = Native.Authority;
pub const Source = Authority.Source;
const C = @import("composition_codegen.zig");
const X = @import("symbolic_external.zig");
const F = X.Lane;
pub const P = @import("native_gkr_parameters.zig");
pub const Mode = enum { fractions, composition };
pub const Artifact = struct {
    a: std.mem.Allocator,
    descriptor: Source.Descriptor,
    mode: Mode,
    terms: [4]u32,
    program: C.Program,
    parameter_slots: []u32,
    pub fn deinit(s: *@This()) void {
        s.program.deinit();
        s.a.free(s.parameter_slots);
        s.* = undefined;
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    roots: *std.ArrayList(u32),
    local: *const CPU.rv64_native_gkr_v2.LocalElementsFor(F),
    shared: *const Authority.SharedFor(F),
    groups: [4]std.ArrayList(u32) = @splat(.empty),
    pub const Local = struct {
        parent: *Collector,
        pub fn emit(s: *@This(), relation: anytype, tuple: anytype, weight: F) void {
            s.parent.append(0, weight, s.parent.local.denominatorFor(F, relation, tuple));
        }
    };
    pub const Global = struct {
        parent: *Collector,
        pub fn emit(s: *@This(), relation: Authority.Global.Relation, tuple: anytype, weight: F) void {
            const d = switch (relation) {
                .ram => E.denominatorFor(F, s.parent.shared.ram.offset, &s.parent.shared.ram.coefficients, &tuple, true),
                .kio => E.denominatorFor(F, s.parent.shared.kio.offset, &s.parent.shared.kio.coefficients, &tuple, true),
                .wire => E.denominatorFor(F, s.parent.shared.wire.offset, &s.parent.shared.wire.coefficients, &tuple, true),
            };
            s.parent.append(1 + @intFromEnum(relation), weight, d);
        }
    };
    fn append(s: *@This(), kind: usize, n: F, d: F) void {
        s.groups[kind].appendSlice(s.a, &.{ n.id, d.id }) catch @panic("oom");
    }
    fn deinit(s: *@This()) void {
        for (&s.groups) |*g| g.deinit(s.a);
    }
};
fn secureInput(column: usize, offset: i8) F {
    var words: [8]F = undefined;
    for (&words, 0..) |*word, i| word.* = F.input(2, column + i, offset);
    return F.fromPartialEvals(words);
}
pub fn record(a: std.mem.Allocator, descriptor: Source.Descriptor, mode: Mode) !Artifact {
    const shape = try Authority.shape(descriptor);
    const counts = try Native.terms(descriptor);
    var recording = X.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const fixed = try a.alloc(F, shape.fixed);
    defer a.free(fixed);
    const main = try a.alloc(F, shape.main);
    defer a.free(main);
    const previous = try a.alloc(F, shape.main);
    defer a.free(previous);
    for (fixed, 0..) |*value, i| value.* = F.input(0, i, 0);
    for (main, previous, 0..) |*value, *prior, i| {
        value.* = F.input(1, i, 0);
        prior.* = if (Authority.previousMain(descriptor, i)) F.input(1, i, -1) else F.zero();
    }
    var public: Authority.PublicFor(F) = undefined;
    public.cpu = .{ .steps = F.parameter(P.cpu_steps), .epoch = F.parameter(P.epoch), .initial_pc = undefined, .final_pc = undefined, .wide_clock = false };
    for (&public.cpu.initial_pc, &public.cpu.final_pc, 0..) |*initial, *final, i| {
        initial.* = F.parameter(P.initial_pc + @as(u32, @intCast(i)));
        final.* = F.parameter(P.final_pc + @as(u32, @intCast(i)));
    }
    public.rows = F.parameter(P.rows);
    public.nonempty = F.parameter(P.nonempty);
    public.span = .{ .calls = F.parameter(P.calls), .first_id = F.parameter(P.first_id), .nonempty = F.parameter(P.calls_nonempty) };
    var sp: [Source.Public.count]F = undefined;
    for (&sp, 0..) |*value, i| value.* = F.parameter(P.source_public + @as(u32, @intCast(i)));
    sp[Source.Public.epoch] = public.cpu.epoch;
    sp[Source.Public.initial_pc] = public.cpu.initial_pc[0].add(public.cpu.initial_pc[1].mul(F.fromU32(65536)));
    var local: CPU.rv64_native_gkr_v2.LocalElementsFor(F) = undefined;
    for (&local.z, &local.alpha, 0..) |*z, *alpha, i| {
        z.* = F.parameter(P.local + @as(u32, @intCast(2 * i)));
        alpha.* = F.parameter(P.local + @as(u32, @intCast(2 * i + 1)));
    }
    var shared: Authority.SharedFor(F) = undefined;
    inline for (.{ "ram", "kio", "wire" }) |name| {
        const start = @field(P, name);
        @field(shared, name).offset = F.parameter(start);
        for (&@field(shared, name).coefficients, 0..) |*value, i| value.* = F.parameter(start + 1 + @as(u32, @intCast(i)));
    }
    var roots: std.ArrayList(u32) = .empty;
    defer roots.deinit(a);
    if (mode == .fractions) {
        var collector = Collector{ .a = a, .roots = &roots, .local = &local, .shared = &shared };
        defer collector.deinit();
        var ls = Collector.Local{ .parent = &collector };
        var gs = Collector.Global{ .parent = &collector };
        if (Authority.hasLocal(descriptor)) try descriptor.emit(F, fixed, main, previous, &sp, &ls);
        try Authority.emitGlobalQueries(descriptor, F, fixed, main, sp[Source.Public.sponge_first_id], &gs);
        for (collector.groups, counts) |g, count| {
            if (g.items.len != 2 * count) return error.NativeGkrEmitterTermCount;
            try roots.appendSlice(a, g.items);
        }
    } else {
        var weights: [4][]F = @splat(&.{});
        defer for (weights) |w| if (w.len != 0) a.free(w);
        for (counts, &weights, 0..) |count, *w, k| {
            if (count == 0) continue;
            const lanes = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, count));
            if (lanes > P.max_weights) return error.NativeGkrWeightsOverflow;
            w.* = try a.alloc(F, lanes);
            for (w.*, 0..) |*value, i| value.* = F.parameter(P.weights + @as(u32, @intCast(k * P.max_weights + i)));
        }
        const values = try a.alloc(F, shape.constraints + 3);
        defer a.free(values);
        var sink = E.SinkFor(F){ .values = values };
        const cw: [4][]const F = .{ weights[0], weights[1], weights[2], weights[3] };
        try Native.emitFor(F, descriptor, public, &sp, &local, &shared, cw, F.parameter(P.gamma), F.parameter(P.target), .{ .eq = secureInput(0, 0), .eq_next2 = secureInput(0, 2), .prefix = secureInput(8, 0), .prefix_previous = secureInput(8, -1) }, .{ .first = F.input(2, 16, 0), .second = F.input(2, 17, 0), .carry = secureInput(18, 0), .eq0 = F.parameter(P.eq0), .eq1 = F.parameter(P.eq1) }, fixed, main, previous, &sink);
        if (sink.count != values.len) return error.NativeGkrComponentShape;
        for (values) |value| try roots.append(a, value.id);
    }
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/native-gkr/raw-source-and-reduced-air/v2");
    h.update(&.{ @intFromEnum(mode), @intFromBool(descriptor.cpu_u8_pairs), @intFromBool(descriptor.cpu_compact_decode) });
    for (Source.Frame.originWords(descriptor.origin)) |word| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, word, .little);
        h.update(&b);
    }
    var program = try recording.builder.finish(h.finalResult(), roots.items);
    errdefer program.deinit();
    const slots = try a.alloc(u32, program.parameters.len);
    errdefer a.free(slots);
    for (program.parameters, slots) |value, *slot| {
        const words = value.toM31Array();
        for (words[1..]) |word| if (!word.isZero()) return error.NativeGkrUnmappedParameter;
        if (words[0].v == 0 or words[0].v > P.count) return error.NativeGkrUnmappedParameter;
        slot.* = words[0].v - 1;
    }
    return .{ .a = a, .descriptor = descriptor, .mode = mode, .terms = counts, .program = program, .parameter_slots = slots };
}

test "native CPU raw source and reduced AIR retain all source-derived groups" {
    const a = std.testing.allocator;
    for (@import("joined_fixture_support.zig").descriptors()) |descriptor| {
        var raw = try record(a, descriptor, .fractions);
        defer raw.deinit();
        var total: u32 = 0;
        for (raw.terms) |count| total += count;
        try std.testing.expectEqual(@as(usize, total) * 2, raw.program.roots.len);
        const sorts = try raw.program.sorts(a);
        defer a.free(sorts);
        for (0..total) |query| try std.testing.expectEqual(C.ir.Sort.base, sorts[raw.program.roots[2 * query]]);
        var air = try record(a, descriptor, .composition);
        defer air.deinit();
        try std.testing.expectEqual((try Authority.shape(descriptor)).constraints + 3, air.program.roots.len);
        for (air.program.inputs) |input| if (input.tree == 2) try std.testing.expect(input.column < 26);
        // Force the same callback source template later compiled by nvcc.
        if (descriptor.origin == .bridge and descriptor.origin.bridge == .keccak) {
            var output: std.ArrayList(u8) = .empty;
            defer output.deinit(a);
            try emitSource(a, output.writer(a), &raw, "native_cpu_keccak");
            try std.testing.expect(std.mem.indexOf(u8, output.items, "projected::sum_on") != null);
            const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_GKR_SOURCE_OUT") catch null;
            if (path) |value| {
                defer a.free(value);
                try std.fs.cwd().writeFile(.{ .sub_path = value, .data = output.items });
                const bin = try std.fmt.allocPrint(a, "{s}.bin", .{value});
                defer a.free(bin);
                try @import("native_gkr_source_fixture.zig").write(a, &raw, bin);
            }
        }
    }
}

/// Source callbacks for the actual numerical batch traversal. Generated code
/// loads only one query's dependency schedule, including source-owned shifted
/// MAIN columns. It never constructs a full raw N/D plane.
pub fn emitSource(a: std.mem.Allocator, w: anytype, artifact: *const Artifact, name: []const u8) !void {
    if (artifact.mode != .fractions or name.len == 0 or std.ascii.isDigit(name[0])) return error.InvalidNativeGkrSource;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidNativeGkrSource;
    const p = &artifact.program;
    try p.validate();
    const sorts = try p.sorts(a);
    defer a.free(sorts);
    const shape = try Authority.shape(artifact.descriptor);
    try w.writeAll("#include \"rv64/native_gkr_source.h\"\n#include \"rv64/projected_gkr.cuh\"\n#include \"rv64/composition.cuh\"\nusing namespace stwo::cuda::rv64;\n");
    try w.print("struct {s}_Source:StwoRv64NativeGkrSource{{\nbool validate(Custody&c,uint32_t count)const{{\nif(reserved0||reserved1||row_log<5||row_log>23||kind>3||count>max_count)return false;const uint64_t rows=1ull<<row_log;uint32_t terms=0,lanes=0;switch(kind){{\n", .{name});
    for (artifact.terms, 0..) |terms, k| try w.print("case {}:terms={};lanes={};break;\n", .{ k, terms, if (terms == 0) @as(usize, 0) else @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms)) });
    try w.print("}}if(!terms||rows*lanes!=count||fixed_words!=rows*{}ull||main_words!=rows*{}ull)return false;\nreturn c.range(fixed,fixed_words,false)&&c.range(main,main_words,false)&&c.range(parameters,{}ull,false)&&c.range(status,1,true);}}\n__device__ Fraction get(uint32_t index)const{{\nconst uint32_t rows=1u<<row_log,row=index&(rows-1),lane=index>>row_log;uint32_t query=0;switch(kind){{\n", .{ shape.fixed, shape.main, artifact.parameter_slots.len * 8 });
    var first: u32 = 0;
    for (artifact.terms, 0..) |terms, k| {
        try w.print("case {}:if(lane>={}u)return {{zero(),one()}};query={}u+lane;break;\n", .{ k, terms, first });
        first += terms;
    }
    try w.writeAll("default:atomicOr(status,8u);return {zero(),zero()};}\nconst uint32_t *tree0=fixed,*tree1=main;switch(query){\n");
    for (0..first) |query| {
        var subset = p.*;
        subset.roots = p.roots[2 * query ..][0..2];
        const order = try C.schedule(a, &subset);
        defer a.free(order);
        if (sorts[subset.roots[0]] != .base) return error.NativeGkrNumeratorNotBase;
        try w.print("case {}u:{{\n", .{query});
        for (order) |i| {
            const node = p.nodes[i];
            if (node.op == .input) {
                const input = p.inputs[node.value];
                if (input.tree > 1) return error.InvalidNativeGkrSource;
                try w.print("const uint32_t v{}=tree{}[{}ull*rows+", .{ i, input.tree, input.column });
                if (input.offset == 0) try w.writeAll("row") else try w.print("composition_mask_row(row,row_log,row_log,{})", .{input.offset});
                try w.print("];if(v{}>=q::kPrime){{atomicOr(status,2u);return {{zero(),zero()}};}}\n", .{i});
            } else try C.emitValue(w, p, sorts, i);
        }
        try w.print("const OM31 denominator={s}v{}{s};if(is_zero(denominator))atomicOr(status,4u);return {{base(v{}),denominator}};}}\n", .{ if (sorts[subset.roots[1]] == .base) "base(" else "", subset.roots[1], if (sorts[subset.roots[1]] == .base) ")" else "", subset.roots[0] });
    }
    try w.writeAll("default:atomicOr(status,8u);return {zero(),zero()};}}};\n");
    // Eq and the centered cyclic scan use the already qualified shared kernels.
    // This kernel writes only their raw prefix difference, from actual MAIN.
    try w.print("__global__ void {s}_binding_kernel({s}_Source source,const uint32_t*weights,const uint32_t*metadata,StwoRv64Plane eq,StwoRv64Plane prefix){{const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x,rows=1u<<source.row_log;if(row>=rows)return;store(prefix.words,prefix.stride,row,zero());const auto gamma=from_words(metadata),target=from_words(metadata+8),e=load(eq.words,eq.stride,row);if(!canonical(gamma)||!canonical(target)||!canonical(e)){{atomicOr(source.status,2u);return;}}OM31 value=zero();\n", .{ name, name });
    for (artifact.terms, 0..) |terms, k| {
        if (terms == 0) continue;
        const lanes = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms));
        try w.print("source.kind={};for(uint32_t lane=0;lane<{}u;++lane){{const auto w=from_words(weights+8u*({}u+lane));if(!canonical(w)){{atomicOr(source.status,2u);return;}}const auto f=source.get(lane*rows+row);value=add(value,mul(w,add(f.n,mul(gamma,f.d))));}}\n", .{ k, lanes, k * P.max_weights });
    }
    try w.writeAll("store(prefix.words,prefix.stride,row,sub(mul(e,value),target));}\n");
    const first_kind = for (artifact.terms, 0..) |terms, k| {
        if (terms != 0) break k;
    } else return error.InvalidNativeGkrSource;
    const first_lanes = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, artifact.terms[first_kind]));
    try w.print("extern \"C\" __attribute__((visibility(\"default\"))) int {s}_binding(void*ctx,uint32_t lane,const StwoRv64NativeGkrSource*raw,const uint32_t*weights,const uint32_t*metadata,StwoRv64Plane eq,StwoRv64Plane prefix){{if(!raw)return int(cudaErrorInvalidValue);{s}_Source source;static_cast<StwoRv64NativeGkrSource&>(source)=*raw;source.kind={};if(source.row_log<5||source.row_log>23)return int(cudaErrorInvalidValue);const uint32_t rows=1u<<source.row_log;Custody c(ctx,lane);if(!source.validate(c,rows*{}u)||!c.range(weights,{}u,false)||!c.range(metadata,16,false)||!c.plane(eq,rows,8,false)||!c.plane(prefix,rows,8,true))return c.status?c.status:int(cudaErrorInvalidValue);{s}_binding_kernel<<<(rows+127)/128,128,0,c.stream>>>(source,weights,metadata,eq,prefix);return int(cudaPeekAtLastError());}}\n", .{ name, name, first_kind, first_lanes, 4 * P.max_weights * 8, name });
    try w.print("extern \"C\" __attribute__((visibility(\"default\"))) int {s}_validate(void*c,uint32_t l,const void*s,uint32_t n){{return projected::validate_on<{s}_Source>(c,l,s,n);}}\n", .{ name, name });
    try w.print("extern \"C\" __attribute__((visibility(\"default\"))) int {s}_layer(void*c,uint32_t l,const void*s,uint32_t n,uint32_t levels,StwoRv64Plane on,StwoRv64Plane od){{return projected::layer_on<{s}_Source>(c,l,s,n,levels,on,od);}}\n", .{ name, name });
    try w.print("extern \"C\" __attribute__((visibility(\"default\"))) int {s}_sum(void*c,uint32_t l,const void*s,uint32_t n,StwoRv64Plane eq,const uint32_t*x,StwoRv64Plane a,StwoRv64Plane b,StwoRv64Plane out){{return projected::sum_on<{s}_Source>(c,l,s,n,eq,x,a,b,out);}}\n", .{ name, name });
    try w.print("extern \"C\" __attribute__((visibility(\"default\"))) int {s}_fold(void*c,uint32_t l,const void*s,uint32_t n,const uint32_t*x,StwoRv64Plane on,StwoRv64Plane od){{return projected::fold_on<{s}_Source>(c,l,s,n,x,on,od);}}\n", .{ name, name });
    try w.print("extern \"C\" __attribute__((visibility(\"default\"))) int {s}_mask(void*c,uint32_t l,const void*s,uint32_t*out){{return projected::mask_on<{s}_Source>(c,l,s,out);}}\n", .{ name, name });
}
