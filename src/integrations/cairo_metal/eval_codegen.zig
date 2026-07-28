const std = @import("std");
const eval = @import("stwo_cairo_frontend").witness.eval_program;
const shared = @import("stwo_cairo_frontend").codegen.eval_program;

pub const codegen_version: u64 = 2;
pub const default_fused_instruction_cap: usize = 512;
pub const max_fused_instruction_cap: usize = 4096;
pub const hybrid_fusion_source_cap: usize = 90 * 1024;

pub const FusedPart = shared.FusedPart;

pub const HybridFusionPolicy = struct {
    baseline_operation_cap: usize = 2048,
    maximum_operation_cap: usize = max_fused_instruction_cap,
    maximum_source_bytes: usize = hybrid_fusion_source_cap,

    fn validate(self: HybridFusionPolicy) !void {
        if (self.baseline_operation_cap == 0 or
            self.baseline_operation_cap > self.maximum_operation_cap or
            self.maximum_operation_cap > max_fused_instruction_cap or
            self.maximum_source_bytes == 0)
            return error.InvalidFusionPolicy;
    }
};

pub const FusionSlice = struct {
    start: usize,
    end: usize,
    operations: usize,
    source_bytes: usize,
};

const FusionCandidate = struct {
    source_bytes: usize,
};

pub const FusionPartition = struct {
    allocator: std.mem.Allocator,
    slices: []FusionSlice,

    pub fn deinit(self: *FusionPartition) void {
        self.allocator.free(self.slices);
        self.* = undefined;
    }
};

pub fn kernelName(allocator: std.mem.Allocator, semantic_hash: u64) ![]u8 {
    return std.fmt.allocPrint(allocator, "stwo_zig_eval_{x:0>16}", .{semantic_hash});
}

pub fn fusedKernelName(allocator: std.mem.Allocator, parts: []const FusedPart) ![]u8 {
    try validateFusionGroup(parts);
    return std.fmt.allocPrint(allocator, "stwo_zig_eval_fused_{x:0>16}", .{fusedGroupHash(parts)});
}

pub fn fusedKernelHash(parts: []const FusedPart) !u64 {
    try validateFusionGroup(parts);
    return fusedGroupHash(parts);
}

pub fn fusionSliceKernelName(
    allocator: std.mem.Allocator,
    parts: []const FusedPart,
    slice: FusionSlice,
) ![]u8 {
    if (slice.start >= slice.end or slice.end > parts.len)
        return error.InvalidFusionGroup;
    const group = parts[slice.start..slice.end];
    return if (group.len == 1)
        kernelName(allocator, group[0].program.header.semantic_hash)
    else
        fusedKernelName(allocator, group);
}

pub const instructionCount = shared.instructionCount;
pub const fusionOperationCount = shared.fusionOperationCount;

pub fn fusionGroupEnd(parts: []const FusedPart, start: usize, instruction_cap: usize) !usize {
    return shared.fusionGroupEnd(
        parts,
        start,
        instruction_cap,
        max_fused_instruction_cap,
    );
}

/// Finds an exact-size bounded partition without changing the existing greedy
/// cap policy. Groups above the baseline are admitted only when their emitted
/// MSL function fits both hybrid bounds.
pub fn hybridFusionPartition(
    allocator: std.mem.Allocator,
    parts: []const FusedPart,
    policy: HybridFusionPolicy,
) !FusionPartition {
    try policy.validate();
    try validatePartSequence(parts);

    const candidate_count = std.math.mul(usize, parts.len, parts.len) catch
        return error.InvalidFusionGroup;
    const candidates = try allocator.alloc(?FusionCandidate, candidate_count);
    defer allocator.free(candidates);
    @memset(candidates, null);
    for (0..parts.len) |start| {
        var operations: usize = 0;
        for (start..parts.len) |last| {
            operations = std.math.add(
                usize,
                operations,
                fusionOperationCount(parts[last].program),
            ) catch return error.InvalidFusionGroup;
            const part_count = last + 1 - start;
            if (part_count > 1 and operations > policy.maximum_operation_cap) break;

            const source_bytes = try emittedKernelSourceBytes(allocator, parts[start .. last + 1]);
            if (part_count > 1 and operations > policy.baseline_operation_cap and
                source_bytes > policy.maximum_source_bytes)
                continue;
            candidates[start * parts.len + last] = .{ .source_bytes = source_bytes };
        }
    }

    const minimum_counts = try minimumSliceCounts(allocator, candidates, parts.len, null);
    defer allocator.free(minimum_counts);
    const slice_count = minimum_counts[0] orelse return error.NoFusionPartition;
    const maximum_sources = try minimumMaximumSources(
        allocator,
        candidates,
        parts.len,
        minimum_counts,
    );
    defer allocator.free(maximum_sources);
    const maximum_source = maximum_sources[0] orelse return error.NoFusionPartition;
    const bounded_counts = try minimumSliceCounts(
        allocator,
        candidates,
        parts.len,
        maximum_source,
    );
    defer allocator.free(bounded_counts);
    if (bounded_counts[0] == null or bounded_counts[0].? != slice_count)
        return error.NoFusionPartition;
    const next_ends = try minimumSquaredSourcePartition(
        allocator,
        candidates,
        parts.len,
        bounded_counts,
        maximum_source,
    );
    defer allocator.free(next_ends);
    const hybrid_slices = try materializePartition(
        allocator,
        parts,
        next_ends,
        slice_count,
    );
    var admitted_above_baseline = false;
    for (hybrid_slices) |slice| {
        admitted_above_baseline = admitted_above_baseline or
            slice.end - slice.start > 1 and slice.operations > policy.baseline_operation_cap;
    }
    if (admitted_above_baseline)
        return .{ .allocator = allocator, .slices = hybrid_slices };

    allocator.free(hybrid_slices);
    const baseline_slices = try greedyPartition(allocator, parts, policy.baseline_operation_cap);
    return .{ .allocator = allocator, .slices = baseline_slices };
}

fn minimumSliceCounts(
    allocator: std.mem.Allocator,
    candidates: []const ?FusionCandidate,
    part_count: usize,
    maximum_source: ?usize,
) ![]?usize {
    const counts = try allocator.alloc(?usize, part_count + 1);
    @memset(counts, null);
    counts[part_count] = 0;
    var start = part_count;
    while (start > 0) {
        start -= 1;
        for (start..part_count) |last| {
            const candidate = candidates[start * part_count + last] orelse continue;
            if (maximum_source) |limit| if (candidate.source_bytes > limit) continue;
            const suffix = counts[last + 1] orelse continue;
            const count = suffix + 1;
            if (counts[start] == null or count < counts[start].?) counts[start] = count;
        }
    }
    return counts;
}

fn minimumMaximumSources(
    allocator: std.mem.Allocator,
    candidates: []const ?FusionCandidate,
    part_count: usize,
    minimum_counts: []const ?usize,
) ![]?usize {
    const maxima = try allocator.alloc(?usize, part_count + 1);
    @memset(maxima, null);
    maxima[part_count] = 0;
    var start = part_count;
    while (start > 0) {
        start -= 1;
        const count = minimum_counts[start] orelse continue;
        for (start..part_count) |last| {
            const candidate = candidates[start * part_count + last] orelse continue;
            const suffix_count = minimum_counts[last + 1] orelse continue;
            if (suffix_count + 1 != count) continue;
            const suffix_maximum = maxima[last + 1] orelse continue;
            const maximum = @max(candidate.source_bytes, suffix_maximum);
            if (maxima[start] == null or maximum < maxima[start].?) maxima[start] = maximum;
        }
    }
    return maxima;
}

fn minimumSquaredSourcePartition(
    allocator: std.mem.Allocator,
    candidates: []const ?FusionCandidate,
    part_count: usize,
    minimum_counts: []const ?usize,
    maximum_source: usize,
) ![]usize {
    const sums = try allocator.alloc(?u128, part_count + 1);
    defer allocator.free(sums);
    @memset(sums, null);
    sums[part_count] = 0;
    const next_ends = try allocator.alloc(usize, part_count);
    errdefer allocator.free(next_ends);
    var start = part_count;
    while (start > 0) {
        start -= 1;
        const count = minimum_counts[start] orelse continue;
        for (start..part_count) |last| {
            const candidate = candidates[start * part_count + last] orelse continue;
            if (candidate.source_bytes > maximum_source) continue;
            const suffix_count = minimum_counts[last + 1] orelse continue;
            const suffix_sum = sums[last + 1] orelse continue;
            if (suffix_count + 1 != count) continue;
            const source: u128 = candidate.source_bytes;
            const squared = std.math.mul(u128, source, source) catch
                return error.FusionPartitionCostOverflow;
            const sum = std.math.add(u128, squared, suffix_sum) catch
                return error.FusionPartitionCostOverflow;
            if (sums[start] == null or sum < sums[start].?) {
                sums[start] = sum;
                next_ends[start] = last + 1;
            }
        }
    }
    if (sums[0] == null) return error.NoFusionPartition;
    return next_ends;
}

fn materializePartition(
    allocator: std.mem.Allocator,
    parts: []const FusedPart,
    next_ends: []const usize,
    slice_count: usize,
) ![]FusionSlice {
    const slices = try allocator.alloc(FusionSlice, slice_count);
    errdefer allocator.free(slices);
    var start: usize = 0;
    for (slices) |*slice| {
        const end = next_ends[start];
        slice.* = try describeSlice(allocator, parts, start, end);
        start = end;
    }
    if (start != parts.len) return error.NoFusionPartition;
    return slices;
}

fn greedyPartition(
    allocator: std.mem.Allocator,
    parts: []const FusedPart,
    operation_cap: usize,
) ![]FusionSlice {
    var slices = std.ArrayList(FusionSlice).empty;
    errdefer slices.deinit(allocator);
    var start: usize = 0;
    while (start < parts.len) {
        const end = try fusionGroupEnd(parts, start, operation_cap);
        try slices.append(allocator, try describeSlice(allocator, parts, start, end));
        start = end;
    }
    return slices.toOwnedSlice(allocator);
}

fn describeSlice(
    allocator: std.mem.Allocator,
    parts: []const FusedPart,
    start: usize,
    end: usize,
) !FusionSlice {
    var operations: usize = 0;
    for (parts[start..end]) |part| {
        operations = std.math.add(usize, operations, fusionOperationCount(part.program)) catch
            return error.InvalidFusionGroup;
    }
    return .{
        .start = start,
        .end = end,
        .operations = operations,
        .source_bytes = try emittedKernelSourceBytes(allocator, parts[start..end]),
    };
}

fn emittedKernelSourceBytes(allocator: std.mem.Allocator, parts: []const FusedPart) !usize {
    const source = if (parts.len == 1)
        try generateKernel(allocator, parts[0].program, false)
    else
        try generateFusedKernel(allocator, parts, false);
    defer allocator.free(source);
    return source.len;
}

pub fn cacheKey(semantic_hash: u64) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (std.mem.asBytes(&semantic_hash)) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3;
    }
    for (std.mem.asBytes(&codegen_version)) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3;
    }
    return hash;
}

pub fn generate(allocator: std.mem.Allocator, program: eval.Program) ![]u8 {
    return generateKernel(allocator, program, true);
}

pub fn preambleSource() []const u8 {
    return preamble;
}

pub fn generateKernel(allocator: std.mem.Allocator, program: eval.Program, include_preamble: bool) ![]u8 {
    try program.validate();
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    if (include_preamble) try writer.writeAll(preamble);
    const name = try kernelName(allocator, program.header.semantic_hash);
    defer allocator.free(name);
    try writer.print(
        \\kernel void {s}(
        \\    device uint *arena [[buffer(0)]],
        \\    constant EvalArgs &args [[buffer(1)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= args.row_count) return;
        \\
    , .{name});

    try emitProgramBody(allocator, writer, program, 0);
    try writer.writeAll(
        \\    Qm31 result = qm_mul_base(part_acc, arena[args.denom_inv + (row >> args.trace_log_size)]);
        \\    arena[args.coord_0 + row] = m31_add(arena[args.coord_0 + row], result.a);
        \\    arena[args.coord_1 + row] = m31_add(arena[args.coord_1 + row], result.b);
        \\    arena[args.coord_2 + row] = m31_add(arena[args.coord_2 + row], result.c);
        \\    arena[args.coord_3 + row] = m31_add(arena[args.coord_3 + row], result.d);
        \\}
        \\
    );
    return source.toOwnedSlice(allocator);
}

pub fn generateFusedKernel(
    allocator: std.mem.Allocator,
    parts: []const FusedPart,
    include_preamble: bool,
) ![]u8 {
    try validateFusionGroup(parts);
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    if (include_preamble) try writer.writeAll(preamble);
    const name = try fusedKernelName(allocator, parts);
    defer allocator.free(name);
    try writer.print(
        \\kernel void {s}(
        \\    device uint *arena [[buffer(0)]],
        \\    constant EvalArgs &args [[buffer(1)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= args.row_count) return;
        \\    uint denominator = arena[args.denom_inv + (row >> args.trace_log_size)];
        \\    Qm31 cumulative = {{
        \\        arena[args.coord_0 + row], arena[args.coord_1 + row],
        \\        arena[args.coord_2 + row], arena[args.coord_3 + row]
        \\    }};
        \\
    , .{name});
    const first_rc_base = parts[0].rc_base;
    for (parts) |part| {
        try writer.writeAll("    {\n");
        try emitProgramBody(allocator, writer, part.program, part.rc_base - first_rc_base);
        try writer.writeAll(
            "    Qm31 part_result = qm_mul_base(part_acc, denominator);\n" ++
                "    cumulative = qm_add(cumulative, part_result);\n    }\n",
        );
    }
    try writer.writeAll(
        \\    arena[args.coord_0 + row] = cumulative.a;
        \\    arena[args.coord_1 + row] = cumulative.b;
        \\    arena[args.coord_2 + row] = cumulative.c;
        \\    arena[args.coord_3 + row] = cumulative.d;
        \\}
        \\
    );
    return source.toOwnedSlice(allocator);
}

fn emitProgramBody(
    allocator: std.mem.Allocator,
    writer: anytype,
    program: eval.Program,
    rc_offset: u32,
) !void {
    var emitter = MetalProgramEmitter(@TypeOf(writer)){ .writer = writer };
    try shared.walk(allocator, program, rc_offset, &emitter);
}

fn MetalProgramEmitter(comptime Writer: type) type {
    return struct {
        writer: Writer,

        pub fn base(self: *@This(), step: shared.BaseStep) !void {
            const inst = step.instruction;
            const decl = if (step.declare) "uint " else "";
            switch (inst.op) {
                .trace_col, .preprocessed_col => try self.writer.print(
                    "    {s}b{} = trace_value(arena, args, {}u, {}u, row, {});\n",
                    .{ decl, inst.dst, inst.interaction, inst.a, inst.imm },
                ),
                .param => try self.writer.print("    {s}b{} = arena[args.base_params + {}u];\n", .{ decl, inst.dst, inst.a }),
                .constant => try self.writer.print("    {s}b{} = {}u;\n", .{ decl, inst.dst, inst.a }),
                .add => try self.writer.print("    {s}b{} = m31_add(b{}, b{});\n", .{ decl, inst.dst, inst.a, inst.b }),
                .sub => try self.writer.print("    {s}b{} = m31_sub(b{}, b{});\n", .{ decl, inst.dst, inst.a, inst.b }),
                .mul => try self.writer.print("    {s}b{} = m31_mul(b{}, b{});\n", .{ decl, inst.dst, inst.a, inst.b }),
                .neg => try self.writer.print("    {s}b{} = m31_neg(b{});\n", .{ decl, inst.dst, inst.a }),
                .inv => try self.writer.print("    {s}b{} = m31_inv(b{});\n", .{ decl, inst.dst, inst.a }),
            }
        }

        pub fn extended(self: *@This(), step: shared.ExtStep) !void {
            const inst = step.instruction;
            const decl = if (step.declare) "Qm31 " else "";
            switch (inst.op) {
                .secure_col => try self.writer.print("    {s}e{} = {{ b{}, b{}, b{}, b{} }};\n", .{ decl, inst.dst, inst.a, inst.b, inst.c, inst.d }),
                .param => try self.writer.print("    {s}e{} = load_qm31(arena, args.ext_params + {}u * 4u);\n", .{ decl, inst.dst, inst.a }),
                .constant => try self.writer.print("    {s}e{} = {{ {}u, {}u, {}u, {}u }};\n", .{ decl, inst.dst, inst.a, inst.b, inst.c, inst.d }),
                .add => try self.writer.print("    {s}e{} = qm_add(e{}, e{});\n", .{ decl, inst.dst, inst.a, inst.b }),
                .sub => try self.writer.print("    {s}e{} = qm_sub(e{}, e{});\n", .{ decl, inst.dst, inst.a, inst.b }),
                .mul => try self.writer.print("    {s}e{} = qm_mul(e{}, e{});\n", .{ decl, inst.dst, inst.a, inst.b }),
                .neg => try self.writer.print("    {s}e{} = qm_neg(e{});\n", .{ decl, inst.dst, inst.a }),
            }
        }

        pub fn beginConstraints(self: *@This()) !void {
            try self.writer.writeAll(
                "    Qm31 part_acc = { 0u, 0u, 0u, 0u };\n",
            );
        }

        pub fn constraint(
            self: *@This(),
            step: shared.ConstraintStep,
        ) !void {
            try self.writer.print(
                "    part_acc = qm_add(part_acc, qm_mul(e{}, load_qm31(arena, args.random_coeffs + (args.rc_base + {}u) * 4u)));\n",
                .{ step.root, step.random_coefficient_offset },
            );
        }
    };
}

fn validateFusionGroup(parts: []const FusedPart) !void {
    return shared.validateFusionGroup(parts, max_fused_instruction_cap);
}

fn validatePartSequence(parts: []const FusedPart) !void {
    return shared.validatePartSequence(parts);
}

fn fusedGroupHash(parts: []const FusedPart) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    hashInt(&hash, codegen_version);
    hashInt(&hash, @as(u64, @intCast(parts.len)));
    const first_rc_base = parts[0].rc_base;
    for (parts) |part| {
        hashInt(&hash, part.program.header.semantic_hash);
        hashInt(&hash, part.rc_base - first_rc_base);
    }
    return hash;
}

fn hashInt(hash: *u64, value: anytype) void {
    const T = @TypeOf(value);
    const U = std.meta.Int(.unsigned, @bitSizeOf(T));
    const unsigned: U = @bitCast(value);
    for (0..@sizeOf(T)) |index| {
        hash.* ^= @as(u8, @truncate(unsigned >> @intCast(index * 8)));
        hash.* *%= 0x100000001b3;
    }
}

const preamble =
    \\#include <metal_stdlib>
    \\using namespace metal;
    \\constant uint M31_P = 0x7fffffffu;
    \\struct Qm31 { uint a; uint b; uint c; uint d; };
    \\struct EvalArgs {
    \\    uint trace_offsets;
    \\    uint interaction_offsets;
    \\    uint base_params;
    \\    uint ext_params;
    \\    uint random_coeffs;
    \\    uint denom_inv;
    \\    uint coord_0;
    \\    uint coord_1;
    \\    uint coord_2;
    \\    uint coord_3;
    \\    uint row_count;
    \\    uint trace_log_size;
    \\    uint domain_log_size;
    \\    uint rc_base;
    \\};
    \\inline uint m31_reduce(ulong v) { v = (v & M31_P) + (v >> 31); v = (v & M31_P) + (v >> 31); return v == M31_P ? 0u : uint(v); }
    \\inline uint m31_add(uint a, uint b) { return m31_reduce(ulong(a) + b); }
    \\inline uint m31_sub(uint a, uint b) { return a >= b ? a - b : a + M31_P - b; }
    \\inline uint m31_mul(uint a, uint b) { return m31_reduce(ulong(a) * b); }
    \\inline uint m31_neg(uint a) { return a == 0u ? 0u : M31_P - a; }
    \\inline uint m31_inv(uint v) { uint r = 1u, b = v, e = M31_P - 2u; while (e != 0u) { if (e & 1u) r = m31_mul(r, b); b = m31_mul(b, b); e >>= 1u; } return r; }
    \\inline Qm31 qm_add(Qm31 l, Qm31 r) { return { m31_add(l.a,r.a), m31_add(l.b,r.b), m31_add(l.c,r.c), m31_add(l.d,r.d) }; }
    \\inline Qm31 qm_sub(Qm31 l, Qm31 r) { return { m31_sub(l.a,r.a), m31_sub(l.b,r.b), m31_sub(l.c,r.c), m31_sub(l.d,r.d) }; }
    \\inline Qm31 qm_neg(Qm31 v) { return { m31_neg(v.a), m31_neg(v.b), m31_neg(v.c), m31_neg(v.d) }; }
    \\inline Qm31 qm_mul_base(Qm31 v, uint s) { return { m31_mul(v.a,s), m31_mul(v.b,s), m31_mul(v.c,s), m31_mul(v.d,s) }; }
    \\inline Qm31 qm_mul(Qm31 l, Qm31 r) {
    \\    uint x0=m31_sub(m31_mul(l.a,r.a),m31_mul(l.b,r.b)), x1=m31_add(m31_mul(l.a,r.b),m31_mul(l.b,r.a));
    \\    uint y0=m31_sub(m31_mul(l.c,r.c),m31_mul(l.d,r.d)), y1=m31_add(m31_mul(l.c,r.d),m31_mul(l.d,r.c));
    \\    uint c0=m31_sub(m31_mul(l.a,r.c),m31_mul(l.b,r.d)), c1=m31_add(m31_mul(l.a,r.d),m31_mul(l.b,r.c));
    \\    uint c2=m31_sub(m31_mul(l.c,r.a),m31_mul(l.d,r.b)), c3=m31_add(m31_mul(l.c,r.b),m31_mul(l.d,r.a));
    \\    return { m31_add(x0,m31_sub(m31_add(y0,y0),y1)), m31_add(x1,m31_add(y0,m31_add(y1,y1))), m31_add(c0,c2), m31_add(c1,c3) };
    \\}
    \\inline Qm31 load_qm31(device uint *arena, uint off) { return { arena[off], arena[off+1u], arena[off+2u], arena[off+3u] }; }
    \\inline uint bit_reverse(uint i, uint bits) { return bits == 0u ? 0u : reverse_bits(i) >> (32u-bits); }
    \\inline uint offset_circle(uint i, uint domain_log, uint eval_log, int offset) {
    \\    uint prev=bit_reverse(i,eval_log), half_size=1u<<(eval_log-1u); int step=offset*int(1u<<(eval_log-domain_log-1u));
    \\    if (prev<half_size) { int p=(int(prev)+step)%int(half_size); if(p<0)p+=int(half_size); prev=uint(p); }
    \\    else { int p=(int(prev)-step)%int(half_size); if(p<0)p+=int(half_size); prev=uint(p)+half_size; }
    \\    return bit_reverse(prev,eval_log);
    \\}
    \\inline uint trace_value(device uint *arena, constant EvalArgs &args, uint interaction, uint column, uint row, int offset) {
    \\    uint target=offset==0 ? row : offset_circle(row,args.domain_log_size,ctz(args.row_count),offset);
    \\    uint global=arena[args.interaction_offsets+interaction]+column;
    \\    return arena[arena[args.trace_offsets+global]+target];
    \\}
    \\
;

test "Metal evaluation codegen: emits fused arena kernel" {
    var base = [_]eval.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 2, .b = 0, .imm = -1 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 7, .b = 0, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 2, .a = 0, .b = 1, .imm = 0 },
    };
    var ext = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 2, .b = 1, .c = 0, .d = 1 },
        .{ .op = .param, .dst = 1, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 2, .a = 0, .b = 1, .c = 0, .d = 0 },
    };
    var roots = [_]u32{2};
    const program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0x1234, .capability_bits = eval.Capability.prefinalized_logup | eval.Capability.ext_mul, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 1, .n_constraints = 1, .max_base_regs = 3, .max_ext_regs = 3, .domain_log_size = 8 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    const source = try generate(std.testing.allocator, program);
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, "b2 = m31_mul(b0, b1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "qm_mul(e0, e1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "args.coord_3 + row") != null);

    const kernel_only = try generateKernel(
        std.testing.allocator,
        program,
        false,
    );
    defer std.testing.allocator.free(kernel_only);
    try std.testing.expectEqualStrings(
        \\kernel void stwo_zig_eval_0000000000001234(
        \\    device uint *arena [[buffer(0)]],
        \\    constant EvalArgs &args [[buffer(1)]],
        \\    uint row [[thread_position_in_grid]]) {
        \\    if (row >= args.row_count) return;
        \\    uint b0 = trace_value(arena, args, 0u, 2u, row, -1);
        \\    uint b1 = 7u;
        \\    uint b2 = m31_mul(b0, b1);
        \\    Qm31 e0 = { b2, b1, b0, b1 };
        \\    Qm31 e1 = load_qm31(arena, args.ext_params + 0u * 4u);
        \\    Qm31 e2 = qm_mul(e0, e1);
        \\    Qm31 part_acc = { 0u, 0u, 0u, 0u };
        \\    part_acc = qm_add(part_acc, qm_mul(e2, load_qm31(arena, args.random_coeffs + (args.rc_base + 0u) * 4u)));
        \\    Qm31 result = qm_mul_base(part_acc, arena[args.denom_inv + (row >> args.trace_log_size)]);
        \\    arena[args.coord_0 + row] = m31_add(arena[args.coord_0 + row], result.a);
        \\    arena[args.coord_1 + row] = m31_add(arena[args.coord_1 + row], result.b);
        \\    arena[args.coord_2 + row] = m31_add(arena[args.coord_2 + row], result.c);
        \\    arena[args.coord_3 + row] = m31_add(arena[args.coord_3 + row], result.d);
        \\}
        \\
    ,
        kernel_only,
    );
}

test "Metal evaluation codegen: fuses adjacent parts with one accumulator store" {
    var base = [_]eval.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    var ext = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
    };
    var roots = [_]u32{0};
    const first = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0x1111, .capability_bits = eval.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 1, .max_ext_regs = 1, .domain_log_size = 8 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    var second = first;
    second.header.semantic_hash = 0x2222;
    const parts = [_]FusedPart{
        .{ .program = first, .rc_base = 0 },
        .{ .program = second, .rc_base = 1 },
    };
    const source = try generateFusedKernel(std.testing.allocator, &parts, true);
    defer std.testing.allocator.free(source);
    const name = try fusedKernelName(std.testing.allocator, &parts);
    defer std.testing.allocator.free(name);
    try std.testing.expect(std.mem.indexOf(u8, source, name) != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, "arena[args.coord_0 + row] ="));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, source, "Qm31 part_result"));
    try std.testing.expect(std.mem.indexOf(u8, source, "args.rc_base + 1u") != null);
}

test "Metal evaluation codegen: rejects a noncontiguous fusion group" {
    var base = [_]eval.BaseInst{
        .{ .op = .constant, .interaction = 0, .dst = 0, .a = 1, .b = 0, .imm = 0 },
    };
    var ext = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
    };
    var roots = [_]u32{0};
    const program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0x3333, .capability_bits = eval.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 1, .max_ext_regs = 1, .domain_log_size = 8 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    const parts = [_]FusedPart{
        .{ .program = program, .rc_base = 0 },
        .{ .program = program, .rc_base = 2 },
    };
    try std.testing.expectError(
        error.InvalidFusionGroup,
        generateFusedKernel(std.testing.allocator, &parts, false),
    );
}
