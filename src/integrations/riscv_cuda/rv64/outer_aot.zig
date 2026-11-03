//! Program-only CUDA artifacts for the independently pinned OM31 circuit AIR.
//! Uses the existing RV64 OM31 numerical ABI and emitter. Geometry and fresh
//! challenge parameters are invocation data; no per-shape code compilation.
const std = @import("std");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const C = @import("composition_codegen.zig");
pub const Group = struct { component: u32, part: u32, first: u32, count: u32 };
pub fn groups(a: std.mem.Allocator, bundle: *const CPU.air.Bundle) ![]Group {
    var out: std.ArrayList(Group) = .empty;
    errdefer out.deinit(a);
    for (bundle.components, 0..) |component, ci| for (component.parts, 0..) |part, pi| {
        var first: u32 = 0;
        while (first < part.program.constraint_roots.len) {
            const count = @min(Outer.record.MAX_ROOTS, @as(u32, @intCast(part.program.constraint_roots.len)) - first);
            try out.append(a, .{ .component = @intCast(ci), .part = @intCast(pi), .first = first, .count = count });
            first += count;
        }
    };
    return out.toOwnedSlice(a);
}
pub fn write(a: std.mem.Allocator, directory: std.fs.Dir) !void {
    const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Outer.prove.parsePinnedAir(a, bytes);
    defer bundle.deinit();
    const catalogue = try groups(a, &bundle);
    defer a.free(catalogue);
    var declarations: std.ArrayList(u8) = .empty;
    defer declarations.deinit(a);
    var identities: std.ArrayList([64]u8) = .empty;
    defer identities.deinit(a);
    var masks: std.ArrayList(usize) = .empty;
    defer masks.deinit(a);
    var params: std.ArrayList(usize) = .empty;
    defer params.deinit(a);
    const names = try a.alloc([]u8, catalogue.len);
    defer a.free(names);
    var made: usize = 0;
    defer for (names[0..made]) |name| a.free(name);
    var manifest: std.ArrayList(u8) = .empty;
    defer manifest.deinit(a);
    try manifest.appendSlice(a, "{\"profile\":\"native-om31-circuit\",\"geometry_independent\":true,\"groups\":[\n");
    for (catalogue, 0..) |group, id| {
        var artifact = try Outer.record.record(a, &bundle.components[group.component], group.part, group.first, group.count);
        defer artifact.deinit();
        names[id] = try C.kernelName(a, &artifact.program);
        made += 1;
        var source: std.ArrayList(u8) = .empty;
        defer source.deinit(a);
        try C.emit(a, source.writer(a), &artifact.program, names[id]);
        const filename = try std.fmt.allocPrint(a, "outer-group-{}.cu", .{id});
        defer a.free(filename);
        try directory.writeFile(.{ .sub_path = filename, .data = source.items });
        var identity: [64]u8 = undefined;
        @memcpy(identity[0..32], &artifact.program.identity);
        @memcpy(identity[32..], &(try C.identity(&artifact.program)));
        try identities.append(a, identity);
        try masks.append(a, artifact.program.inputs.len);
        try params.append(a, artifact.parameter_slots.len);
        try declarations.writer(a).print("extern \"C\" __global__ void {s}(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);\n", .{names[id]});
        try manifest.writer(a).print("{s}{{\"id\":{},\"component\":{},\"part\":{},\"first\":{},\"count\":{},\"filename\":\"{s}\",\"program_identity\":\"{s}\",\"source_identity\":\"{s}\"}}\n", .{ if (id == 0) "" else ",", id, group.component, group.part, group.first, group.count, filename, std.fmt.bytesToHex(artifact.program.identity, .lower), std.fmt.bytesToHex(try C.identity(&artifact.program), .lower) });
    }
    try manifest.appendSlice(a, "]}\n");
    try directory.writeFile(.{ .sub_path = "outer-manifest.json", .data = manifest.items });
    var dispatch: std.ArrayList(u8) = .empty;
    defer dispatch.deinit(a);
    const w = dispatch.writer(a);
    try w.writeAll("#include <cuda_runtime.h>\n#include <cstring>\n#include \"rv64/composition_dispatch.cuh\"\n");
    try w.writeAll(declarations.items);
    try w.writeAll("static const void *kernels[]={");
    for (names, 0..) |name, i| try w.print("{s}(void*){s}", .{ if (i == 0) "" else ",", name });
    try w.writeAll("};\nstatic const uint32_t groups[]={");
    for (catalogue, 0..) |_, i| try w.print("{s}0u", .{if (i == 0) "" else ","});
    try w.writeAll("};\nstatic const uint32_t masks[]={");
    for (masks.items, 0..) |count, i| try w.print("{s}{}u", .{ if (i == 0) "" else ",", count });
    try w.writeAll("};\nstatic const uint32_t params[]={");
    for (params.items, 0..) |count, i| try w.print("{s}{}u", .{ if (i == 0) "" else ",", count });
    try w.writeAll("};\nstatic const uint32_t roots[]={");
    for (catalogue, 0..) |group, i| try w.print("{s}{}u", .{ if (i == 0) "" else ",", group.count });
    try w.writeAll("};\nstatic const uint8_t identities[][64]={\n");
    for (identities.items) |identity| {
        try w.writeAll("{");
        for (identity, 0..) |byte, i| try w.print("{s}{}", .{ if (i == 0) "" else ",", byte });
        try w.writeAll("},\n");
    }
    try w.writeAll("};\nextern \"C\" int stwo_circuit_om31_composition_identity(uint32_t id,uint8_t*out){if(!out||id>=sizeof(kernels)/sizeof(kernels[0]))return 1;std::memcpy(out,identities[id],64);return 0;}\nextern \"C\" int stwo_circuit_om31_composition_role_on(void*c,uint32_t l,const StwoRv64CompositionRole*j,uint32_t*n){if(!j||j->role>=sizeof(kernels)/sizeof(kernels[0])||j->mask_count!=masks[j->role]||j->parameter_count!=params[j->role]||j->constraint_count!=roots[j->role])return int(cudaErrorInvalidValue);return stwo::cuda::rv64::composition_dispatch(c,l,j,n,kernels,groups,sizeof(kernels)/sizeof(kernels[0]));}\n");
    try directory.writeFile(.{ .sub_path = "outer-dispatch.cu", .data = dispatch.items });
    std.debug.print("OM31_OUTER_AOT groups={} pinned_authority=true geometry_independent=true\n", .{catalogue.len});
}
