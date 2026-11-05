//! Companion kernels for bounded residency of unchanged outer Blake roots.
//! The existing catalogue and composition code identity remain unchanged.
const std = @import("std");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const Aot = @import("outer_aot.zig");
const C = @import("composition_codegen.zig");
const P = @import("composition_sparse.zig");
const E = @import("composition_sparse_codegen.zig");

pub fn write(a: std.mem.Allocator, directory: std.fs.Dir) !void {
    const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Outer.prove.parsePinnedAir(a, bytes);
    defer bundle.deinit();
    const catalogue = try Aot.groups(a, &bundle);
    defer a.free(catalogue);
    var dispatch: std.ArrayList(u8) = .empty;
    defer dispatch.deinit(a);
    const w = dispatch.writer(a);
    try w.writeAll("#include <cstring>\n#include \"rv64/composition_dispatch.cuh\"\n");
    for ([_]usize{ 4, 5 }) |role| {
        const parent = catalogue[role];
        var artifact = try Outer.record.record(a, &bundle.components[parent.component], parent.part, parent.first, parent.count);
        defer artifact.deinit();
        const program = &artifact.program;
        var plan = try P.init(a, program, 32);
        defer plan.deinit(a);
        try plan.validate(a, program);
        // This implementation requires whole original roots, in original order.
        // Reject an additive split rather than silently expanding its contract.
        if (plan.terms.len != program.roots.len) return error.OuterChunkRootSplit;
        for (plan.terms, program.roots, 0..) |term, node, index| {
            if (term.negative or term.root != index or term.node != node) return error.OuterChunkRootCoverMismatch;
        }
        var cache = try P.cache(a, &plan, 32);
        defer cache.deinit(a);
        try cache.validate(a, &plan);
        const mapping = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-outer-chunks/v1", .role = role, .parent_source_identity = std.fmt.bytesToHex(try C.identity(program), .lower), .parameters = artifact.parameter_slots.len, .roots = program.roots.len, .inputs = program.inputs, .plan = plan, .cache = cache, .whole_original_roots = true }, .{ .whitespace = .indent_2 });
        defer a.free(mapping);
        const mapping_name = try std.fmt.allocPrint(a, "role-{}-mapping.json", .{role});
        defer a.free(mapping_name);
        try directory.writeFile(.{ .sub_path = mapping_name, .data = mapping });
        for (plan.groups, 0..) |_, group| {
            const name = try std.fmt.allocPrint(a, "stwo_outer_chunks_{}_{}", .{ role, group });
            defer a.free(name);
            var source: std.ArrayList(u8) = .empty;
            defer source.deinit(a);
            try E.emit(a, source.writer(a), program, &plan, @intCast(group), name);
            const filename = try std.fmt.allocPrint(a, "role-{}-group-{}.cu", .{ role, group });
            defer a.free(filename);
            try directory.writeFile(.{ .sub_path = filename, .data = source.items });
            try w.print("extern \"C\" __global__ void {s}(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);\n", .{name});
        }
        try w.print("static const void*kernels_{}[]={{", .{role});
        for (plan.groups, 0..) |_, group| try w.print("{s}(const void*)stwo_outer_chunks_{}_{}", .{ if (group == 0) "" else ",", role, group });
        try w.print("}};\nstatic const uint32_t sizes_{}[{}]={{}};\nstatic const uint8_t identity_{}[96]={{", .{ role, plan.groups.len, role });
        const identity = program.identity ++ plan.identity ++ (try C.identity(program));
        for (identity, 0..) |byte, i| try w.print("{s}{}", .{ if (i == 0) "" else ",", byte });
        try w.writeAll("};\n");
        try w.print("static int run_{}(void*c,uint32_t lane,uint32_t group,const StwoRv64CompositionRole*j,uint32_t*n){{if(!j||!n||lane||j->eval_log<20||j->eval_log>28||j->trace_log<4||group>={}||j->role!={}||j->mask_count!={}||j->parameter_count!={}||j->constraint_count!={}||j->trees[0]!=j->trees[1]||j->trees[0]!=j->trees[2]||j->tree_words[0]!=(uint64_t(32)<<j->eval_log)||j->tree_words[1]!=j->tree_words[0]||j->tree_words[2]!=j->tree_words[0])return int(cudaErrorInvalidValue);auto local=*j;local.role=group;return stwo::cuda::rv64::composition_dispatch(c,lane,&local,n,kernels_{},sizes_{},{});}}\n", .{ role, plan.groups.len, role, program.inputs.len, artifact.parameter_slots.len, program.roots.len, role, role, plan.groups.len });
        std.debug.print("OUTER_CHUNKS role={} roots={} groups={} columns={} fills={} slots=32 whole_roots=true\n", .{ role, program.roots.len, plan.groups.len, plan.union_columns, cache.fills });
    }
    try w.writeAll("extern \"C\" int stwo_outer_chunks_identity(uint32_t role,uint8_t*out){if(!out)return 1;switch(role){case 4:std::memcpy(out,identity_4,96);return 0;case 5:std::memcpy(out,identity_5,96);return 0;default:return 1;}}\nextern \"C\" int stwo_outer_chunks_group_on(void*c,uint32_t lane,uint32_t group,const StwoRv64CompositionRole*j,uint32_t*n){if(n)*n=0;if(!j||!n)return int(cudaErrorInvalidValue);switch(j->role){case 4:return run_4(c,lane,group,j,n);case 5:return run_5(c,lane,group,j,n);default:return int(cudaErrorInvalidValue);}}\n");
    try directory.writeFile(.{ .sub_path = "dispatch.cu", .data = dispatch.items });
}
