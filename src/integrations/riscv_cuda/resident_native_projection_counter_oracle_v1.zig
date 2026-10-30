//! TEST-ONLY CPU tuples/counts are reference vectors, never producer inputs.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const P = @import("resident_native_projection_counter_v1.zig");
const Original = @import("resident_native_projection_program_v1.zig");
const A = @import("../../frontends/riscv/prover/block_v5_native_fused_algebra_v1.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Test = @import("resident_native_projection_test_v1.zig");
const L = @import("../../frontends/riscv/prover/block_v7_native_relation_layout_v1.zig");
pub fn exportOracle(a: std.mem.Allocator, path: []const u8) !void {
    var selected: [6]?Original.Source.Slot = @splat(null);
    for (0..Trace.N_FAMILIES) |fi| {
        var shape = Test.shapeFor(@enumFromInt(fi));
        var layout = try L.Layout.init(a, &shape, 0, 1);
        defer layout.deinit();
        for (layout.slots) |slot| {
            const k = P.kind(slot) catch continue;
            if (selected[@intFromEnum(k)] == null) selected[@intFromEnum(k)] = slot;
        }
    }
    var out = std.Io.Writer.Allocating.init(a);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll("#include <cuda_runtime.h>\n#include <cstdio>\n#include <vector>\n");
    try w.writeAll(P.preamble);
    for (selected, 0..) |maybe, i| {
        var p = try P.Owned.init(a, maybe orelse return error.MissingTable);
        defer p.deinit();
        const name = try std.fmt.allocPrint(a, "counts_{d}", .{i});
        defer a.free(name);
        try P.emit(w, name, &p);
    }
    try w.writeAll("#define CHECK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,\"CUDA %s:%d\\n\",cudaGetErrorString(e),__LINE__);return 2;}}while(0)\nint main(){uint positives=0,negatives=0;\n");
    for (selected, 0..) |maybe, id| {
        const slot = maybe.?;
        const table = try P.kind(slot);
        const main = try a.alloc(Q, slot.width);
        defer a.free(main);
        for ([_]u32{ 0, 1, 255, 1234567 }) |pattern| {
            for (main) |*v| v.* = Q.fromBase(M.fromCanonical(pattern));
            var rec = P.Recorder(Q){ .selected = Original.domain(slot) };
            const pair = try A.Algebra(Q).projection(slot, main, &rec);
            var valid = true;
            var indexes: [2]usize = @splat(0);
            var weights: [2]u32 = @splat(0);
            for (0..pair.entry_count) |i| {
                const numerator = try pair.numerators[i].tryIntoM31();
                weights[i] = numerator.v;
                if (numerator.isZero()) continue;
                indexes[i] = P.Schema.indexSecure(table, rec.tuples[i][0..P.Schema.arity(table)]) catch {
                    valid = false;
                    continue;
                };
            }
            try w.print("{{std::vector<uint> main({d}*8,{d}u),want({d},0u),got({d});uint *dm,*dc,*ds,status=0;CHECK(cudaMalloc(&dm,main.size()*4));CHECK(cudaMalloc(&dc,want.size()*4));CHECK(cudaMalloc(&ds,4));CHECK(cudaMemcpy(dm,main.data(),main.size()*4,cudaMemcpyHostToDevice));CHECK(cudaMemset(dc,0,want.size()*4));CHECK(cudaMemset(ds,0,4));counts_{d}<<<1,32>>>(dm,dc,8,ds);CHECK(cudaGetLastError());CHECK(cudaDeviceSynchronize());CHECK(cudaMemcpy(&status,ds,4,cudaMemcpyDeviceToHost));\n", .{ slot.width, pattern, P.Schema.size(table), P.Schema.size(table), id });
            if (valid) {
                for (0..pair.entry_count) |i| if (weights[i] != 0) try w.print("want[{d}]=uint((ulong(want[{d}])+ulong({d}u)*8u)%2147483647ull);\n", .{ indexes[i], indexes[i], weights[i] });
                try w.print("if(status){{fprintf(stderr,\"unexpectedstatus table{d} pattern{d} %u\\n\",status);return 3;}}CHECK(cudaMemcpy(got.data(),dc,got.size()*4,cudaMemcpyDeviceToHost));if(got!=want){{fprintf(stderr,\"counter table{d} pattern{d} mismatch\\n\");return 4;}}positives++;\n", .{ id, pattern, id, pattern });
            } else try w.print("if(!(status&4u)){{fprintf(stderr,\"missedinvalid table{d} pattern{d}\\n\");return 5;}}negatives++;\n", .{ id, pattern });
            try w.writeAll("CHECK(cudaFree(dm));CHECK(cudaFree(dc));CHECK(cudaFree(ds));}\n");
        }
    }
    try w.writeAll("printf(\"PASS native table counter sixschemas positives=%u negatives=%u\\n\",positives,negatives);return 0;}\n");
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(out.written());
}
test "resident native table counter CUDA oracle export" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_COUNTER_CUDA") catch |err| if (err == error.EnvironmentVariableNotFound) return else return err;
    defer a.free(path);
    try exportOracle(a, path);
}
