//! Immutable raw-retirement classification plan and proof-arena GPU bucketing.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Opcode = @import("../../frontends/riscv/runner/decode.zig").Opcode;
const common = cuda.runtime.stages.common;
pub const OPCODE_COUNT = @intFromEnum(Opcode.FENCE) + 1;
pub const FIRST_ID: u32 = (1 << 28) + 65536;
pub const Slot = enum(u32) { metadata, keys_in, keys_out, indices_in, indices_out, scratch };
pub fn opcodeMap() [OPCODE_COUNT]u32 {
    var out: [OPCODE_COUNT]u32 = @splat(std.math.maxInt(u32));
    for (std.enums.values(Opcode)) |opcode| {
        const family = Trace.proofOpcodeFamily(opcode) catch continue;
        out[@intFromEnum(opcode)] = @intFromEnum(family);
    }
    return out;
}
extern fn stwo_native_ingress_temp_bytes_v1(u32, *usize) c_int;
extern fn stwo_native_ingress_on([*]const u32, u32, [*]const u32, u32, [*]const u32, [*]u64, [*]u64, [*]u32, [*]u32, ?*anyopaque, usize, [*]u32, ?*anyopaque) c_int;
pub const Plan = struct {
    rows: u32,
    metadata: [OPCODE_COUNT + 17]u32,
    scratch_bytes: usize,
    total_bytes: usize,
    pub fn init(counts: [17]u32, cap: usize) !Plan {
        var rows: u32 = 0;
        for (counts) |count| rows = try std.math.add(u32, rows, count);
        if (rows > (1 << 24)) return error.InvalidNativeIngressGeometry;
        var scratch: usize = 0;
        if (rows != 0 and stwo_native_ingress_temp_bytes_v1(rows, &scratch) != 0) return error.NativeIngressWorkspaceFailure;
        const words = try std.math.add(usize, OPCODE_COUNT + 17 + 6 * @as(usize, rows), (scratch + 3) / 4);
        const bytes = try std.math.mul(usize, words + (if (rows == 0) @as(usize, 5) else 0), 4);
        if (bytes > cap) return error.NativeIngressResourceLimit;
        return .{ .rows = rows, .metadata = opcodeMap() ++ counts, .scratch_bytes = scratch, .total_bytes = bytes };
    }
    pub fn requirements(self: Plan) [6]cuda.runtime.arena.Requirement {
        const sizes = [_]usize{ self.metadata.len, 2 * @as(usize, self.rows), 2 * @as(usize, self.rows), self.rows, self.rows, @max(1, (self.scratch_bytes + 3) / 4) };
        var out: [6]cuda.runtime.arena.Requirement = undefined;
        for (&out, sizes, 0..) |*r, words, i| r.* = .{ .id = FIRST_ID + @as(u32, @intCast(i)), .words = @max(1, words), .alignment_words = 64, .live_from = .ingress, .live_through = .trace_generation };
        return out;
    }
};
pub const Bound = struct {
    plan: *const Plan,
    slots: [6]common.Words,
    primed: bool = false,
    completed: bool = false,
    pub fn init(plan: *const Plan, tx: anytype) !Bound {
        var out: Bound = .{ .plan = plan, .slots = undefined };
        const requirements = plan.requirements();
        for (&out.slots, requirements) |*slot, r| {
            slot.* = try tx.slot(r.id);
            if (slot.len != r.words) return error.InvalidNativeIngressBinding;
        }
        return out;
    }
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.InvalidNativeIngressState;
        try common.requireStage(session, .ingress);
        try session.context.uploadSlice(u32, self.slots[0], &self.plan.metadata);
        self.primed = true;
    }
    pub fn execute(self: *Bound, session: anytype, raw: common.Words, status: common.Words) !common.Words {
        if (!self.primed or self.completed or raw.len != 24 * @as(usize, self.plan.rows) or status.len != 1) return error.InvalidNativeIngressState;
        try common.requireStage(session, .trace_generation);
        if (self.plan.rows == 0) {
            self.completed = true;
            return self.slots[4].sub(0, 0);
        }
        const map = try self.slots[0].sub(0, OPCODE_COUNT);
        const counts = try self.slots[0].sub(OPCODE_COUNT, 17);
        const ki = try self.slots[1].cast(u64);
        const ko = try self.slots[2].cast(u64);
        try common.record(session, .trace_generation, stwo_native_ingress_on(try ptr(session, raw), self.plan.rows, try ptr(session, map), OPCODE_COUNT, try ptr(session, counts), try session.context.deviceSlicePointer(u64, ki, ki.len), try session.context.deviceSlicePointer(u64, ko, ko.len), try ptr(session, self.slots[3]), try ptr(session, self.slots[4]), @ptrCast(try ptr(session, self.slots[5])), self.slots[5].len * 4, try ptr(session, status), session.context.stream));
        self.completed = true;
        return self.slots[4];
    }
};
fn ptr(session: anytype, w: common.Words) ![*]u32 {
    return session.context.deviceSlicePointer(u32, w, w.len);
}
pub fn exportOracle(a: std.mem.Allocator, path: []const u8) !void {
    const n = 1003;
    const map = opcodeMap();
    var supported: std.ArrayList(u32) = .empty;
    defer supported.deinit(a);
    for (map, 0..) |family, opcode| if (family < 17) try supported.append(a, @intCast(opcode));
    var raw: [n * 24]u32 = @splat(0);
    var expected: [n]u32 = undefined;
    var counts: [17]u32 = @splat(0);
    for (0..n) |i| {
        const opcode = supported.items[(i * 31 + 17) % supported.items.len];
        raw[24 * i + 2] = opcode;
        counts[map[opcode]] += 1;
    }
    var at: usize = 0;
    for (0..17) |family| for (0..n) |i| if (map[raw[24 * i + 2]] == family) {
        expected[at] = @intCast(i);
        at += 1;
    };
    var writer: std.Io.Writer.Allocating = .init(a);
    defer writer.deinit();
    const w = &writer.writer;
    try w.writeAll(@embedFile("native/resident_native_ingress_v1.cu"));
    try w.writeAll("\n#include <vector>\n#include <cstdio>\n#define CHECK(x)do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,\"CUDA %s line%d\\n\",cudaGetErrorString(e),__LINE__);return 2;}}while(0)\nint main(){\n");
    inline for (.{ "raw", "map", "counts", "expected" }, .{ &raw, &map, &counts, &expected }) |name, values| {
        try w.print("const uint32_t {s}[]={{", .{name});
        for (values, 0..) |v, i| try w.print("{s}{d}u", .{ if (i == 0) "" else ",", v });
        try w.writeAll("};\n");
    }
    try w.print("const unsigned n={d};uint32_t*dr,*dm,*dc,*ii,*io,*status;uint64_t*ki,*ko;void*scratch;size_t bytes=0;CHECK(cudaError_t(stwo_native_ingress_temp_bytes_v1(n,&bytes)));CHECK(cudaMalloc(&dr,sizeof(raw)));CHECK(cudaMalloc(&dm,sizeof(map)));CHECK(cudaMalloc(&dc,sizeof(counts)));CHECK(cudaMalloc(&ki,8*n));CHECK(cudaMalloc(&ko,8*n));CHECK(cudaMalloc(&ii,4*n));CHECK(cudaMalloc(&io,4*n));CHECK(cudaMalloc(&status,4));CHECK(cudaMalloc(&scratch,bytes));CHECK(cudaMemcpy(dr,raw,sizeof(raw),cudaMemcpyHostToDevice));CHECK(cudaMemcpy(dm,map,sizeof(map),cudaMemcpyHostToDevice));CHECK(cudaMemcpy(dc,counts,sizeof(counts),cudaMemcpyHostToDevice));CHECK(cudaMemset(status,0,4));\n", .{n});
    try w.print("CHECK(cudaError_t(stwo_native_ingress_on(dr,n,dm,{d},dc,ki,ko,ii,io,scratch,bytes,status,nullptr)));uint32_t error=0;CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error)return 3;std::vector<uint32_t>actual(n);CHECK(cudaMemcpy(actual.data(),io,4*n,cudaMemcpyDeviceToHost));for(unsigned i=0;i<n;i++)if(actual[i]!=expected[i])return 4;\n", .{OPCODE_COUNT});
    try w.print("if(stwo_native_ingress_on(dr,n,dm,{d},dc,ki,ko,ii,io,scratch,bytes-1,status,nullptr)!=int(cudaErrorInvalidValue))return 5;uint32_t wrong=counts[0]+1;CHECK(cudaMemcpy(dc,&wrong,4,cudaMemcpyHostToDevice));CHECK(cudaError_t(stwo_native_ingress_on(dr,n,dm,{d},dc,ki,ko,ii,io,scratch,bytes,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(!(error&2))return 6;CHECK(cudaMemcpy(dc,counts,sizeof(counts),cudaMemcpyHostToDevice));CHECK(cudaMemset(status,0,4));wrong=999;CHECK(cudaMemcpy(dr+2,&wrong,4,cudaMemcpyHostToDevice));CHECK(cudaError_t(stwo_native_ingress_on(dr,n,dm,{d},dc,ki,ko,ii,io,scratch,bytes,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(!(error&1))return 7;\n", .{ OPCODE_COUNT, OPCODE_COUNT, OPCODE_COUNT });
    try w.writeAll("CHECK(cudaFree(dr));CHECK(cudaFree(dm));CHECK(cudaFree(dc));CHECK(cudaFree(ki));CHECK(cudaFree(ko));CHECK(cudaFree(ii));CHECK(cudaFree(io));CHECK(cudaFree(status));CHECK(cudaFree(scratch));printf(\"PASS native GPU raw retirement stable family bucketing rows=%u families=17 hostiles=3\\n\",n);return 0;}\n");
    var f = try std.fs.cwd().createFile(path, .{});
    defer f.close();
    try f.writeAll(writer.written());
}
test "resident native ingress opcode map is exact original classification" {
    const map = opcodeMap();
    for (std.enums.values(Opcode)) |opcode| {
        const expected = Trace.proofOpcodeFamily(opcode) catch {
            try std.testing.expectEqual(std.math.maxInt(u32), map[@intFromEnum(opcode)]);
            continue;
        };
        try std.testing.expectEqual(@as(u32, @intFromEnum(expected)), map[@intFromEnum(opcode)]);
    }
}
