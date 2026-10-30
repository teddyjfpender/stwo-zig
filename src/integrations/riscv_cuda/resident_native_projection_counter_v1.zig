//! Table counters extracted from the original physical projection declarations.
//! Cold graphs contain no witness values. Each original entry retains its signed
//! weight; the output counter is canonical table-row order, not committed order.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../frontends/riscv/recursion/air/composition_graph_recorder.zig");
const Field = @import("../../frontends/riscv/recursion/air/block_v6_partitioned_composition_v1.zig").Field;
const Algebra = @import("../../frontends/riscv/prover/block_v5_native_fused_algebra_v1.zig");
const P = @import("resident_native_projection_program_v1.zig");
const Relation = @import("../../frontends/riscv/air/lang/relation.zig");
pub const Schema = @import("../../frontends/riscv/air/lookups/tables/schema_definition.zig");
pub const preamble = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig").preamble;
pub fn kind(slot: P.Source.Slot) !Schema.Kind {
    return switch (P.domain(slot)) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        else => error.NotNativeTableProjection,
    };
}
pub fn Recorder(comptime S: type) type {
    return struct {
        selected: Relation.Domain,
        count: usize = 0,
        tuples: [2][4]S = undefined,
        pub const Element = struct {
            owner: *Recorder(S),
            requested: Relation.Domain,
            arity: u8,
            pub fn combineSecure(self: @This(), values: []const S) !S {
                if (self.requested != self.owner.selected or values.len != self.arity or values.len > 4 or self.owner.count >= 2) return error.InvalidNativeTableProjection;
                @memcpy(self.owner.tuples[self.owner.count][0..values.len], values);
                self.owner.count += 1;
                return S.one();
            }
        };
        pub fn get(self: *@This(), domain: Relation.Domain) Element {
            return .{ .owner = self, .requested = domain, .arity = Relation.universal_descriptors[@intFromEnum(domain)].arity };
        }
    };
}
pub const Owned = struct {
    a: std.mem.Allocator,
    slot: P.Source.Slot,
    table: Schema.Kind,
    entries: usize,
    circuit: R.Circuit,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, slot: P.Source.Slot) !Owned {
        const table = try kind(slot);
        if (slot.width == 0 or slot.width > 512) return error.InvalidNativeTableProjection;
        var b = R.Builder.init(a);
        defer b.deinit();
        const main = try a.alloc(Field, slot.width);
        defer a.free(main);
        for (main) |*v| v.* = .{ .symbol = (try b.input()).value };
        try b.activate();
        errdefer if (b.active) b.deactivate();
        var recorder = Recorder(Field){ .selected = P.domain(slot) };
        const pair = try Algebra.Algebra(Field).projection(slot, main, &recorder);
        if (recorder.count != pair.entry_count) return error.InvalidNativeTableProjection;
        for (0..recorder.count) |i| {
            try b.constrainZero(pair.numerators[i].symbol);
            for (recorder.tuples[i][0..Schema.arity(table)]) |v| try b.constrainZero(v.symbol);
        }
        b.deactivate();
        var circuit = try b.finish();
        errdefer circuit.deinit();
        var result = Owned{ .a = a, .slot = slot, .table = table, .entries = recorder.count, .circuit = circuit, .identity = undefined };
        result.identity = result.digest();
        return result;
    }
    fn digest(self: *const Owned) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        P.Source.mixSlot(&channel, self.slot);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo-native-table-counter-v1");
        h.update(&channel.digestBytes());
        h.update(&self.circuit.identity_digest);
        h.update(&.{ @intFromEnum(self.table), @intCast(self.entries) });
        h.update(@embedFile("../../frontends/riscv/air/lookups/tables/schema_definition.zig"));
        return h.finalResult();
    }
    pub fn validate(self: *const Owned) !void {
        try self.circuit.validate();
        if (self.table != try kind(self.slot) or self.entries == 0 or self.entries > 2 or self.circuit.input_count != self.slot.width or self.circuit.outputs.len != self.entries * (1 + Schema.arity(self.table)) or !std.mem.eql(u8, &self.identity, &self.digest())) return error.InvalidNativeTableProjection;
    }
    pub fn deinit(self: *Owned) void {
        self.circuit.deinit();
        self.* = undefined;
    }
};
/// ABI: main SoA, canonical signed-M31 counter, domain rows, sticky error.
/// Counter must be initialized to zero and contain Schema.size(table) words.
pub fn emit(w: anytype, name: []const u8, p: *const Owned) !void {
    try p.validate();
    if (name.len == 0) return error.InvalidNativeTableProjection;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidNativeTableProjection;
    try w.print("extern \"C\" __global__ void {s}(const uint* main,uint* counter,uint rows,uint* status){{uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;\n", .{name});
    var input: usize = 0;
    for (p.circuit.nodes, 0..) |node, i| {
        try w.print("RiscvQm31 v{d}=", .{i});
        switch (node.op) {
            .input => {
                try w.print("RiscvQm31{{main[ulong({d}u)*rows+row],0u,0u,0u}}", .{input});
                input += 1;
            },
            .constant => |x| try w.print("RiscvQm31{{{d}u,{d}u,{d}u,{d}u}}", .{ x[0], x[1], x[2], x[3] }),
            .add, .sub, .mul => |x| try w.print("riscv_qm_{s}(v{d},v{d})", .{ @tagName(node.op), x.lhs, x.rhs }),
            .neg => |x| try w.print("riscv_qm_sub(RiscvQm31{{0u,0u,0u,0u}},v{d})", .{x}),
            .inverse => return error.NonPolynomialNativeProjectionProgram,
        }
        try w.writeAll(";\n");
    }
    const stride = 1 + Schema.arity(p.table);
    for (0..p.entries) |entry| {
        const roots = p.circuit.outputs[entry * stride ..][0..stride];
        try w.print("{{RiscvQm31 weight=v{d};if(weight.b|weight.c|weight.d){{atomicOr(status,1u);return;}}if(weight.a){{uint t[4]={{0u,0u,0u,0u}};\n", .{roots[0]});
        for (roots[1..], 0..) |r, i| try w.print("if(v{d}.b|v{d}.c|v{d}.d){{atomicOr(status,2u);return;}}t[{d}]=v{d}.a;\n", .{ r, r, r, i, r });
        try w.writeAll("uint index=0;bool valid=true;\n");
        switch (p.table) {
            .bitwise => try w.writeAll("valid=t[0]<256u&&t[1]<256u&&t[2]<256u&&t[3]<4u;uint expected=t[3]==0u?(t[0]&t[1]):t[3]==1u?(t[0]|t[1]):t[3]==2u?(t[0]^t[1]):0u;valid=valid&&t[2]==expected;index=t[0]|(t[1]<<8)|(t[3]<<16);\n"),
            .range_check_20 => try w.writeAll("valid=t[0]<(1u<<20);index=t[0];\n"),
            .range_check_8_11 => try w.writeAll("valid=t[0]<256u&&t[1]<2048u;index=t[0]|(t[1]<<8);\n"),
            .range_check_8_8_4 => try w.writeAll("valid=t[0]<256u&&t[1]<256u&&t[2]<16u;index=t[0]|(t[1]<<8)|(t[2]<<16);\n"),
            .range_check_8_8 => try w.writeAll("valid=t[0]<256u&&t[1]<256u;index=t[0]|(t[1]<<8);\n"),
            .range_check_m31 => try w.writeAll("valid=t[0]<256u&&t[1]<128u&&!(t[0]==255u&&t[1]==127u);index=t[0]|(t[1]<<8);\n"),
        }
        try w.writeAll("if(!valid){atomicOr(status,4u);return;}uint old=atomicCAS(counter+index,0u,0u),seen;do{seen=old;if(seen>=2147483647u){atomicOr(status,8u);return;}ulong sum=ulong(seen)+weight.a;uint next=uint(sum>=2147483647ull?sum-2147483647ull:sum);old=atomicCAS(counter+index,seen,next);}while(old!=seen);}}\n");
    }
    try w.writeAll("}\n");
}
