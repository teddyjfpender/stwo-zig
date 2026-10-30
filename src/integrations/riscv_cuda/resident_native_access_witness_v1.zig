//! Mechanical device export of the original native RW access byte witness.
//! MAIN is already resident; base_clock must come from the admitted frame.
//! This constructor has no proof authority: the original 68 equations remain
//! mandatory over the same MAIN and these 48 committed witness columns.
const std = @import("std");
const Core = @import("stwo_core");
const Access = @import("../../frontends/riscv/prover/block_execution_access_bridge_v2.zig");
const Integer = @import("../../frontends/riscv/prover/block_execution_integer_bridge_v2.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Range = @import("../../frontends/riscv/prover/block_execution_byte_range_v2.zig");
const Q = Core.fields.qm31.QM31;
const M = Core.fields.m31.M31;
pub const MAIN_COUNT = Trace.nColumnsForFamily(.load_store);
pub const WITNESS_COUNT = Integer.COLUMN_COUNT;
pub fn columns(comptime slot: u8, main: *const [MAIN_COUNT]u32, base_clock: u64) ![WITNESS_COUNT]u32 {
    comptime std.debug.assert(slot == 1 or slot == 2);
    var secure: [MAIN_COUNT]Q = undefined;
    for (main, &secure) |value, *out| {
        if (value >= Core.fields.m31.Modulus) return error.NonCanonicalAccessMain;
        out.* = Q.fromBase(M.fromU32Unchecked(value));
    }
    const pairs = try Access.fromCommittedMain(Q, .load_store, &secure);
    if (pairs.len <= slot) return error.InvalidNativeAccessSlot;
    const pair = try Access.rwPairForMode(Q, .load_store, slot, pairs.items[slot], 1);
    const witness = (try Integer.Witness.fromPair(pair, base_clock)).columns();
    var result: [WITNESS_COUNT]u32 = undefined;
    for (witness, &result) |value, *out| {
        const limbs = value.toM31Array();
        for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseAccessWitness;
        out.* = limbs[0].toU32();
    }
    return result;
}
pub fn Writer(comptime slot: u8) type {
    return struct {
        pub fn run(main: [*]const u32, output: [*]u32, rows: usize, index: usize, base_clock: u64) callconv(.c) u32 {
            if (rows < 2 or rows > (1 << 24) or rows & (rows - 1) != 0 or index >= rows) return 1;
            var input: [MAIN_COUNT]u32 = undefined;
            for (&input, 0..) |*value, column| value.* = main[column * rows + index];
            const result = columns(slot, &input, base_clock) catch return 2;
            // Commit stores only after all original validation has succeeded.
            for (result, 0..) |value, column| output[column * rows + index] = value;
            return 0;
        }
        pub fn bytes(main: [*]const u32, witness: [*]const u32, rows: usize, index: usize, output: *[29]u32) callconv(.c) u32 {
            if (rows < 2 or rows > (1 << 24) or rows & (rows - 1) != 0 or index >= rows) return 1;
            var secure: [MAIN_COUNT]Q = undefined;
            for (&secure, 0..) |*value, c| {
                const raw = main[c * rows + index];
                if (raw >= Core.fields.m31.Modulus) return 2;
                value.* = Q.fromBase(M.fromU32Unchecked(raw));
            }
            const pairs = Access.fromCommittedMain(Q, .load_store, &secure) catch return 2;
            const pair = Access.rwPairForMode(Q, .load_store, slot, pairs.items[slot], 1) catch return 2;
            const decoded = Access.decodePair(pair) catch return 2;
            if (!decoded.active) {
                output.* = @splat(0);
                return 0;
            }
            var byte_columns: [WITNESS_COUNT]Q = undefined;
            for (&byte_columns, 0..) |*value, c| {
                const raw = witness[c * rows + index];
                if (raw >= Core.fields.m31.Modulus) return 2;
                value.* = Q.fromBase(M.fromU32Unchecked(raw));
            }
            const values = Range.bytesAtPoint(pair, Integer.Witness.fromColumns(byte_columns));
            var result: [29]u32 = undefined;
            result[0] = 1;
            for (values, result[1..]) |value, *out| {
                const limbs = value.toM31Array();
                for (limbs[1..]) |limb| if (!limb.isZero()) return 2;
                if (limbs[0].v >= 256) return 2;
                out.* = limbs[0].v;
            }
            output.* = result;
            return 0;
        }
    };
}
pub fn exportWriters() void {
    comptime {
        @setEvalBranchQuota(2_000_000);
        @export(&Writer(1).run, .{ .name = "stwo_native_access_witness_1_v1" });
        @export(&Writer(2).run, .{ .name = "stwo_native_access_witness_2_v1" });
        @export(&Writer(1).bytes, .{ .name = "stwo_native_access_bytes_1_v1" });
        @export(&Writer(2).bytes, .{ .name = "stwo_native_access_bytes_2_v1" });
    }
}

fn writeArray(writer: anytype, name: []const u8, words: []const u32) !void {
    try writer.print("const unsigned {s}[]={{", .{name});
    for (words, 0..) |word, i| try writer.print("{s}{d}u", .{ if (i == 0) "" else ",", word });
    try writer.writeAll("};\n");
}
/// Appended only to a test executable. Production receives resident MAIN.
pub fn exportOracle(a: std.mem.Allocator, path: []const u8) !void {
    const rows = 8;
    var storage: [MAIN_COUNT][rows]M = @splat(@splat(M.zero()));
    var slices: [Trace.MAX_FAMILY_COLUMNS][]M = undefined;
    for (&storage, 0..) |*column, i| slices[i] = column;
    for (0..6) |i| {
        const load = i % 2 == 0;
        const value: u32 = 0x12345678 + @as(u32, @intCast(37 * i));
        const row = Trace.TraceRow{
            .clk = @intCast(1 + i * 16384),
            .pc = 0x1000,
            .opcode = if (load) .LW else .SW,
            .rd = if (load) 4 else 0,
            .rs1 = 1,
            .rs2 = if (load) 0 else 3,
            .imm = 0,
            .rs1_val = @intCast(0x2000 + 256 * i),
            .rs2_val = if (load) 0 else value,
            .rd_val = if (load) value else 0,
            .mem_addr = @intCast(0x2000 + 256 * i),
            .mem_val = value,
            .mem_prev_word = value,
            .mem_next_word = value,
            .is_load = load,
            .is_store = !load,
            .branch_taken = false,
            .next_pc = 0x1004,
            .inst_word = if (load) (1 << 15) | (2 << 12) | (4 << 7) | 3 else (3 << 20) | (1 << 15) | (2 << 12) | 0x23,
        };
        try Trace.validateFamilyRow(row, .load_store);
        Trace.fillFamilyColumns(&slices, i, row, .load_store);
    }
    var main: [MAIN_COUNT * rows]u32 = undefined;
    for (storage, 0..) |column, c| for (column, 0..) |value, r| {
        main[c * rows + r] = value.v;
    };
    var w: std.Io.Writer.Allocating = .init(a);
    defer w.deinit();
    const out = &w.writer;
    try out.writeAll("\n#include <cstdio>\n#include <vector>\n#define CHECK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,\"CUDA %s line%d\\n\",cudaGetErrorString(e),__LINE__);return 2;}}while(0)\nint main(){unsigned words=0;\n");
    try writeArray(out, "input", &main);
    inline for (.{ 1, 2 }) |slot| {
        for ([_]u64{ 0, 0x1_fffffff0, std.math.maxInt(u64) - (1 << 24) }) |base| {
            var expected: [WITNESS_COUNT * rows]u32 = undefined;
            var counter = try @import("../../frontends/riscv/air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            for (0..rows) |r| {
                var secure: [MAIN_COUNT]Q = undefined;
                for (&secure, 0..) |*value, c| value.* = Q.fromBase(storage[c][r]);
                const pairs = try Access.fromCommittedMain(Q, .load_store, &secure);
                const pair = try Access.rwPairForMode(Q, .load_store, slot, pairs.items[slot], 1);
                const witness = try Integer.Witness.fromPair(pair, base);
                const original = witness.columns();
                for (original, 0..) |value, c| expected[c * rows + r] = value.toM31Array()[0].v;
                if ((try Access.decodePair(pair)).active) {
                    const bytes = Range.bytesAtPoint(pair, witness);
                    for (0..14) |i| try counter.registerRaw(Q.one(), bytes[2 * i ..][0..2]);
                }
            }
            try out.writeAll("{\n");
            try writeArray(out, "expected", &expected);
            try out.print("unsigned *main,*output,*status;CHECK(cudaMalloc(&main,sizeof(input)));CHECK(cudaMalloc(&output,sizeof(expected)));CHECK(cudaMalloc(&status,4));CHECK(cudaMemcpy(main,input,sizeof(input),cudaMemcpyHostToDevice));CHECK(cudaMemset(status,0,4));CHECK(cudaError_t(stwo_native_access_witness_on({d},main,output,8,{d}ull,status,nullptr)));unsigned error=0;CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error)return 3;std::vector<unsigned>actual(sizeof(expected)/4);CHECK(cudaMemcpy(actual.data(),output,sizeof(expected),cudaMemcpyDeviceToHost));for(unsigned i=0;i<actual.size();i++)if(actual[i]!=expected[i]){{fprintf(stderr,\"FAIL witness slot{d} word%u actual%u expected%u\\n\",i,actual[i],expected[i]);return 4;}}words+=actual.size();\n", .{ slot, base, slot });
            try out.writeAll("std::vector<unsigned>counts(65536,0),actual_counts(65536);\n");
            for (counter.values, 0..) |value, i| if (!value.isZero()) {
                try out.print("counts[{d}]={d};\n", .{ i, value.v });
            };
            try out.print("unsigned*dc;CHECK(cudaMalloc(&dc,65536*4));CHECK(cudaMemset(dc,0,65536*4));CHECK(cudaError_t(stwo_native_access_count_on({d},main,output,dc,8,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error)return 7;CHECK(cudaMemcpy(actual_counts.data(),dc,65536*4,cudaMemcpyDeviceToHost));for(unsigned i=0;i<65536;i++)if(actual_counts[i]!=counts[i]){{fprintf(stderr,\"counter slot{d} index%u got%u expected%u\\n\",i,actual_counts[i],counts[i]);return 8;}}words+=65536;\n", .{ slot, slot });
            try out.print("std::vector<unsigned>near_modulus(65536,2147483646u);CHECK(cudaMemcpy(dc,near_modulus.data(),65536*4,cudaMemcpyHostToDevice));CHECK(cudaError_t(stwo_native_access_count_on({d},main,output,dc,8,status,nullptr)));CHECK(cudaMemcpy(actual_counts.data(),dc,65536*4,cudaMemcpyDeviceToHost));for(unsigned i=0;i<65536;i++)if(actual_counts[i]!=(counts[i]?counts[i]-1u:2147483646u))return 9;words+=65536;unsigned bad_count=2147483647u;CHECK(cudaMemcpy(dc,&bad_count,4,cudaMemcpyHostToDevice));CHECK(cudaError_t(stwo_native_access_count_on({d},main,output,dc,8,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error!=4)return 11;CHECK(cudaMemset(dc,0,65536*4));CHECK(cudaMemset(status,0,4));unsigned invalid=256u;CHECK(cudaMemcpy(output+{d},&invalid,4,cudaMemcpyHostToDevice));CHECK(cudaError_t(stwo_native_access_count_on({d},main,output,dc,8,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error!=2)return 10;CHECK(cudaFree(dc));\n", .{ slot, slot, if (slot == 1) @as(u32, 0) else 1, slot });
            try out.print("CHECK(cudaMemset(status,0,4));CHECK(cudaError_t(stwo_native_access_witness_on({d},main,output,8,18446744073709551615ull,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error!=2)return 5;unsigned bad=2147483647u;CHECK(cudaMemcpy(main,&bad,4,cudaMemcpyHostToDevice));CHECK(cudaMemset(status,0,4));CHECK(cudaError_t(stwo_native_access_witness_on({d},main,output,8,0,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error!=2)return 6;CHECK(cudaFree(main));CHECK(cudaFree(output));CHECK(cudaFree(status));}}\n", .{ slot, slot });
        }
    }
    try out.writeAll("printf(\"PASS original native access GPU48witness+range8_8counter words=%u hostiles=24 modular_counter_wrap=6\\n\",words);return 0;}\n");
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(w.written());
}

test "native access witness original padding and canonical admission" {
    var main: [MAIN_COUNT]u32 = @splat(0);
    inline for (.{ 1, 2 }) |slot| {
        try std.testing.expectEqual(@as([WITNESS_COUNT]u32, @splat(0)), try columns(slot, &main, 0));
    }
    main[0] = Core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalAccessMain, columns(1, &main, 0));
    var source: [2 * MAIN_COUNT]u32 = @splat(0);
    source[0] = Core.fields.m31.Modulus;
    var output: [2 * WITNESS_COUNT]u32 = @splat(123);
    try std.testing.expectEqual(@as(u32, 2), Writer(1).run(&source, &output, 2, 0, 0));
    for (output) |value| try std.testing.expectEqual(@as(u32, 123), value);
}
