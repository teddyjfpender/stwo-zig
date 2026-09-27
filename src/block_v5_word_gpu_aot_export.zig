//! Offline export of canonical typed word/range/two-event RAM kernels. No proof, transcript,
//! GPU runtime or witness is created. Dynamic claims/challenges remain slots.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const gpu = @import("frontends/riscv/prover/block_v5_word_gpu_program_v1.zig");
const protocol = @import("frontends/riscv/prover/block_v5_word_memory_protocol_v1.zig");
const Word = @import("frontends/riscv/prover/block_v5_word_memory_component_v1.zig").Spec;
const Range = @import("frontends/riscv/prover/block_v5_range16_component_v1.zig").Spec;
const Lane = @import("frontends/riscv/prover/block_v5_ram_lanes_component_v1.zig").Spec;
const lane_gpu = @import("frontends/riscv/prover/block_v5_ram_lanes_gpu_program_v1.zig");
const lane_protocol = @import("frontends/riscv/prover/block_v5_ram_lanes_protocol_v1.zig");
const metal = @import("backends/metal/runtime/secure_polynomial_codegen_v1.zig");
const cuda = @import("backends/cuda/secure_polynomial_resident_codegen_v1.zig");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3 or (!std.mem.eql(u8, args[1], "metal") and !std.mem.eql(u8, args[1], "cuda"))) return error.InvalidArguments;
    const c = protocol.Challenges{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
    const endpoint = @import("frontends/riscv/air/block/memory_transition.zig").Transition{ .space = 1, .address = 4, .clock = 1, .before = 0, .after = 1 };
    const word = Word{
        .claim = .{ .first_row = 0, .total_rows = 1, .rows = 1, .log_size = 1, .first = endpoint, .last = endpoint, .preceding = null },
        .interaction_claim = .{ .transition_sum = Q.zero(), .link_sum = Q.zero(), .initial_sum = Q.zero(), .endpoint_sum = Q.zero(), .endpoint_count = 1, .register_endpoint_sum = Q.zero(), .register_endpoint_count = 0, .range_count = 10, .range_sums = @splat(Q.zero()) },
        .challenges = &c,
    };
    const range = Range{ .claim = .{ .sum = Q.zero(), .count = 10 }, .challenges = &c };
    const lane = Lane{
        .claim = .{ .first_event = 0, .total_events = 1, .events = 1, .row_log = 1, .first = endpoint, .last = endpoint, .preceding = null },
        .interaction_claim = .{ .event_count = 1, .transition_sum = Q.zero(), .link_sum = Q.zero(), .initial_sum = Q.zero(), .endpoint_sum = Q.zero(), .endpoint_count = 1, .range_count = 10, .range_sums = @splat(Q.zero()) },
        .challenges = &c,
    };
    var programs: [6]gpu.ir.Program = undefined;
    var initialized: usize = 0;
    defer for (programs[0..initialized]) |*program| program.deinit();
    programs[0] = try gpu.wordEquations(a, word, 2);
    initialized += 1;
    programs[1] = try gpu.wordFractions(a, word, 2);
    initialized += 1;
    programs[2] = try gpu.rangeEquations(a, range);
    initialized += 1;
    programs[3] = try gpu.rangeFractions(a, range);
    initialized += 1;
    programs[4] = try lane_gpu.equations(a, lane, lane.claim.rowCapacity());
    initialized += 1;
    programs[5] = try lane_gpu.fractions(a, lane, lane.claim.rowCapacity());
    initialized += 1;
    const roster = [_]*const gpu.ir.Program{ &programs[0], &programs[1], &programs[2], &programs[3], &programs[4], &programs[5] };
    if (std.mem.eql(u8, args[1], "metal")) try writeCatalog(metal, a, args[2], &roster, "kernels.metal") else try writeCatalog(cuda, a, args[2], &roster, "kernels.cu");
}

fn writeCatalog(comptime target: type, a: std.mem.Allocator, path: []const u8, roster: []const *const gpu.ir.Program, filename: []const u8) !void {
    const source = try target.generateLibrary(a, roster);
    defer a.free(source);
    try std.fs.cwd().makePath(path);
    var directory = try std.fs.cwd().openDir(path, .{});
    defer directory.close();
    try directory.writeFile(.{ .sub_path = filename, .data = source });
    const Entry = struct { kind: []const u8, typed_authority: [64]u8, program_identity: [64]u8, executable_identity: [64]u8, kernel: []u8, inputs: usize, parameters: usize, equations_or_buses: usize, abi_schema: ?u32, argument_count: ?u32, cache_key: ?u64 };
    const entries = try a.alloc(Entry, roster.len);
    defer a.free(entries);
    var owned: usize = 0;
    defer for (entries[0..owned]) |entry| a.free(entry.kernel);
    var roster_authority = std.crypto.hash.sha2.Sha256.init(.{});
    roster_authority.update("stwo/typed-secure-source-catalog/v2\x00");
    for (roster, entries) |program, *entry| {
        const executable = try target.identity(program);
        const typed_authority = program.authority;
        roster_authority.update(@tagName(program.kind));
        roster_authority.update(&.{0});
        roster_authority.update(&typed_authority);
        entry.* = .{ .kind = @tagName(program.kind), .typed_authority = std.fmt.bytesToHex(typed_authority, .lower), .program_identity = std.fmt.bytesToHex(program.identity, .lower), .executable_identity = std.fmt.bytesToHex(executable, .lower), .kernel = try target.kernelName(a, program), .inputs = program.inputs.len, .parameters = program.parameters.len, .equations_or_buses = program.roots.len, .abi_schema = if (target == cuda) @intFromEnum(cuda.programSchema(program.kind)) else null, .argument_count = if (target == cuda) 12 else null, .cache_key = if (target == cuda) cuda.cacheKey(executable) else null };
        owned += 1;
    }
    var source_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_sha, .{});
    const manifest = try std.json.Stringify.valueAlloc(a, .{
        .version = 2,
        .target = if (target == metal) "metal" else "cuda",
        .word_protocol_version = protocol.VERSION,
        .word_protocol_abi = std.fmt.bytesToHex(protocol.abiId(), .lower),
        .ram_lanes_protocol_version = lane_protocol.VERSION,
        .ram_lanes_protocol_abi = std.fmt.bytesToHex(lane_protocol.abiId(), .lower),
        .typed_authority = std.fmt.bytesToHex(roster_authority.finalResult(), .lower),
        .source_file = filename,
        .source_sha256 = std.fmt.bytesToHex(source_sha, .lower),
        .programs = entries,
        .cuda_helpers = if (target == cuda) cuda.helperEntries() else [0]cuda.SourceEntry{},
        .dynamic_claims_and_challenges = true,
        .proof_acceptance_authority = false,
        .device_compiled = false,
        .device_executed = false,
    }, .{ .whitespace = .indent_2 });
    defer a.free(manifest);
    try directory.writeFile(.{ .sub_path = "source_manifest.json", .data = manifest });
}
