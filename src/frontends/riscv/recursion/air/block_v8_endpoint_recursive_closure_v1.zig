//! Shared finite-family implementation; original equation authorities remain independent.
const Family = @import("../block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return struct {
        const Traits = @import("../block_v8_endpoint_recursive_source_v1.zig").For(family);
        const is_local = Traits.is_local;
        // Symbolic endpoint ledger over exactly the original physical claim ports.
        // CPU/program boundary and snapshot bytes are independently admitted public
        // operands; no host closure result is accepted by these equations.
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const M = core.fields.m31.M31;
        const G = @import("composition_graph_recorder.zig");
        const S = G.Scalar;
        const A = @import("block_v8_window_closure_algebra_v1.zig");
        const Profile = @import("../block_v8_endpoint_recursive_profile_v1.zig").For(family);
        const NATIVE_WORDS = 104;
        fn words(a: std.mem.Allocator, p: *const Profile.Owned) ![]u32 {
            const i = p.statement.input;
            const changes = if (is_local) 0 else (p.statement.trusted.window orelse return error.UnsupportedEndpointClosurePolicy).changes.len;
            if (i.endpoint_count >= (core.fields.m31.Modulus - 1) / 24 or i.program_plan.expected_fetches >= core.fields.m31.Modulus) return error.UnboundedEndpointClosureCounts;
            const result = try a.alloc(u32, try std.math.add(usize, NATIVE_WORDS, try std.math.mul(usize, 3, changes)));
            errdefer a.free(result);
            const data = &i.shape.public_data;
            const completion = data.completion orelse return error.MissingCompletion;
            if (completion.kind != .halt_flag and completion.kind != .unretired_program_fetch and completion.kind != .unretired_self_loop) return error.UnsupportedEndpointCompletion;
            result[0] = data.initial_pc;
            result[1] = data.final_pc;
            result[2] = data.clock;
            @memcpy(result[3..35], &data.initial_regs);
            @memcpy(result[35..67], &data.final_regs);
            @memcpy(result[67..99], &data.reg_last_clock);
            result[99] = completion.address;
            if (completion.kind == .halt_flag) {
                result[100..104].* = .{ completion.value, completion.clock, 0, 0 };
            } else {
                const decoded = try @import("../../air/program/decode.zig").decodeProgramWordForProfile(p.scope.descriptor.scope.execution_profile, completion.value);
                @memcpy(result[100..104], &decoded);
            }
            if (!is_local) for (p.statement.trusted.window.?.changes, 0..) |change, index| @memcpy(result[NATIVE_WORDS + 3 * index ..][0..3], &[_]u32{ change.address, change.before, change.after });
            return result;
        }
        pub fn appendPublic(a: std.mem.Allocator, p: *const Profile.Owned, output: *std.ArrayList(Q)) !void {
            const w = try words(a, p);
            defer a.free(w);
            for (w) |value| for (0..4) |byte| try output.append(a, Q.fromBase(M.fromCanonical((value >> @as(u5, @intCast(8 * byte))) & 255)));
        }
        fn word(bytes: [4]S) S {
            var result = S.zero();
            for (bytes, 0..) |byte, index| result = result.add(byte.mul(S.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * index))))));
            return result;
        }
        fn halves(bytes: [4]S) [2]S {
            const radix = S.fromBase(M.fromCanonical(256));
            return .{ bytes[0].add(bytes[1].mul(radix)), bytes[2].add(bytes[3].mul(radix)) };
        }
        fn relation(comptime n: usize, pair: [2]S) A.Relation(S, n) {
            var out = A.Relation(S, n){ .z = pair[0], .powers = undefined };
            var power = S.one();
            for (&out.powers) |*v| {
                v.* = power;
                power = power.mul(pair[1]);
            }
            return out;
        }
        pub fn record(a: std.mem.Allocator, b: *G.Builder, p: *const Profile.Owned, ports: []const S, bytes: []const S, draws: [53][2]S) !void {
            const w = try words(a, p);
            defer a.free(w);
            if (bytes.len != 4 * w.len) return error.InvalidEndpointClosurePublicFrame;
            const words_s = try a.alloc([4]S, w.len);
            defer a.free(words_s);
            for (words_s, 0..) |*out, index| out.* = bytes[4 * index ..][0..4].*;
            var boundary = A.Boundary(S){ .initial_pc = word(words_s[0]), .final_pc = word(words_s[1]), .final_clock_plus_one = word(words_s[2]).add(S.one()), .initial_register_bytes = undefined, .final_register_bytes = undefined, .register_last_clock = undefined };
            for (0..32) |reg| {
                boundary.initial_register_bytes[reg] = words_s[3 + reg];
                boundary.final_register_bytes[reg] = words_s[35 + reg];
                boundary.register_last_clock[reg] = word(words_s[67 + reg]);
            }
            const terminal = p.statement.input.shape.public_data.completion.?.kind == .halt_flag;
            if (terminal) {
                const halt = p.scope.descriptor.scope.halt orelse return error.MissingTerminalHaltPolicy;
                const last = halt.permitted_final_instruction_cycle orelse return error.MissingTerminalHaltPolicy;
                try b.constrainZero(word(words_s[99]).sub(S.fromBase(M.fromCanonical(halt.halt_address))));
                try b.constrainZero(word(words_s[100]).sub(S.one()));
                try b.constrainZero(word(words_s[101]).sub(S.fromBase(M.fromCanonical(@intCast(@import("../../access_clock.zig").maximum(last))))));
                try b.constrainZero(word(words_s[102]));
                try b.constrainZero(word(words_s[103]));
            } else try b.constrainZero(word(words_s[99]).sub(boundary.final_pc));
            const universal = try G.ChallengeSet.init(draws[0..47].*);
            const state = universal.get(.registers_state);
            const memory_access = universal.get(.memory_access);
            const program = universal.get(.program_access);
            const projections = p.context.local.?.native.layout.slots;
            var fetch_bound: u64 = if (terminal) 0 else 1;
            for (projections) |slot| if (slot.kind == .program) {
                fetch_bound = try std.math.add(u64, fetch_bound, slot.n_rows);
            };
            if (fetch_bound >= core.fields.m31.Modulus) return error.UnboundedEndpointClosureCounts;
            const native = try A.native(S, projections, ports[8..][0..projections.len], boundary, .{ .z = state.z, .powers = state.alpha_powers[0..2].* }, .{ .z = memory_access.z, .powers = memory_access.alpha_powers[0..7].* });
            const gap_sums = ports[8 + projections.len ..][0..p.context.local.?.native.clock_v3.len];
            var at: usize = 8 + p.claims.native.len;
            const endpoint = ports[at..][0..11];
            at += 11;
            const range = ports[at..][0..2];
            at += 2;
            try b.constrainZero(native.state);
            try b.constrainZero(native.registers);
            try b.constrainZero(native.ordinary_memory.add(native.clock_memory).add(endpoint[0]));
            var ranges = range[0];
            for (gap_sums) |sum| ranges = ranges.add(sum);
            for (endpoint[2..9]) |sum| ranges = ranges.add(sum);
            try b.constrainZero(ranges);
            const range_requests = try std.math.add(u32, try std.math.mul(u32, p.statement.input.endpoint_count, 13), try @import("../../prover/block_v8_native_endpoint_profile_v1.zig").gapRequests(p.statement.input.shape, p.scope.descriptor.scope.native_profile));
            if (range_requests >= core.fields.m31.Modulus) return error.UnboundedEndpointClosureCounts;
            try b.constrainZero(range[1].sub(S.fromBase(M.fromCanonical(range_requests))));
            var tuple: [5]S = undefined;
            for (&tuple, 0..) |*v, part| v.* = word(words_s[99 + part]);
            var exports = A.SourceExports(S){ .program = if (terminal) S.zero() else (try program.combine(&tuple)).inverse().neg(), .transition = endpoint[1], .fetches = if (terminal) S.zero() else S.one(), .events = S.fromBase(M.fromCanonical(p.statement.input.endpoint_count)), .tables = native.tables, .byte_requests = endpoint[9].add(endpoint[10]) };
            for (projections, 0..) |slot, index| if (slot.kind == .program) {
                exports.program = exports.program.add(ports[8 + index]);
                exports.fetches = exports.fetches.add(S.fromBase(M.fromCanonical(slot.n_rows)));
            };
            const program_provider = ports[at];
            const table_providers = ports[at + 1 ..][0..6].*;
            at += 7;
            if (is_local) {
                if (at != ports.len) return error.InvalidEndpointClosurePhysicalFrame;
                try b.constrainZero(exports.program.add(program_provider));
                for (exports.tables, table_providers, 0..) |request, provider_sum, index| {
                    var sum = request.add(provider_sum);
                    if (index == @intFromEnum(@import("../../air/lookups/tables/schema.zig").Kind.range_check_8_8)) sum = sum.add(exports.byte_requests);
                    try b.constrainZero(sum);
                }
                try b.constrainZero(exports.fetches.sub(S.fromBase(M.fromCanonical(@intCast(p.statement.input.program_plan.expected_fetches)))));
                // Endpoint plane1 stays authenticated and OPEN under the local draw.
                // Only a later bridge can rebind this same endpoint-main commitment.
            } else {
                const ram = try a.alloc([31]S, p.statement.input.memory_geometry.len);
                defer a.free(ram);
                for (ram) |*sums| {
                    @memcpy(sums[0..29], ports[at..][0..29]);
                    @memcpy(sums[29..31], ports[at + 84 ..][0..2]);
                    at += 86;
                }
                const interval = ports[at..][0..2].*;
                const global_range = ports[at + 2 ..][0..2].*;
                if (at + 4 != ports.len) return error.InvalidEndpointClosurePhysicalFrame;
                const delta_relation = relation(5, draws[49]);
                var delta = S.zero();
                for (0..p.statement.trusted.window.?.changes.len) |index| {
                    const offset = NATIVE_WORDS + 3 * index;
                    const address = halves(words_s[offset]);
                    const before = halves(words_s[offset + 1]);
                    const after = halves(words_s[offset + 2]);
                    delta = delta.add(delta_relation.combine(.{ S.one(), address[0], address[1], after[0], after[1] }).inverse());
                    delta = delta.sub(delta_relation.combine(.{ S.one(), address[0], address[1], before[0], before[1] }).inverse());
                }
                const memory = try A.memory(S, ram, interval, global_range, delta);
                for (memory.constraints) |constraint| try b.constrainZero(constraint);
                for (A.global(S, &.{exports}, program_provider, memory.transition, table_providers, S.fromBase(M.fromCanonical(@intCast(p.statement.input.program_plan.expected_fetches))), S.fromBase(M.fromCanonical(p.statement.input.endpoint_count)))) |constraint| try b.constrainZero(constraint);
            }
        }
    };
}
