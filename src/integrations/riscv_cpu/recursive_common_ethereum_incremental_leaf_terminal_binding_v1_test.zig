const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const terminal = @import("recursive_common_ethereum_incremental_leaf_terminal_binding_v1.zig");
const fixture = @import("recursive_common_ethereum_incremental_leaf_terminal_fixture_v1.zig");
const support = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
const role = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const binding = @import("recursive_common_ethereum_incremental_leaf_role_binding_v4.zig");
const global = @import("recursive_common_ethereum_incremental_leaf_global_binding_v1.zig");
const admission_mod = @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig");
const fixed = @import("ethereum_fixed_program_admission_v1.zig");
const arithmetic = frontend.recursion.arithmetic_circuit;
const Value = arithmetic.Value;
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const layout = frontend.recursion.span_statement.canonical_layout;
const cap = 2;
const LOCAL = 0;
const GLOBAL = LOCAL + 412;
const GLOBAL_AUX = GLOBAL + 412;
const CLOCKS = GLOBAL_AUX + global.AUX_COUNT;
const CLOCK_AUX = CLOCKS + support.CLOCK_LIMB_COUNT;
const ROLES = CLOCK_AUX + support.CLOCK_AUX_INPUT_COUNT;
const SELECTORS = ROLES + role.HEADER_WORD_COUNT + cap * role.TUPLE_WORD_COUNT;
const SOURCES = SELECTORS + cap * 5;
const COMPLETION = SOURCES + (binding.budget(cap) catch unreachable).input_count;
const COUNT = COMPLETION + 12;
const HALT_WORD = role.HEADER_WORD_COUNT + role.TUPLE_WORD_COUNT;

const Fixture = struct {
    circuit: arithmetic.Circuit,
    inputs: [COUNT]QM31,
    local: [412]u32,
    published: [412]u32,
    words: [role.HEADER_WORD_COUNT + cap * role.TUPLE_WORD_COUNT]u32,
    output: frontend.runner.result_mod.OutputWord,

    fn init(check_policy: bool) !Fixture {
        const allocator = std.testing.allocator;
        const elf = fixture.programElf();
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&elf, &sha, .{});
        const owner = try fixed.OwnedV1.createWithCompletionFromElf(allocator, &elf, sha);
        defer owner.deinit();
        const admission = try admission_mod.ProgramAdmissionV1.createWithFixedProgram(allocator, owner);
        defer admission.deinit();
        if (check_policy) {
            var admitted = try support.buildWithCompletionPolicy(allocator, cap, admission, true, .fixed_program_narrow_v1, .terminal_halt_v1);
            defer admitted.deinit(allocator);
            var reserved: usize = 0;
            for (admitted.bindings) |source| switch (source) {
                .completion_opening_word => return error.UnexpectedTerminalOpening,
                .role_source => |part| switch (part) {
                    .nonfinal_inverse => return error.UnexpectedTerminalNonfinalInput,
                    .terminal_reserved => reserved += 1,
                    else => {},
                },
                else => {},
            };
            try std.testing.expectEqual(@as(usize, 1), reserved);
            try std.testing.expectEqual(try support.inputCountWithGlobalProgram(cap), admitted.bindings.len);
            try std.testing.expectError(error.EthereumTerminalAdmissionRequired, support.buildWithCompletionPolicy(allocator, cap, admission, false, .fixed_program_narrow_v1, .terminal_halt_v1));
            try std.testing.expectError(error.EthereumTerminalAdmissionRequired, support.buildWithCompletionPolicy(allocator, cap, null, true, .fixed_program_narrow_v1, .terminal_halt_v1));
            try std.testing.expectError(error.EthereumTerminalAdmissionRequired, support.buildWithCompletionPolicy(allocator, cap, admission, true, .legacy_v4, .terminal_halt_v1));
        }
        var execution = try fixture.run(allocator);
        defer execution.deinit();
        try std.testing.expectEqual(frontend.runner.result_mod.CompletionReason.halt_flag, execution.base.completion_reason);
        try std.testing.expectEqual(try admission.haltFlagAddress(), execution.base.completion_address);
        var builder = arithmetic.Builder.initDefault(allocator);
        defer builder.deinit();
        var nodes: [COUNT]Value = undefined;
        for (&nodes, 0..) |*node, index| node.* = try builder.input(@intCast(index));
        try global.constrain(&builder, nodes[LOCAL..GLOBAL], nodes[GLOBAL..GLOBAL_AUX], nodes[GLOBAL_AUX..CLOCKS]);
        try support.constrainRawClocks(&builder, nodes[LOCAL..GLOBAL], nodes[CLOCKS..CLOCK_AUX], nodes[CLOCK_AUX..ROLES]);
        try binding.constrain(&builder, allocator, cap, nodes[SOURCES..COMPLETION], nodes[ROLES..SELECTORS], nodes[SELECTORS..SOURCES]);
        // Production addRoleTerms owns these one-hot constraints and metadata.
        for (0..cap) |slot| {
            var sum = Value.zero();
            for (nodes[SELECTORS + slot * 5 ..][0..5]) |selector| {
                _ = try builder.markOutput(try builder.mul(selector, try builder.sub(selector, Value.one())));
                sum = try builder.add(sum, selector);
            }
            _ = try builder.markOutput(try builder.sub(sum, Value.one()));
        }
        try terminal.constrain(&builder, admission, cap, .{
            .statement = nodes[GLOBAL..GLOBAL_AUX],
            .global_aux = nodes[GLOBAL_AUX..CLOCKS],
            .native_end_bits = nodes[ROLES - 25 .. ROLES],
            .role_sources = nodes[SOURCES..COMPLETION],
            .role_words = nodes[ROLES..SELECTORS],
            .selectors = nodes[SELECTORS..SOURCES],
            .completion = nodes[COMPLETION..],
        });
        var result = Fixture{ .circuit = try builder.finish(), .inputs = @splat(QM31.zero()), .local = @splat(0), .published = @splat(0), .words = undefined, .output = execution.base.output_words[0] };
        errdefer result.circuit.deinit();
        const cycle_count: u64 = @intCast(execution.base.step_count);
        setU64(&result.published, layout.first_cycle_start, (@as(u64, 1) << 40) + 7);
        setU64(&result.published, layout.executed_cycle_count_start, cycle_count);
        setU64(&result.published, layout.total_cycles_start, (@as(u64, 1) << 40) + 7 + cycle_count);
        result.published[layout.program_start] = admission.programRoot();
        result.published[layout.first_segment_start] = 1;
        result.published[layout.job_segment_count_start] = 2;
        result.published[layout.executed_segment_count_start] = 1;
        const completion = try frontend.air.public_data.completionFromRun(&execution.base);
        const tuple = try role.TupleV4.init(.halt_memory, &.{ 1, completion.address, completion.clock, completion.value & 255, (completion.value >> 8) & 255, (completion.value >> 16) & 255, completion.value >> 24 });
        try std.testing.expectEqual(@as(usize, 1), execution.base.output_words.len);
        const output = result.output;
        const output_tuple = try role.TupleV4.init(.output_memory, &.{ 1, output.addr, output.clock, output.value & 255, (output.value >> 8) & 255, (output.value >> 16) & 255, output.value >> 24 });
        const words = try role.testingCanonicalWordsAlloc(allocator, &.{ output_tuple, tuple }, cap);
        defer allocator.free(words);
        @memcpy(&result.words, words);
        const values = [_]u32{ completion.address & 65535, completion.address >> 16, completion.value & 65535, completion.value >> 16, 0, 0, 0, 0, @intFromEnum(completion.kind), completion.clock & 65535, completion.clock >> 16, 0 };
        for (result.inputs[COMPLETION..], values) |*out, value| out.* = field(value);
        try result.refresh();
        return result;
    }
    fn refresh(self: *Fixture) !void {
        const projection = frontend.recursion.segment_leaf_local_projection_v3;
        for (&self.local, 0..) |*word, index| word.* = switch (try projection.canonicalWordSourceV1(index)) {
            .global_word => |at| self.published[at],
            .local_cycle_count_limb => |limb| self.published[layout.executed_cycle_count_start + @as(usize, limb)],
            .zero => 0,
        };
        for (self.inputs[LOCAL..GLOBAL], self.local) |*out, value| out.* = field(value);
        for (self.inputs[GLOBAL..GLOBAL_AUX], self.published) |*out, value| out.* = field(value);
        for (self.inputs[GLOBAL_AUX..CLOCKS], 0..) |*out, index| out.* = try global.auxValue(try global.sourceAt(index), &self.published);
        const raw = support.segment_v2;
        const native = [_]M31{M31.zero()} ** raw.FIXED_CANONICAL_WORDS;
        for (self.inputs[CLOCK_AUX..ROLES], 0..) |*out, index| out.* = try support.clockAuxValue(try support.clockAuxSourceAt(index), &self.local, &native);
        for (self.inputs[ROLES..SELECTORS], self.words) |*out, value| out.* = field(value);
        @memset(self.inputs[SELECTORS..SOURCES], QM31.zero());
        for (0..cap) |slot| self.inputs[SELECTORS + 5 * slot + self.words[role.HEADER_WORD_COUNT + slot * role.TUPLE_WORD_COUNT]] = QM31.one();
        const claim = frontend.recursion.vm_public_claim;
        const encoded = try std.testing.allocator.alloc(M31, try (try claim.defaultShape()).wordCount());
        defer std.testing.allocator.free(encoded);
        @memset(encoded, M31.zero());
        const shape = try claim.defaultShape();
        encoded[claim.canonical_layout.outputWordCountStart(shape)] = M31.one();
        const output_slot = claim.canonical_layout.outputSlotPresent(shape, 0);
        encoded[output_slot] = M31.one();
        for ([_]usize{ 1, 3, 5 }, [_]u32{ self.output.addr, self.output.value, self.output.clock }) |offset, word| {
            encoded[output_slot + offset] = M31.fromCanonical(word & 65535);
            encoded[output_slot + offset + 1] = M31.fromCanonical(word >> 16);
        }
        for (self.inputs[SOURCES..COMPLETION], 0..) |*out, index| out.* = try binding.read(try binding.sourceAt(cap, index), encoded, &self.words);
    }
    fn expect(self: *Fixture, accepted: bool) !void {
        var evaluation = try self.circuit.evaluate(std.testing.allocator, &self.inputs);
        defer evaluation.deinit();
        try std.testing.expectEqual(accepted, try self.circuit.outputsAreZero(evaluation.values));
    }
};
fn field(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
fn setU64(words: *[412]u32, at: usize, value: u64) void {
    for (0..4) |limb| words[at + limb] = @intCast((value >> @as(u6, @intCast(16 * limb))) & 65535);
}

test "Ethereum terminal halt graph admits genuine ELF halt and exact completion fields" {
    var value = try Fixture.init(true);
    defer value.circuit.deinit();
    try value.expect(true);
    const valid = value.inputs;
    for (COMPLETION..COUNT) |index| {
        value.inputs = valid;
        value.inputs[index] = value.inputs[index].add(QM31.one());
        try value.expect(false);
    }
}

test "Ethereum terminal halt graph rejects forged role order raw value and ELF address" {
    var value = try Fixture.init(false);
    defer value.circuit.deinit();
    const valid = value;
    for (0..8) |mutation| {
        value = valid;
        switch (mutation) {
            0 => {
                value.words[HALT_WORD + 6] += 4;
                value.inputs[COMPLETION] = value.inputs[COMPLETION].add(field(4));
            },
            1 => {
                value.words[HALT_WORD + 10] = 0;
                value.inputs[COMPLETION + 2] = QM31.zero();
            },
            2 => value.words[HALT_WORD] = 4,
            3 => value.words[HALT_WORD] = 0,
            4 => value.words[role.HEADER_WORD_COUNT] = 3,
            5 => {
                @memcpy(value.words[role.HEADER_WORD_COUNT..][0..role.TUPLE_WORD_COUNT], valid.words[HALT_WORD..]);
                @memset(value.words[HALT_WORD..], 0);
            },
            6 => {
                value.words[HALT_WORD + 10] = 256;
                value.inputs[COMPLETION + 2] = field(256);
            },
            7 => {
                value.words[HALT_WORD + 4] = 0;
                value.words[HALT_WORD + 5] = 32768; // 1 + M31 modulus recomposes to 1.
            },
            else => unreachable,
        }
        try value.refresh();
        try value.expect(false);
    }
}

test "Ethereum terminal halt graph rejects nonfinal global spans and invalid access clocks" {
    var value = try Fixture.init(false);
    defer value.circuit.deinit();
    const valid = value;
    value.published[layout.total_cycles_start] += 1;
    try value.refresh();
    try value.expect(false);
    value = valid;
    value.published[layout.total_cycles_start + 2] += 1;
    try value.refresh();
    try value.expect(false);
    value = valid;
    value.published[layout.job_segment_count_start] += 1;
    try value.refresh();
    try value.expect(false);
    const end: u32 = valid.local[layout.executed_cycle_count_start];
    for ([_]u32{ 0, 4, 4 * end, 4 * end + 3, 1 << 26 }) |clock| {
        value = valid;
        value.words[HALT_WORD + 8] = clock & 65535;
        value.words[HALT_WORD + 9] = clock >> 16;
        value.inputs[COMPLETION + 9] = field(clock & 65535);
        value.inputs[COMPLETION + 10] = field(clock >> 16);
        try value.refresh();
        try value.expect(false);
    }
    value = valid;
    value.published[layout.program_start] += 1;
    try value.refresh();
    try value.expect(false);
    value = valid;
    const exit_root = GLOBAL + layout.exit_state_start + layout.machine_state_rw_digest_start_offset;
    value.inputs[exit_root] = value.inputs[exit_root].add(QM31.one());
    try value.expect(false);
    value = valid;
    // Carrying the final segment index is valid and has no new witness input.
    value.published[layout.first_segment_start] = 65535;
    value.published[layout.job_segment_count_start] = 0;
    value.published[layout.job_segment_count_start + 1] = 1;
    try value.refresh();
    try value.expect(true);
}
