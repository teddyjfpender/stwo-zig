const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact = @import("ethereum_incremental_boundary_artifact_v3.zig");
const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const authority_v1 = @import("ethereum_incremental_boundary_authority_v1.zig");
const boundary_v3 = @import("ethereum_incremental_boundary_authority_v3.zig");
const support = @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");

const memory_state = frontend.runner.memory_state;
const public_data = frontend.air.public_data;

const left_input_words = [_]u32{11};

test "STWIMT03 round trips and coldly derives a public-input role" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator, .left);
    defer case.deinit();
    var decoded = try artifact.decodeAlloc(
        allocator,
        case.artifact_bytes,
        artifact.default_limits,
    );
    defer decoded.deinit();

    const reencoded = try artifact.encodeOwnedAlloc(
        allocator,
        &decoded,
        artifact.default_limits,
    );
    defer allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, case.artifact_bytes, reencoded);

    const authority = case.authority();
    var cold = try artifact.coldReconstruct(
        allocator,
        &decoded,
        &case.wire.data,
        authority,
        artifact.default_limits,
    );
    defer cold.deinit();
    try std.testing.expectEqual(@as(usize, 1), cold.sources.len);
    try std.testing.expectEqual(@as(u32, 0x2000), cold.sources[0].word.addr);
    try std.testing.expectEqual(@as(u32, 0), cold.sources[0].entry_clock);
    try std.testing.expect(cold.sources[0].word.role.is_public_input);
    try std.testing.expect(cold.transitions[0].public_links.input_entry != null);
    try std.testing.expectEqual(@as(u32, 11), cold.transitions[0].merkle_words.entry);
    try std.testing.expect(!artifact.PRODUCTION_ACTIVE);
    try std.testing.expect(!artifact.PROOF_ADMISSIBLE);
    try std.testing.expect(!artifact.RECURSIVE_ADMISSIBLE);
}

test "STWIMT03 rejects raw corruption and resealed reserved bytes" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator, .left);
    defer case.deinit();
    const changed = try allocator.dupe(u8, case.artifact_bytes);
    defer allocator.free(changed);

    changed[artifact.testing.ENTRY_CLOCKS_OFFSET] ^= 1;
    try std.testing.expectError(
        error.IncrementalBoundaryArtifactV3ContentMismatch,
        artifact.decodeAlloc(allocator, changed, artifact.default_limits),
    );
    changed[artifact.testing.ENTRY_CLOCKS_OFFSET] ^= 1;
    changed[artifact.testing.RESERVED_OFFSET] = 1;
    try artifact.testing.reseal(changed);
    try std.testing.expectError(
        error.InvalidIncrementalBoundaryArtifactV3Header,
        artifact.decodeAlloc(allocator, changed, artifact.default_limits),
    );
}

test "STWIMT03 rejects a resealed entry-clock mutation" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator, .left);
    defer case.deinit();
    const changed = try allocator.dupe(u8, case.artifact_bytes);
    defer allocator.free(changed);
    std.mem.writeInt(
        u32,
        changed[artifact.testing.ENTRY_CLOCKS_OFFSET..][0..4],
        1,
        .little,
    );
    try artifact.testing.reseal(changed);
    var decoded = try artifact.decodeAlloc(
        allocator,
        changed,
        artifact.default_limits,
    );
    defer decoded.deinit();
    try std.testing.expectError(
        error.IncrementalBoundaryArtifactV3EntryClockMismatch,
        artifact.coldReconstruct(
            allocator,
            &decoded,
            &case.wire.data,
            case.authority(),
            artifact.default_limits,
        ),
    );
}

test "STWIMT03 binds ordered clocks to the V2 touched-word order" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator, .right);
    defer case.deinit();
    const changed = try allocator.dupe(u8, case.artifact_bytes);
    defer allocator.free(changed);
    const clocks = artifact.testing.ENTRY_CLOCKS_OFFSET;
    const first = std.mem.readInt(u32, changed[clocks..][0..4], .little);
    const second = std.mem.readInt(u32, changed[clocks + 4 ..][0..4], .little);
    std.mem.writeInt(u32, changed[clocks..][0..4], second, .little);
    std.mem.writeInt(u32, changed[clocks + 4 ..][0..4], first, .little);
    try artifact.testing.reseal(changed);
    var decoded = try artifact.decodeAlloc(
        allocator,
        changed,
        artifact.default_limits,
    );
    defer decoded.deinit();
    try std.testing.expectError(
        error.IncrementalBoundaryArtifactV3EntryClockMismatch,
        artifact.coldReconstruct(
            allocator,
            &decoded,
            &case.wire.data,
            case.authority(),
            artifact.default_limits,
        ),
    );
}

test "STWIMT03 rejects public-wire identity and backing-word mutations" {
    const allocator = std.testing.allocator;
    var left = try Case.init(allocator, .left);
    defer left.deinit();
    var right = try Case.init(allocator, .right);
    defer right.deinit();
    var decoded = try artifact.decodeAlloc(
        allocator,
        left.artifact_bytes,
        artifact.default_limits,
    );
    defer decoded.deinit();

    try std.testing.expectError(
        error.IncrementalBoundaryArtifactV3PublicWireMismatch,
        artifact.coldReconstruct(
            allocator,
            &decoded,
            &right.wire.data,
            left.authority(),
            artifact.default_limits,
        ),
    );

    const original = left.wire.words[0];
    defer left.wire.words[0] = original;
    const left_authority = left.authority();
    left.wire.words[0] = original.add(@import("stwo_core").fields.m31.M31.one());
    var rejected = false;
    if (artifact.coldReconstruct(
        allocator,
        &decoded,
        &left.wire.data,
        left_authority,
        artifact.default_limits,
    )) |value| {
        var unexpected = value;
        unexpected.deinit();
    } else |_| rejected = true;
    try std.testing.expect(rejected);
}

test "STWIMT03 rejects resealed root drift against nested STWIMT02" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator, .left);
    defer case.deinit();
    const changed = try allocator.dupe(u8, case.artifact_bytes);
    defer allocator.free(changed);
    const offset = artifact.testing.ENTRY_ROOT_OFFSET;
    const root = std.mem.readInt(u32, changed[offset..][0..4], .little);
    std.mem.writeInt(u32, changed[offset..][0..4], root ^ 1, .little);
    try artifact.testing.reseal(changed);
    try std.testing.expectError(
        error.IncrementalBoundaryArtifactV3TransitionMismatch,
        artifact.decodeAlloc(allocator, changed, artifact.default_limits),
    );
}

test "STWIMT03 derives public values and rejects caller-side raw IO drift" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator, .left);
    defer case.deinit();
    var decoded = try artifact.decodeAlloc(
        allocator,
        case.artifact_bytes,
        artifact.default_limits,
    );
    defer decoded.deinit();
    const changed_input = [_]u32{12};
    var changed_data = case.public_data;
    changed_data.io_entries.input_words = &changed_input;
    var changed_authority = case.authority();
    changed_authority.public_data = &changed_data;
    try std.testing.expectError(
        error.PublicMemoryValueMismatch,
        artifact.coldReconstruct(
            allocator,
            &decoded,
            &case.wire.data,
            changed_authority,
            artifact.default_limits,
        ),
    );
}

const Side = enum { left, right };

const Case = struct {
    allocator: std.mem.Allocator,
    side: Side,
    wire: support.OwnedWire,
    transition_bytes: []u8,
    artifact_bytes: []u8,
    public_data: public_data.PublicData,
    layout: memory_state.MemoryLayout,

    fn init(allocator: std.mem.Allocator, side: Side) !Case {
        var fixture = try support.Fixture.init();
        const source = switch (side) {
            .left => fixture.leftSource(),
            .right => fixture.rightSource(),
        };
        var wire = try support.OwnedWire.init(allocator, &source);
        errdefer wire.deinit();
        const metadata = try wire.data.metadata();

        const initial: []const authority_v1.SparseWordV1 = switch (side) {
            .left => &[_]authority_v1.SparseWordV1{
                .{ .address = 0x2000, .value = 11 },
            },
            .right => &[_]authority_v1.SparseWordV1{
                .{ .address = 0x2000, .value = 12 },
            },
        };
        const touched: []const authority_v1.TouchedWordV1 = switch (side) {
            .left => &[_]authority_v1.TouchedWordV1{
                .{
                    .address = 0x2000,
                    .old_word = 11,
                    .new_word = 12,
                    .final_clock = 3,
                },
            },
            .right => &[_]authority_v1.TouchedWordV1{
                .{
                    .address = 0x2000,
                    .old_word = 12,
                    .new_word = 13,
                    .final_clock = 7,
                },
                .{
                    .address = 0x2004,
                    .old_word = 0,
                    .new_word = 9,
                    .final_clock = 6,
                },
            },
        };
        var session = try authority_v1.SessionTree.init(
            allocator,
            [_]u8{0x73} ** 32,
            metadata.segment_index,
            initial,
            try artifact_v2.testing.fullRoot(allocator, initial),
        );
        defer session.deinit();
        var transition = try session.apply(metadata.segment_index, touched);
        defer transition.deinit();
        if (transition.entry_root != metadata.entry_continuation_root or
            transition.exit_root != metadata.exit_continuation_root)
        {
            return error.TestFixtureRootMismatch;
        }
        const transition_bytes = try artifact_v2.encodeAlloc(
            allocator,
            &transition,
            artifact_v2.default_limits,
        );
        errdefer allocator.free(transition_bytes);
        const artifact_bytes = try artifact.encodeAlloc(
            allocator,
            transition_bytes,
            &wire.data,
            artifact.default_limits,
        );
        errdefer allocator.free(artifact_bytes);
        return .{
            .allocator = allocator,
            .side = side,
            .wire = wire,
            .transition_bytes = transition_bytes,
            .artifact_bytes = artifact_bytes,
            .public_data = publicData(side, metadata),
            .layout = layout(side),
        };
    }

    fn deinit(self: *Case) void {
        self.allocator.free(self.artifact_bytes);
        self.allocator.free(self.transition_bytes);
        self.wire.deinit();
        self.* = undefined;
    }

    fn authority(self: *const Case) boundary_v3.SegmentPublicAuthorityV3 {
        const metadata = self.wire.data.metadata() catch unreachable;
        return .{
            .coordinate = .{
                .segment_index = metadata.segment_index,
                .segment_count = metadata.segment_count,
            },
            .segment_role = .{
                .is_first = metadata.is_first,
                .is_last = metadata.is_final,
            },
            .layout = self.layout,
            .public_data = &self.public_data,
            .continuation_roots = .{
                .entry = metadata.entry_continuation_root,
                .exit = metadata.exit_continuation_root,
            },
        };
    }
};

fn publicData(
    side: Side,
    metadata: frontend.air.public_data_v2.Metadata,
) public_data.PublicData {
    const completion: public_data.Completion = if (metadata.completion) |value|
        .{
            .kind = @enumFromInt(@intFromEnum(value.kind)),
            .address = value.address,
            .value = value.value,
            .clock = value.clock,
        }
    else
        public_data.Completion.canonicalSelfLoop(metadata.exit_cpu.pc);
    return .{
        .initial_pc = metadata.entry_cpu.pc,
        .final_pc = metadata.exit_cpu.pc,
        .clock = metadata.global_cycle_end - metadata.global_cycle_start,
        .initial_regs = metadata.entry_cpu.registers,
        .final_regs = metadata.exit_cpu.registers,
        .reg_last_clock = metadata.exit_cpu.predecessor_clocks,
        .program_root = metadata.program[0],
        .initial_rw_root = metadata.entry_continuation_root,
        .final_rw_root = metadata.exit_continuation_root,
        .completion = completion,
        .io_entries = switch (side) {
            .left => .{
                .input_start = 0x2000,
                .input_len = 4,
                .input_words = &left_input_words,
                .output_len = 0,
                .output_len_addr = 0x2100,
                .output_data_addr = 0x2104,
                .output_words = &.{},
            },
            .right => .{
                .input_start = 0x2080,
                .input_len = 0,
                .input_words = &.{},
                .output_len = 0,
                .output_len_addr = 0x2100,
                .output_data_addr = 0x2104,
                .output_words = &.{},
            },
        },
    };
}

fn layout(side: Side) memory_state.MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x2200,
        .stack_bottom = 0x3000,
        .stack_top = 0x4000,
        .io_base = 0x2000,
        .io_end = 0x2200,
        .input_base = if (side == .left) 0x2000 else 0x2080,
        .input_end = if (side == .left) 0x2004 else 0x2080,
        .output_len_addr = 0x2100,
        .output_data_addr = 0x2104,
        .output_base = 0x2100,
        .output_end = 0x2200,
    };
}
