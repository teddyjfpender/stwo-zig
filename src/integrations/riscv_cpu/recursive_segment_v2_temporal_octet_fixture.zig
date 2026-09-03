//! Eight-leaf real SegmentV2 fixture for the first generic recursion level.
//!
//! The fixture deliberately uses the existing all-family RV32 program instead
//! of introducing a recursion-specific guest. Seven one-cycle yields and one
//! terminal segment therefore exercise continuation custody while presenting
//! eight adjacent, independently verified leaves to the aggregation hook.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const ingress = @import("recursive_segment_v2_leaf_outer_proof_test.zig");
const subject = integration.recursive_segment_v2_leaf_outer;
const runner = frontend.runner;
const recursion = frontend.recursion;
const span = recursion.span_statement;
const protocol = recursion.protocol;

pub const LEAF_COUNT: usize = 8;

/// Eight adjacent independently verified SegmentV2 leaves. Every leaf crosses
/// prove/serialize/preflight/decode/fresh-verify custody before publication.
pub fn runTemporalOctetGateWithHook(
    allocator: std.mem.Allocator,
    comptime Hook: type,
) !void {
    comptime {
        if (!@hasDecl(Hook, "run"))
            @compileError("temporal V2 octet hook must declare run");
        @import("stwo_prover_api").assertProverEngine(subject.Engine);
    }

    var elf = try buildTemporalOctetElf();
    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();

    var profiles: [LEAF_COUNT]runner.Poseidon2SegmentResult = undefined;
    var profile_count: usize = 0;
    defer for (profiles[0..profile_count]) |*profile| profile.deinit();
    profiles[0] = try session.startSegment(1);
    profile_count = 1;
    for (1..LEAF_COUNT) |index| {
        const continuation = profiles[index - 1].base.continuation orelse
            return error.MissingTemporalContinuation;
        profiles[index] = try session.resumeSegment(
            continuation,
            if (index + 1 == LEAF_COUNT) 64 else 1,
        );
        profile_count += 1;
    }
    if (!profiles[LEAF_COUNT - 1].base.isComplete())
        return error.IncompleteTemporalExecution;

    var results: [LEAF_COUNT]*const runner.SegmentResult = undefined;
    for (&results, &profiles) |*destination, *profile|
        destination.* = &profile.base;
    for (results) |result|
        if (result.cycle_count != 1)
            return error.NonUniformTemporalLeafGeometry;

    var declared_program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        results[0].execution_trace.rows.items,
        results[0].rw_memory.program_words,
        null,
    );
    defer declared_program.deinit(allocator);

    const public_input = ingress.digest("recursive-v2-octet-input");
    const public_output = ingress.digest("recursive-v2-octet-output");
    var states: [LEAF_COUNT + 1]span.MachineState = undefined;
    states[0] = try ingress.machineState(
        results[0].entry_cpu,
        boundaryDigest(0, .rw),
        boundaryDigest(0, .public_io),
    );
    for (results, 0..) |result, index| {
        states[index + 1] = try ingress.machineState(
            result.exit_cpu,
            boundaryDigest(@intCast(index + 1), .rw),
            boundaryDigest(@intCast(index + 1), .public_io),
        );
        if (index != 0) {
            const entry = try ingress.machineState(
                result.entry_cpu,
                boundaryDigest(@intCast(index), .rw),
                boundaryDigest(@intCast(index), .public_io),
            );
            if (!std.meta.eql(entry, states[index]))
                return error.InvalidTemporalBoundary;
        }
    }

    var total_cycles: u64 = 0;
    for (results) |result|
        total_cycles = try std.math.add(
            u64,
            total_cycles,
            @intCast(result.cycle_count),
        );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            ingress.scalarDigest(declared_program.tree.root),
            states[0],
            states[LEAF_COUNT],
            public_input,
            public_output,
            total_cycles,
        ),
        LEAF_COUNT,
    );

    var statements: [LEAF_COUNT]span.SpanStatement = undefined;
    for (&statements, results, 0..) |*statement, result, index| {
        statement.* = try ingress.leafStatement(
            job,
            result,
            states[index],
            states[index + 1],
            if (index == 0)
                try span.EdgeClaim.present(public_input)
            else
                span.EdgeClaim.absent(),
            if (index + 1 == LEAF_COUNT)
                try span.EdgeClaim.present(public_output)
            else
                span.EdgeClaim.absent(),
        );
    }
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        ingress.digest("recursive-v2-segment-vk"),
        ingress.digest("recursive-v2-parent-vk"),
    );

    var prepared: [LEAF_COUNT]subject.PreparedNativeV2LeafOuter = undefined;
    var prepared_count: usize = 0;
    defer for (prepared[0..prepared_count]) |*leaf| leaf.deinit();
    for (&prepared, results, statements) |*destination, result, statement| {
        destination.* = try ingress.prepareTemporalNativeLeaf(
            allocator,
            result,
            statement,
            keys,
        );
        prepared_count += 1;
    }
    for (prepared, 0..) |left, left_index|
        for (prepared[left_index + 1 ..]) |right|
            if (std.mem.eql(u8, &left.identity, &right.identity))
                return error.DuplicateTemporalLeaf;
    try Hook.run(allocator, &prepared);
}

const BoundaryKind = enum(u32) {
    public_io = 0x4f43_0000,
    rw = 0x5257_0000,
};

fn boundaryDigest(index: u32, kind: BoundaryKind) span.Digest {
    return ingress.scalarDigest(@intFromEnum(kind) + index);
}

/// Derive an eight-instruction homogeneous program from the repository-owned
/// ELF builder without duplicating its private ELF layout. The source program
/// prefix is located and validated word-for-word before mutation; this keeps
/// the fixture robust to header/layout movement while ensuring every segment
/// has one identical LUI-family proof geometry.
fn buildTemporalOctetElf() ![frontend.testing.guest_precompile_test_elf.all_family_elf_size]u8 {
    const fixture = frontend.testing.guest_precompile_test_elf;
    var elf = fixture.buildAllFamilies();
    const offset = try findUniqueProgramOffset(
        &elf,
        &fixture.all_family_instructions,
    );
    const instructions = [_]u32{
        0x0010_00B7, // LUI x1, 0x100.
        0x0010_0137, // LUI x2, 0x100.
        0x0010_01B7, // LUI x3, 0x100.
        0x0010_0237, // LUI x4, 0x100.
        0x0010_02B7, // LUI x5, 0x100.
        0x0010_0337, // LUI x6, 0x100.
        0x0010_03B7, // LUI x7, 0x100.
        0x0010_0437, // LUI x8, 0x100.
        0x0000_006F, // JAL x0, 0: proof-bearing completion.
    };
    for (instructions, 0..) |instruction, index|
        std.mem.writeInt(
            u32,
            elf[offset + index * @sizeOf(u32) ..][0..@sizeOf(u32)],
            instruction,
            .little,
        );
    return elf;
}

fn findUniqueProgramOffset(elf: []const u8, instructions: []const u32) !usize {
    const byte_count = try std.math.mul(
        usize,
        instructions.len,
        @sizeOf(u32),
    );
    var found: ?usize = null;
    var offset: usize = 0;
    while (offset + byte_count <= elf.len) : (offset += @sizeOf(u32)) {
        var matches = true;
        for (instructions, 0..) |instruction, index| {
            const word_offset = offset + index * @sizeOf(u32);
            if (std.mem.readInt(
                u32,
                elf[word_offset..][0..@sizeOf(u32)],
                .little,
            ) != instruction) {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
        if (found != null) return error.AmbiguousProgramImage;
        found = offset;
    }
    return found orelse error.ProgramImageNotFound;
}
