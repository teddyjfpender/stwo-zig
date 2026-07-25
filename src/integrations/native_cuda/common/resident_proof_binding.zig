//! Binding for the one-read statement-prefixed SWPC terminal envelope.

const std = @import("std");
const column = @import("../../../backends/cuda/runtime/column.zig");
const views = @import("resident_views.zig");

const Words = column.DeviceSlice(u32);

pub fn bind(
    comptime geometry_mod: type,
    comptime proof_bundle: type,
    comptime slots: type,
    provider: anytype,
    prepared: anytype,
) !views.Proof {
    const statement_words = if (@hasDecl(
        geometry_mod,
        "terminal_statement_words",
    ))
        geometry_mod.terminal_statement_words
    else
        0;
    return bindAt(
        proof_bundle,
        provider,
        slots.proof_bundle,
        statement_words,
        prepared,
    );
}

/// Binds the terminal proof view when the frontend assigns arena slots at
/// runtime. Structural plans remain responsible for authenticating `proof_slot`
/// and the exact statement prefix; this helper owns only the common SWPC
/// extent and section layout checks.
pub fn bindAt(
    comptime proof_bundle: type,
    provider: anytype,
    proof_slot: anytype,
    statement_words: usize,
    prepared: anytype,
) !views.Proof {
    const terminal = try exactWords(
        provider,
        proof_slot,
        try add(prepared.proof.total_words, statement_words),
    );
    const statement = try terminal.sub(0, statement_words);
    const bundle = try terminal.sub(
        statement_words,
        prepared.proof.total_words,
    );
    return .{
        .terminal = terminal,
        .statement = statement,
        .bundle = bundle,
        .degree_verdict = try bundle.sub(15, 1),
        .trace_commitments = try section(
            proof_bundle,
            bundle,
            prepared,
            .trace_commitments,
        ),
        .sampled_values = try section(
            proof_bundle,
            bundle,
            prepared,
            .sampled_values,
        ),
        .fri_commitments = try section(
            proof_bundle,
            bundle,
            prepared,
            .fri_commitments,
        ),
        .fri_last_layer = try section(
            proof_bundle,
            bundle,
            prepared,
            .fri_last_layer,
        ),
        .pow_nonce = try section(
            proof_bundle,
            bundle,
            prepared,
            .proof_of_work,
        ),
        .decommitment = try section(
            proof_bundle,
            bundle,
            prepared,
            .decommitment,
        ),
    };
}

fn section(
    comptime proof_bundle: type,
    bundle: Words,
    prepared: anytype,
    kind: proof_bundle.SectionKind,
) !Words {
    const descriptor = prepared.proof.section(kind);
    return bundle.sub(
        descriptor.offset_words,
        descriptor.words,
    );
}

fn exactWords(
    provider: anytype,
    id: anytype,
    expected: usize,
) !Words {
    const value = try provider.slot(id);
    if (value.len != expected) return error.InvalidKernelDescriptor;
    return value;
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

test "dynamic proof slot preserves exact statement and SWPC sections" {
    const shared = @import("proof_bundle.zig");
    const Layout = struct {};
    const Decommit = struct { words: usize };
    const Descriptor = struct {
        pub fn sectionLengths(
            _: Layout,
            decommit: Decommit,
        ) ![shared.section_count]usize {
            return .{ 8, 4, 8, 4, 4, decommit.words };
        }

        pub fn fixedHeader(
            _: Layout,
            _: Decommit,
            total_words: usize,
        ) ![shared.fixed_header_words]u32 {
            var header = [_]u32{0} ** shared.fixed_header_words;
            header[0] = shared.magic;
            header[1] = shared.version;
            header[2] = try shared.u32Count(total_words);
            header[3] = shared.section_count;
            header[15] = std.math.maxInt(u32);
            return header;
        }
    };
    const Bundle = shared.BundleFor(Layout, Decommit, Descriptor);
    const Provider = struct {
        expected_slot: u16,
        words: Words,

        pub fn slot(self: @This(), id: u16) !Words {
            if (id != self.expected_slot) return error.UnknownSlot;
            return self.words;
        }
    };

    var proof = try Bundle.init(
        std.testing.allocator,
        .{},
        .{ .words = 11 },
    );
    defer proof.deinit(std.testing.allocator);
    const statement_words: usize = 3;
    const provider = Provider{
        .expected_slot = 0x441,
        .words = .{
            .address = 0x1000,
            .len = proof.total_words + statement_words,
            .owner = 7,
            .generation = 9,
        },
    };
    const prepared = struct { proof: Bundle }{ .proof = proof };
    const bound = try bindAt(
        shared,
        provider,
        @as(u16, 0x441),
        statement_words,
        prepared,
    );

    try std.testing.expectEqual(provider.words.len, bound.terminal.len);
    try std.testing.expectEqual(statement_words, bound.statement.len);
    try std.testing.expectEqual(proof.total_words, bound.bundle.len);
    try std.testing.expectEqual(
        provider.words.address + statement_words * @sizeOf(u32),
        bound.bundle.address,
    );
    inline for (std.meta.fields(shared.SectionKind)) |field| {
        const kind: shared.SectionKind = @enumFromInt(field.value);
        const expected = proof.section(kind);
        const actual = switch (kind) {
            .trace_commitments => bound.trace_commitments,
            .sampled_values => bound.sampled_values,
            .fri_commitments => bound.fri_commitments,
            .fri_last_layer => bound.fri_last_layer,
            .proof_of_work => bound.pow_nonce,
            .decommitment => bound.decommitment,
        };
        try std.testing.expectEqual(expected.words, actual.len);
        try std.testing.expectEqual(
            bound.bundle.address + expected.offset_words * @sizeOf(u32),
            actual.address,
        );
    }
}

test "dynamic proof slot rejects a non-exact resident extent" {
    const shared = @import("proof_bundle.zig");
    const Prepared = struct {
        proof: struct {
            total_words: usize,

            pub fn section(
                _: @This(),
                _: shared.SectionKind,
            ) shared.Section {
                unreachable;
            }
        },
    };
    const Provider = struct {
        pub fn slot(_: @This(), _: u16) !Words {
            return .{ .address = 0x1000, .len = 63, .owner = 7 };
        }
    };

    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        bindAt(
            shared,
            Provider{},
            @as(u16, 0x441),
            0,
            Prepared{ .proof = .{ .total_words = 64 } },
        ),
    );
}
