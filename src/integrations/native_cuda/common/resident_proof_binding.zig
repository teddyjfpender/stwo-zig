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
    const terminal = try exactWords(
        provider,
        slots.proof_bundle,
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
