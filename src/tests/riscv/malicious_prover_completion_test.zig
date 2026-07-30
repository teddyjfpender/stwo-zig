//! Malicious prover: an ALTERED COMPLETION CONDITION.
//!
//! The prover keeps the honest witness and honestly executes the guest, then
//! claims it stopped at a different moment: the public halt tuple is rewritten
//! so the halt access clock names the *previous* instruction bucket. The
//! forgery is deliberately canonical rather than malformed — one whole access
//! stride back keeps the ordinal, keeps the value inside the protocol's
//! subclock lattice, and keeps it inside this execution's clock window — so
//! `PublicData.validate` accepts it and the refusal cannot be a shape check.
//!
//! # Why this is not a post-hoc mutation of a proof
//!
//! The altered tuple is the prover's ORIGINAL public statement. It is the
//! `public_data` argument of `runRiscVWithEngineAndPublicDataUsingChannel`, so
//! it is the statement the whole transaction is derived from, not a field
//! edited on a `RunOutput` after a proof existed. Nothing about serialization
//! or proof integrity is exercised here; the question is whether the prover
//! will *accept the job* of proving a completion its own memory image does not
//! support.
//!
//! # What the committed completion word is
//!
//! `runner.runWithInput` captures the RW-memory snapshot the proof commits to
//! (`runner/mod.zig:312`, `memory_state.capture`), and the aligned word at
//! `__halt_flag` is flagged `role.is_public_completion` inside it. That word
//! carries `final_word` and `final_clock` — the value the store wrote and the
//! access clock it wrote at. The honest statement's completion tuple is that
//! word: `committedHaltWord` below reads it out of `guest.run.rw_memory` and
//! the first test pins the three-way equality. So the admission check is a
//! comparison against committed data, not a recomputation of the statement
//! from itself.
//!
//! # Pinned stage and error, and why "before transcript mixing" holds
//!
//! Pinned: `Stage.admission` with `error.InvalidStatement`, raised by
//! `prover/commitment_witness.zig:51-59` — the loop that requires the claimed
//! address to carry the public-completion role, the claimed value and the
//! claimed clock.
//!
//! That check runs inside `derive`, called from `proveStages` at
//! `prover/orchestration.zig:184`; `bindCompletion` is its first statement
//! (`prover/orchestration.zig:330`). The first two transcript events of the
//! production path are `pcs_config.mixInto(channel)` and
//! `statement.public_data.mixInto(channel)` at `prover/orchestration.zig:193`
//! and `:194`. So the refusal is strictly before Fiat-Shamir opens, and the
//! second test observes that positively rather than by reading the source: the
//! caller-owned channel still holds its pristine digest and zero draws after
//! the rejected run, while a reference channel that has taken only the *first*
//! production event already reads differently.
//!
//! # Deviation from the issue's predicted behaviour
//!
//! The prediction (`.admission` / `error.InvalidStatement`) holds exactly. The
//! one prediction that does NOT hold is the suggested `+STRIDE` strengthening:
//! the honest halt access is the last access of the last instruction, so its
//! clock is exactly `access_clock.maximum(step_count)` and a forward stride
//! leaves the execution window. That alteration is refused by the structural
//! clock range check instead of by the committed-word comparison — a weaker
//! property, and the last test pins it as such so the difference is recorded
//! rather than hidden. The equality-not-bound-check claim is instead carried by
//! `canonical-but-wrong halt tuples`, which moves the clock inside the window
//! in both the ordinal and the instruction direction and also moves the value
//! and the address.

const std = @import("std");

const riscv_cpu = @import("stwo_riscv_cpu_integration");
const frontend = @import("stwo_riscv_frontend");
const access_clock = frontend.access_clock;
const memory_state = frontend.runner.memory_state;
const orchestration = frontend.testing.prover_orchestration;
const public_data = frontend.air.public_data;

const committed = @import("committed_forgery_harness.zig");
const harness = @import("malicious_prover_harness.zig");

const Channel = riscv_cpu.CpuProverEngine.Channel;

/// The word the committed RW-memory snapshot carries at `address`.
fn committedWordAt(
    guest: *const committed.Guest,
    address: u32,
) !memory_state.WordState {
    for (guest.run.rw_memory.words) |word| {
        if (word.addr == address) return word;
    }
    return error.AddressAbsentFromCommittedSnapshot;
}

/// The committed memory word the honest halt tuple is read out of.
///
/// Located by the same two facts `bindCompletion` uses — the aligned address
/// and the public-completion role — so a snapshot that stopped carrying the
/// role fails this fixture instead of silently making every forgery below
/// unfalsifiable.
fn committedHaltWord(
    guest: *const committed.Guest,
    address: u32,
) !memory_state.WordState {
    const word = try committedWordAt(guest, address);
    if (!word.role.is_public_completion) return error.NoCommittedCompletionWord;
    return word;
}

/// The prover's original public statement with the halt tuple replaced.
///
/// Everything else — registers, clocks, roots, the whole I/O block — is the
/// honest derivation, so the only thing the pipeline can object to is the
/// completion record.
fn withCompletion(
    honest: public_data.PublicData,
    completion: public_data.Completion,
) public_data.PublicData {
    var forged = honest;
    forged.completion = completion;
    return forged;
}

fn withClock(honest: public_data.Completion, clock: u32) public_data.Completion {
    var altered = honest;
    altered.clock = clock;
    return altered;
}

// Runtime: milliseconds. The forged statement is refused before any tree is
// committed, so no proof is attempted; the honest proof is the shared
// harness's obligation and is not repeated here.
test "malicious prover: an altered but canonical halt clock is refused at admission" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    const honest = guest.public.data.completion orelse
        return error.FixtureHasNoCompletion;
    try std.testing.expectEqual(public_data.CompletionKind.halt_flag, honest.kind);

    // The honest tuple IS the committed memory word: same value, same access
    // clock. This is what makes the rejection below a disagreement with
    // committed data rather than with a second derivation of the statement.
    const word = try committedHaltWord(&guest, honest.address);
    try std.testing.expectEqual(word.final_word, honest.value);
    try std.testing.expectEqual(word.final_clock, honest.clock);

    // And that clock is the store access of the last retired instruction —
    // the epilogue's `SW x2, 0(x1)`, whose third access sets the flag.
    try std.testing.expectEqual(
        access_clock.encode(guest.public.data.clock, .third),
        honest.clock,
    );

    // The forgery: one whole access stride back, i.e. the same ordinal in the
    // previous instruction's bucket.
    try std.testing.expect(honest.clock > access_clock.STRIDE);
    const altered = withClock(honest, honest.clock - access_clock.STRIDE);
    const forged = withCompletion(guest.public.data, altered);

    // Structurally valid, and canonical in the protocol's own sense: it is a
    // real subclock of a real instruction of this execution. `validate` is the
    // shape check `statement_validation.zig:68` runs, so a rejection there is
    // ruled out before the pipeline is asked.
    try std.testing.expect(access_clock.isCanonical(altered.clock));
    try std.testing.expect(
        access_clock.isWithinExecution(altered.clock, guest.public.data.clock, false),
    );
    try forged.validate();

    // ... and it disagrees with the committed word, which is the only thing
    // left for the pipeline to notice.
    try std.testing.expect(altered.clock != word.final_clock);

    try harness.expectRejected(
        &guest,
        .{ .statement = forged },
        .admission,
        error.InvalidStatement,
    );
}

// Runtime: milliseconds. The rejected run allocates a proof workspace and
// stops in `derive`; no tree is committed and no challenge is drawn.
test "malicious prover: the altered halt tuple is refused before any transcript event" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, harness.SPEC);
    defer guest.deinit();

    const honest = guest.public.data.completion orelse
        return error.FixtureHasNoCompletion;
    const forged = withCompletion(
        guest.public.data,
        withClock(honest, honest.clock - access_clock.STRIDE),
    );

    var observed = Channel{};
    const pristine = observed.digestBytes();

    // A channel that had reached even the FIRST production transcript event
    // would no longer read `pristine`. Replaying the opening two events of
    // `proveStages` on a separate channel is what makes "the digest did not
    // move" evidence instead of an assertion about an inert value.
    var reference = Channel{};
    committed.PCS_CONFIG.mixInto(&reference);
    const after_config = reference.digestBytes();
    try std.testing.expect(!std.mem.eql(u8, &pristine, &after_config));
    guest.public.data.mixInto(&reference);
    const after_statement = reference.digestBytes();
    try std.testing.expect(!std.mem.eql(u8, &after_config, &after_statement));

    // The production transaction, entered with the malicious statement and a
    // channel this test owns.
    try std.testing.expectError(
        error.InvalidStatement,
        orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
            riscv_cpu.CpuProverEngine,
            .prove,
            allocator,
            committed.PCS_CONFIG,
            &guest.run.execution_trace,
            &guest.run.state_chain_tracker,
            &guest.run.rw_memory,
            null,
            forged,
            &observed,
            null,
            null,
        ),
    );

    const after_rejection = observed.digestBytes();
    try std.testing.expectEqualSlices(u8, &pristine, &after_rejection);
    try std.testing.expectEqual(@as(u32, 0), observed.n_draws);
}

// Runtime: milliseconds. Four rejected statements, none of which reaches a
// commitment.
test "malicious prover: every canonical-but-wrong halt tuple is refused at admission" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    const honest = guest.public.data.completion orelse
        return error.FixtureHasNoCompletion;
    const word = try committedHaltWord(&guest, honest.address);
    const last_instruction = guest.public.data.clock;

    // Each case moves one field of the halt tuple off the committed word while
    // staying inside everything `PublicData.validate` can see. The clock moves
    // at two different granularities — one ordinal back inside the halting
    // instruction's own bucket, then a whole instruction back — and the value
    // and the address move too, so the refusal is a field-wise equality against
    // committed data rather than a range check on the clock.
    const cases = [_]struct {
        label: []const u8,
        completion: public_data.Completion,
    }{
        .{
            .label = "the halting instruction's second access",
            .completion = withClock(honest, access_clock.encode(last_instruction, .second)),
        },
        .{
            // A different bucket AND a different ordinal from the case above.
            // `encode(last_instruction - 1, .third)` would be the same word as
            // test 1's `honest.clock - access_clock.STRIDE`, which would make
            // this row a re-run rather than a second granularity.
            .label = "the previous instruction's first access",
            .completion = withClock(honest, access_clock.encode(last_instruction - 1, .first)),
        },
        .{
            .label = "a halt word one greater than the committed word",
            .completion = .{
                .kind = honest.kind,
                .address = honest.address,
                .value = honest.value + 1,
                .clock = honest.clock,
            },
        },
        .{
            // The published output word: aligned, committed, and carrying the
            // wrong role, so the completion loop refuses it on the role rather
            // than on the address being absent.
            .label = "the published output word instead of the halt flag",
            .completion = .{
                .kind = honest.kind,
                .address = guest.public.data.io_entries.output_data_addr,
                .value = honest.value,
                .clock = honest.clock,
            },
        },
    };

    // The last case names a word the snapshot really carries, so what refuses
    // it is the completion role of a committed word and not an address the
    // memory image never mentions.
    const output_word = try committedWordAt(
        &guest,
        guest.public.data.io_entries.output_data_addr,
    );
    try std.testing.expect(output_word.role.is_public_output);
    try std.testing.expect(!output_word.role.is_public_completion);

    for (cases) |case| {
        const forged = withCompletion(guest.public.data, case.completion);
        expectCanonicalRefusal(&guest, forged, word) catch |err| {
            std.debug.print(
                "altered halt tuple ({s}) was not refused at admission: {s}\n",
                .{ case.label, @errorName(err) },
            );
            return err;
        };
    }
}

/// One canonical-but-wrong halt tuple: structurally valid, unequal to the
/// committed word, refused at admission.
fn expectCanonicalRefusal(
    guest: *const committed.Guest,
    forged: public_data.PublicData,
    word: memory_state.WordState,
) !void {
    try forged.validate();
    const completion = forged.completion.?;
    try std.testing.expect(
        completion.address != word.addr or
            completion.value != word.final_word or
            completion.clock != word.final_clock,
    );
    try harness.expectRejected(
        guest,
        .{ .statement = forged },
        .admission,
        error.InvalidStatement,
    );
}

// Runtime: microseconds. Row-local: it decides a statement, not a proof.
test "malicious prover: a forward halt-clock shift is refused by the structural window" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    const honest = guest.public.data.completion orelse
        return error.FixtureHasNoCompletion;

    // The honest halt access is the last access of the last instruction, so it
    // sits exactly on the execution bound. Recorded here because it is the
    // reason the attack above moves backward: a forward stride is still a
    // well-formed subclock, but it is not one this execution could have.
    try std.testing.expectEqual(
        access_clock.maximum(guest.public.data.clock),
        @as(u64, honest.clock),
    );

    const forward = withClock(honest, honest.clock + access_clock.STRIDE);
    try std.testing.expect(access_clock.isCanonical(forward.clock));
    try std.testing.expect(
        !access_clock.isWithinExecution(forward.clock, guest.public.data.clock, false),
    );

    // So this one never reaches the committed-word comparison: the shape check
    // owns it. Pinning the exact structural error keeps the distinction between
    // the two refusals visible.
    const forged = withCompletion(guest.public.data, forward);
    try std.testing.expectError(error.InvalidCompletionClock, forged.validate());
}
