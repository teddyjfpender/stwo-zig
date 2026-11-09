//! Forged public output: the prover publishes an output word its execution
//! never wrote, and publishes it as the *original* statement of the proof.
//!
//! # The attack
//!
//! The fixture guest's epilogue publishes two public output words: the length
//! word (`output_len = 4`) and one data word holding the register the spec
//! names — here `x6 = 9`. The malicious prover copies the honest output words,
//! raises the data word's value by one, and proves *that* statement. Nothing in
//! the witness is touched: the committed trace, the RW-memory snapshot and both
//! Merkle roots are the honest ones. The prover simply asserts a different
//! answer than the execution it is proving.
//!
//! The forgery is deliberately confined to the data word. `PublicData.validate`
//! ties `output_words[0].value` to `io_entries.output_len` — so raising the
//! length word is a *format* violation, refused before the transcript opens —
//! while a data word's value is unconstrained by the statement's own shape.
//! Both halves are pinned below, because the interesting claim is that the
//! surviving forgery is caught by the protocol and not by a format check.
//!
//! # Why this is not a post-hoc mutation
//!
//! "The attacks must not be post-hoc mutations of an honest proof" means the
//! forged value must be inside the Fiat-Shamir statement the proof is built
//! over, not spliced into a finished proof. Three independent facts establish
//! that here, and the second and third are executable:
//!
//!  1. Source order. `prover/orchestration.zig:proveStages` opens the
//!     transcript with exactly two events —
//!     `pcs_config.mixInto(channel); statement.public_data.mixInto(channel);` —
//!     before `Engine.init`, before Tree 0, Tree 1 and Tree 2 are committed and
//!     before `interaction_trace.drawChallenges` draws a single relation
//!     challenge. `statement.public_data` is the caller's statement verbatim:
//!     `statement_geometry.build` assigns `statement.public_data = public_data`
//!     and `bindCommitmentRoots` afterwards overwrites only the three commitment
//!     roots, never `io_entries`. `prover/verifier.zig` opens with the same two
//!     calls on the proof's own statement, so prover and verifier commit to the
//!     same forged words. This attack file therefore hands its statement to
//!     `harness.attempt`, which passes it to the production entrypoint as the
//!     prover's own public data; there is no second statement anywhere.
//!  2. Transcript preimage. `the forged public output word is the transcript's
//!     own preimage` replays those two production calls on the production
//!     channel type and shows that the honest and forged mixes differ in
//!     exactly one `u32` — the forged value, in the output-word slot that
//!     `air/public_data.zig`'s pinned mix-order test fixes — that the resulting
//!     channel digests differ, and that the relation challenges drawn from the
//!     forged prefix differ from the honest ones. Restoring the word reproduces
//!     the honest digest bit for bit, so the difference is attributable to that
//!     word alone.
//!  3. Attribution. `the forged public output word moves only the
//!     memory-access public term` decomposes `public_logup.relationSums` over
//!     the four public domains under one fixed production-shaped challenge set:
//!     `registers_state`, `merkle` and `program_access` are bit-identical
//!     between the honest and forged statements, and only `memory_access`
//!     moves. That is the same attribution `public_relation_binding_test.zig`
//!     pins for this mutation on the diagnostic path; this file adds the
//!     end-to-end leg the diagnostic cannot give.
//!
//! # The pinned stage and error
//!
//! `.verification` / `error.LogupSumNonZero`, exactly as the issue predicts.
//! The proving path never evaluates the public compensation — the only caller
//! of `logup.verifyGlobalCancellation` in the frontend is `prover/verifier.zig`
//! — so the forged statement is admitted, a complete and internally consistent
//! proof is produced over it, and the verifier's global LogUp closure is what
//! refuses it: the public boundary consumes a memory tuple carrying the forged
//! word, the committed memory trace emits the honest one, and the two no longer
//! cancel.
//!
//! Pinning the stage is what makes this evidence. A statement forgery caught at
//! `.admission` would mean a format check, not the protocol, rejected it; a
//! `.prover_constraints` rejection would mean it never reached the interaction
//! argument at all. Only `.verification` says the forgery survived commitment
//! and lost to the lookup argument.
//!
//! The honest control — the unmodified statement of this same guest verifying
//! through this same `attempt` path — is the shared harness's
//! `the unmodified request is accepted` self-check and is not repeated here; a
//! second honest proof would cost about eleven seconds for an obligation
//! already discharged.
//!
//! Runtime: milliseconds for the three statement-local tests and for the
//! admission attempt, which is decided before the transcript opens; about
//! eleven seconds for the end-to-end one, which produces one real proof over
//! the forged statement.

const std = @import("std");

const QM31 = @import("stwo_core").fields.qm31.QM31;

const riscv_cpu = @import("stwo_riscv_cpu_integration");
const frontend = @import("stwo_riscv_frontend");
const public_data_mod = frontend.air.public_data;
const public_logup = frontend.air.public_logup;
const relation_challenges = frontend.air.relation_challenges;

const committed = @import("committed_forgery_harness.zig");
const harness = @import("malicious_prover_harness.zig");

const OutputWord = public_data_mod.OutputWord;
const PublicData = public_data_mod.PublicData;

/// Index of the length word in `io_entries.output_words`, whose value the
/// statement's own shape ties to `output_len`.
const LENGTH_WORD: usize = 0;
/// Index of the single published data word: the vehicle of the attack.
const DATA_WORD: usize = 1;
/// Both of them, and no others: the fixture's epilogue publishes one word.
const OUTPUT_WORD_COUNT: usize = 2;

/// What the honest run stores at `output_data_addr`: the third body `ADDI`
/// computes `x6 = x3 + 1 = 9` and the epilogue publishes `x6`.
const HONEST_PUBLISHED_VALUE: u32 = 9;

/// The honest output words with word `index` raised by one. Caller-owned.
///
/// A copy, not an in-place edit of the guest's own words: the guest's public
/// data is the honest baseline every one of these tests compares against, and
/// a shared buffer would make the "restoring the word reproduces the honest
/// digest" control vacuous.
fn forgedOutputWords(
    allocator: std.mem.Allocator,
    guest: *const committed.Guest,
    index: usize,
) ![]OutputWord {
    const words = try allocator.alloc(OutputWord, guest.public.output_words.len);
    @memcpy(words, guest.public.output_words);
    words[index].value +%= 1;
    return words;
}

/// The guest's honest statement with `words` substituted for its output words.
fn withOutputWords(honest: PublicData, words: []const OutputWord) PublicData {
    var forged = honest;
    forged.io_entries.output_words = words;
    return forged;
}

/// The production Fiat-Shamir prefix over `statement`, replayed with the two
/// calls `proveStages` and `verifyRiscVWithEngineUsingChannel` open with, in
/// that order, on the production channel type.
fn transcriptPrefix(statement: PublicData) riscv_cpu.CpuProverEngine.Channel {
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    committed.PCS_CONFIG.mixInto(&channel);
    statement.mixInto(&channel);
    return channel;
}

/// Every `u32` a statement offers the transcript, in `mixInto` order.
///
/// `PublicData.mixInto` reaches the channel only through `mixU32s`, so
/// recording that one call captures the whole Fiat-Shamir preimage of the
/// statement. The field order it produces is pinned by
/// `air/public_data.zig`'s `transcript mix order matches pinned Stark-V`.
const MixRecorder = struct {
    words: [256]u32 = undefined,
    len: usize = 0,

    pub fn mixU32s(self: *MixRecorder, values: []const u32) void {
        std.debug.assert(self.len + values.len <= self.words.len);
        @memcpy(self.words[self.len..][0..values.len], values);
        self.len += values.len;
    }

    fn record(statement: PublicData) MixRecorder {
        var recorder = MixRecorder{};
        statement.mixInto(&recorder);
        return recorder;
    }

    fn slice(self: *const MixRecorder) []const u32 {
        return self.words[0..self.len];
    }
};

/// The one honest statement fact every test below forges against, asserted
/// rather than assumed: two output words, a length word whose value is the
/// declared length, and one data word at `output_data_addr` holding the
/// published register.
fn expectHonestOutputShape(guest: *const committed.Guest) !void {
    const io = guest.public.data.io_entries;
    try std.testing.expectEqual(OUTPUT_WORD_COUNT, io.output_words.len);
    try std.testing.expectEqual(io.output_len, io.output_words[LENGTH_WORD].value);
    try std.testing.expectEqual(io.output_data_addr, io.output_words[DATA_WORD].addr);
    try std.testing.expectEqual(HONEST_PUBLISHED_VALUE, io.output_words[DATA_WORD].value);
}

// Runtime: milliseconds. One eleven-instruction run, no proof.
test "malicious prover: the forged public output word is structurally valid" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();
    try expectHonestOutputShape(&guest);
    try guest.public.data.validate();

    // The load-bearing assertion of the whole attack: the forged statement is
    // well-formed public data. Whatever refuses it downstream is refusing the
    // claim it makes about the execution, not its shape.
    const forged_data = try forgedOutputWords(std.testing.allocator, &guest, DATA_WORD);
    defer std.testing.allocator.free(forged_data);
    const forged = withOutputWords(guest.public.data, forged_data);
    try forged.validate();
    try std.testing.expectEqual(
        HONEST_PUBLISHED_VALUE + 1,
        forged.io_entries.output_words[DATA_WORD].value,
    );

    // The contrast that makes "structurally valid" a real property rather than
    // a description: the length word carries a shape invariant, so the same
    // one-word bump there is a format violation.
    const forged_length = try forgedOutputWords(std.testing.allocator, &guest, LENGTH_WORD);
    defer std.testing.allocator.free(forged_length);
    try std.testing.expectError(
        error.OutputLengthWordMismatch,
        withOutputWords(guest.public.data, forged_length).validate(),
    );
}

// Runtime: milliseconds. One eleven-instruction run, no proof.
test "malicious prover: the forged public output word is the transcript's own preimage" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, harness.SPEC);
    defer guest.deinit();
    try expectHonestOutputShape(&guest);

    const forged_words = try forgedOutputWords(allocator, &guest, DATA_WORD);
    defer allocator.free(forged_words);
    const forged = withOutputWords(guest.public.data, forged_words);

    // The forged value is *in* the Fiat-Shamir preimage, and it is the only
    // thing in it that moved.
    const honest_mix = MixRecorder.record(guest.public.data);
    const forged_mix = MixRecorder.record(forged);
    try std.testing.expectEqual(honest_mix.len, forged_mix.len);
    var differing: usize = 0;
    var position: usize = 0;
    for (honest_mix.slice(), forged_mix.slice(), 0..) |honest_word, forged_word, index| {
        if (honest_word == forged_word) continue;
        differing += 1;
        position = index;
    }
    try std.testing.expectEqual(@as(usize, 1), differing);
    try std.testing.expectEqual(HONEST_PUBLISHED_VALUE, honest_mix.slice()[position]);
    try std.testing.expectEqual(HONEST_PUBLISHED_VALUE + 1, forged_mix.slice()[position]);

    // `mixInto` emits `{addr, value, clock}` per output word after the fixed
    // header and the input words, so the moved slot is the data word's value.
    const header = honest_mix.len - 3 * OUTPUT_WORD_COUNT;
    try std.testing.expectEqual(header + 3 * DATA_WORD + 1, position);

    // The transcript state the production prover and verifier both reach after
    // their two opening events already distinguishes the two statements, so
    // every challenge drawn afterwards is a function of the forged statement.
    const honest_prefix = transcriptPrefix(guest.public.data);
    var forged_prefix = transcriptPrefix(forged);
    try std.testing.expect(!std.mem.eql(
        u8,
        &honest_prefix.digestBytes(),
        &forged_prefix.digestBytes(),
    ));

    var honest_channel = honest_prefix;
    const honest_relations = try relation_challenges.Relations.draw(allocator, &honest_channel);
    const forged_relations = try relation_challenges.Relations.draw(allocator, &forged_prefix);
    try std.testing.expect(
        !honest_relations.memory_access.z.eql(forged_relations.memory_access.z),
    );
    try std.testing.expect(
        !honest_relations.registers_state.alpha.eql(forged_relations.registers_state.alpha),
    );

    // The control: the divergence above is attributable to that one word and
    // to nothing else about how these statements were built.
    forged_words[DATA_WORD].value -%= 1;
    const restored = transcriptPrefix(withOutputWords(guest.public.data, forged_words));
    try std.testing.expectEqualSlices(
        u8,
        &honest_prefix.digestBytes(),
        &restored.digestBytes(),
    );
}

// Runtime: milliseconds. One eleven-instruction run, no proof.
test "malicious prover: the forged public output word moves only the memory-access public term" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, harness.SPEC);
    defer guest.deinit();
    try expectHonestOutputShape(&guest);

    const forged_words = try forgedOutputWords(allocator, &guest, DATA_WORD);
    defer allocator.free(forged_words);
    const forged = withOutputWords(guest.public.data, forged_words);

    // One challenge set for both statements — a comparison under two different
    // challenge sets would say nothing about which domain moved. This is a
    // fixed, transcript-derived challenge set, not production's relation
    // challenges: production draws those in `interaction_trace.drawChallenges`
    // (`orchestration.zig:237`), after the tree roots are mixed, whereas this
    // channel has seen only the two opening events. The only property the
    // comparison needs is that both statements are measured under one and the
    // same set.
    var channel = transcriptPrefix(guest.public.data);
    const relations = try relation_challenges.Relations.draw(allocator, &channel);

    const honest_sums = try public_logup.relationSums(&guest.public.data, &relations);
    const forged_sums = try public_logup.relationSums(&forged, &relations);

    // The three domains the forgery must not disturb. A moved `registers_state`
    // or `program_access` term would mean the rejection below could be
    // explained by the CPU boundary or the completion sentinel instead of by
    // the public memory word the attack actually forged.
    try std.testing.expect(honest_sums.registers_state.eql(forged_sums.registers_state));
    try std.testing.expect(honest_sums.merkle.eql(forged_sums.merkle));
    try std.testing.expect(honest_sums.program_access.eql(forged_sums.program_access));
    try std.testing.expect(!honest_sums.memory_access.eql(forged_sums.memory_access));

    // The public boundary is exactly the term `verifyGlobalCancellation` adds
    // to the committed claims, so a nonzero delta here is a closure that no
    // longer closes: the honest total cancels the committed trace and the
    // forged one cannot.
    const honest_total = try public_logup.sum(&guest.public.data, &relations);
    const forged_total = try public_logup.sum(&forged, &relations);
    try std.testing.expect(honest_sums.total().eql(honest_total));
    try std.testing.expect(!forged_total.sub(honest_total).eql(QM31.zero()));

    // The control, again: restoring the word restores every domain exactly.
    forged_words[DATA_WORD].value -%= 1;
    const restored = try public_logup.relationSums(
        &withOutputWords(guest.public.data, forged_words),
        &relations,
    );
    try std.testing.expect(honest_sums.memory_access.eql(restored.memory_access));
    try std.testing.expect(honest_sums.total().eql(restored.total()));
}

// Runtime: about eleven seconds. One real proof over the forged statement; the
// honest leg is the shared harness's, not repeated here.
test "malicious prover: a forged public output word is rejected at verification" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, harness.SPEC);
    defer guest.deinit();
    try expectHonestOutputShape(&guest);

    const forged_words = try forgedOutputWords(allocator, &guest, DATA_WORD);
    defer allocator.free(forged_words);
    const forged = withOutputWords(guest.public.data, forged_words);
    // Asserted here too, immediately before the attempt, so the end-to-end
    // rejection cannot be read as a refusal of malformed public data.
    try forged.validate();

    try harness.expectRejected(
        &guest,
        .{ .statement = forged },
        .verification,
        error.LogupSumNonZero,
    );
}

// Runtime: milliseconds. Admission is decided before any transcript event, so
// this attempt costs a witness derivation and no proof.
test "malicious prover: a forged public output length word is refused at admission" {
    // The boundary of the attack above. The length word is the one output word
    // the statement's own shape constrains, so forging it never reaches the
    // interaction argument: `statement_validation.validate` maps
    // `PublicData.validate`'s refusal onto `error.InvalidStatement` before the
    // channel has seen a single event. Pinning it keeps the verification
    // rejection above meaningful — it shows that reaching verification at all
    // required a forgery the format check cannot see.
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, harness.SPEC);
    defer guest.deinit();
    try expectHonestOutputShape(&guest);

    const forged_words = try forgedOutputWords(allocator, &guest, LENGTH_WORD);
    defer allocator.free(forged_words);
    try harness.expectRejected(
        &guest,
        .{ .statement = withOutputWords(guest.public.data, forged_words) },
        .admission,
        error.InvalidStatement,
    );
}
