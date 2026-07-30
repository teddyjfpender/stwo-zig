//! The opcode-family precondition, stated as tests instead of as a comment.
//!
//! `runner/trace.zig` exposes two family maps over the same opcode set:
//!
//!   - `proofOpcodeFamily` is **partial** and fallible over raw `Opcode`. ECALL
//!     and EBREAK are execution-only (`isa/decode.zig` `proofOpcode`), so it
//!     answers `error.UnsupportedForProof` for them.
//!   - `opcodeFamily` is **total** and infallible over `trace.ProofOpcode`, the
//!     newtype the filter produces. Its precondition is no longer a claim about
//!     call order: the argument type has no inhabitant without a family, and
//!     `ProofOpcode.classify` is the only route into it from a raw `Opcode`.
//!
//! That precondition used to be documented but not enforced: `opcodeFamily` was
//! `proofOpcodeFamily(opcode) catch unreachable`, and `unreachable` in
//! ReleaseFast is undefined behaviour. One caller --
//! `air/opcode_memory.zig` `deriveRegisterBoundary` -- runs at the *first*
//! statement of `prover.proveRiscVTraceOnlyNoPublicIoUsingChannel`, which is strictly
//! before `prover/statement_geometry.build` invokes the filter. On an
//! ECALL-terminated trace it therefore reached the `unreachable`: a Debug build
//! panicked with "attempt to unwrap error: UnsupportedForProof", and a
//! ReleaseFast build silently mis-derived a garbage family and surfaced the
//! corruption much later as an unrelated-looking
//! `error.InvalidRegisterAccessChain`.
//!
//! This file locks three things.
//!
//! 1. **The map itself.** Every one of the 46 admitted opcodes is pinned to the
//!    family the manifest names, in a table written out here rather than read
//!    back from `opcode_manifest.zig`. A test that asks the manifest what the
//!    manifest says cannot notice a reclassification; this one can. The two
//!    execution-only opcodes are pinned as *rejected*, not as any family.
//!
//! 2. **Fail-closed behaviour at the pre-filter caller.** `deriveRegisterBoundary`
//!    on rows containing an ECALL must produce a defined error and must not
//!    produce `error.InvalidRegisterAccessChain`, which is the exact signature
//!    of the silent mis-derivation: reporting an admission failure as a witness
//!    failure points the reader at the wrong module. The property is asserted
//!    in that fix-agnostic form as well as against the identifier the fix
//!    currently uses.
//!
//! 3. **Fail-closed behaviour at the two prove entrypoints.** This used to be
//!    what stood in for a proof of the precondition at the *remaining*
//!    unchecked call sites (`air/interaction_gen.zig`,
//!    `prover/opcode_trace.zig`): those sites live in
//!    `main_trace`/`interaction_trace`, which `prover/orchestration.zig` runs
//!    only after `derive`, so a trace carrying an unsupported opcode had to be
//!    rejected inside `derive` for them to be safe. Both now resolve families
//!    through the filter itself, so their safety no longer depends on stage
//!    order -- but end-to-end rejection is still worth pinning, because a
//!    caller that reaches proving with an unprovable trace is a defect whatever
//!    the downstream stages do with it.
//!
//! 4. **The structural fact itself**, which is what a revert cannot survive:
//!    the total map's parameter type *is* the filtered type, so a pre-filter
//!    caller cannot reach it and restoring the raw-`Opcode` signature fails at
//!    compile time rather than in whichever caller is next to forget. Pinned by
//!    "the total family map is reachable only through the filter" below, plus
//!    "an empty opcode shard is named rather than assumed away" for the same
//!    defect class one call site over (`unreachable` guarding `rows[0]`).
//!
//!    A twin of the first assertion sits beside the code, in `runner/trace.zig`.
//!    It is duplicated here rather than left there because
//!    `src/frontends/riscv/**` is a separate Zig module (`stwo_riscv_frontend`)
//!    whose in-file tests no product step, release gate or workflow compiles --
//!    `-Driscv-test-filter` reports "selects no test" for every test name
//!    defined in that tree. The copy that runs is this one. Prefer adding new
//!    obligations here.
//!
//! Every regression above is cheap by construction: all of them fail before any
//! FFT, commitment or Merkle work happens, so this file belongs in the fast
//! `test-riscv` suite rather than the exhaustive gate.
//!
//! Optimization modes: the original defect was invisible in Debug (it panicked
//! rather than failing a test) and silent in ReleaseFast (UB). Nothing here
//! depends on the mode -- the assertions are ordinary error checks -- so the
//! file is meaningful under `-Doptimize=Debug`, `ReleaseSafe` and `ReleaseFast`
//! alike, and is worth running under at least Debug and ReleaseFast.

const std = @import("std");

const pcs = @import("stwo_core").pcs;
const isa_decode = @import("stwo_riscv_frontend").isa.decode;
const opcode_manifest = @import("stwo_riscv_frontend").opcode_manifest;
const interaction_gen = @import("stwo_riscv_frontend").air.interaction_gen;
const opcode_memory = @import("stwo_riscv_frontend").air.opcode_memory;
const relation_challenges = @import("stwo_riscv_frontend").air.relation_challenges;
const runner = @import("stwo_riscv_frontend").runner;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const riscv_cpu = @import("stwo_riscv_cpu_integration");

const Family = trace_mod.OpcodeFamily;
const Opcode = isa_decode.Opcode;
const TraceRow = trace_mod.TraceRow;

/// Every admitted RV32IM opcode and the proof family it must keep.
///
/// Written out rather than derived so that a change to `opcode_manifest.zig`
/// has to be made twice, deliberately, before it can move an opcode between
/// components. The families are protocol-visible: `component_order.zig` orders
/// the statement's opcode shards by family, so reclassifying one opcode changes
/// the proof of every program that uses it.
const pinned_families = [_]struct { Opcode, Family }{
    // R-type base ALU.
    .{ .ADD, .base_alu_reg },
    .{ .SUB, .base_alu_reg },
    .{ .XOR, .base_alu_reg },
    .{ .OR, .base_alu_reg },
    .{ .AND, .base_alu_reg },
    // R-type shifts and comparisons split off from the base ALU.
    .{ .SLL, .shifts_reg },
    .{ .SRL, .shifts_reg },
    .{ .SRA, .shifts_reg },
    .{ .SLT, .lt_reg },
    .{ .SLTU, .lt_reg },
    // I-type base ALU.
    .{ .ADDI, .base_alu_imm },
    .{ .XORI, .base_alu_imm },
    .{ .ORI, .base_alu_imm },
    .{ .ANDI, .base_alu_imm },
    .{ .SLTI, .lt_imm },
    .{ .SLTIU, .lt_imm },
    // Shift immediates carry their amount in the rs2 field, hence their own
    // witness schema.
    .{ .SLLI, .shifts_imm },
    .{ .SRLI, .shifts_imm },
    .{ .SRAI, .shifts_imm },
    // Loads and stores share one family; the row's is_load/is_store selectors
    // pick the access shape.
    .{ .LB, .load_store },
    .{ .LH, .load_store },
    .{ .LW, .load_store },
    .{ .LBU, .load_store },
    .{ .LHU, .load_store },
    .{ .SB, .load_store },
    .{ .SH, .load_store },
    .{ .SW, .load_store },
    // Branches split by comparison kind, not by taken-ness.
    .{ .BEQ, .branch_eq },
    .{ .BNE, .branch_eq },
    .{ .BLT, .branch_lt },
    .{ .BGE, .branch_lt },
    .{ .BLTU, .branch_lt },
    .{ .BGEU, .branch_lt },
    // Jumps and upper immediates each own a family.
    .{ .JAL, .jal },
    .{ .JALR, .jalr },
    .{ .LUI, .lui },
    .{ .AUIPC, .auipc },
    // M extension: low product, high product, and the division group.
    .{ .MUL, .mul },
    .{ .MULH, .mulh },
    .{ .MULHSU, .mulh },
    .{ .MULHU, .mulh },
    .{ .DIV, .div },
    .{ .DIVU, .div },
    .{ .REM, .div },
    .{ .REMU, .div },
    // Local protocol extension.
    .{ .FENCE, .fence },
};

/// The opcodes that must never receive a family. `opcode_manifest.zig` lists
/// them as `unsupported_entries` and gives them no `Entry`.
const execution_only = [_]Opcode{ .ECALL, .EBREAK };

test "opcode family precondition: every admitted opcode keeps its pinned family" {
    try std.testing.expectEqual(@as(usize, 46), pinned_families.len);
    // The admitted set and the manifest must have exactly the same size: an
    // opcode added to one and not the other is caught here rather than by
    // whichever component happens to receive the extra rows.
    try std.testing.expectEqual(opcode_manifest.entries.len, pinned_families.len);

    var seen_protocol_id = [_]bool{false} ** opcode_manifest.entries.len;
    for (pinned_families) |pin| {
        const opcode, const expected = pin;

        // The partial map admits it and answers the pinned family.
        const resolved = trace_mod.proofOpcodeFamily(opcode) catch |err| {
            std.debug.print(
                "{s} is admitted by the manifest but rejected by proofOpcodeFamily: {s}\n",
                .{ @tagName(opcode), @errorName(err) },
            );
            return error.AdmittedOpcodeRejected;
        };
        try std.testing.expectEqual(expected, resolved);

        // The total map agrees with it. This is the invariant that makes the
        // total map safe to call at all: it is the same function on the
        // admitted domain -- and the domain is now the argument type, so there
        // is no "off that domain" behaviour left to differ. Reaching the total
        // map requires the filter, which is the point of `ProofOpcode`.
        const filtered = try trace_mod.ProofOpcode.classify(opcode);
        try std.testing.expectEqual(expected, trace_mod.opcodeFamily(filtered));

        // And the manifest entry itself agrees, so the pin covers the source of
        // truth and not only the two wrappers over it.
        const proof_opcode = try isa_decode.proofOpcode(opcode);
        try std.testing.expectEqual(expected, opcode_manifest.family(proof_opcode));

        const id = proof_opcode.protocolId();
        try std.testing.expect(!seen_protocol_id[id]);
        seen_protocol_id[id] = true;
    }
    // Every protocol ID is claimed exactly once, so no manifest entry is
    // unreachable from the architectural opcode set and none is aliased.
    for (seen_protocol_id, 0..) |claimed, id| {
        if (claimed) continue;
        std.debug.print(
            "manifest protocol id {d} ({s}) is not reachable from any pinned opcode\n",
            .{ id, opcode_manifest.entries[id].mnemonic },
        );
        return error.UnreachableManifestEntry;
    }
}

test "opcode family precondition: the admitted set is exactly the architectural set minus ECALL and EBREAK" {
    // Pins the *domain* of the precondition, not just its values. If a new
    // opcode is decoded but left out of `proofOpcode`'s admitted arm, it lands
    // here instead of in a caller that assumed totality.
    var admitted: usize = 0;
    for (std.enums.values(Opcode)) |opcode| {
        const is_execution_only = for (execution_only) |excluded| {
            if (opcode == excluded) break true;
        } else false;

        if (is_execution_only) {
            try std.testing.expectError(
                error.UnsupportedForProof,
                trace_mod.proofOpcodeFamily(opcode),
            );
            continue;
        }

        const found = for (pinned_families) |pin| {
            if (pin[0] == opcode) break true;
        } else false;
        if (!found) {
            std.debug.print(
                "{s} is decoded but appears in neither the pinned family table nor the execution-only list\n",
                .{@tagName(opcode)},
            );
            return error.UnpinnedOpcode;
        }
        admitted += 1;
    }
    try std.testing.expectEqual(@as(usize, 46), admitted);
    try std.testing.expectEqual(execution_only.len, opcode_manifest.unsupported_entries.len);
}

test "opcode family precondition: the family filter rejects an execution-only row before witness generation" {
    const allocator = std.testing.allocator;
    for (execution_only) |opcode| {
        var trace = trace_mod.Trace.init(allocator);
        defer trace.deinit();
        try trace.append(rowFor(opcode, 1, 0x10004));

        try std.testing.expectError(
            error.UnsupportedForProof,
            trace.groupByOpcodeFamily(allocator),
        );
        // The witness generator refuses on the same grounds, so a caller that
        // skipped the filter still cannot materialise family columns from a row
        // that has no family.
        try std.testing.expectError(
            error.UnsupportedForProof,
            trace.columnsForFamily(allocator, .base_alu_reg, 0),
        );
    }
}

test "opcode family precondition: the total family map is reachable only through the filter" {
    // The structural half of the fix, and the half a revert cannot survive.
    //
    // The defect was not that `opcodeFamily` mishandled ECALL -- it was that
    // `opcodeFamily` *accepted* ECALL's type at all, so "the filter has already
    // run" was a claim in prose that one of four call sites did not honour.
    // Restoring the raw-`Opcode` signature restores exactly that hazard, and
    // must fail here rather than in whichever caller is next to forget.
    //
    // A twin of this assertion sits beside the code in `runner/trace.zig`. It
    // is duplicated rather than moved because `src/frontends/riscv/**` is a
    // separate Zig module whose in-file tests no product step, release gate or
    // workflow compiles -- confirmed with `-Driscv-test-filter`, which reports
    // that every test name defined under that tree selects no test. The copy
    // that runs is this one.
    const total = @typeInfo(@TypeOf(trace_mod.opcodeFamily)).@"fn";
    try std.testing.expectEqual(@as(usize, 1), total.params.len);
    try std.testing.expectEqual(trace_mod.ProofOpcode, total.params[0].type.?);
    // Total: no error union, so no caller is invited to decide what to do with
    // an opcode that has no family. There is no such value of this type.
    try std.testing.expectEqual(Family, total.return_type.?);

    // The only constructor from a raw opcode is fallible, so the type cannot be
    // entered without discharging the admission question.
    const filter = @typeInfo(@TypeOf(trace_mod.ProofOpcode.classify)).@"fn";
    try std.testing.expectEqual(Opcode, filter.params[0].type.?);
    const returns = @typeInfo(filter.return_type.?);
    try std.testing.expect(returns == .error_union);
    try std.testing.expectEqual(trace_mod.ProofOpcode, returns.error_union.payload);

    // The newtype wraps the *proof* opcode set, not the architectural one, so a
    // `ProofOpcode` written as a struct literal still cannot name ECALL: the
    // manifest enum has no such tag. Without this the newtype would only be a
    // convention, bypassable by anyone who spelled the literal out.
    const fields = @typeInfo(trace_mod.ProofOpcode).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqual(opcode_manifest.Opcode, fields[0].type);
    for (execution_only) |excluded| {
        for (std.enums.values(opcode_manifest.Opcode)) |id| {
            if (!std.mem.eql(u8, @tagName(id), @tagName(excluded))) continue;
            std.debug.print(
                "{s} has a proof-opcode tag, so a ProofOpcode literal can name it\n",
                .{@tagName(excluded)},
            );
            return error.ExecutionOnlyOpcodeIsRepresentable;
        }
    }
    for (std.enums.values(opcode_manifest.Opcode)) |id| {
        // Total on every inhabitant; this loop is the totality proof.
        _ = trace_mod.opcodeFamily(.{ .id = id });
    }
}

test "opcode family precondition: the filter is handed out as a value, index-parallel to the rows" {
    // How the post-filter stages get a `ProofOpcode` without reclassifying.
    // `prover/opcode_trace.zig` runs its family lookup inside a `void` worker
    // body that had no way to report an inadmissible opcode even if it noticed
    // one; it now consumes this slice, so the fallible step happens once, where
    // an error can still be returned.
    const allocator = std.testing.allocator;
    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    try trace.append(addiRow(1, 0x10000, 1, 42));
    try trace.append(rowFor(.FENCE, 2, 0x10004));

    const filtered = try trace.proofOpcodes(allocator);
    defer allocator.free(filtered);
    try std.testing.expectEqual(trace.rows.items.len, filtered.len);
    try std.testing.expectEqual(Family.base_alu_imm, trace_mod.opcodeFamily(filtered[0]));
    try std.testing.expectEqual(Family.fence, trace_mod.opcodeFamily(filtered[1]));

    // Fails closed on the first row with no proof encoding, exactly as
    // `groupByOpcodeFamily` does, so holding the slice really is evidence.
    for (execution_only) |opcode| {
        var rejected = trace_mod.Trace.init(allocator);
        defer rejected.deinit();
        try rejected.append(rowFor(opcode, 1, 0x10000));
        try std.testing.expectError(
            error.UnsupportedForProof,
            rejected.proofOpcodes(allocator),
        );
    }
}

test "opcode family precondition: an empty opcode shard is named rather than assumed away" {
    // The same defect class, one call site over. `genOpcodeInteraction` reads
    // its component's family off `rows[0]` and guarded that with
    // `if (rows.len == 0) unreachable`, which is a check only in safe builds; at
    // `-Doptimize=ReleaseFast` it is a licence to read the first element of an
    // empty slice. `statement_geometry` never describes an empty shard, so this
    // is a geometry defect, and it now has a name that says so in every
    // optimization mode.
    var relations = relation_challenges.Relations.dummy();
    try std.testing.expectError(
        error.EmptyOpcodeShard,
        interaction_gen.genOpcodeInteraction(std.testing.allocator, &.{}, 1, &relations),
    );
}

test "opcode family precondition: the pre-filter caller is declared fallible on unsupported opcodes" {
    // A log-free structural guard against the exact regression, worth having
    // beside the behavioural test below because it costs nothing and fires at
    // compile time.
    //
    // `deriveRegisterBoundary` reaches the family map before any filter has
    // run. While it resolved families through the *total* map, its error set
    // was `error{InvalidRegisterAccessChain}` alone -- there was no way for it
    // to report an inadmissible opcode, which is the same statement as "it
    // consumed one via `catch unreachable`". Resolving them fallibly is what
    // puts `UnsupportedForProof` into the signature, so the signature is a
    // faithful witness for the fix and a revert cannot restore the old
    // behaviour without also shrinking this set.
    const signature = @typeInfo(@TypeOf(opcode_memory.deriveRegisterBoundary)).@"fn";
    const returns = @typeInfo(signature.return_type.?).error_union;
    const members = @typeInfo(returns.error_set).error_set orelse return; // anyerror admits it

    for (members) |member| {
        if (std.mem.eql(u8, member.name, "UnsupportedForProof")) return;
    }
    std.debug.print(
        "deriveRegisterBoundary cannot report an inadmissible opcode; its error set is:\n",
        .{},
    );
    for (members) |member| std.debug.print("    error.{s}\n", .{member.name});
    return error.PreFilterCallerNotFallible;
}

test "opcode family precondition: register boundary derivation fails closed on an ECALL row" {
    // The exact pre-filter caller that carried the defect. `deriveRegisterBoundary`
    // walks raw trace rows at the top of the prove entrypoint, before any filter
    // has run, so it is the one place that must resolve families fallibly.
    const clean = [_]TraceRow{addiRow(1, 0x10000, 1, 42)};
    const with_ecall = [_]TraceRow{
        addiRow(1, 0x10000, 1, 42),
        rowFor(.ECALL, 2, 0x10004),
    };

    // The prefix on its own is a well-formed access chain, so any chain error
    // reported for the longer slice is attributable to the ECALL row.
    const baseline = try opcode_memory.deriveRegisterBoundary(&clean);

    if (opcode_memory.deriveRegisterBoundary(&with_ecall)) |derived| {
        // A fix that chooses to *skip* unsupported rows instead of rejecting
        // them is acceptable only if the skipped row contributes nothing. A
        // mis-derived family would have observed the ECALL row's rs1/rs2 and
        // moved the boundary.
        try std.testing.expectEqualSlices(u32, &baseline.initial, &derived.initial);
        try std.testing.expectEqualSlices(u32, &baseline.final, &derived.final);
        try std.testing.expectEqualSlices(u32, &baseline.last_clock, &derived.last_clock);
    } else |err| {
        // The mis-derivation signature. In ReleaseFast the old `catch unreachable`
        // produced a garbage family whose access chain did not close, and the
        // failure surfaced here under a name that blames witness generation for
        // an admission defect.
        const failure: anyerror = err;
        try expectNotMisderived(failure);
        // The identifier the current fix uses. `error.UnsupportedForProof` is
        // the codebase-wide name for "this opcode has no proof encoding"; the
        // property above is what actually pins the behaviour, this pins the
        // spelling.
        try std.testing.expectEqual(@as(anyerror, error.UnsupportedForProof), failure);
    }
}

test "opcode family precondition: the trace-only prove entrypoint rejects an ECALL-terminated run" {
    // A real runner-produced trace, not a synthetic one. `runner.run` is the
    // non-strict entrypoint (`runWithHost` with no host), so an ECALL is
    // retired into the trace as an ordinary row and then halts the machine.
    // `src/tools/riscv/bench/runner.zig` reaches the prover through exactly
    // this shape, which is how the defect was hit in production.
    const allocator = std.testing.allocator;
    const elf = ecallElf();
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    try std.testing.expectEqual(runner.CompletionReason.ecall, run.completion_reason);
    try std.testing.expectEqual(@as(usize, 2), run.execution_trace.rows.items.len);
    try std.testing.expectEqual(Opcode.ECALL, run.execution_trace.rows.items[1].opcode);

    // `proveRiscV` calls `deriveRegisterBoundary` as its first statement, so
    // this returns long before any commitment work. Reaching the assertion at
    // all is half the result: the pre-fix Debug build aborted the process here.
    const result = riscv_cpu.proveRiscV(
        allocator,
        cheapConfig(),
        &run.execution_trace,
        &run.state_chain_tracker,
        &run.rw_memory,
    );
    if (result) |output| {
        var owned = output;
        owned.deinit(allocator);
        return error.UnsupportedOpcodeProved;
    } else |err| {
        const failure: anyerror = err;
        try expectNotMisderived(failure);
        try std.testing.expectEqual(@as(anyerror, error.UnsupportedForProof), failure);
    }
}

test "opcode family precondition: the public-data prove entrypoint rejects the row before any witness stage" {
    // The second entrypoint takes public data from the caller and so never
    // calls `deriveRegisterBoundary`. It is the one that matters for the
    // remaining unchecked `opcodeFamily` call sites: `prover/orchestration.zig`
    // runs `derive` -- program commitment, then `statement_geometry.build`'s
    // `groupByOpcodeFamily` -- before `main_trace.generateAndCommit` and
    // `interaction_trace.generateAndCommit`, which are the stages that own
    // those call sites. If that order ever inverted, the total map's
    // `std.debug.panic` would abort this test process instead of returning.
    const allocator = std.testing.allocator;
    const elf = ecallElf();
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    const result = riscv_cpu.proveRiscVWithPublicData(
        allocator,
        cheapConfig(),
        &run.execution_trace,
        null,
        null,
        null,
        .{
            .initial_pc = run.initial_pc,
            .final_pc = run.final_pc,
            .clock = @intCast(run.step_count),
            .initial_regs = run.initial_regs,
            .final_regs = run.final_regs,
            .reg_last_clock = .{0} ** 32,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .io_entries = .{
                .input_start = 0,
                .input_len = 0,
                .input_words = &.{},
                .output_len = 0,
                .output_len_addr = 0,
                .output_data_addr = 0,
                .output_words = &.{},
            },
        },
    );
    if (result) |output| {
        var owned = output;
        owned.deinit(allocator);
        return error.UnsupportedOpcodeProved;
    } else |err| {
        const failure: anyerror = err;
        try expectNotMisderived(failure);
        // Whichever gate inside `derive` fires first, the rejection must name
        // the opcode's admissibility and not some downstream artefact.
        //
        // As of this writing it is `error.UnsupportedInstructionClass`, raised
        // by the program-commitment decoder (`air/program/decode.zig` ->
        // `isa/decode.zig` `proofOpcode`): `CommitmentWitness.build` decodes
        // every fetched word, and it runs before `statement_geometry.build`
        // reaches `groupByOpcodeFamily`. Both spellings are accepted because
        // which of the two gates fires first is an implementation detail; that
        // *some* gate inside `derive` fires is the property.
        switch (failure) {
            error.UnsupportedForProof, error.UnsupportedInstructionClass => {},
            else => {
                std.debug.print(
                    "expected an admission rejection, got {s}\n",
                    .{@errorName(err)},
                );
                return error.UnexpectedRejectionReason;
            },
        }
    }
}

/// The failure the defect used to produce. Kept as a helper so every regression
/// above rejects it by the same name: an unsupported opcode must never be
/// reported as a broken register access chain, because that sends the reader to
/// witness generation for a defect that lives in opcode admission.
fn expectNotMisderived(err: anyerror) !void {
    if (err != error.InvalidRegisterAccessChain) return;
    std.debug.print(
        "an unsupported opcode was reported as error.InvalidRegisterAccessChain: " ++
            "the family was mis-derived rather than rejected\n",
        .{},
    );
    return error.OpcodeFamilyMisderived;
}

/// Security parameters low enough to be free; nothing here reaches proving.
fn cheapConfig() pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 1,
        },
    };
}

/// A row with the shape the runner appends for an unsupported opcode: the
/// architectural register fields are populated, which is what made the
/// mis-derived `branch_eq` classification observe rs1/rs2 that no proof row
/// should ever have read.
fn rowFor(opcode: Opcode, clk: u32, pc: u32) TraceRow {
    return .{
        .clk = clk,
        .pc = pc,
        .opcode = opcode,
        .rd = 0,
        .rs1 = 7,
        .rs2 = 9,
        .imm = 0,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc + 4,
        .inst_word = if (opcode == .ECALL) 0x00000073 else 0x00100073,
    };
}

/// `addi xrd, x0, imm` as the runner would record it: one source read of x0 and
/// one destination write, both at their first observation, so the access chain
/// closes on its own.
fn addiRow(clk: u32, pc: u32, rd: u5, value: u32) TraceRow {
    return .{
        .clk = clk,
        .pc = pc,
        .opcode = .ADDI,
        .rd = rd,
        .rs1 = 0,
        .rs2 = 0,
        .imm = @intCast(value),
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = value,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc + 4,
        .inst_word = 0x02A00093,
    };
}

/// A minimal ET_EXEC RV32 image loaded at 0x10000:
///
///     0x10000: addi x1, x0, 42   (0x02a00093)
///     0x10004: ecall             (0x00000073)
///
/// Built by hand rather than through the guest fixture because the fixture's
/// prologue and halt-flag epilogue are exactly what keeps ECALL out of a trace;
/// the point here is a trace that has one.
fn ecallElf() [92]u8 {
    var elf = [_]u8{0} ** 92;
    // e_ident
    elf[0] = 0x7f;
    elf[1] = 'E';
    elf[2] = 'L';
    elf[3] = 'F';
    elf[4] = 1; // ELFCLASS32
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EI_VERSION
    elf[16] = 2; // e_type = ET_EXEC
    elf[18] = 0xf3; // e_machine = EM_RISCV
    elf[20] = 1; // e_version
    elf[26] = 0x01; // e_entry = 0x0001_0000
    elf[28] = 52; // e_phoff
    elf[40] = 52; // e_ehsize
    elf[42] = 32; // e_phentsize
    elf[44] = 1; // e_phnum
    // One PT_LOAD covering both instructions.
    elf[52] = 1; // p_type = PT_LOAD
    elf[56] = 84; // p_offset
    elf[62] = 0x01; // p_vaddr = 0x0001_0000
    elf[68] = 8; // p_filesz
    elf[72] = 8; // p_memsz
    // addi x1, x0, 42
    elf[84] = 0x93;
    elf[85] = 0x00;
    elf[86] = 0xa0;
    elf[87] = 0x02;
    // ecall
    elf[88] = 0x73;
    return elf;
}
