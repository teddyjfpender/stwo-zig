//! Stable protocol-capacity storage for one RISC-V proof or verification.
//!
//! ## Why this module exists
//!
//! `core` consumes `[]const Component` / `[]const ComponentProver` fat pointers
//! that *borrow* the component values behind them, so those values must stay
//! addressable until `Engine.prove` / `core_verifier.verify` returns. A stack
//! frame satisfies that only accidentally. It also fails at scale: a Debug build
//! gives every by-value copy and every error-propagation site in a function its
//! own permanent frame slot, so a proving path whose values embed a 12,808-byte
//! `RiscVStatement` reserved megabytes of frame against macOS's 8 MiB
//! main-thread stack. Moving the capacity-sized arrays here, and returning
//! `!void` from the stage function that uses them, removes both problems
//! without changing a single protocol value. Splitting that path into per-tree
//! stage modules shortened each frame but did not remove the need: the
//! components `core` borrows still outlive every stage that built them.
//!
//! ## Capacity story (this is not unbounded state)
//!
//! Every array here is sized by a protocol capacity constant --
//! `MAX_COMPONENTS`, `MAX_INFRA_COMPONENTS`, `LOOKUP_TABLE_COUNT`,
//! `MAX_HASH_COMPONENTS` -- never by the witness. Both workspaces therefore
//! have exactly one comptime-known byte size, reported by `byteSize()` and
//! pinned by a test. There is no growth path, no reallocation, and no eviction
//! policy to reason about: the only failure mode is `error.OutOfMemory` from the
//! single `create` allocation. Statement admission (`statement_validation`)
//! rejects any statement whose component counts exceed these capacities before
//! any workspace slot is written, so the `push`/index assertions below are
//! programmer invariants rather than input validation.
//!
//! ## Ownership
//!
//! - The workspace block is **owned** by the caller of `create` and released by
//!   `destroy`. One allocation per proof, taken at the boundary that already
//!   takes an allocator, never inside a stage or row loop.
//! - `statement`, `components`, and every scratch array are **borrowed** by the
//!   proving/verification stages through the workspace pointer. No stage may
//!   retain a pointer past `destroy`.
//! - Column buffers referenced from `opcode_columns` and `clock_main` are
//!   acquired by the AIR generators, or **transferred** to the commitment
//!   scheme at a commit point. Retained Tree-1 buffers are released by
//!   `main_trace.Retained.deinit` after `Engine.prove`.
//!   `destroy` frees the workspace block only; it never frees a column buffer,
//!   because the workspace never allocated one.
//! - A workspace value must not be copied. All access goes through the pointer
//!   returned by `create`; the component fat pointers handed to `core` point
//!   into that block.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const m31 = @import("stwo_core").fields.m31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const clock_update_component = @import("../air/clock_update_component.zig");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const hash_component = @import("../air/memory_commitment/hash_component.zig");
const opcode_component = @import("../air/lookups/opcode_component.zig");
const lookup_table_component = @import("../air/lookups/tables/component.zig");
const riscv_component = @import("../air/component.zig");
const semantic_component = @import("../air/semantic_component.zig");
const statement_mod = @import("../air/statement.zig");
const trace_mod = @import("../runner/trace.zig");
const opcode_trace = @import("opcode_trace.zig");
const statement_validation = @import("statement_validation.zig");
const types = @import("types.zig");

const M31 = m31.M31;
const MAX_COMPONENTS = statement_mod.MAX_COMPONENTS;
const MAX_INFRA_COMPONENTS = statement_mod.MAX_INFRA_COMPONENTS;

/// The pinned component registry contains exactly two hash components: the
/// sparse Merkle node table and the Poseidon2 permutation table.
pub const MAX_HASH_COMPONENTS: usize = 2;

/// Each opcode shard publishes a semantic component and a lookup component;
/// each infrastructure component publishes one. This is the same bound the
/// previous exact-size allocation used (`2 * n_components + n_infra`).
pub const MAX_COMPONENT_HANDLES: usize = 2 * MAX_COMPONENTS + MAX_INFRA_COMPONENTS;

/// Component values plus the fat-pointer array that `core` iterates.
///
/// `Handle` is `ComponentProver` on the proving side and `Component` on the
/// verification side; the underlying component values are the same types in
/// both directions, which is why prover and verifier can no longer drift into
/// two independent declarations of this storage.
///
/// Indexing is deliberately identical to the previous per-side declarations:
/// `semantic`/`opcode_lookup` by opcode-shard index, `infra` by infrastructure
/// index, `table` by `component_order.lookupTableIndex`, `hash` by discovery
/// order. Component order is protocol-visible, so it is `handles` order --
/// the order `push` was called in -- that must never change.
pub fn ComponentTable(comptime Handle: type) type {
    return struct {
        const Self = @This();

        semantic: [MAX_COMPONENTS]semantic_component.SemanticComponent,
        opcode_lookup: [MAX_COMPONENTS]opcode_component.OpcodeLookupComponent,
        infra: [MAX_INFRA_COMPONENTS]riscv_component.RiscVTraceComponent,
        hash: [MAX_HASH_COMPONENTS]hash_component.HashComponent,
        table: [component_order.LOOKUP_TABLE_COUNT]lookup_table_component.LookupTableComponent,
        clock: clock_update_component.ClockUpdateComponent,
        handles: [MAX_COMPONENT_HANDLES]Handle,
        n_hash: usize,
        n_handles: usize,

        fn reset(self: *Self) void {
            self.n_hash = 0;
            self.n_handles = 0;
        }

        /// Appends one component in protocol declaration order.
        ///
        /// Capacity cannot be exceeded for an admitted statement: `push` is
        /// called at most twice per opcode shard and once per infrastructure
        /// component, and admission bounds both counts.
        pub fn push(self: *Self, handle: Handle) void {
            std.debug.assert(self.n_handles < MAX_COMPONENT_HANDLES);
            self.handles[self.n_handles] = handle;
            self.n_handles += 1;
        }

        /// Reserves the next hash-component slot and returns it for in-place
        /// initialization, keeping a 456-byte component value out of the
        /// caller's frame.
        pub fn nextHash(self: *Self) *hash_component.HashComponent {
            std.debug.assert(self.n_hash < MAX_HASH_COMPONENTS);
            const slot = &self.hash[self.n_hash];
            self.n_hash += 1;
            return slot;
        }

        /// Declaration-ordered components, **borrowed** from this table. The
        /// slice and everything it points at stay valid until `destroy`.
        pub fn active(self: *const Self) []const Handle {
            return self.handles[0..self.n_handles];
        }
    };
}

/// Proving-side workspace: statement, per-stage scratch, and prover components.
pub const ProofWorkspace = struct {
    /// The single authoritative statement for this proof. Callers read and
    /// mutate it in place so no 12,808-byte copy lands in a stage frame.
    statement: types.RiscVStatement,

    /// Opcode-family columns produced by `generateOpcodeColumns`, possibly on a
    /// helper thread. `opcode_error` is the single failure channel.
    opcode_columns: opcode_trace.Columns,
    opcode_error: ?anyerror,

    /// Row counts of the sharded RW-memory boundary table, in shard order.
    memory_shard_lengths: [MAX_INFRA_COMPONENTS]usize,
    memory_shard_count: usize,

    /// Unified clock-update main columns, borrowed by interaction generation
    /// after Tree 1 has been committed.
    clock_main: [clock_update_interaction.N_MAIN_COLUMNS][]M31,

    components: ComponentTable(prover_component.ComponentProver),

    pub fn byteSize() usize {
        return @sizeOf(ProofWorkspace);
    }

    /// Allocates and prepares one workspace. Owned by the caller; release with
    /// `destroy`. Fields whose first writer is a stage (`opcode_columns` and
    /// the component arrays) stay `undefined` exactly as the previous stack
    /// locals did.
    pub fn create(allocator: std.mem.Allocator) !*ProofWorkspace {
        const self = try allocator.create(ProofWorkspace);
        self.statement.n_components = 0;
        self.statement.n_infra = 0;
        self.opcode_error = null;
        self.memory_shard_count = 0;
        self.clock_main = .{&.{}} ** clock_update_interaction.N_MAIN_COLUMNS;
        self.components.reset();
        return self;
    }

    /// Frees the workspace block. Column buffers referenced from the workspace
    /// are released by the caller's `defer`s before this runs; see the module
    /// ownership note.
    pub fn destroy(self: *ProofWorkspace, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    /// Admission check against the workspace-owned statement.
    ///
    /// Exists so the fixed-capacity statement is passed as a workspace field
    /// rather than copied into the caller's frame at the call site.
    pub fn validateStatement(
        self: *const ProofWorkspace,
        policy: statement_validation.AdmissionPolicy,
    ) types.ProverError!void {
        return statement_validation.validate(self.statement, policy);
    }

    /// Thread entry for overlapped opcode-column generation.
    ///
    /// Writes `opcode_columns` on success and `opcode_error` on failure. The
    /// 12,808-byte statement copy `opcode_trace.generate` takes by value lands
    /// in this frame, which is either the helper thread's stack or a shallow
    /// point on the main stack, never the orchestration frame.
    pub fn generateOpcodeColumns(
        self: *ProofWorkspace,
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
    ) void {
        self.opcode_columns = opcode_trace.generate(
            allocator,
            exec_trace,
            self.statement,
        ) catch |err| {
            self.opcode_error = err;
            return;
        };
    }

    /// Releases the opcode-family column buffers described by `statement`.
    ///
    /// Wrapping `opcode_trace.Columns.deinit` here matters for frame size: as a
    /// bare `defer` the by-value statement argument was materialized once per
    /// error-propagation site of the enclosing function.
    pub fn releaseOpcodeColumns(self: *ProofWorkspace, allocator: std.mem.Allocator) void {
        self.opcode_columns.deinit(allocator, self.statement);
    }

    /// Releases the clock-update main columns owned by the workspace.
    pub fn releaseClockMain(self: *ProofWorkspace, allocator: std.mem.Allocator) void {
        for (self.clock_main) |column| allocator.free(column);
        self.clock_main = .{&.{}} ** clock_update_interaction.N_MAIN_COLUMNS;
    }
};

/// Verification-side workspace: canonical claim plus verifier components.
pub const VerificationWorkspace = struct {
    /// Canonical claimed sums and interaction log sizes. Fixed capacity
    /// (`MAX_INTERACTION_COLUMNS` log sizes) makes this ~124 KiB, which is why
    /// it may not live in a verifier stack frame.
    canonical: statement_mod.CanonicalInteractionClaim,
    components: ComponentTable(core_air_components.Component),

    pub fn byteSize() usize {
        return @sizeOf(VerificationWorkspace);
    }

    /// Allocates and prepares one workspace. Owned by the caller; release with
    /// `destroy`.
    pub fn create(allocator: std.mem.Allocator) !*VerificationWorkspace {
        const self = try allocator.create(VerificationWorkspace);
        self.canonical.n_log_sizes = 0;
        self.components.reset();
        return self;
    }

    pub fn destroy(self: *VerificationWorkspace, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    /// Computes the canonical claim into workspace storage.
    ///
    /// `RiscVInteractionClaim.canonical` returns by value; performing that
    /// return here confines the temporary to this frame instead of reserving
    /// several ~124 KiB slots in the verifier frame.
    pub fn canonicalize(
        self: *VerificationWorkspace,
        claim: *const types.RiscVInteractionClaim,
        statement: *const types.RiscVStatement,
    ) !void {
        self.canonical = try claim.canonical(statement);
    }
};

test "workspace capacities are comptime-fixed and independent of the witness" {
    // A capacity change is a protocol-capacity change; it must be deliberate.
    try std.testing.expectEqual(@as(usize, 1024), MAX_COMPONENT_HANDLES);
    try std.testing.expectEqual(@as(usize, 2), MAX_HASH_COMPONENTS);
    // Declared per-proof memory budget. Both sizes are comptime constants, so a
    // component type that grows past the budget fails here rather than silently
    // raising the prover's high-water mark. Measured on this revision:
    // 2,492,560 B proving, 1,251,704 B verification.
    try std.testing.expect(ProofWorkspace.byteSize() <= 4 << 20);
    try std.testing.expect(VerificationWorkspace.byteSize() <= 2 << 20);
}

test "created proof workspace starts empty and releases cleanly" {
    const allocator = std.testing.allocator;
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    try std.testing.expectEqual(@as(u32, 0), workspace.statement.n_components);
    try std.testing.expectEqual(@as(u32, 0), workspace.statement.n_infra);
    try std.testing.expectEqual(@as(usize, 0), workspace.memory_shard_count);
    try std.testing.expectEqual(@as(usize, 0), workspace.components.n_handles);
    try std.testing.expect(workspace.opcode_error == null);
    for (workspace.clock_main) |column| try std.testing.expectEqual(@as(usize, 0), column.len);

    workspace.releaseClockMain(allocator);
}

test "component table preserves push order and bounds hash slots" {
    const allocator = std.testing.allocator;
    const workspace = try VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    try std.testing.expectEqual(@as(usize, 0), workspace.components.active().len);
    const first = workspace.components.nextHash();
    const second = workspace.components.nextHash();
    try std.testing.expect(first != second);
    try std.testing.expectEqual(@as(usize, MAX_HASH_COMPONENTS), workspace.components.n_hash);
}

test "workspace create reports allocation failure" {
    // Deliberately not `expectError`: its failure path formats the success
    // payload, and `std.fmt` on a `*ProofWorkspace` instantiates a printer whose
    // own frame is as large as the workspace. That is the class of hidden stack
    // cost this module exists to remove.
    var proof_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    if (ProofWorkspace.create(proof_failing.allocator())) |unexpected| {
        unexpected.destroy(proof_failing.allocator());
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.OutOfMemory, err);

    var verify_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    if (VerificationWorkspace.create(verify_failing.allocator())) |unexpected| {
        unexpected.destroy(verify_failing.allocator());
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.OutOfMemory, err);
}
