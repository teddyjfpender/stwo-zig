//! Compile-time stage adapter contract and a cryptography-free 256-node plan.
//!
//! A parent completion borrows two live child leases, validates them in left
//! then right order, builds and seals the parent, and releases both leases as
//! soon as the sealed durable artifact exists.  No live lease or capture is
//! representable in `RecursiveNodeArtifactV1`.
//!
//! The sealed producer result is still only transport.  Before commit, a
//! long-lived WorkerSession must cold-open those newly encoded bytes through
//! the kind-specific verifier and retain that new verifier lease.  It must
//! never promote producer-owned state as the parent lease.

const std = @import("std");

const artifact_mod = @import("recursive_node_artifact_v1.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const PARENT_TASK_COUNT: usize = artifact_mod.PARENT_NODE_COUNT;
pub const ANCESTOR_COUNT: usize = artifact_mod.ROOT_HEIGHT;

pub const Error = artifact_mod.Error || error{
    AdapterStageMismatch,
    InvalidMockFoldPlan,
    MissingStageAdapterDeclaration,
};

/// Stable worker-facing description.  A future single pipeline worker can
/// dispatch `describe -> deriveSemanticInputs -> coldOpen -> build` through a
/// compile-time adapter registry without giving the controller circuit logic.
pub const StageDescriptionV1 = struct {
    stage_kind: artifact_mod.StageKindV1,
    coordinate: artifact_mod.TaskCoordinateV1,
    input_count: u8,
    output_artifact_kind: u32 = artifact_mod.RECURSIVE_NODE_ARTIFACT_KIND,
    production_activation: bool = PRODUCTION_ACTIVATION,

    pub fn validate(self: *const StageDescriptionV1) Error!void {
        try self.coordinate.validate();
        const expected_input_count: u8 = if (self.stage_kind == .leaf_wrapper)
            1
        else
            2;
        if (self.input_count != expected_input_count or
            self.output_artifact_kind !=
                artifact_mod.RECURSIVE_NODE_ARTIFACT_KIND or
            self.production_activation)
        {
            return error.AdapterStageMismatch;
        }
    }
};

/// Returns a stage-specific runner only when the adapter exposes the complete
/// cold-open/build/seal ownership contract.  The concrete function signatures
/// are type-checked when a runner method is instantiated.
pub fn StageAdapter(
    comptime Adapter: type,
    comptime expected_stage: artifact_mod.StageKindV1,
) type {
    comptime assertAdapterDeclarations(Adapter, expected_stage);
    return struct {
        pub const stage_kind = expected_stage;

        pub fn describe(
            expected_task: *const Adapter.ExpectedTask,
        ) !StageDescriptionV1 {
            const result = try Adapter.describe(expected_task);
            try result.validate();
            if (result.stage_kind != expected_stage)
                return error.AdapterStageMismatch;
            return result;
        }

        pub fn deriveSemanticInputs(
            context: *const Adapter.BuildContext,
            input_refs: [2]artifact_mod.ArtifactRefV1,
            expected_task: *const Adapter.ExpectedTask,
        ) !artifact_mod.SemanticInputsV1 {
            const result = try Adapter.deriveSemanticInputs(
                context,
                input_refs,
                expected_task,
            );
            try result.validate();
            if (result.stage_kind != expected_stage)
                return error.AdapterStageMismatch;
            return result;
        }

        pub fn completeLeaf(
            authorities: *const Adapter.Authorities,
            context: *Adapter.BuildContext,
            input_ref: artifact_mod.ArtifactRefV1,
            expected_task: *const Adapter.ExpectedTask,
        ) !artifact_mod.RecursiveNodeArtifactV1 {
            if (expected_stage != .leaf_wrapper)
                return error.AdapterStageMismatch;
            const input_refs = [2]artifact_mod.ArtifactRefV1{
                input_ref,
                artifact_mod.ArtifactRefV1.zero(),
            };
            const description = try describe(expected_task);
            const semantic = try deriveSemanticInputs(
                context,
                input_refs,
                expected_task,
            );
            if (!std.meta.eql(description.coordinate, semantic.coordinate))
                return error.AdapterStageMismatch;
            var input = try Adapter.coldOpen(authorities, input_ref);
            defer input.deinit();
            if (!std.meta.eql(try Adapter.reference(&input), input_ref))
                return error.InvalidChildOrder;
            try Adapter.validateFresh(&input, expected_task);
            var owned = try Adapter.buildLeaf(context, &input, expected_task);
            defer owned.deinit();
            const sealed = try Adapter.seal(&owned);
            try sealed.validate();
            if (!std.mem.eql(
                u8,
                &sealed.semantic_inputs_identity_sha256,
                &semantic.identity_sha256,
            )) return error.InvalidArtifactIdentity;
            return sealed;
        }

        pub fn completeParent(
            authorities: *const Adapter.Authorities,
            context: *Adapter.BuildContext,
            child_refs: [2]artifact_mod.ArtifactRefV1,
            expected_task: *const Adapter.ExpectedTask,
        ) !artifact_mod.RecursiveNodeArtifactV1 {
            if (expected_stage == .leaf_wrapper)
                return error.AdapterStageMismatch;
            var left = try Adapter.coldOpen(authorities, child_refs[0]);
            var right = Adapter.coldOpen(
                authorities,
                child_refs[1],
            ) catch |err| {
                left.deinit();
                return err;
            };
            const actual_left = Adapter.reference(&left) catch |err| {
                left.deinit();
                right.deinit();
                return err;
            };
            const actual_right = Adapter.reference(&right) catch |err| {
                left.deinit();
                right.deinit();
                return err;
            };
            const actual_refs = [2]artifact_mod.ArtifactRefV1{
                actual_left,
                actual_right,
            };
            if (!std.meta.eql(actual_refs, child_refs)) {
                left.deinit();
                right.deinit();
                return error.InvalidChildOrder;
            }
            return completeParentFromLeases(
                context,
                &left,
                &right,
                expected_task,
            );
        }

        /// Primary long-lived-worker path.  Passing the two handles transfers
        /// their live admission lifetime to this call.  Both are released on
        /// every success or error after entry, immediately after any sealed
        /// parent has been produced.  The handles never enter durable bytes.
        pub fn completeParentFromLeases(
            context: *Adapter.BuildContext,
            left: *Adapter.Lease,
            right: *Adapter.Lease,
            expected_task: *const Adapter.ExpectedTask,
        ) !artifact_mod.RecursiveNodeArtifactV1 {
            if (expected_stage == .leaf_wrapper)
                return error.AdapterStageMismatch;
            defer left.deinit();
            defer right.deinit();
            const child_refs = [2]artifact_mod.ArtifactRefV1{
                try Adapter.reference(left),
                try Adapter.reference(right),
            };
            const description = try describe(expected_task);
            const semantic = try deriveSemanticInputs(
                context,
                child_refs,
                expected_task,
            );
            if (!std.meta.eql(description.coordinate, semantic.coordinate))
                return error.AdapterStageMismatch;
            try Adapter.validateFresh(left, expected_task);
            try Adapter.validateFresh(right, expected_task);
            var owned = try Adapter.buildParent(
                context,
                left,
                right,
                expected_task,
            );
            defer owned.deinit();
            const sealed = try Adapter.seal(&owned);
            try sealed.validate();
            if (!std.meta.eql(sealed.ordered_children, child_refs))
                return error.InvalidChildOrder;
            if (!std.mem.eql(
                u8,
                &sealed.semantic_inputs_identity_sha256,
                &semantic.identity_sha256,
            )) return error.InvalidArtifactIdentity;
            return sealed;
        }
    };
}

pub fn LeafWrapperStageAdapter(comptime Adapter: type) type {
    return StageAdapter(Adapter, .leaf_wrapper);
}

pub fn FoldStageAdapter(comptime Adapter: type) type {
    return StageAdapter(Adapter, .fold);
}

pub fn RootStageAdapter(comptime Adapter: type) type {
    return StageAdapter(Adapter, .root);
}

fn assertAdapterDeclarations(
    comptime Adapter: type,
    comptime expected_stage: artifact_mod.StageKindV1,
) void {
    inline for (.{
        "stage_kind",
        "Authorities",
        "BuildContext",
        "ExpectedTask",
        "Lease",
        "OwnedArtifact",
        "coldOpen",
        "describe",
        "deriveSemanticInputs",
        "reference",
        "validateFresh",
        "seal",
    }) |name| {
        if (!@hasDecl(Adapter, name))
            @compileError("StageAdapter is missing declaration: " ++ name);
    }
    if (Adapter.stage_kind != expected_stage)
        @compileError("StageAdapter stage_kind mismatch");
    if (expected_stage == .leaf_wrapper) {
        if (!@hasDecl(Adapter, "buildLeaf"))
            @compileError("leaf StageAdapter is missing buildLeaf");
    } else if (!@hasDecl(Adapter, "buildParent")) {
        @compileError("parent StageAdapter is missing buildParent");
    }
}

pub const MockParentTaskV1 = struct {
    ordinal: u16,
    parent: artifact_mod.TaskCoordinateV1,
    left: artifact_mod.TaskCoordinateV1,
    right: artifact_mod.TaskCoordinateV1,

    pub fn validate(self: *const MockParentTaskV1) Error!void {
        try self.parent.validate();
        try self.left.validate();
        try self.right.validate();
        if (self.parent.height == 0 or
            self.ordinal != try self.parent.parentTaskOrdinal() or
            self.left.height + 1 != self.parent.height or
            self.right.height != self.left.height or
            self.left.index != self.parent.index * 2 or
            self.right.index != self.left.index + 1)
        {
            return error.InvalidMockFoldPlan;
        }
    }
};

/// Exact breadth-wise task graph for a homogeneous 256-leaf binary fold.  It
/// proves only coordinates and child order; it contains no circuit or proof.
pub const MockHomogeneousFoldPlanV1 = struct {
    tasks: [PARENT_TASK_COUNT]MockParentTaskV1,

    pub fn init() Error!MockHomogeneousFoldPlanV1 {
        var result: MockHomogeneousFoldPlanV1 = undefined;
        var cursor: usize = 0;
        var height: u8 = 1;
        while (height <= artifact_mod.ROOT_HEIGHT) : (height += 1) {
            const count = try artifact_mod.nodeCount(height);
            for (0..count) |index| {
                const parent = try artifact_mod.TaskCoordinateV1.init(
                    height,
                    @intCast(index),
                );
                const child_height = height - 1;
                result.tasks[cursor] = .{
                    .ordinal = @intCast(cursor),
                    .parent = parent,
                    .left = try artifact_mod.TaskCoordinateV1.init(
                        child_height,
                        @intCast(index * 2),
                    ),
                    .right = try artifact_mod.TaskCoordinateV1.init(
                        child_height,
                        @intCast(index * 2 + 1),
                    ),
                };
                cursor += 1;
            }
        }
        if (cursor != result.tasks.len) return error.InvalidMockFoldPlan;
        try result.validate();
        return result;
    }

    pub fn validate(self: *const MockHomogeneousFoldPlanV1) Error!void {
        for (&self.tasks, 0..) |*parent_task, ordinal| {
            try parent_task.validate();
            if (parent_task.ordinal != ordinal)
                return error.InvalidMockFoldPlan;
        }
        const root = &self.tasks[self.tasks.len - 1];
        if (root.parent.height != artifact_mod.ROOT_HEIGHT or
            root.parent.index != 0 or
            root.parent.global_ordinal != artifact_mod.TOTAL_NODE_COUNT - 1)
        {
            return error.InvalidMockFoldPlan;
        }
    }

    pub fn task(
        self: *const MockHomogeneousFoldPlanV1,
        parent_height: u8,
        parent_index: u32,
    ) Error!*const MockParentTaskV1 {
        if (parent_height == 0 or parent_height > artifact_mod.ROOT_HEIGHT)
            return error.InvalidMockFoldPlan;
        const coordinate = try artifact_mod.TaskCoordinateV1.init(
            parent_height,
            parent_index,
        );
        const ordinal = try coordinate.parentTaskOrdinal();
        const result = &self.tasks[ordinal];
        try result.validate();
        if (!std.meta.eql(result.parent, coordinate))
            return error.InvalidMockFoldPlan;
        return result;
    }

    /// The eight parents invalidated by changing one height-zero leaf.
    pub fn ancestorPath(
        self: *const MockHomogeneousFoldPlanV1,
        leaf_index: u16,
    ) Error![ANCESTOR_COUNT]artifact_mod.TaskCoordinateV1 {
        try self.validate();
        if (leaf_index >= artifact_mod.PADDED_LEAF_COUNT)
            return error.InvalidMockFoldPlan;
        var result: [ANCESTOR_COUNT]artifact_mod.TaskCoordinateV1 = undefined;
        var index: u32 = leaf_index;
        for (&result, 1..) |*coordinate, height| {
            index /= 2;
            coordinate.* = try artifact_mod.TaskCoordinateV1.init(
                @intCast(height),
                index,
            );
        }
        return result;
    }
};

comptime {
    if (PARENT_TASK_COUNT != 255 or ANCESTOR_COUNT != 8 or
        PRODUCTION_ACTIVATION)
    {
        @compileError("recursive stage adapter V1 constants drifted");
    }
}
