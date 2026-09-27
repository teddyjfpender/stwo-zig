//! Exact original PAGE public claim bytes and first eight commitment roots.
//! A recursive PAGE verifies one source page only; whole-source closure remains
//! a separate exact-roster PAGE/lane/range join obligation.
const std = @import("std");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("../prover/block_v5_memory_source_unified_page_protocol_v1.zig");
const Components = @import("../prover/block_v5_memory_source_unified_page_components_v1.zig");
const Statements = @import("air/block_v5_memory_source_page_statement_v1.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Admit = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    const Captures = @import("../prover/block_v5_memory_source_page_recursive_capture_v1.zig").ForKind(kind);
    const Frames = struct {
        pub const PUBLIC_CIRCUIT = Statements.publicCircuit(kind);
        pub const Statement = Statements.ForKind(kind);
    };
    const Family = struct {
        pub const Admission = Admit;
        pub const Capture = Captures.VerifiedCapture;
        pub const Claims = struct { semantic: Protocol.SemanticPin, components: Components.ForKind(kind).Claims };
        pub const Statement = Frames;
        pub const IDENTITY_TAG: u32 = if (kind == .raw) 0x50475249 else 0x50474649; // PGRI/PGFI
        pub const SCHEDULE_TAG: u32 = if (kind == .raw) 0x50475257 else 0x50474657;
        pub fn rootsCount(_: *const Admission.Prepared) usize {
            return 8;
        }
        pub fn claims(capture: *const Capture) Claims {
            return .{ .semantic = capture.original.frame.semantic, .components = capture.original.frame.claims };
        }
        pub fn validateClaims(admitted: *const Admission.Prepared, proposed: Claims) !void {
            var bounded = @import("stwo_prover_engine").host_budget_allocator.HostBudgetAllocator.init(admitted.allocator, admitted.limits.page.max_receiver_heap_bytes);
            const a = bounded.allocator();
            var recorded = try Frames.Statement.init(a, admitted, proposed.semantic, proposed.components);
            defer recorded.deinit();
            // Independently rebuild actual graph/components/fixed roots under
            // the exact original page-local challenges and closures.
            const Frame = @import("../prover/block_v5_memory_source_page_capture_frame_v1.zig").ForKind(kind);
            const Original = @import("../prover/block_v5_memory_source_unified_page_proof_v1.zig").ForKind(kind);
            var original = try Original.Admission.init(a, admitted.context, admitted.pin, admitted.fold_rows, proposed.semantic.claims, admitted.limits.page);
            defer original.deinit();
            const C = Components.ForKind(kind);
            const geometry = C.Geometry{ .source_log = if (kind == .raw) admitted.pin.raw.page.row_log else admitted.pin.page.row_log, .capture_log = if (kind == .raw) admitted.pin.geometry.connector_log else admitted.pin.geometry.capture_log, .core_logs = admitted.pin.geometry.logs, .arithmetic_logs = original.fixed.arithmetic.logs, .capture_requests = @as(u64, admitted.pin.geometry.compressions) * if (kind == .raw) 32 else @import("../prover/block_v5_memory_source_blake_capture_air_v1.zig").requestMass() };
            const owner = try C.Owner.init(a, original.graph, &original.fixed.plan, &original.fixed.arithmetic, &original.fixed.source_inputs, &original.fixed.capture_inputs, geometry, recorded.relations, proposed.components, admitted.core_setup, admitted.arithmetic_setup, admitted.limits.page.composition);
            defer owner.deinit();
            var frame = try Frame.init(a, proposed.components, proposed.semantic, geometry, owner);
            defer frame.deinit(a);
            const recipe = try admitted.reconstruct(a, &frame, recorded.relations);
            defer recipe.deinit();
        }
        pub fn statement(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: Claims) !Frames.Statement {
            return Frames.Statement.init(a, admitted, proposed.semantic, proposed.components);
        }
        pub fn publicInputs(a: std.mem.Allocator, _: *const Admission.Prepared, proposed: Claims) ![]@import("stwo_core").fields.qm31.QM31 {
            return @import("air/block_v5_memory_source_page_composition_v1.zig").publicInputs(kind, a, proposed.components);
        }
    };
    const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamilyWithRoots(Family, 8);
    return struct {
        pub const Claims = Family.Claims;
        pub const VERSION = API.VERSION;
        pub const PUBLIC_CIRCUIT = API.PUBLIC_CIRCUIT;
        pub const MAX_WIRES = API.MAX_WIRES;
        pub const Source = API.Source;
        pub const Wire = API.Wire;
        pub const Values = API.Values;
        pub const Prepared = API.Prepared;
        pub const scheduleDigest = API.scheduleDigest;
        pub const collectFixedSchedule = API.collectFixedSchedule;
        pub const supply = API.supply;
        pub const prepare = API.prepare;
    };
}
