//! Host scalar ownership contracts; resident handles use counted host storage.
const std = @import("std");
const Core = @import("stwo_core");
const M31 = Core.fields.m31.M31;
const QM31 = Core.fields.qm31.QM31;
const OM31 = Core.fields.om31.OM31;
const Line = @import("line_evaluation.zig");
const Column = @import("secure_column.zig");
const Storage = @import("resident_storage.zig").ResidentStorage;

const Resident = struct {
    destroyed: usize = 0,
    fn destroy(raw: *anyopaque) void {
        const self: *Resident = @ptrCast(@alignCast(raw));
        self.destroyed += 1;
    }
    fn storage(self: *Resident) Storage {
        return .{ .handle = self, .destroyFn = destroy };
    }
};

fn domain(log: u32) !Core.poly.line.LineDomain {
    return Core.poly.line.LineDomain.init(Core.circle.Coset.halfOdds(log));
}

fn failing() std.testing.FailingAllocator {
    return std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
}

test "scalar ownership: line constructor refusal retains owned and resident inputs" {
    inline for (.{ QM31, OM31 }) |F| {
        const E = Line.ForField(F).LineEvaluation;
        const a = std.testing.allocator;
        const values = try a.alloc(F, 4);
        @memset(values, F.one());
        // Rejection transfers nothing: caller reuses the same allocation.
        try std.testing.expectError(error.InvalidLength, E.initOwned(try domain(3), values));
        for (values) |value| try std.testing.expect(value.eql(F.one()));
        var owned = try E.initOwned(try domain(2), values);
        defer owned.deinit(a);
        var resident = Resident{};
        try std.testing.expectError(error.InvalidLength, E.initResident(try domain(3), values, resident.storage()));
        try std.testing.expectEqual(@as(usize, 0), resident.destroyed);
        var accepted = try E.initResident(try domain(2), values, resident.storage());
        accepted.deinit(a);
        try std.testing.expectEqual(@as(usize, 1), resident.destroyed);
        for (owned.values) |value| try std.testing.expect(value.eql(F.one()));
    }
}

test "scalar ownership: line allocation refusal and retry preserve borrowed resident sources" {
    inline for (.{ QM31, OM31 }) |F| {
        const E = Line.ForField(F).LineEvaluation;
        const a = std.testing.allocator;
        const d = try domain(2);
        var values = [_]F{ F.one(), F.zero(), F.one(), F.zero() };
        const before = values;
        var fa = failing();
        try std.testing.expectError(error.OutOfMemory, E.newZero(fa.allocator(), d));
        var zero = try E.newZero(a, d);
        zero.deinit(a);
        var borrowed = try E.initBorrowed(d, &values);
        defer borrowed.deinit(a);
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, borrowed.cloneOwned(fa.allocator()));
        try std.testing.expectEqualSlices(F, &before, &values);
        var clone = try borrowed.cloneOwned(a);
        try std.testing.expect(clone.owns_values and clone.resident_storage == null);
        clone.deinit(a);
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, borrowed.interpolate(fa.allocator()));
        try std.testing.expectEqualSlices(F, &before, &values);
        var poly = try borrowed.interpolate(a);
        poly.deinit(a);
        try std.testing.expectEqualSlices(F, &before, &values);
        var tracker = Resident{};
        var resident = try E.initResident(d, &values, tracker.storage());
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, resident.interpolate(fa.allocator()));
        try std.testing.expectEqual(@as(usize, 0), tracker.destroyed);
        try std.testing.expectEqualSlices(F, &before, &values);
        var resident_poly = try resident.interpolate(a);
        try std.testing.expectEqual(@as(usize, 0), tracker.destroyed);
        try std.testing.expectEqualSlices(F, &before, &values);
        resident.deinit(a);
        try std.testing.expectEqual(@as(usize, 1), tracker.destroyed);
        resident_poly.deinit(a);
    }
}

test "scalar ownership: inconsistent postconstruction length rejects without mutation or allocation leak" {
    inline for (.{ QM31, OM31 }) |F| {
        const E = Line.ForField(F).LineEvaluation;
        const a = std.testing.allocator;
        var values = [_]F{ F.one(), F.zero(), F.one(), F.zero() };
        const before = values;
        var borrowed = try E.initBorrowed(try domain(2), &values);
        defer borrowed.deinit(a);
        borrowed.domain_value = try domain(3);
        // The arena reclaims a historical leaked temporary after the assertion,
        // so this regression detects the leak without leaking the test process.
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var counted = std.testing.FailingAllocator.init(arena.allocator(), .{});
        try std.testing.expectError(error.InvalidLength, borrowed.interpolate(counted.allocator()));
        try std.testing.expectEqual(counted.allocated_bytes, counted.freed_bytes);
        try std.testing.expectEqualSlices(F, &before, &values);
        borrowed.domain_value = try domain(2);
        var retry = try borrowed.interpolate(a);
        retry.deinit(a);
        var owned = try E.initOwned(try domain(2), try a.dupe(F, &values));
        defer owned.deinit(a);
        owned.domain_value = try domain(3);
        try std.testing.expectError(error.InvalidLength, owned.interpolate(a));
        try std.testing.expect(owned.owns_values);
        try std.testing.expectEqualSlices(F, &before, owned.values);
    }
}

test "scalar ownership: arithmetic refusal releases borrowed and resident temporaries" {
    inline for (.{ QM31, OM31 }) |F| {
        const E = Line.ForField(F).LineEvaluation;
        const a = std.testing.allocator;
        var values = [_]F{ F.one(), F.zero(), F.one(), F.zero() };
        const before = values;
        var d = try domain(2);
        // Deliberately violate the public domain invariant to exercise the
        // existing typed arithmetic error, not a valid proof input.
        d.coset_value.initial.x = M31.zero();
        var tracker = Resident{};
        var borrowed = try E.initBorrowed(d, &values);
        defer borrowed.deinit(a);
        var resident = try E.initResident(d, &values, tracker.storage());
        for ([_]*E{ &borrowed, &resident }) |evaluation| {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var counted = std.testing.FailingAllocator.init(arena.allocator(), .{});
            try std.testing.expectError(error.DivisionByZero, evaluation.interpolate(counted.allocator()));
            try std.testing.expectEqual(counted.allocated_bytes, counted.freed_bytes);
            try std.testing.expectEqualSlices(F, &before, &values);
            try std.testing.expectEqual(@as(usize, 0), tracker.destroyed);
        }
        resident.deinit(a);
        try std.testing.expectEqual(@as(usize, 1), tracker.destroyed);
    }
}

test "scalar ownership: column constructor refusal retains all buffers and resident lease" {
    inline for (.{ QM31, OM31 }) |F| {
        const C = Column.SecureColumnByCoordsFor(F);
        const degree = @typeInfo(@TypeOf(F.zero().toM31Array())).array.len;
        const a = std.testing.allocator;
        var columns: [degree][]M31 = undefined;
        for (&columns) |*col| {
            col.* = try a.alloc(M31, 2);
            @memset(col.*, M31.one());
        }
        var invalid = columns;
        invalid[degree - 1] = invalid[degree - 1][0..1];
        try std.testing.expectError(error.InconsistentColumnLength, C.initOwned(invalid));
        for (columns) |col| try std.testing.expectEqualSlices(M31, &.{ M31.one(), M31.one() }, col);
        var owner = try C.initOwned(columns);
        defer owner.deinit(a);
        var tracker = Resident{};
        try std.testing.expectError(error.InconsistentColumnLength, C.initResident(invalid, tracker.storage()));
        try std.testing.expectEqual(@as(usize, 0), tracker.destroyed);
        var resident = try C.initResident(columns, tracker.storage());
        resident.deinit(a);
        try std.testing.expectEqual(@as(usize, 1), tracker.destroyed);
        try std.testing.expectEqual(@as(usize, 2), owner.len());
    }
}

test "scalar ownership: column allocation refusal clone retry and resident destruction" {
    inline for (.{ QM31, OM31 }) |F| {
        const C = Column.SecureColumnByCoordsFor(F);
        const a = std.testing.allocator;
        const degree = @typeInfo(@TypeOf(F.zero().toM31Array())).array.len;
        const values = [_]F{ F.one(), F.zero() };
        const base = [_]M31{ M31.one(), M31.zero() };
        var fa = failing();
        try std.testing.expectError(error.OutOfMemory, C.zeros(fa.allocator(), 2));
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, C.uninitialized(fa.allocator(), 2));
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, C.fromBaseFieldCol(fa.allocator(), &base));
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, C.fromSecureSlice(fa.allocator(), &values));
        var backing = try C.fromSecureSlice(a, &values);
        defer backing.deinit(a);
        backing.representation = .coefficients;
        var tracker = Resident{};
        var resident = try C.initResident(backing.columns, tracker.storage());
        resident.representation = .coefficients;
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, resident.cloneOwned(fa.allocator()));
        fa = failing();
        try std.testing.expectError(error.OutOfMemory, resident.toVec(fa.allocator()));
        try std.testing.expectEqual(@as(usize, 0), tracker.destroyed);
        var clone = try resident.cloneOwned(a);
        defer clone.deinit(a);
        try std.testing.expect(clone.owns_columns and clone.contiguous and clone.resident_storage == null);
        try std.testing.expectEqual(C.Representation.coefficients, clone.representation);
        const vector = try resident.toVec(a);
        defer a.free(vector);
        try std.testing.expectEqualSlices(F, &values, vector);
        for (0..degree) |i| try std.testing.expectEqualSlices(M31, backing.columns[i], clone.columns[i]);
        resident.deinit(a);
        try std.testing.expectEqual(@as(usize, 1), tracker.destroyed);
        try std.testing.expectEqualSlices(F, &values, vector);
        try std.testing.expect(clone.at(0).eql(F.one()));
    }
}
