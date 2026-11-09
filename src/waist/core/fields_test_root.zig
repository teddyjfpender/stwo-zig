test {
    _ = @import("fields/cm31.zig");
    _ = @import("fields/m31.zig");
    _ = @import("fields/mod.zig");
    _ = @import("fields/qm31.zig");
    _ = @import("fields/om31_test.zig");
    _ = @import("fields/tests/cm31_fri_case.zig");
}

test "field root: complete OM31 property discovery" {
    inline for (.{
        "om31: irreducible tower norm Legendre and full Euler witnesses",
        "om31: high-limb independent schoolbook multiplication oracle",
        "om31: inversion independently matches exponentiation in polynomial oracle",
        "om31: field laws conjugation norm and scalar operations",
        "om31: embedded QM31 remains exactly compatible",
        "om31: canonical32byte encoding rejects every noncanonical coordinate",
        "om31: scaled norm batch covers tails stripes subfields and zero weights",
        "om31: batch zero and geometry failures are output atomic",
        "om31: native packed products and secure by base preserve independent lanes",
        "om31: explicit16row groups preserve high-limb column-major products",
        "om31: packed norm batches match scalar across every native tail and high limb",
        "om31: packed batch rejects all aliases and zero before output mutation",
        "om31: quadratic conjugation equals p4 Frobenius and fixes embedded QM31",
    }) |required| {
        var found: usize = 0;
        for (@import("builtin").test_functions) |entry| {
            if (@import("std").mem.endsWith(u8, entry.name, ".test." ++ required)) found += 1;
        }
        try @import("std").testing.expectEqual(@as(usize, 1), found);
    }
}
