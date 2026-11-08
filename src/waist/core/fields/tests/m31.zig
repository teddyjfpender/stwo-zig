const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

const M31 = m31.M31;
const Modulus = m31.Modulus;
const PACK_WIDTH = m31.PACK_WIDTH;
const PackedM31 = m31.PackedM31;
const loadPacked = m31.loadPacked;
const storePacked = m31.storePacked;
const addPacked = m31.addPacked;
const subPacked = m31.subPacked;
const mulPacked = m31.mulPacked;
const negPacked = m31.negPacked;
const butterflyPacked = m31.butterflyPacked;
const ibutterflyPacked = m31.ibutterflyPacked;

fn randElem(rng: std.Random) M31 {
    while (true) {
        const x = rng.int(u32) & Modulus;
        if (x != Modulus) return M31.fromCanonical(x);
    }
}

test "m31: canonical reduction" {
    const p = Modulus;
    try std.testing.expect(M31.fromU64(p).isZero());
    try std.testing.expectEqual(@as(u32, 1), M31.fromU64(p + 1).toU32());
    try std.testing.expect(M31.fromU64(@as(u64, 2) * p).isZero());
    try std.testing.expectEqual(@as(u32, 1), M31.fromU64(@as(u64, 2) * p + 1).toU32());
}

test "m31: basic identities" {
    const a = M31.fromCanonical(123456789);
    const b = M31.fromCanonical(987654321);

    try std.testing.expect(a.add(M31.zero()).eql(a));
    try std.testing.expect(a.mul(M31.one()).eql(a));
    try std.testing.expect(a.sub(a).isZero());
    try std.testing.expect(a.add(b).sub(b).eql(a));

    const minus_one = M31.fromCanonical(Modulus - 1);
    try std.testing.expect(minus_one.mul(minus_one).eql(M31.one()));
}

test "m31: inversion" {
    const a = M31.fromCanonical(7);
    const inv_a = try a.inv();
    try std.testing.expect(a.mul(inv_a).eql(M31.one()));

    try std.testing.expectError(M31.Error.DivisionByZero, M31.zero().inv());
}

test "m31: randomized ring laws" {
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9abc_def0);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const a = randElem(rng);
        const b = randElem(rng);
        const c = randElem(rng);

        // Commutativity.
        try std.testing.expect(a.add(b).eql(b.add(a)));
        try std.testing.expect(a.mul(b).eql(b.mul(a)));

        // Associativity.
        try std.testing.expect(a.add(b).add(c).eql(a.add(b.add(c))));
        try std.testing.expect(a.mul(b).mul(c).eql(a.mul(b.mul(c))));

        // Distributivity.
        try std.testing.expect(a.mul(b.add(c)).eql(a.mul(b).add(a.mul(c))));

        // Inversion property for non-zero.
        if (!a.isZero()) {
            const inv_a = try a.inv();
            try std.testing.expect(a.mul(inv_a).eql(M31.one()));
        }
    }
}

test "m31: packed add matches scalar" {
    var a_arr: [PACK_WIDTH]M31 = undefined;
    var b_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        a_arr[i] = M31.fromCanonical(@intCast(i * 100 + 1));
        b_arr[i] = M31.fromCanonical(@intCast(i * 200 + 3));
    }
    const a_packed = loadPacked(&a_arr);
    const b_packed = loadPacked(&b_arr);
    const sum_packed = addPacked(a_packed, b_packed);
    var result: [PACK_WIDTH]M31 = undefined;
    storePacked(&result, sum_packed);
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(result[i].eql(a_arr[i].add(b_arr[i])));
    }
}

test "m31: packed sub matches scalar" {
    var a_arr: [PACK_WIDTH]M31 = undefined;
    var b_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        // Mix values so some lanes have a < b and some a >= b.
        a_arr[i] = M31.fromCanonical(@intCast(i * 37 + 5));
        b_arr[i] = M31.fromCanonical(@intCast(i * 53 + 1000));
    }
    const a_packed = loadPacked(&a_arr);
    const b_packed = loadPacked(&b_arr);
    const diff_packed = subPacked(a_packed, b_packed);
    var result: [PACK_WIDTH]M31 = undefined;
    storePacked(&result, diff_packed);
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(result[i].eql(a_arr[i].sub(b_arr[i])));
    }
}

test "m31: packed mul matches scalar" {
    var a_arr: [PACK_WIDTH]M31 = undefined;
    var b_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        a_arr[i] = M31.fromCanonical(@intCast(i * 12345 + 7));
        b_arr[i] = M31.fromCanonical(@intCast(i * 67890 + 11));
    }
    const a_packed = loadPacked(&a_arr);
    const b_packed = loadPacked(&b_arr);
    const prod_packed = mulPacked(a_packed, b_packed);
    var result: [PACK_WIDTH]M31 = undefined;
    storePacked(&result, prod_packed);
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(result[i].eql(a_arr[i].mul(b_arr[i])));
    }
}

test "m31: packed mul with large values" {
    // Test with values close to the modulus to stress the reduction.
    var a_arr: [PACK_WIDTH]M31 = undefined;
    var b_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        a_arr[i] = M31.fromCanonical(Modulus - 1 - @as(u32, @intCast(i)));
        b_arr[i] = M31.fromCanonical(Modulus - 2 - @as(u32, @intCast(i)));
    }
    const a_packed = loadPacked(&a_arr);
    const b_packed = loadPacked(&b_arr);
    const prod_packed = mulPacked(a_packed, b_packed);
    var result: [PACK_WIDTH]M31 = undefined;
    storePacked(&result, prod_packed);
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(result[i].eql(a_arr[i].mul(b_arr[i])));
    }
}

test "m31: packed neg matches scalar" {
    var a_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        a_arr[i] = M31.fromCanonical(@intCast(i * 500));
    }
    const a_packed = loadPacked(&a_arr);
    const neg_packed = negPacked(a_packed);
    var result: [PACK_WIDTH]M31 = undefined;
    storePacked(&result, neg_packed);
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(result[i].eql(a_arr[i].neg()));
    }
}

test "m31: packed butterfly matches scalar" {
    var lhs_packed_arr: [PACK_WIDTH]M31 = undefined;
    var rhs_packed_arr: [PACK_WIDTH]M31 = undefined;
    var lhs_scalar: [PACK_WIDTH]M31 = undefined;
    var rhs_scalar: [PACK_WIDTH]M31 = undefined;
    var twid_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        lhs_packed_arr[i] = M31.fromCanonical(@intCast(i * 1000 + 42));
        rhs_packed_arr[i] = M31.fromCanonical(@intCast(i * 777 + 99));
        lhs_scalar[i] = lhs_packed_arr[i];
        rhs_scalar[i] = rhs_packed_arr[i];
        twid_arr[i] = M31.fromCanonical(@intCast(i * 333 + 17));
    }
    // Apply packed butterfly.
    butterflyPacked(&lhs_packed_arr, &rhs_packed_arr, loadPacked(&twid_arr));
    // Apply scalar butterfly.
    for (0..PACK_WIDTH) |i| {
        const m = rhs_scalar[i].mul(twid_arr[i]);
        const new_lhs = lhs_scalar[i].add(m);
        const new_rhs = lhs_scalar[i].sub(m);
        lhs_scalar[i] = new_lhs;
        rhs_scalar[i] = new_rhs;
    }
    // Compare.
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(lhs_packed_arr[i].eql(lhs_scalar[i]));
        try std.testing.expect(rhs_packed_arr[i].eql(rhs_scalar[i]));
    }
}

test "m31: packed ibutterfly matches scalar" {
    var lhs_packed_arr: [PACK_WIDTH]M31 = undefined;
    var rhs_packed_arr: [PACK_WIDTH]M31 = undefined;
    var lhs_scalar: [PACK_WIDTH]M31 = undefined;
    var rhs_scalar: [PACK_WIDTH]M31 = undefined;
    var itwid_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        lhs_packed_arr[i] = M31.fromCanonical(@intCast(i * 500 + 10));
        rhs_packed_arr[i] = M31.fromCanonical(@intCast(i * 300 + 20));
        lhs_scalar[i] = lhs_packed_arr[i];
        rhs_scalar[i] = rhs_packed_arr[i];
        itwid_arr[i] = M31.fromCanonical(@intCast(i * 200 + 5));
    }
    // Apply packed inverse butterfly.
    ibutterflyPacked(&lhs_packed_arr, &rhs_packed_arr, loadPacked(&itwid_arr));
    // Apply scalar inverse butterfly.
    for (0..PACK_WIDTH) |i| {
        const new_lhs = lhs_scalar[i].add(rhs_scalar[i]);
        const new_rhs = lhs_scalar[i].sub(rhs_scalar[i]).mul(itwid_arr[i]);
        lhs_scalar[i] = new_lhs;
        rhs_scalar[i] = new_rhs;
    }
    // Compare.
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(lhs_packed_arr[i].eql(lhs_scalar[i]));
        try std.testing.expect(rhs_packed_arr[i].eql(rhs_scalar[i]));
    }
}

test "m31: packed randomized ring laws" {
    var prng = std.Random.DefaultPrng.init(0xdead_beef_cafe_babe);
    const rng = prng.random();

    for (0..1000) |_| {
        var a_arr: [PACK_WIDTH]M31 = undefined;
        var b_arr: [PACK_WIDTH]M31 = undefined;
        var c_arr: [PACK_WIDTH]M31 = undefined;
        for (0..PACK_WIDTH) |i| {
            a_arr[i] = randElem(rng);
            b_arr[i] = randElem(rng);
            c_arr[i] = randElem(rng);
        }
        const a = loadPacked(&a_arr);
        const b = loadPacked(&b_arr);
        const c = loadPacked(&c_arr);

        // Commutativity of add.
        {
            var r1: [PACK_WIDTH]M31 = undefined;
            var r2: [PACK_WIDTH]M31 = undefined;
            storePacked(&r1, addPacked(a, b));
            storePacked(&r2, addPacked(b, a));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(r1[i].eql(r2[i]));
            }
        }
        // Commutativity of mul.
        {
            var r1: [PACK_WIDTH]M31 = undefined;
            var r2: [PACK_WIDTH]M31 = undefined;
            storePacked(&r1, mulPacked(a, b));
            storePacked(&r2, mulPacked(b, a));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(r1[i].eql(r2[i]));
            }
        }
        // Associativity of add.
        {
            var r1: [PACK_WIDTH]M31 = undefined;
            var r2: [PACK_WIDTH]M31 = undefined;
            storePacked(&r1, addPacked(addPacked(a, b), c));
            storePacked(&r2, addPacked(a, addPacked(b, c)));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(r1[i].eql(r2[i]));
            }
        }
        // Distributivity: a * (b + c) == a*b + a*c.
        {
            var r1: [PACK_WIDTH]M31 = undefined;
            var r2: [PACK_WIDTH]M31 = undefined;
            storePacked(&r1, mulPacked(a, addPacked(b, c)));
            storePacked(&r2, addPacked(mulPacked(a, b), mulPacked(a, c)));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(r1[i].eql(r2[i]));
            }
        }
        // a - a == 0.
        {
            var r: [PACK_WIDTH]M31 = undefined;
            storePacked(&r, subPacked(a, a));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(r[i].isZero());
            }
        }
    }
}

test "m31: packed add edge cases" {
    // Test adding zero.
    {
        var a_arr: [PACK_WIDTH]M31 = undefined;
        for (0..PACK_WIDTH) |i| {
            a_arr[i] = M31.fromCanonical(@intCast(i * 100_000));
        }
        const a = loadPacked(&a_arr);
        const zero_vec: PackedM31 = @splat(0);
        const result = addPacked(a, zero_vec);
        try std.testing.expect(@reduce(.And, result == a));
    }
    // Test P-1 + 1 = 0 (modular wrap).
    {
        const pm1: PackedM31 = @splat(Modulus - 1);
        const one: PackedM31 = @splat(1);
        const result = addPacked(pm1, one);
        const expected: PackedM31 = @splat(0);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test P-1 + P-1 = P-2 (double wrap).
    {
        const pm1: PackedM31 = @splat(Modulus - 1);
        const result = addPacked(pm1, pm1);
        const expected: PackedM31 = @splat(Modulus - 2);
        try std.testing.expect(@reduce(.And, result == expected));
    }
}

test "m31: packed sub edge cases" {
    // Test 0 - 0 = 0.
    {
        const zero_vec: PackedM31 = @splat(0);
        const result = subPacked(zero_vec, zero_vec);
        try std.testing.expect(@reduce(.And, result == zero_vec));
    }
    // Test 0 - 1 = P-1 (wrap around).
    {
        const zero_vec: PackedM31 = @splat(0);
        const one_vec: PackedM31 = @splat(1);
        const result = subPacked(zero_vec, one_vec);
        const expected: PackedM31 = @splat(Modulus - 1);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test 0 - (P-1) = 1.
    {
        const zero_vec: PackedM31 = @splat(0);
        const pm1: PackedM31 = @splat(Modulus - 1);
        const result = subPacked(zero_vec, pm1);
        const expected: PackedM31 = @splat(1);
        try std.testing.expect(@reduce(.And, result == expected));
    }
}

test "m31: packed neg edge cases" {
    // neg(0) = 0.
    {
        const zero_vec: PackedM31 = @splat(0);
        const result = negPacked(zero_vec);
        try std.testing.expect(@reduce(.And, result == zero_vec));
    }
    // neg(1) = P-1.
    {
        const one_vec: PackedM31 = @splat(1);
        const result = negPacked(one_vec);
        const expected: PackedM31 = @splat(Modulus - 1);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // neg(P-1) = 1.
    {
        const pm1: PackedM31 = @splat(Modulus - 1);
        const result = negPacked(pm1);
        const expected: PackedM31 = @splat(1);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // a + neg(a) = 0 for random inputs.
    {
        var prng = std.Random.DefaultPrng.init(0xFACE);
        const rng = prng.random();
        var a_arr: [PACK_WIDTH]M31 = undefined;
        for (0..PACK_WIDTH) |i| {
            a_arr[i] = randElem(rng);
        }
        const a = loadPacked(&a_arr);
        const result = addPacked(a, negPacked(a));
        const zero_vec: PackedM31 = @splat(0);
        try std.testing.expect(@reduce(.And, result == zero_vec));
    }
}

test "m31: packed mul matches scalar for random inputs" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const rng = prng.random();
    var a_arr: [PACK_WIDTH]M31 = undefined;
    var b_arr: [PACK_WIDTH]M31 = undefined;
    for (0..PACK_WIDTH) |i| {
        a_arr[i] = randElem(rng);
        b_arr[i] = randElem(rng);
    }
    const a_packed = loadPacked(&a_arr);
    const b_packed = loadPacked(&b_arr);
    const prod = mulPacked(a_packed, b_packed);
    var result: [PACK_WIDTH]M31 = undefined;
    storePacked(&result, prod);
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(result[i].eql(a_arr[i].mul(b_arr[i])));
    }
}

test "m31: packed mul with Modulus-1 values" {
    // (P-1) * (P-1) = 1 in M31 because P-1 = -1 mod P.
    {
        const pm1: PackedM31 = @splat(Modulus - 1);
        const result = mulPacked(pm1, pm1);
        const expected: PackedM31 = @splat(1);
        var result_arr: [PACK_WIDTH]M31 = undefined;
        storePacked(&result_arr, result);
        var expected_arr: [PACK_WIDTH]M31 = undefined;
        storePacked(&expected_arr, expected);
        for (0..PACK_WIDTH) |i| {
            try std.testing.expect(result_arr[i].eql(expected_arr[i]));
        }
    }
    // (P-1) * 1 = P-1.
    {
        const pm1: PackedM31 = @splat(Modulus - 1);
        const one: PackedM31 = @splat(1);
        const result = mulPacked(pm1, one);
        try std.testing.expect(@reduce(.And, result == pm1));
    }
    // a * 0 = 0.
    {
        const pm1: PackedM31 = @splat(Modulus - 1);
        const zero_vec: PackedM31 = @splat(0);
        const result = mulPacked(pm1, zero_vec);
        try std.testing.expect(@reduce(.And, result == zero_vec));
    }
}

test "m31: packed mul with zero values" {
    // 0 * 0 = 0.
    {
        const zero_vec: PackedM31 = @splat(0);
        const result = mulPacked(zero_vec, zero_vec);
        try std.testing.expect(@reduce(.And, result == zero_vec));
    }
    // 0 * random = 0.
    {
        var prng = std.Random.DefaultPrng.init(0xBAADF00D);
        const rng = prng.random();
        var b_arr: [PACK_WIDTH]M31 = undefined;
        for (0..PACK_WIDTH) |i| {
            b_arr[i] = randElem(rng);
        }
        const zero_vec: PackedM31 = @splat(0);
        const b = loadPacked(&b_arr);
        const result = mulPacked(zero_vec, b);
        try std.testing.expect(@reduce(.And, result == zero_vec));
    }
}

test "m31: packed all ops match scalar for many random rounds" {
    var prng = std.Random.DefaultPrng.init(0xCAFEBABE_12345678);
    const rng = prng.random();

    for (0..500) |_| {
        var a_arr: [PACK_WIDTH]M31 = undefined;
        var b_arr: [PACK_WIDTH]M31 = undefined;
        for (0..PACK_WIDTH) |i| {
            a_arr[i] = randElem(rng);
            b_arr[i] = randElem(rng);
        }
        const a = loadPacked(&a_arr);
        const b = loadPacked(&b_arr);

        // add
        {
            var result: [PACK_WIDTH]M31 = undefined;
            storePacked(&result, addPacked(a, b));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(result[i].eql(a_arr[i].add(b_arr[i])));
            }
        }
        // sub
        {
            var result: [PACK_WIDTH]M31 = undefined;
            storePacked(&result, subPacked(a, b));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(result[i].eql(a_arr[i].sub(b_arr[i])));
            }
        }
        // mul
        {
            var result: [PACK_WIDTH]M31 = undefined;
            storePacked(&result, mulPacked(a, b));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(result[i].eql(a_arr[i].mul(b_arr[i])));
            }
        }
        // neg
        {
            var result: [PACK_WIDTH]M31 = undefined;
            storePacked(&result, negPacked(a));
            for (0..PACK_WIDTH) |i| {
                try std.testing.expect(result[i].eql(a_arr[i].neg()));
            }
        }
    }
}

test "m31: packed butterfly matches scalar fft.butterfly" {
    const fft_mod = @import("stwo_core").fft;
    var lhs: [PACK_WIDTH]M31 = undefined;
    var rhs: [PACK_WIDTH]M31 = undefined;
    var lhs_scalar: [PACK_WIDTH]M31 = undefined;
    var rhs_scalar: [PACK_WIDTH]M31 = undefined;
    const twid = M31.fromCanonical(12345);
    var prng = std.Random.DefaultPrng.init(0xCAFE);
    const rng = prng.random();
    for (0..PACK_WIDTH) |i| {
        lhs[i] = randElem(rng);
        rhs[i] = randElem(rng);
        lhs_scalar[i] = lhs[i];
        rhs_scalar[i] = rhs[i];
    }
    // Packed butterfly.
    butterflyPacked(&lhs, &rhs, @as(PackedM31, @splat(twid.v)));
    // Scalar butterfly.
    for (0..PACK_WIDTH) |i| {
        fft_mod.butterfly(M31, &lhs_scalar[i], &rhs_scalar[i], twid);
    }
    // Compare.
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(lhs[i].eql(lhs_scalar[i]));
        try std.testing.expect(rhs[i].eql(rhs_scalar[i]));
    }
}

test "m31: packed ibutterfly matches scalar fft.ibutterfly" {
    const fft_mod = @import("stwo_core").fft;
    var lhs: [PACK_WIDTH]M31 = undefined;
    var rhs: [PACK_WIDTH]M31 = undefined;
    var lhs_scalar: [PACK_WIDTH]M31 = undefined;
    var rhs_scalar: [PACK_WIDTH]M31 = undefined;
    const itwid = M31.fromCanonical(54321);
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    const rng = prng.random();
    for (0..PACK_WIDTH) |i| {
        lhs[i] = randElem(rng);
        rhs[i] = randElem(rng);
        lhs_scalar[i] = lhs[i];
        rhs_scalar[i] = rhs[i];
    }
    // Packed inverse butterfly.
    ibutterflyPacked(&lhs, &rhs, @as(PackedM31, @splat(itwid.v)));
    // Scalar inverse butterfly.
    for (0..PACK_WIDTH) |i| {
        fft_mod.ibutterfly(M31, &lhs_scalar[i], &rhs_scalar[i], itwid);
    }
    // Compare.
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(lhs[i].eql(lhs_scalar[i]));
        try std.testing.expect(rhs[i].eql(rhs_scalar[i]));
    }
}

test "m31: packed butterfly roundtrip (butterfly then ibutterfly)" {
    var lhs: [PACK_WIDTH]M31 = undefined;
    var rhs: [PACK_WIDTH]M31 = undefined;
    const twid = M31.fromCanonical(7);
    const itwid = (M31.fromCanonical(7).inv() catch unreachable);
    var prng = std.Random.DefaultPrng.init(0xF00D);
    const rng = prng.random();
    for (0..PACK_WIDTH) |i| {
        lhs[i] = randElem(rng);
        rhs[i] = randElem(rng);
    }
    const orig_lhs = lhs;
    const orig_rhs = rhs;
    // Forward then inverse butterfly.
    butterflyPacked(&lhs, &rhs, @as(PackedM31, @splat(twid.v)));
    ibutterflyPacked(&lhs, &rhs, @as(PackedM31, @splat(itwid.v)));
    // After roundtrip: lhs = 2*orig_lhs, rhs = 2*orig_rhs.
    for (0..PACK_WIDTH) |i| {
        try std.testing.expect(lhs[i].eql(orig_lhs[i].add(orig_lhs[i])));
        try std.testing.expect(rhs[i].eql(orig_rhs[i].add(orig_rhs[i])));
    }
}

test "m31: SIMD memory contract accepts natural alignment and rejects butterfly aliases" {
    try std.testing.expectEqual(@alignOf(M31), m31.SimdMemoryContract.natural_alignment);
    try std.testing.expectEqual(@as(usize, 0), m31.SimdMemoryContract.caller_scratch_bytes);
    try std.testing.expect(!m31.SimdMemoryContract.vector_byte_alignment_required);
    try std.testing.expect(!m31.SimdMemoryContract.butterfly_aliasing_supported);

    var values: [PACK_WIDTH * 3 + 1]M31 = undefined;
    const base = values[0..].ptr;
    try std.testing.expect(!m31.disjointM31Ranges(base, base, PACK_WIDTH));
    if (PACK_WIDTH > 1) {
        try std.testing.expect(!m31.disjointM31Ranges(base, base + 1, PACK_WIDTH));
    }
    try std.testing.expect(m31.disjointM31Ranges(base, base + PACK_WIDTH, PACK_WIDTH));
    try std.testing.expect(!m31.disjointM31Ranges(base, base + PACK_WIDTH, std.math.maxInt(usize)));
}

test "m31: packed loads and stores support vector-unaligned natural pointers" {
    const allocator = std.testing.allocator;
    const vector_bytes = PACK_WIDTH * @sizeOf(M31);
    const alignment = comptime std.mem.Alignment.fromByteUnits(@max(@alignOf(M31), vector_bytes));
    const offset: usize = if (PACK_WIDTH > 1) 1 else 0;
    const input_storage = try allocator.alignedAlloc(M31, alignment, PACK_WIDTH + offset);
    defer allocator.free(input_storage);
    const output_storage = try allocator.alignedAlloc(M31, alignment, PACK_WIDTH + offset);
    defer allocator.free(output_storage);
    const input = input_storage[offset..];
    const output = output_storage[offset..];

    for (input, 0..) |*value, lane| value.* = M31.fromCanonical(@intCast(17 * lane + 3));
    storePacked(output.ptr, loadPacked(input.ptr));
    try std.testing.expectEqualSlices(M31, input, output);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(input.ptr) % @alignOf(M31));
    if (PACK_WIDTH > 1) {
        try std.testing.expect(@intFromPtr(input.ptr) % vector_bytes != 0);
    }
}
