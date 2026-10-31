//! Variable-time modular inversion on four 64-bit limbs for an odd modulus.
//! Binary extended Euclid with modular accumulators (HAC 14.61 shape). Used
//! only on public ECDSA recovery data: the secp256k1 field inverse behind
//! `to_affine` and the scalar inverse of `r`. Never use with secret inputs.
pub type Limbs = [u64; 4];

#[inline(always)]
fn is_zero(x: &Limbs) -> bool {
    x[0] | x[1] | x[2] | x[3] == 0
}
#[inline(always)]
fn is_one(x: &Limbs) -> bool {
    x[0] == 1 && x[1] | x[2] | x[3] == 0
}
#[inline(always)]
fn shr1(x: &mut Limbs, top: u64) {
    x[0] = (x[0] >> 1) | (x[1] << 63);
    x[1] = (x[1] >> 1) | (x[2] << 63);
    x[2] = (x[2] >> 1) | (x[3] << 63);
    x[3] = (x[3] >> 1) | (top << 63);
}
#[inline(always)]
fn geq(a: &Limbs, b: &Limbs) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}
/// a -= b, returning the borrow.
#[inline(always)]
fn sub_assign(a: &mut Limbs, b: &Limbs) -> bool {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        a[i] = d;
        borrow = (b1 | b2) as u64;
    }
    borrow != 0
}
/// a += b, returning the carry.
#[inline(always)]
fn add_assign(a: &mut Limbs, b: &Limbs) -> u64 {
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        a[i] = s;
        carry = (c1 | c2) as u64;
    }
    carry
}
/// x = x / 2 mod m for odd m, with x < m.
#[inline(always)]
fn half_mod(x: &mut Limbs, m: &Limbs) {
    if x[0] & 1 == 0 {
        shr1(x, 0);
    } else {
        let carry = add_assign(x, m);
        shr1(x, carry);
    }
}
/// a = a - b mod m with a, b < m.
#[inline(always)]
fn sub_mod(a: &mut Limbs, b: &Limbs, m: &Limbs) {
    if sub_assign(a, b) {
        add_assign(a, m);
    }
}

/// Inverse of `a` modulo the odd `m`, for canonical `a < m`. Returns `None`
/// for zero. Loops are data dependent by design.
pub fn inv_mod_vartime(a: Limbs, m: Limbs) -> Option<Limbs> {
    if is_zero(&a) {
        return None;
    }
    let (mut u, mut v) = (a, m);
    let mut x1: Limbs = [1, 0, 0, 0];
    let mut x2: Limbs = [0; 4];
    while !is_one(&u) && !is_one(&v) {
        while u[0] & 1 == 0 {
            shr1(&mut u, 0);
            half_mod(&mut x1, &m);
        }
        while v[0] & 1 == 0 {
            shr1(&mut v, 0);
            half_mod(&mut x2, &m);
        }
        if geq(&u, &v) {
            sub_assign(&mut u, &v);
            sub_mod(&mut x1, &x2, &m);
        } else {
            sub_assign(&mut v, &u);
            sub_mod(&mut x2, &x1, &m);
        }
    }
    Some(if is_one(&u) { x1 } else { x2 })
}
