import Base

# All public arithmetic accepts canonical residues 0 <= x < 2^31-1.
# reduce accepts any U32: the folded sum is at most p+1.
def canon(x: U32, ge: Bool) -> U32:
  match ge:
    case True{}:
      (x - 2147483647 : U32)
    case False{}:
      x

def reduce(+x: U32) -> U32:
  +r = (U32.and(x, 2147483647) + U32.shrn(x, 31n) : U32)
  canon(r, U32.is_ge(r, 2147483647))

def add(a: U32, b: U32) -> U32:
  +s = (a + b : U32)
  canon(s, U32.is_ge(s, 2147483647))

def sub(a: U32, b: U32) -> U32:
  +s = (a + (2147483647 - b : U32) : U32)
  canon(s, U32.is_ge(s, 2147483647))

# Rotate a canonical residue left 16 bits in its 31-bit representation.
def shift16(+x: U32) -> U32:
  (U32.shln(U32.and(x, 32767), 16n) + U32.shrn(x, 15n) : U32)

# Each 16x16 product fits U32. Each cross product fits 31 bits;
# add reduces the cross sum before rotation. hi*hi*2 < 2^31.
def mul(+a: U32, +b: U32) -> U32:
  +a0 = U32.and(a, 65535)
  +a1 = U32.shrn(a, 16n)
  +b0 = U32.and(b, 65535)
  +b1 = U32.shrn(b, 16n)
  +p00 = (a0 * b0 : U32)
  +p11 = (a1 * b1 : U32)
  +cross_raw = ((a0 + a1) * (b0 + b1) - p00 - p11 : U32)
  lo = reduce(p00)
  cross = shift16(canon(cross_raw, U32.is_ge(cross_raw, 2147483647)))
  hi = (2 * p11 : U32)
  add(add(lo, cross), hi)
