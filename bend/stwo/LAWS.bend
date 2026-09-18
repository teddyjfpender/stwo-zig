import Base
import ./m31.bend as M
import ./butterfly.bend as B

# Frozen boundary laws. These prove the named examples, NOT universal field
# correctness. Random/edge parity is a separate executable admission gate.
law mul_max:
  {M.mul(2147483646, 2147483646) == 1 : U32}
law mul_limb_carry:
  {M.mul(65535, 65535) == 2147352578 : U32}
law add_wrap:
  {M.add(2147483646, 1) == 0 : U32}
law sub_wrap:
  {M.sub(0, 1) == 2147483646 : U32}
law reduce_max_u32:
  {M.reduce(4294967295) == 1 : U32}
law butterfly_reference:
  {B.forward(10, 20, 3) == (70, 2147483597) : U32 & U32}
law inverse_reference:
  {B.inverse(70, 2147483597, 1431655765) == (20, 40) : U32 & U32}
