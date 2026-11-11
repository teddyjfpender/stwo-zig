#!/usr/bin/env python3
"""Independent integer intervals for twelve signed BYTE-convolution products."""
import json
P=21888242871839275222246405745257275088696311157297823662689037894645226208583
OFFSET=1<<21
p=P.to_bytes(32,'little')
carry_lo=carry_hi=0
rows=[]
for n in range(65):
 pairs=max(0,min(31,n)-max(0,n-31)+1) if n<=62 else 0
 products=12*18*pairs*255*255
 quotient=255*sum(p[j] for j in range(32) if 0<=n-j<33)
 linear=255 if n<32 else 0
 coefficient=products+quotient+linear
 lo=-coefficient+(-OFFSET if n else 0)+( -256*(OFFSET-1) if n<64 else 0)
 hi=coefficient+(OFFSET-1 if n else 0)+(256*OFFSET if n<64 else 0)
 if n<64:
  carry_lo=(-coefficient+carry_lo)//256
  carry_hi=-((-coefficient-carry_hi)//256)
  assert -OFFSET<=carry_lo<=carry_hi<OFFSET
 else: assert coefficient==0
 assert max(abs(lo),abs(hi))<(1<<31)-1
 rows.append({'limb':n,'product_bound':products,'quotient_bound':quotient,'coefficient_abs':coefficient,'residual_min':lo,'residual_max':hi,'valid_witness_carry_min':carry_lo,'valid_witness_carry_max':carry_hi})
qmax=216*P-431
assert qmax.bit_length()<=264
print(json.dumps({'P':P,'products':12,'max_abs_coefficient':18,'input_limbs':32,'quotient_bytes':33,'max_abs_quotient':qmax,'quotient_bits':qmax.bit_length(),'carry_offset':OFFSET,'carry_bits':22,'max_abs_valid_carry':max(max(abs(r['valid_witness_carry_min']),abs(r['valid_witness_carry_max'])) for r in rows),'max_abs_integer_residual':max(max(abs(r['residual_min']),abs(r['residual_max'])) for r in rows),'limbs':rows},indent=2))
