import Base
import ./m31.bend as M

def forward(+a: U32, b: U32, w: U32) -> U32 & U32:
  +t = M.mul(b, w)
  (M.add(a, t), M.sub(a, t))

def inverse(+a: U32, +b: U32, iw: U32) -> U32 & U32:
  (M.add(a, b), M.mul(M.sub(a, b), iw))
