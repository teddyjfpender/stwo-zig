import Base
import ./m31.bend as M

type Value is Data:
  Q{a: U32, b: U32, c: U32, d: U32}

def add(x: Value, y: Value) -> Value:
  match x y:
    case Q{a,b,c,d} Q{e,f,g,h}:
      Q{M.add(a,e),M.add(b,f),M.add(c,g),M.add(d,h)}

def sub(x: Value, y: Value) -> Value:
  match x y:
    case Q{a,b,c,d} Q{e,f,g,h}:
      Q{M.sub(a,e),M.sub(b,f),M.sub(c,g),M.sub(d,h)}

def scale(x: Value, +w: U32) -> Value:
  match x:
    case Q{a,b,c,d}:
      Q{M.mul(a,w),M.mul(b,w),M.mul(c,w),M.mul(d,w)}

# (a+bi)+(c+di)u, i^2=-1, u^2=2+i, matching core/fields/qm31.zig.
def mul(x: Value, y: Value) -> Value:
  match x y:
    case Q{+a,+b,+c,+d} Q{+e,+f,+g,+h}:
      +r = M.sub(M.mul(c,g), M.mul(d,h))
      +s = M.add(M.mul(c,h), M.mul(d,g))
      Q{
        M.add(M.sub(M.mul(a,e), M.mul(b,f)), M.sub(M.add(r,r),s)),
        M.add(M.add(M.mul(a,f), M.mul(b,e)), M.add(r,M.add(s,s))),
        M.add(M.sub(M.mul(a,g), M.mul(b,h)), M.sub(M.mul(c,e), M.mul(d,f))),
        M.add(M.add(M.mul(a,h), M.mul(b,g)), M.add(M.mul(c,f), M.mul(d,e)))
      }

def array(x: Value) -> Array<U32>:
  match x:
    case Q{a,b,c,d}:
      ANode{ANode{ALeaf{a},ALeaf{b}},ANode{ALeaf{c},ALeaf{d}}}
