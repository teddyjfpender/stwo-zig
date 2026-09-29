import Base
import ./qm31.bend as Q

# Both circle-to-line and line-to-line use this primitive, with inverse y or
# inverse x respectively. Domain generation and multi-fold alpha squaring
# remain host-side; no normalization by 2 is introduced.
def pair(+a: Q.Value, +b: Q.Value, inv: U32, alpha: Q.Value) -> Array<U32>:
  Q.array(Q.add(Q.add(a,b), Q.mul(alpha, Q.scale(Q.sub(a,b),inv))))

def fold(inverses: Array<U32>, values: Array<U32>, +alpha: Q.Value) -> Array<U32>:
  match inverses values:
    case ALeaf{inv} ANode{ANode{ANode{ALeaf{a},ALeaf{b}},ANode{ALeaf{c},ALeaf{d}}},ANode{ANode{ALeaf{e},ALeaf{f}},ANode{ALeaf{g},ALeaf{h}}}}:
      pair(Q.Q{a,b,c,d}, Q.Q{e,f,g,h}, inv, alpha)
    case ANode{il,ir} ANode{l,r}:
      a b = fold(il,l,alpha) fold(ir,r,alpha)
      ANode{a,b}
    case inverses values:
      values

def run(alpha: Array<U32>, inverses: Array<U32>, values: Array<U32>) -> Array<U32>:
  match alpha:
    case ANode{ANode{ALeaf{a},ALeaf{b}},ANode{ALeaf{c},ALeaf{d}}}:
      fold(inverses,values,Q.Q{a,b,c,d})
    case alpha:
      values
