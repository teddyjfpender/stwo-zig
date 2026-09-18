import Base
import ./m31.bend as M
import ./butterfly.bend as B

# Twiddles are prepared by the Zig oracle in the exact Circle-domain order.
# This is a Circle FFT, including its special final y/-y/-x/x layer.
type Plan is Data:
  Tip{w: U32}
  Fork{w: U32, left: Plan, right: Plan}

# Helpers destructure function parameters (Bend forbids computed scrutinees).
def leaves(pair: U32 & U32) -> Array<U32> & Array<U32>:
  (s, d) = pair
  (ALeaf{s}, ALeaf{d})

def join_pairs(l: Array<U32> & Array<U32>, r: Array<U32> & Array<U32>) ->
  Array<U32> & Array<U32>:
  (sl, dl) = l
  (sr, dr) = r
  (ANode{sl, sr}, ANode{dl, dr})

def join(pair: Array<U32> & Array<U32>) -> Array<U32>:
  (s, d) = pair
  ANode{s, d}

# Zip butterfly pairs over equal-sized halves with balanced parallel calls.
# Only validated full trees enter the process boundary.
def zip_forward(a: Array<U32>, b: Array<U32>, +w: U32) -> Array<U32> & Array<U32>:
  match a b:
    case ALeaf{x} ALeaf{y}:
      leaves(B.forward(x, y, w))
    case ANode{al, ar} ANode{bl, br}:
      l r = zip_forward(al, bl, w) zip_forward(ar, br, w)
      join_pairs(l, r)
    case a b:
      (a, b)

def zip_inverse(a: Array<U32>, b: Array<U32>, +w: U32) -> Array<U32> & Array<U32>:
  match a b:
    case ALeaf{x} ALeaf{y}:
      leaves(B.inverse(x, y, w))
    case ANode{al, ar} ANode{bl, br}:
      l r = zip_inverse(al, bl, w) zip_inverse(ar, br, w)
      join_pairs(l, r)
    case a b:
      (a, b)

# Two phases per level: butterfly, then independent child transforms.
# Fuel = 2*log_size makes the decreasing recursion explicit to the checker.
def forward(fuel: Nat, phase: Bool, plan: Plan, values: Array<U32>) -> Array<U32>:
  match fuel phase plan values:
    case 0n phase plan values:
      values
    case 1n+p True{} Tip{w} ANode{a, b}:
      join(zip_forward(a, b, w))
    case 1n+p True{} Fork{w, pl, pr} ANode{a, b}:
      forward(p, False{}, Fork{0, pl, pr}, join(zip_forward(a, b, w)))
    case 1n+ +p False{} Fork{w, pl, pr} ANode{a, b}:
      l r = forward(p, True{}, pl, a) forward(p, True{}, pr, b)
      ANode{l, r}
    case 1n+p phase plan values:
      values

def inverse(plan: Plan, values: Array<U32>) -> Array<U32>:
  match plan values:
    case Tip{w} ANode{a, b}:
      join(zip_inverse(a, b, w))
    case Fork{w, pl, pr} ANode{a, b}:
      l r = inverse(pl, a) inverse(pr, b)
      join(zip_inverse(l, r, w))
    case plan values:
      values

def scale(values: Array<U32>, +factor: U32) -> Array<U32>:
  match values:
    case ALeaf{x}:
      ALeaf{M.mul(x, factor)}
    case ANode{a, b}:
      l r = scale(a, factor) scale(b, factor)
      ANode{l, r}

def interpolate(plan: Plan, values: Array<U32>, factor: U32) -> Array<U32>:
  scale(inverse(plan, values), factor)
