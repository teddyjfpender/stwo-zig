import Base
import ./circle_fft.bend as C
import ./m31.bend as M
import ./interactions.bend as I
import ./fri.bend as F

type Request is Type:
  Request{op: U32, fuel: Nat, factor: U32, plan: C.Plan, values: Array<U32>, inverses: Array<U32>, alpha: Array<U32>}

def read() -> IO(Request):
  import "./transport.c"

def write(values: Array<U32>) -> IO(Unit):
  import "./transport.c"

def batch_mul(a: Array<U32>, b: Array<U32>) -> Array<U32>:
  match a b:
    case ALeaf{x} ALeaf{y}:
      ALeaf{M.mul(x, y)}
    case ANode{al, ar} ANode{bl, br}:
      l r = batch_mul(al, bl) batch_mul(ar, br)
      ANode{l, r}
    case a b:
      a

def multiply(values: Array<U32>) -> Array<U32>:
  match values:
    case ANode{a, b}:
      batch_mul(a, b)
    case ALeaf{x}:
      ALeaf{x}

def run(req: Request) -> Array<U32>:
  match req:
    case Request{0, fuel, factor, plan, values, inverses, alpha}:
      C.forward(fuel, True{}, plan, values)
    case Request{1, fuel, factor, plan, values, inverses, alpha}:
      C.interpolate(plan, values, factor)
    case Request{2, fuel, factor, plan, values, inverses, alpha}:
      multiply(values)
    case Request{3, fuel, factor, plan, values, inverses, alpha}:
      I.prefix(values)
    case Request{4, fuel, factor, plan, values, inverses, alpha}:
      F.run(alpha, inverses, values)
    case Request{op, fuel, factor, plan, values, inverses, alpha}:
      values

def main() -> IO(Unit):
  do IO<Unit>:
    req : Request <- read()
    write(run(req))
