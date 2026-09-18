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

# Flat leaf multiplication avoids per-field split/join allocation.
def mul_loop(n: Nat, pa: Array<U32> & U32, pb: Array<U32> & U32) -> Array<U32>:
  match n pa pb:
    case 0n Tuple{a, x} Tuple{b, y}:
      a
    case 1n+ +p Tuple{a, x} Tuple{b, y}:
      a = Array.set(U32, a, U32.from_nat(p), M.mul(x, y))
      mul_loop(p, C.read_at(p, a), C.read_at(p, b))

def mul_fork(a: Array<U32>, b: Array<U32>, +size: U32, stop: Bool) -> Array<U32>:
  match a b stop:
    case a b True{}:
      +n = U32.to_nat(size)
      mul_loop(n, C.read_at(n, a), C.read_at(n, b))
    case ANode{al, ar} ANode{bl, br} False{}:
      +half = U32.shr(size)
      +stop = U32.is_le(half, 4096)
      l r = mul_fork(al, bl, half, stop) mul_fork(ar, br, half, stop)
      ANode{l, r}
    case a b False{}:
      a

def mul_start(pair: Array<U32> & U32, b: Array<U32>) -> Array<U32>:
  (a, +size) = pair
  mul_fork(a, b, size, U32.is_le(size, 4096))

def batch_mul(a: Array<U32>, b: Array<U32>) -> Array<U32>:
  mul_start(Array.size(U32, a), b)

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
      C.interpolate(fuel, plan, values, factor)
    case Request{2, fuel, factor, plan, values, inverses, alpha}:
      multiply(values)
    case Request{3, fuel, factor, plan, values, inverses, alpha}:
      I.prefix(values)
    case Request{4, fuel, factor, plan, values, inverses, alpha}:
      F.run(alpha, inverses, values)
    case Request{5, fuel, factor, plan, values, inverses, alpha}:
      C.extension(fuel, plan, values)
    case Request{op, fuel, factor, plan, values, inverses, alpha}:
      values

# A bounded session amortizes process/runtime startup across prover columns.
# The ordinary runner requests one iteration; persistent mode requests 65536.
def iterations() -> IO(Nat):
  import "./transport.c"

def serve(n: Nat) -> IO(Unit):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+p:
      do IO<Unit>:
        req : Request <- read()
        done : Unit <- write(run(req))
        serve(p)

def main() -> IO(Unit):
  do IO<Unit>:
    n : Nat <- iterations()
    serve(n)
