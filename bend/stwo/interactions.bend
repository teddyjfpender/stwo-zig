import Base
import ./m31.bend as M

# Inclusive independent-prefix prototype, not a typed interaction generator.
# Scan bounded flat chunks; only chunk totals enter the parallel prefix tree.
type Sums is Type:
  Chunk{values: Array<U32>}
  Branch{left_sum: U32, left: Sums, right: Sums}

def next(n: Nat, i: U32, a: Array<U32>) -> Array<U32> & U32:
  match n:
    case 0n:
      (a, 0)
    case 1n+p:
      Array.get(U32, a, i)

def scan(n: Nat, +i: U32, acc: U32, pair: Array<U32> & U32) -> U32 & Sums:
  match n pair:
    case 0n Tuple{a, x}:
      (acc, Chunk{a})
    case 1n+ +p Tuple{a, x}:
      +sum = M.add(acc, x)
      a = Array.set(U32, a, i, sum)
      +j = (i + 1 : U32)
      scan(p, j, sum, next(p, j, a))

def merge(left: U32 & Sums, right: U32 & Sums) -> U32 & Sums:
  (+a, l) = left
  (b, r) = right
  (M.add(a, b), Branch{a, l, r})

def up(values: Array<U32>, +size: U32, stop: Bool) -> U32 & Sums:
  match values stop:
    case values True{}:
      scan(U32.to_nat(size), 0, 0, Array.get(U32, values, 0))
    case ANode{a, b} False{}:
      +half = U32.shr(size)
      +stop = U32.is_le(half, 4096)
      l r = up(a, half, stop) up(b, half, stop)
      merge(l, r)
    case values False{}:
      (0, Chunk{values})

def read_at(n: Nat, a: Array<U32>) -> Array<U32> & U32:
  match n:
    case 0n:
      (a, 0)
    case 1n+p:
      Array.get(U32, a, U32.from_nat(p))

def offset_loop(n: Nat, +offset: U32, pair: Array<U32> & U32) -> Array<U32>:
  match n pair:
    case 0n Tuple{a, x}:
      a
    case 1n+ +p Tuple{a, x}:
      a = Array.set(U32, a, U32.from_nat(p), M.add(x, offset))
      offset_loop(p, offset, read_at(p, a))

def offset_start(pair: Array<U32> & U32, offset: U32) -> Array<U32>:
  (a, size) = pair
  +n = U32.to_nat(size)
  offset_loop(n, offset, read_at(n, a))

def down(tree: Sums, +offset: U32) -> Array<U32>:
  match tree:
    case Chunk{values}:
      offset_start(Array.size(U32, values), offset)
    case Branch{left_sum, left, right}:
      l r = down(left, offset) down(right, M.add(offset, left_sum))
      ANode{l, r}

def finish(pair: U32 & Sums) -> Array<U32>:
  (sum, tree) = pair
  down(tree, 0)

def prefix_start(pair: Array<U32> & U32) -> Array<U32>:
  (values, +size) = pair
  finish(up(values, size, U32.is_le(size, 4096)))

def prefix(values: Array<U32>) -> Array<U32>:
  prefix_start(Array.size(U32, values))
