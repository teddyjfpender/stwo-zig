import Base
import ./m31.bend as M

# Inclusive independent-prefix prototype. This is not a typed interaction
# generator: denominators, tuple projection and claim binding stay in Zig.
type Sums is Type:
  One{x: U32}
  Branch{sum: U32, left_sum: U32, left: Sums, right: Sums}

def merge(left: U32 & Sums, right: U32 & Sums) -> U32 & Sums:
  (+a, l) = left
  (b, r) = right
  +s = M.add(a, b)
  (s, Branch{s, a, l, r})

def up(values: Array<U32>) -> U32 & Sums:
  match values:
    case ALeaf{+x}:
      (x, One{x})
    case ANode{a, b}:
      l r = up(a) up(b)
      merge(l, r)

def down(tree: Sums, +offset: U32) -> Array<U32>:
  match tree:
    case One{x}:
      ALeaf{M.add(offset, x)}
    case Branch{sum, left_sum, left, right}:
      l r = down(left, offset) down(right, M.add(offset, left_sum))
      ANode{l, r}

def finish(pair: U32 & Sums) -> Array<U32>:
  (sum, tree) = pair
  down(tree, 0)

def prefix(values: Array<U32>) -> Array<U32>:
  finish(up(values))
