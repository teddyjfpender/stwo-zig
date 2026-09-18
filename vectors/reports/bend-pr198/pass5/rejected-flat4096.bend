import Base
import ./m31.bend as M

# Twiddles are prepared by the Zig oracle in the exact Circle-domain order.
# This is a Circle FFT, including its special final y/-y/-x/x layer.
type Plan is Type:
  Block{depth: Nat, twiddles: Array<U32>}
  Fork{w: U32, left: Plan, right: Plan}

# Helpers destructure function parameters (Bend forbids computed scrutinees).
def join_pairs(l: Array<U32> & Array<U32>, r: Array<U32> & Array<U32>) ->
  Array<U32> & Array<U32>:
  (sl, dl) = l
  (sr, dr) = r
  (ANode{sl, sr}, ANode{dl, dr})

def join(pair: Array<U32> & Array<U32>) -> Array<U32>:
  (s, d) = pair
  ANode{s, d}

# Bounded, in-place leaf work. Array.get/set compile to flat-buffer accesses.
def read_at(n: Nat, a: Array<U32>) -> Array<U32> & U32:
  match n:
    case 0n:
      (a, 0)
    case 1n+p:
      Array.get(U32, a, U32.from_nat(p))

def zip_loop(n: Nat, +w: U32, pa: Array<U32> & U32, pb: Array<U32> & U32) -> Array<U32> & Array<U32>:
  match n pa pb:
    case 0n Tuple{a, x} Tuple{b, y}:
      (a, b)
    case 1n+ +p Tuple{a, +x} Tuple{b, y}:
      +t = M.mul(y, w)
      a = Array.set(U32, a, U32.from_nat(p), M.add(x, t))
      b = Array.set(U32, b, U32.from_nat(p), M.sub(x, t))
      zip_loop(p, w, read_at(p, a), read_at(p, b))

def zip_forward_fork(a: Array<U32>, b: Array<U32>, +w: U32, +size: U32, stop: Bool) -> Array<U32> & Array<U32>:
  match a b stop:
    case a b True{}:
      +count = U32.to_nat(size)
      zip_loop(count, w, read_at(count, a), read_at(count, b))
    case ANode{al, ar} ANode{bl, br} False{}:
      +half = U32.shr(size)
      +stop = U32.is_le(half, 1024)
      l r = zip_forward_fork(al, bl, w, half, stop) zip_forward_fork(ar, br, w, half, stop)
      join_pairs(l, r)
    case a b False{}:
      (a, b)

def zip_forward_start(pair: Array<U32> & U32, b: Array<U32>, w: U32) -> Array<U32> & Array<U32>:
  (a, +size) = pair
  zip_forward_fork(a, b, w, size, U32.is_le(size, 1024))

def zip_forward(a: Array<U32>, b: Array<U32>, w: U32) -> Array<U32> & Array<U32>:
  zip_forward_start(Array.size(U32, a), b, w)

def izip_loop(n: Nat, +w: U32, pa: Array<U32> & U32, pb: Array<U32> & U32) -> Array<U32> & Array<U32>:
  match n pa pb:
    case 0n Tuple{a, x} Tuple{b, +y}:
      (a, b)
    case 1n+ +p Tuple{a, +x} Tuple{b, +y}:
      a = Array.set(U32, a, U32.from_nat(p), M.add(x, y))
      b = Array.set(U32, b, U32.from_nat(p), M.mul(M.sub(x, y), w))
      izip_loop(p, w, read_at(p, a), read_at(p, b))

def zip_inverse_fork(a: Array<U32>, b: Array<U32>, +w: U32, +size: U32, stop: Bool) -> Array<U32> & Array<U32>:
  match a b stop:
    case a b True{}:
      +count = U32.to_nat(size)
      izip_loop(count, w, read_at(count, a), read_at(count, b))
    case ANode{al, ar} ANode{bl, br} False{}:
      +half = U32.shr(size)
      +stop = U32.is_le(half, 1024)
      l r = zip_inverse_fork(al, bl, w, half, stop) zip_inverse_fork(ar, br, w, half, stop)
      join_pairs(l, r)
    case a b False{}:
      (a, b)

def zip_inverse_start(pair: Array<U32> & U32, b: Array<U32>, w: U32) -> Array<U32> & Array<U32>:
  (a, +size) = pair
  zip_inverse_fork(a, b, w, size, U32.is_le(size, 1024))

def zip_inverse(a: Array<U32>, b: Array<U32>, w: U32) -> Array<U32> & Array<U32>:
  zip_inverse_start(Array.size(U32, a), b, w)

# Work inside a leaf block never splits its array or schedules tiny tasks.
def write_pair(inverse: Bool, +i: U32, +j: U32, +w: U32, +x: U32, pair: Array<U32> & U32) -> Array<U32>:
  match inverse pair:
    case False{} Tuple{a, y}:
      +t = M.mul(y, w)
      a = Array.set(U32, a, i, M.add(x, t))
      Array.set(U32, a, j, M.sub(x, t))
    case True{} Tuple{a, +y}:
      a = Array.set(U32, a, i, M.add(x, y))
      Array.set(U32, a, j, M.mul(M.sub(x, y), w))

def read_pair(inverse: Bool, i: U32, +j: U32, w: U32, pair: Array<U32> & U32) -> Array<U32>:
  (a, x) = pair
  write_pair(inverse, i, j, w, x, Array.get(U32, a, j))

def local_layer(n: Nat, +inverse: Bool, +offset: U32, +half: U32, +w: U32, a: Array<U32>) -> Array<U32>:
  match n:
    case 0n:
      a
    case 1n+ +p:
      +i = (offset + U32.from_nat(p) : U32)
      a = read_pair(inverse, i, (i + half : U32), w, Array.get(U32, a, i))
      local_layer(p, inverse, offset, half, w, a)

# Flat leaf stages use heap-indexed twiddles. No per-butterfly Plan allocation.
def plan_read(n: Nat, +groups: U32, t: Array<U32>) -> Array<U32> & U32:
  match n:
    case 0n:
      (t, 0)
    case 1n+p:
      Array.get(U32, t, (groups + U32.from_nat(p) : U32))

def flat_groups(n: Nat, +inverse: Bool, +groups: U32, +half: U32, pt: Array<U32> & U32, a: Array<U32>) -> Array<U32> & Array<U32>:
  match n pt:
    case 0n Tuple{t, w}:
      (t, a)
    case 1n+ +p Tuple{t, w}:
      +offset = (2 * half * U32.from_nat(p) : U32)
      a = local_layer(U32.to_nat(half), inverse, offset, half, w, a)
      flat_groups(p, inverse, groups, half, plan_read(p, groups, t), a)

def flat_stages(n: Nat, +inverse: Bool, +groups: U32, +half: U32, pair: Array<U32> & Array<U32>) -> Array<U32>:
  match n inverse pair:
    case 0n inverse Tuple{t, a}:
      a
    case 1n+p False{} Tuple{t, a}:
      flat_stages(p, False{}, (groups * 2 : U32), U32.shr(half), flat_groups(U32.to_nat(groups), False{}, groups, half, plan_read(U32.to_nat(groups), groups, t), a))
    case 1n+p True{} Tuple{t, a}:
      flat_stages(p, True{}, U32.shr(groups), (half * 2 : U32), flat_groups(U32.to_nat(groups), True{}, groups, half, plan_read(U32.to_nat(groups), groups, t), a))

def local_forward_start(plan: Plan, pair: Array<U32> & U32) -> Array<U32>:
  match plan pair:
    case Block{depth, t} Tuple{a, size}:
      flat_stages(depth, False{}, 1, U32.shr(size), (t, a))
    case plan Tuple{a, size}:
      a

def local_inverse_start(plan: Plan, pair: Array<U32> & U32) -> Array<U32>:
  match plan pair:
    case Block{depth, t} Tuple{a, size}:
      flat_stages(depth, True{}, U32.shr(size), 1, (t, a))
    case plan Tuple{a, size}:
      a

# Only subtransforms larger than 4096 values enter the fork/join scheduler.
def forward_go(fuel: Nat, stop: Bool, phase: Bool, plan: Plan, values: Array<U32>) -> Array<U32>:
  match fuel stop phase plan values:
    case fuel True{} phase plan values:
      local_forward_start(plan, Array.size(U32, values))
    case 0n False{} phase plan values:
      values
    case 1n+p False{} True{} Fork{w, pl, pr} ANode{a, b}:
      forward_go(p, False{}, False{}, Fork{0, pl, pr}, join(zip_forward(a, b, w)))
    case 1n+ +p False{} False{} Fork{w, pl, pr} ANode{a, b}:
      +stop = Nat.is_le(p, 24n)
      l r = forward_go(p, stop, True{}, pl, a) forward_go(p, stop, True{}, pr, b)
      ANode{l, r}
    case 1n+p False{} phase plan values:
      values

def forward(+fuel: Nat, phase: Bool, plan: Plan, values: Array<U32>) -> Array<U32>:
  forward_go(fuel, Nat.is_le(fuel, 24n), phase, plan, values)

def inverse_go(depth: Nat, stop: Bool, plan: Plan, values: Array<U32>) -> Array<U32>:
  match depth stop plan values:
    case depth True{} plan values:
      local_inverse_start(plan, Array.size(U32, values))
    case 1n+ +p False{} Fork{w, pl, pr} ANode{a, b}:
      +stop = Nat.is_le(p, 12n)
      l r = inverse_go(p, stop, pl, a) inverse_go(p, stop, pr, b)
      join(zip_inverse(l, r, w))
    case depth False{} plan values:
      values

def inverse_start(+depth: Nat, plan: Plan, values: Array<U32>) -> Array<U32>:
  inverse_go(depth, Nat.is_le(depth, 12n), plan, values)

def inverse(depth: Nat, plan: Plan, values: Array<U32>) -> Array<U32>:
  inverse_start(depth, plan, values)

# Normalize in bounded flat chunks, avoiding one task/allocation per element.
def scale_loop(n: Nat, +factor: U32, pair: Array<U32> & U32) -> Array<U32>:
  match n pair:
    case 0n Tuple{a, x}:
      a
    case 1n+ +p Tuple{a, x}:
      a = Array.set(U32, a, U32.from_nat(p), M.mul(x, factor))
      scale_loop(p, factor, read_at(p, a))

def scale_fork(values: Array<U32>, +size: U32, stop: Bool, +factor: U32) -> Array<U32>:
  match values stop:
    case values True{}:
      +n = U32.to_nat(size)
      scale_loop(n, factor, read_at(n, values))
    case ANode{a, b} False{}:
      +half = U32.shr(size)
      +stop = U32.is_le(half, 4096)
      l r = scale_fork(a, half, stop, factor) scale_fork(b, half, stop, factor)
      ANode{l, r}
    case values False{}:
      values

def scale_start(pair: Array<U32> & U32, factor: U32) -> Array<U32>:
  (values, +size) = pair
  scale_fork(values, size, U32.is_le(size, 4096), factor)

def scale(values: Array<U32>, factor: U32) -> Array<U32>:
  scale_start(Array.size(U32, values), factor)

def interpolate(fuel: Nat, plan: Plan, values: Array<U32>, factor: U32) -> Array<U32>:
  scale(inverse(U32.to_nat(U32.shr(U32.from_nat(fuel))), plan, values), factor)

# Exact 2x LDE has a zero upper coefficient half. Its first butterfly layer
# produces two copies of the lower half, so no twiddle multiplication is needed.
def extension_apply(fuel: Nat, plan: Plan, pair: Array<U32> & Array<U32>) -> Array<U32>:
  match fuel plan pair:
    case 2n+ +p Fork{w, pl, pr} Tuple{a, b}:
      l r = forward(p, True{}, pl, a) forward(p, True{}, pr, b)
      ANode{l, r}
    case fuel plan Tuple{a, b}:
      ANode{a, b}

def extension(fuel: Nat, plan: Plan, values: Array<U32>) -> Array<U32>:
  match plan values:
    case Fork{w, pl, pr} ANode{a, b}:
      extension_apply(fuel, Fork{w, pl, pr}, Array.clone(U32, a))
    case plan values:
      forward(fuel, True{}, plan, values)
