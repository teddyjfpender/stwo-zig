import TensorFrontend
open TensorFrontend.Security TensorFrontend.Data

/-- Executable cross-check: recompute the totals from the term list and print
them next to the integer bits the kernel checked. -/
def main : IO Unit := do
  IO.println s!"toy20 johnson: sum_with_work (float) = {floatBits toy20JohnsonWith 200}, best integer bits (exact) = {bestBits toy20JohnsonWith 200 128}"
  IO.println s!"toy20 johnson: sum_without_work (float) = {floatBits toy20JohnsonWithout 200}, best integer bits (exact) = {bestBits toy20JohnsonWithout 200 128}"
