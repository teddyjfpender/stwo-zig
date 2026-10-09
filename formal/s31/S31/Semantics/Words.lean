import S31.Semantics.Types

namespace S31.Words

/-- Little-endian radix encoding, with mathematical rather than machine integers. -/
def decode (base : Nat) : List Nat → Nat
  | [] => 0
  | x :: xs => x + base * decode base xs

def encode (base : Nat) : Nat → Nat → List Nat
  | 0, _ => []
  | n + 1, x => x % base :: encode base n (x / base)

abbrev Word := BitVec 32
def word (n : Nat) : Word := BitVec.ofNat 32 n

def bytesLE (n : Nat) (x : Nat) : List Nat := encode 256 n x
def bytesBE (n : Nat) (x : Nat) : List Nat := (bytesLE n x).reverse
def wordsBytes (bytesPerWord : Nat) (xs : List Nat) : List Nat :=
  xs.flatMap (bytesLE bytesPerWord)

def readLE (xs : List Nat) (offset count : Nat) : Nat :=
  decode 256 ((xs.drop offset).take count)
def readBE (xs : List Nat) (offset count : Nat) : Nat :=
  decode 256 (((xs.drop offset).take count).reverse)

def rotr (x : Word) (n : Nat) : Word :=
  x.rotateRight n

def m31Words (xs : List Nat) : List M31 :=
  xs.map RiscvRefinement.M31.reduce

theorem decode_nil (base : Nat) : decode base [] = 0 := rfl
theorem decode_cons (base x : Nat) (xs : List Nat) :
    decode base (x :: xs) = x + base * decode base xs := rfl
theorem encode_length (base n x : Nat) : (encode base n x).length = n := by
  induction n generalizing x with
  | zero => rfl
  | succ n ih => simp [encode, ih]

end S31.Words
