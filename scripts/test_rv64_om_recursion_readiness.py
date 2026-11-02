"""Focused framing/count-law gates; no proof acceptance is implemented here."""
import struct
import unittest
import rv64_om_recursion_readiness as C

def integer(n):
    return struct.pack('<I', n)

def child(height=1, length=4):
    out = b'RV64LGKO'+integer(8)+integer(1)+integer(height)+bytes(64)+integer(height)
    for layer in range(height):
        out += integer(layer)
        for _ in range(layer):
            out += integer(length)+bytes(32*length)
    return out+bytes(128*height)

def stage(raw):
    return b'RV64MGK1'+bytes(32)+integer(1)+integer(0)+bytes(32)+integer(1)+bytes(32)+integer(len(raw))+raw

class CostGate(unittest.TestCase):
    def test_single_layer_literal_kernel_and_hash_framing(self):
        h,c = C.parse_child(child())
        self.assertEqual(([1],[[]]), (h,c))
        n = C.numerical_cost(h,c)
        self.assertEqual((13,9,2,1,3,8,640), tuple(n[k] for k in
            ['om31_mul','om31_add','om31_sub','equality_checks','secure_draws','blake_compressions','blake_G_calls']))
        self.assertEqual(4,n['closure']['om31_mul'])
    def test_exact_short_polynomial_length_changes_transcript_cost(self):
        long = C.numerical_cost(*C.parse_child(child(2,4)))
        short = C.numerical_cost(*C.parse_child(child(2,0)))
        self.assertEqual(12,long['om31_mul']-short['om31_mul'])
        self.assertEqual(12,long['om31_add']-short['om31_add'])
        self.assertEqual(2,long['blake_compressions']-short['blake_compressions'])
    def test_every_coordinate_canonical(self):
        for coordinate in range(8):
            raw = bytearray(child())
            raw[20+coordinate*4:24+coordinate*4] = integer(C.P)
            with self.assertRaises(C.Invalid): C.parse_child(raw)
    def test_complete_manifest_order_kind_and_framing(self):
        raw = stage(child())
        self.assertEqual(1,len(C.manifest(raw,1,0)))
        for offset,value in [(44,1),(80,0)]:
            bad = bytearray(raw);bad[offset:offset+4]=integer(value)
            with self.assertRaises(C.Invalid): C.manifest(bad,1,0)
        with self.assertRaises(C.Invalid): C.manifest(raw,0,1)
        for length in [0,7,43,83,len(raw)-1]:
            with self.assertRaises(C.Invalid): C.manifest(raw[:length],1,0)
        with self.assertRaises(C.Invalid): C.manifest(raw+b'X',1,0)
    def test_child_bounds_topology_and_trailing(self):
        raw = child(2)
        for bad in [raw[:-1],raw+b'X',b'WRONG'+raw[5:]]:
            with self.assertRaises(C.Invalid): C.parse_child(bad)
        bad=bytearray(raw);bad[84:88]=integer(1)
        with self.assertRaises(C.Invalid): C.parse_child(bad)

if __name__ == '__main__': unittest.main()
