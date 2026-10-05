// Circuit hashes pinned by vectors/circuit/official/registries/production.json.
// Changing the production registry requires recompiling this program and
// qualifying its program hash against the new circuit registry.
from starkware.cairo.common.math import assert_nn_le
from circuit_tree import CircuitUnpackerConfig

func assert_production_registry{range_check_ptr}(config: CircuitUnpackerConfig*) {
    assert config.n_supported_circuit_hashes = 6;
    assert config.supported_circuit_hashes[0] = 0x41aa3c1f;
    assert config.supported_circuit_hashes[1] = 0x626986f7;
    assert config.supported_circuit_hashes[2] = 0xce55cb4c;
    assert config.supported_circuit_hashes[3] = 0x896e58b2;
    assert config.supported_circuit_hashes[4] = 0xaac047ff;
    assert config.supported_circuit_hashes[5] = 0x4431c724;
    assert config.supported_circuit_hashes[6] = 0x1e0d9ef2;
    assert config.supported_circuit_hashes[7] = 0x2bcafcd9;
    assert config.supported_circuit_hashes[8] = 0x9655a6ee;
    assert config.supported_circuit_hashes[9] = 0xce0c61eb;
    assert config.supported_circuit_hashes[10] = 0xbbd3e031;
    assert config.supported_circuit_hashes[11] = 0x245350b0;
    assert config.supported_circuit_hashes[12] = 0xe9e21745;
    assert config.supported_circuit_hashes[13] = 0x51c1fa7a;
    assert config.supported_circuit_hashes[14] = 0xbc39dd60;
    assert config.supported_circuit_hashes[15] = 0xfcb4a8ea;
    assert config.supported_circuit_hashes[16] = 0xb79ed666;
    assert config.supported_circuit_hashes[17] = 0x83a16d7e;
    assert config.supported_circuit_hashes[18] = 0xbd6b405e;
    assert config.supported_circuit_hashes[19] = 0xbd6844f3;
    assert config.supported_circuit_hashes[20] = 0x0997020a;
    assert config.supported_circuit_hashes[21] = 0x67c86ca7;
    assert config.supported_circuit_hashes[22] = 0x1e06b2fb;
    assert config.supported_circuit_hashes[23] = 0x72b8e087;
    assert config.supported_circuit_hashes[24] = 0xaad3c943;
    assert config.supported_circuit_hashes[25] = 0xacca5fde;
    assert config.supported_circuit_hashes[26] = 0xc5af89d4;
    assert config.supported_circuit_hashes[27] = 0x92f51b51;
    assert config.supported_circuit_hashes[28] = 0x12735c66;
    assert config.supported_circuit_hashes[29] = 0x5408ab1c;
    assert config.supported_circuit_hashes[30] = 0x397cd1d7;
    assert config.supported_circuit_hashes[31] = 0x0e2e0eb0;
    assert config.supported_circuit_hashes[32] = 0x563d1cef;
    assert config.supported_circuit_hashes[33] = 0x9e543e32;
    assert config.supported_circuit_hashes[34] = 0x92ad7435;
    assert config.supported_circuit_hashes[35] = 0xb49a1989;
    assert config.supported_circuit_hashes[36] = 0xa42c4367;
    assert config.supported_circuit_hashes[37] = 0x28150b87;
    assert config.supported_circuit_hashes[38] = 0x2f0fae62;
    assert config.supported_circuit_hashes[39] = 0x77f5de17;
    assert config.supported_circuit_hashes[40] = 0xa5989715;
    assert config.supported_circuit_hashes[41] = 0x2377c07a;
    assert config.supported_circuit_hashes[42] = 0xc6d1e844;
    assert config.supported_circuit_hashes[43] = 0x54f0a04d;
    assert config.supported_circuit_hashes[44] = 0x8be65a7d;
    assert config.supported_circuit_hashes[45] = 0xfd73c261;
    assert config.supported_circuit_hashes[46] = 0x9078e728;
    assert config.supported_circuit_hashes[47] = 0x973f680f;
    return ();
}
