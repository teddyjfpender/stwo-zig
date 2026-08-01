%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod

from starkware.cairo.common.cairo_keccak.keccak import cairo_keccak, finalize_keccak
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

// Exact CSP adaptation of zksecurity/zkvm-benchmarks stwo/sha3.
//
// The 2 KiB logical input is embedded as 256 little-endian u64 words below.
// This removes host-input hints from the statement: the compiled program hash
// binds every message byte.  The output builtin exposes the low then high
// 128-bit limbs of the raw Keccak-256 digest.  Serializing each limb as 16
// little-endian bytes reconstructs the canonical raw digest.  finalize_keccak
// remains mandatory so the hinted permutations are constrained by the AIR.
func main{
    output_ptr,
    pedersen_ptr,
    range_check_ptr,
    ecdsa_ptr,
    bitwise_ptr: BitwiseBuiltin*,
    ec_op_ptr,
    keccak_ptr,
    poseidon_ptr,
    range_check96_ptr,
    add_mod_ptr,
    mul_mod_ptr,
}() {
    alloc_locals;

    let (local hash_ptr: felt*) = alloc();
    let keccak_ptr_start = hash_ptr;

    let (inputs: felt*) = alloc();
    fill_exact_csp_input(input=inputs);

    let res = cairo_keccak{keccak_ptr=hash_ptr}(inputs=inputs, n_bytes=2048);
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=hash_ptr);

    assert [output_ptr] = res.low;
    assert [output_ptr + 1] = res.high;
    let output_ptr = output_ptr + 2;

    return ();
}

func fill_exact_csp_input(input: felt*) {
    assert input[0] = 0x25d7550589bfe811;
    assert input[1] = 0xa8d57a44b8bb0526;
    assert input[2] = 0x0f0f697219c7519f;
    assert input[3] = 0xe48c2576b32c756b;
    assert input[4] = 0xa359f3010453f758;
    assert input[5] = 0x51f7cd53b76b3364;
    assert input[6] = 0x375240b87f98ce3d;
    assert input[7] = 0xa3cad5584d134eef;
    assert input[8] = 0xf86afa9e1d522ae1;
    assert input[9] = 0x5b3a8ec0ebbd3b23;
    assert input[10] = 0xf2deb4006185b914;
    assert input[11] = 0xf63c189beb977418;
    assert input[12] = 0x98aa1fff377f1ad2;
    assert input[13] = 0xd4407bc8372097c4;
    assert input[14] = 0x525c891b8cef97ee;
    assert input[15] = 0x06377d3ecf1c8d11;
    assert input[16] = 0x1830b5a8c2b6b4f1;
    assert input[17] = 0x22b51a513977599c;
    assert input[18] = 0xe9bae1214a41d25c;
    assert input[19] = 0x176b167f0b6c2238;
    assert input[20] = 0xb10d1e374487c747;
    assert input[21] = 0xc466d38f15180f2f;
    assert input[22] = 0xfc1fa50e1cd2d749;
    assert input[23] = 0x4fb0a7ae641a686c;
    assert input[24] = 0xab7bc45b17af4a08;
    assert input[25] = 0x9e2e4b7f7b3cf431;
    assert input[26] = 0xf08e2d870543806d;
    assert input[27] = 0xab38b3ceab048047;
    assert input[28] = 0xd073d494529e9c00;
    assert input[29] = 0x5d98d6698c967366;
    assert input[30] = 0x957f3347e8cec64b;
    assert input[31] = 0x2da97f0dd2c4f483;
    assert input[32] = 0x15471988ef04d59a;
    assert input[33] = 0x08828305df732841;
    assert input[34] = 0x04cb754a2b990c27;
    assert input[35] = 0x8189fd4df1973637;
    assert input[36] = 0xbe1adefc50f501b8;
    assert input[37] = 0x5792ba0804c4c701;
    assert input[38] = 0x80f11accc9880684;
    assert input[39] = 0xf1f9068e49d7c750;
    assert input[40] = 0x6eadf64c1e3ca261;
    assert input[41] = 0x7c6352e4227dab79;
    assert input[42] = 0xb38ae2bdbcf9e1e3;
    assert input[43] = 0xa255e38193e8c8cd;
    assert input[44] = 0xd2475dd3967542e5;
    assert input[45] = 0xc3839a9742f463d2;
    assert input[46] = 0x250e18f30fe8715b;
    assert input[47] = 0x1338869fa83ee848;
    assert input[48] = 0x0259b92eb8355043;
    assert input[49] = 0xd58701c5be53e976;
    assert input[50] = 0x9cc5df254f243879;
    assert input[51] = 0x341da19140619ac8;
    assert input[52] = 0x53c275557e82d3e8;
    assert input[53] = 0x4c3cfda431be0e41;
    assert input[54] = 0x0abe3e879ceec3a7;
    assert input[55] = 0x9629f6ade3bd683d;
    assert input[56] = 0xbb6d82d0a9f2a03e;
    assert input[57] = 0xa8cb34e0f00f5ad8;
    assert input[58] = 0x15d8bf17fedaaad8;
    assert input[59] = 0x657803c3295bea13;
    assert input[60] = 0xb7ee479a503322c4;
    assert input[61] = 0x69c7b3b76ee1d3ec;
    assert input[62] = 0x99e1f2f3d1750250;
    assert input[63] = 0x1b6f32816b6b96de;
    assert input[64] = 0x31d8c20e2b6947ce;
    assert input[65] = 0xab49bcef23e503cf;
    assert input[66] = 0x43b0d6165e238979;
    assert input[67] = 0x35a7bbf9f64bfbdf;
    assert input[68] = 0x23058b7b69cd5a17;
    assert input[69] = 0x904f4874e790cd72;
    assert input[70] = 0x33ea1f775400ae3a;
    assert input[71] = 0xdc6bf331cb933e5b;
    assert input[72] = 0x6229381d9b07a846;
    assert input[73] = 0x45e701d3e76df1b7;
    assert input[74] = 0xf004fc45bf646ed6;
    assert input[75] = 0xd47fb80a87825676;
    assert input[76] = 0x0a929dfe1f0f619d;
    assert input[77] = 0xca6f51d531ca0671;
    assert input[78] = 0x952b076df532c361;
    assert input[79] = 0x5eca2a11bd207e29;
    assert input[80] = 0xa0a79f46f9aed4d5;
    assert input[81] = 0x3f123c80405b93af;
    assert input[82] = 0x398baed6fa438b9a;
    assert input[83] = 0xb2ebc03b722045cc;
    assert input[84] = 0xe63bb09f7f8888e8;
    assert input[85] = 0x347097c6c18ac87f;
    assert input[86] = 0x092daaf0dc406a67;
    assert input[87] = 0x13c309bf7a241e18;
    assert input[88] = 0xd5292e8ac4f13729;
    assert input[89] = 0xf37c22d6b841fdcd;
    assert input[90] = 0x05258200b0d7a695;
    assert input[91] = 0xa1b9e7eacae67c79;
    assert input[92] = 0x0ae008aef57acbbd;
    assert input[93] = 0x03637a815f319b0c;
    assert input[94] = 0xcd26e89c1e0d7258;
    assert input[95] = 0x6cfabc7477df387d;
    assert input[96] = 0xbfa6267f434d49ab;
    assert input[97] = 0x82c38fa63fb215bc;
    assert input[98] = 0x47257b35d9560b04;
    assert input[99] = 0x001b3aa92e146ddc;
    assert input[100] = 0xb992581cd91940a8;
    assert input[101] = 0x48c1d6fc20c2fdab;
    assert input[102] = 0xf96711a1a6087b9e;
    assert input[103] = 0x034623d070460403;
    assert input[104] = 0x000b44360124d7b7;
    assert input[105] = 0x0de8143633ac7fd6;
    assert input[106] = 0x1d72542f736369f3;
    assert input[107] = 0xb4b5a747580c25a1;
    assert input[108] = 0x26acd36125a6fa5a;
    assert input[109] = 0x561057c1cd79c701;
    assert input[110] = 0xb7af03c480af08fa;
    assert input[111] = 0x39bfd49850e8fb20;
    assert input[112] = 0xe2e4f6e753747377;
    assert input[113] = 0x10bfb4d390b4a0f3;
    assert input[114] = 0x383d5b0eb399a204;
    assert input[115] = 0xbf2b95ec417b0f2b;
    assert input[116] = 0x48348b22bd602dc4;
    assert input[117] = 0xc8a9be4c602a4ecf;
    assert input[118] = 0xd1a96cf0f3226442;
    assert input[119] = 0x61e0e64178bac788;
    assert input[120] = 0x8767dd7d953fda97;
    assert input[121] = 0x0d2b18827f6a087f;
    assert input[122] = 0x79c65880aca7aa7f;
    assert input[123] = 0x52da4ee692b35f39;
    assert input[124] = 0x802c170535a9d393;
    assert input[125] = 0xa76ac884ac91a034;
    assert input[126] = 0xd4499f94843f2e30;
    assert input[127] = 0x2ddeddf8a164e816;
    assert input[128] = 0x11a5da45c05cfd17;
    assert input[129] = 0x2946cea19c6d4d0f;
    assert input[130] = 0xd9bc050e269fe72b;
    assert input[131] = 0x4af6dc3010909495;
    assert input[132] = 0xcd018633bd3492c2;
    assert input[133] = 0x80218c9dc2865865;
    assert input[134] = 0x136375da02beb8c8;
    assert input[135] = 0x0469e491af53fd00;
    assert input[136] = 0x3f8731206c30abbb;
    assert input[137] = 0xd30afd6d58fc4314;
    assert input[138] = 0xe5c7b0eee147abe0;
    assert input[139] = 0xfb580b0fe5e513dc;
    assert input[140] = 0xfb8fedee03113562;
    assert input[141] = 0x79fd2095c0b81e6a;
    assert input[142] = 0x43e1a85cdfba2d5e;
    assert input[143] = 0x12ac5b2a402a99b9;
    assert input[144] = 0x2b99320b2d6d5c28;
    assert input[145] = 0x90aa57a5aad5ad0d;
    assert input[146] = 0x571e9e248f057d72;
    assert input[147] = 0xf711031cb1b0ba82;
    assert input[148] = 0x535289c341a4aca9;
    assert input[149] = 0x39ae186075c00f6f;
    assert input[150] = 0x3a113080d2b1d2e4;
    assert input[151] = 0x46669be54d57c499;
    assert input[152] = 0x34bc84ee8d80866e;
    assert input[153] = 0x2c3be72958013600;
    assert input[154] = 0xb7c2ce6bba925ba0;
    assert input[155] = 0xe7eabc76650dd3bf;
    assert input[156] = 0xc22f725a8c147d87;
    assert input[157] = 0x85114b6895722f69;
    assert input[158] = 0xf652980b7c45f2ed;
    assert input[159] = 0x2c282347f10e1897;
    assert input[160] = 0xf4644ab058ce47a9;
    assert input[161] = 0xc7915c572a525ffd;
    assert input[162] = 0x4cea91190e768c7a;
    assert input[163] = 0x64d0fa2dc5d73408;
    assert input[164] = 0x765e9797632b60e7;
    assert input[165] = 0x3ba75e6e976edae0;
    assert input[166] = 0xff0e4a6ff8ddb7b4;
    assert input[167] = 0x445d0d90e0d86a9d;
    assert input[168] = 0x5dda4effe1108a6f;
    assert input[169] = 0x613748291bbef0bb;
    assert input[170] = 0x4459304c6b519516;
    assert input[171] = 0xf4f2d7c3c718404b;
    assert input[172] = 0x9a7e5188398ff0e2;
    assert input[173] = 0xa3c7aa49082467ba;
    assert input[174] = 0x769bfaad3cf608d9;
    assert input[175] = 0xb2f2b603c9c3d0fc;
    assert input[176] = 0xd6f80c5fb7e9decd;
    assert input[177] = 0xcca07a2acc8abe6f;
    assert input[178] = 0x0b5fd1f3355309f4;
    assert input[179] = 0x5be1be4e0039a7ac;
    assert input[180] = 0x56923316b905744b;
    assert input[181] = 0x3c31c9e6646139c6;
    assert input[182] = 0x49c19d14db5c7eda;
    assert input[183] = 0x75afa3f256abb260;
    assert input[184] = 0x9fcb32e43e054cc0;
    assert input[185] = 0x322066ecbe4e4ff3;
    assert input[186] = 0xbf94b7fb8255dda6;
    assert input[187] = 0xd0df8cffadcb7506;
    assert input[188] = 0x496fc61d3fca269f;
    assert input[189] = 0xd6617aa3a5ec844f;
    assert input[190] = 0x07c279732f7cf5cb;
    assert input[191] = 0xa3ab5aebe5ea1781;
    assert input[192] = 0x5bf9d6624e842995;
    assert input[193] = 0x5334b2b837b26076;
    assert input[194] = 0xed4877855e6b2f13;
    assert input[195] = 0xf6ab1c90eb26fa6c;
    assert input[196] = 0x2cc69bbeb9d96cf2;
    assert input[197] = 0x7327554d6eb245c3;
    assert input[198] = 0x27719a84bd814348;
    assert input[199] = 0xbc7bfbb299716767;
    assert input[200] = 0xab453dae4fb8eb78;
    assert input[201] = 0xb5a81f1e406b01be;
    assert input[202] = 0x195bb23beac43e84;
    assert input[203] = 0x8e69d22924f52463;
    assert input[204] = 0xcef4e4dc6dd414b7;
    assert input[205] = 0x812915fd94a290ac;
    assert input[206] = 0x2ac1ecad593df516;
    assert input[207] = 0x218b4e255188c388;
    assert input[208] = 0xcea7015ba3cae78c;
    assert input[209] = 0x24b6e772731b5d78;
    assert input[210] = 0x853af05f846106d7;
    assert input[211] = 0x55323c57735b8eea;
    assert input[212] = 0xb5be33fbd4778c45;
    assert input[213] = 0x9d2d0c86b5c2ed49;
    assert input[214] = 0xbfc4ba05c64aba45;
    assert input[215] = 0x3291950face887f5;
    assert input[216] = 0xda667a4ce213c7a6;
    assert input[217] = 0x616c725243d53e49;
    assert input[218] = 0x972e546f86264d79;
    assert input[219] = 0xa320563f16686ed7;
    assert input[220] = 0x0f2631ac8ceccd36;
    assert input[221] = 0x32719ee065e9d24f;
    assert input[222] = 0xeaa1d49cd168fca7;
    assert input[223] = 0x63cfd4c777d68c13;
    assert input[224] = 0xf7803a971af2abd1;
    assert input[225] = 0x1d3e4167682f04b0;
    assert input[226] = 0xe2cfb3950784a05e;
    assert input[227] = 0xecf23c44468c7cd9;
    assert input[228] = 0xf5a2971ec789593d;
    assert input[229] = 0x48ad140b4fac6ae8;
    assert input[230] = 0x67a925b224c85ffb;
    assert input[231] = 0xc46f6e4502c12b42;
    assert input[232] = 0xcdcbe5db0148a9ad;
    assert input[233] = 0xbea1c1f0b85eb919;
    assert input[234] = 0x9ba1136b256e5806;
    assert input[235] = 0xa5ef90e1dab79496;
    assert input[236] = 0x51d0b60114f4290d;
    assert input[237] = 0x20ae17e59740caf9;
    assert input[238] = 0xae7498fe5ad6bb5f;
    assert input[239] = 0xcb4495882af44e16;
    assert input[240] = 0x69454d718a1ca2c3;
    assert input[241] = 0x6006523c6e2f2095;
    assert input[242] = 0x7d3cb801f8e3b11e;
    assert input[243] = 0x9c40d0e09f388286;
    assert input[244] = 0xd704b9e0965ea2ed;
    assert input[245] = 0xa5226657978afaea;
    assert input[246] = 0xe8d6f5a91117d2c2;
    assert input[247] = 0x33b19de74cbd0aba;
    assert input[248] = 0x8996888f56ce85dd;
    assert input[249] = 0x2365f7a3e77532cc;
    assert input[250] = 0xb9eb3b5ec0e0264f;
    assert input[251] = 0xe0f75f5aed9619fc;
    assert input[252] = 0xe1cc4e6e6af0e600;
    assert input[253] = 0xb9b44f94b8085b0c;
    assert input[254] = 0xed7959e1fe9c2e86;
    assert input[255] = 0x83c1c10805952e9a;
    return ();
}
